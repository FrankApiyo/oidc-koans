"""The toy provider's /token endpoint: codes, refresh tokens and their revocation.

Codes are single-use and live 60 seconds. Reusing a code, or a rotated refresh
token, revokes every token of its grant (RFC 6749 §4.1.2, RFC 9700 §4.14.2).
"""

import re
import secrets

from toy.auth_request import AuthRequest
from toy.client import s256
from toy.client_auth import Client, authenticate_client
from toy.errors import OAuthError
from toy.http import Request, Response
from toy.jose import constant_time_equal
from toy.provider_state import AccessToken, Grant, IssuedCode

CODE_LIFETIME = 60
ACCESS_LIFETIME = 300
NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}")


class TokenEndpoint:
    """A mixin; its host supplies issuer, _clock, _clients and _id_token()."""

    def __init__(self):
        self._codes: dict[str, IssuedCode] = {}
        self._spent_codes: dict[str, str] = {}
        self._grants: dict[str, Grant] = {}
        self._access: dict[str, AccessToken] = {}
        self._refresh: dict[str, str] = {}
        self._spent_refresh: dict[str, str] = {}
        self._revoked: frozenset[str] = frozenset()
        self._used_jtis: frozenset[str] = frozenset()

    def _store_code(self, grant: Grant, auth: AuthRequest) -> str:
        code = secrets.token_urlsafe(32)
        issued = IssuedCode(grant, auth.redirect_uri, auth.nonce, auth.code_challenge,
                            self._clock.now())
        self._codes = {**self._codes, code: issued}
        return code

    def _token(self, request: Request) -> Response:
        try:
            if request.method != "POST":
                raise OAuthError("invalid_request", "the token endpoint takes POST")
            client = self._client_of(request)
            grant_type = request.form.get("grant_type")
            if grant_type == "authorization_code":
                body = self._redeem_code(client, request.form)
            elif grant_type == "refresh_token":
                body = self._redeem_refresh(client, request.form)
            else:
                raise OAuthError("unsupported_grant_type", f"grant_type {grant_type!r}")
        except OAuthError as error:
            return _token_error(error)
        return Response(200, dict(NO_STORE), body)

    def _client_of(self, request: Request) -> Client:
        authenticated = authenticate_client(
            request, self._clients, issuer=self.issuer, now=self._clock.now(),
            used_jtis=self._used_jtis,
        )
        if authenticated.jti is not None:
            self._used_jtis = self._used_jtis | {authenticated.jti}
        return authenticated.client

    def _redeem_code(self, client: Client, form: dict) -> dict:
        code = form.get("code", "")
        issued = self._codes.get(code)
        if issued is None:
            self._revoke(self._spent_codes.get(code))
            raise OAuthError("invalid_grant", "unknown, used or expired code")
        self._codes = {k: v for k, v in self._codes.items() if k != code}
        self._spent_codes = {**self._spent_codes, code: issued.grant.grant_id}
        if issued.grant.client_id != client.client_id:
            raise OAuthError("invalid_grant", "the code was issued to another client")
        if self._clock.now() - issued.issued_at >= CODE_LIFETIME:
            raise OAuthError("invalid_grant", "the code has expired")
        if "redirect_uri" not in form:
            raise OAuthError("invalid_request", "redirect_uri is required")
        if form["redirect_uri"] != issued.redirect_uri:
            raise OAuthError("invalid_grant", "redirect_uri differs from the request's")
        _check_verifier(issued.code_challenge, form.get("code_verifier"))
        self._grants = {**self._grants, issued.grant.grant_id: issued.grant}
        return self._issue(issued.grant, client, issued.grant.scope, issued.nonce)

    def _redeem_refresh(self, client: Client, form: dict) -> dict:
        token = form.get("refresh_token", "")
        grant_id = self._refresh.get(token)
        if grant_id is None:
            self._revoke(self._spent_refresh.get(token))
            raise OAuthError("invalid_grant", "unknown or used refresh token")
        grant = self._grants[grant_id]
        if grant_id in self._revoked or grant.client_id != client.client_id:
            raise OAuthError("invalid_grant", "the refresh token is not valid for this client")
        scope = tuple(form["scope"].split()) if "scope" in form else grant.scope
        if not set(scope) <= set(grant.scope):
            raise OAuthError("invalid_scope", "a refresh cannot widen the scope")
        self._refresh = {k: v for k, v in self._refresh.items() if k != token}
        self._spent_refresh = {**self._spent_refresh, token: grant_id}
        return self._issue(grant, client, scope, nonce=None)

    def _issue(self, grant: Grant, client: Client, scope: tuple[str, ...], nonce) -> dict:
        now = self._clock.now()
        access_token, refresh_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        record = AccessToken(grant.grant_id, scope, now, now + ACCESS_LIFETIME)
        self._access = {**self._access, access_token: record}
        self._refresh = {**self._refresh, refresh_token: grant.grant_id}
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_LIFETIME,
            "refresh_token": refresh_token,
            "id_token": self._id_token(grant, client, nonce),
            "scope": " ".join(scope),
        }

    def _revoke(self, grant_id: str | None) -> None:
        if grant_id is not None:
            self._revoked = self._revoked | {grant_id}


def _check_verifier(challenge: str | None, verifier: str | None) -> None:
    """RFC 7636 §4.6, and RFC 9700 §4.8.2: no verifier for a code issued without a challenge."""
    if challenge is None:
        if verifier is not None:
            raise OAuthError("invalid_grant", "this code was issued without a code_challenge")
        return
    if verifier is None or not _VERIFIER.fullmatch(verifier):
        raise OAuthError("invalid_grant", "code_verifier is missing or malformed")
    if not constant_time_equal(s256(verifier).encode("ascii"), challenge.encode("ascii")):
        raise OAuthError("invalid_grant", "code_verifier does not match the code_challenge")


def _token_error(error: OAuthError) -> Response:
    body = {"error": error.error, "error_description": error.description}
    if error.error == "invalid_client":
        return Response(401, {**NO_STORE, "WWW-Authenticate": 'Basic realm="token"'}, body)
    return Response(400, dict(NO_STORE), body)
