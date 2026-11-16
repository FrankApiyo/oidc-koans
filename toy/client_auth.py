"""How the toy provider authenticates a client at its token endpoint.

Methods: client_secret_basic, client_secret_post, private_key_jwt (with the RFC 10070
audience rule) and none for public clients. A request may use only one.
"""

import base64
import binascii
from dataclasses import dataclass
from urllib.parse import unquote_to_bytes

from toy.errors import InvalidToken, OAuthError
from toy.http import Request
from toy.id_token import numeric_date
from toy.jose import constant_time_equal, jws_split, jws_verify

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
ASSERTION_ALGS = frozenset({"RS256", "ES256"})


@dataclass(frozen=True)
class Client:
    client_id: str
    redirect_uris: tuple[str, ...]
    secret: bytes | None = None
    jwks: dict | None = None
    extra_audiences: tuple[str, ...] = ()
    post_logout_redirect_uris: tuple[str, ...] = ()
    id_token_signed_response_alg: str | None = None

    @property
    def is_public(self) -> bool:
        return self.secret is None and self.jwks is None


@dataclass(frozen=True)
class Authenticated:
    client: Client
    jti: str | None = None


def authenticate_client(
    request: Request, clients: dict, *, issuer: str, now: int, used_jtis: frozenset[str]
) -> Authenticated:
    """The client a token request comes from, or OAuthError invalid_client / invalid_request."""
    basic = _basic_credentials(request.headers)
    form = request.form
    methods = [basic is not None, "client_secret" in form, "client_assertion" in form]
    if sum(methods) > 1:
        raise OAuthError("invalid_request", "use only one client authentication method")
    if basic is not None:
        return Authenticated(_by_secret(clients, form, *basic))
    if "client_secret" in form:
        secret = form["client_secret"].encode("utf-8")
        return Authenticated(_by_secret(clients, form, form.get("client_id", ""), secret))
    if "client_assertion" in form:
        return _by_assertion(clients, form, issuer, now, used_jtis)
    client = clients.get(form.get("client_id", ""))
    if client is None or not client.is_public:
        raise OAuthError("invalid_client", "this client must authenticate")
    return Authenticated(client)


def header(headers: dict, name: str) -> str | None:
    return next((v for k, v in headers.items() if k.lower() == name.lower()), None)


def _basic_credentials(headers: dict) -> tuple[str, bytes] | None:
    value = header(headers, "Authorization")
    if value is None:
        return None
    scheme, _, encoded = value.partition(" ")
    if scheme.lower() != "basic":
        raise OAuthError("invalid_client", f"unsupported scheme {scheme!r}")
    try:
        user, separator, password = base64.b64decode(encoded, validate=True).partition(b":")
    except binascii.Error as error:
        raise OAuthError("invalid_client", "malformed Basic credentials") from error
    if not separator:
        raise OAuthError("invalid_client", "malformed Basic credentials")
    client_id = _form_decode(user).decode("utf-8", errors="replace")
    return client_id, _form_decode(password)


def _form_decode(raw: bytes) -> bytes:
    return unquote_to_bytes(raw.replace(b"+", b" "))


def _by_secret(clients: dict, form: dict, client_id: str, secret: bytes) -> Client:
    if form.get("client_id", client_id) != client_id:
        raise OAuthError("invalid_request", "client_id does not match the credentials")
    client = clients.get(client_id)
    if client is None or client.secret is None or not constant_time_equal(secret, client.secret):
        raise OAuthError("invalid_client", "unknown client or wrong secret")
    return client


def _by_assertion(clients, form, issuer, now, used_jtis) -> Authenticated:
    if form.get("client_assertion_type") != ASSERTION_TYPE:
        raise OAuthError("invalid_client", "unsupported client_assertion_type")
    assertion = form["client_assertion"]
    try:
        client_id = jws_split(assertion)[1].get("iss")
        client = clients.get(client_id) if isinstance(client_id, str) else None
        if client is None or client.jwks is None:
            raise OAuthError("invalid_client", "no keys registered for this client")
        claims = jws_verify(assertion, client.jwks, ASSERTION_ALGS)
        _check_assertion(claims, client.client_id, form, issuer, now, used_jtis)
    except InvalidToken as error:
        raise OAuthError("invalid_client", f"client assertion: {error.reason}") from error
    return Authenticated(client, claims["jti"])


def _check_assertion(claims, client_id, form, issuer, now, used_jtis) -> None:
    if claims.get("sub") != client_id or form.get("client_id", client_id) != client_id:
        raise OAuthError("invalid_client", "iss, sub and client_id must all be the client")
    if claims.get("aud") not in (issuer, [issuer]):
        raise OAuthError("invalid_client", "aud must be the issuer identifier alone")
    if "exp" not in claims or not now < numeric_date(claims, "exp"):
        raise OAuthError("invalid_client", "the assertion has expired")
    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti or jti in used_jtis:
        raise OAuthError("invalid_client", "jti is missing or was used before")
