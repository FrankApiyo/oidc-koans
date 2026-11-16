"""Parsing an authentication request (OIDC Core 3.1.2.1) whose client and redirect_uri are known."""

import json
import re
from dataclasses import dataclass, field

from toy.errors import OAuthError

_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}")
_SECONDS = re.compile(r"[0-9]+")


@dataclass(frozen=True)
class AuthRequest:
    redirect_uri: str
    scope: tuple[str, ...]
    state: str | None
    nonce: str | None
    code_challenge: str | None
    fingerprint: tuple
    prompts: frozenset[str] = frozenset()
    max_age: int | None = None
    acr_values: tuple[str, ...] = ()
    id_token_hint: str | None = None
    id_token_claims: dict = field(default_factory=dict)
    userinfo_claims: dict = field(default_factory=dict)

    @property
    def acr_requested(self) -> bool:
        return bool(self.acr_values) or "acr" in self.id_token_claims

    @property
    def essential_acr_values(self) -> tuple[str, ...]:
        """The acr values an essential acr claim request demands (OIDC Core 5.5.1.1)."""
        request = self.id_token_claims.get("acr")
        if not isinstance(request, dict) or request.get("essential") is not True:
            return ()
        values = request.get("values", [request.get("value")])
        if not isinstance(values, list):
            return ()
        return tuple(value for value in values if isinstance(value, str))

    @property
    def auth_time_essential(self) -> bool:
        request = self.id_token_claims.get("auth_time")
        return isinstance(request, dict) and request.get("essential") is True

    @property
    def subject_value(self) -> str | None:
        request = self.id_token_claims.get("sub")
        return request.get("value") if isinstance(request, dict) else None


def parse_auth_request(query: dict, *, public_client: bool) -> AuthRequest:
    """An AuthRequest, or OAuthError with the code to send back to the redirect URI."""
    if query.get("response_type") != "code":
        raise OAuthError("unsupported_response_type", "only the code flow is supported")
    scope = tuple(query.get("scope", "").split())
    if "openid" not in scope:
        raise OAuthError("invalid_scope", "an OpenID Connect request needs the openid scope")
    prompts = frozenset(query.get("prompt", "").split())
    if "none" in prompts and len(prompts) > 1:
        raise OAuthError("invalid_request", "prompt=none cannot be combined")
    id_token_claims, userinfo_claims = _claims_request(query.get("claims"))
    return AuthRequest(
        redirect_uri=query["redirect_uri"],
        scope=scope,
        state=query.get("state"),
        nonce=query.get("nonce"),
        code_challenge=_code_challenge(query, public_client),
        fingerprint=tuple(sorted(query.items())),
        prompts=prompts,
        max_age=_max_age(query.get("max_age")),
        acr_values=tuple(query.get("acr_values", "").split()),
        id_token_hint=query.get("id_token_hint"),
        id_token_claims=id_token_claims,
        userinfo_claims=userinfo_claims,
    )


def _code_challenge(query: dict, public_client: bool) -> str | None:
    challenge = query.get("code_challenge")
    method = query.get("code_challenge_method")
    if challenge is None:
        if public_client:
            raise OAuthError("invalid_request", "public clients must send a PKCE code_challenge")
        if method is not None:
            raise OAuthError("invalid_request", "code_challenge_method without code_challenge")
        return None
    if method != "S256":
        raise OAuthError("invalid_request", "code_challenge_method must be S256")
    if not _CHALLENGE.fullmatch(challenge):
        raise OAuthError("invalid_request", "an S256 code_challenge is 43 base64url characters")
    return challenge


def _max_age(text: str | None) -> int | None:
    if text is None:
        return None
    if not _SECONDS.fullmatch(text):
        raise OAuthError("invalid_request", "max_age is a non-negative number of seconds")
    return int(text)


def _claims_request(text: str | None) -> tuple[dict, dict]:
    if text is None:
        return {}, {}
    try:
        request = json.loads(text)
    except json.JSONDecodeError as error:
        raise OAuthError("invalid_request", "claims is not JSON") from error
    if not isinstance(request, dict):
        raise OAuthError("invalid_request", "claims is a JSON object")
    members = (request.get("id_token", {}), request.get("userinfo", {}))
    for member in members:
        if not isinstance(member, dict) or not all(
            value is None or isinstance(value, dict) for value in member.values()
        ):
            raise OAuthError("invalid_request", "each claim request is null or an object")
    return members
