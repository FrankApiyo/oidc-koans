"""The records the toy provider keeps: users, sessions, grants and the tokens that point at them."""

from dataclasses import dataclass

ACR_PASSWORD = "urn:toy:acr:pwd"
ACR_MFA = "urn:toy:acr:mfa"
ACR_VALUES = (ACR_PASSWORD, ACR_MFA)
SCOPES = ("openid", "email")


def known_scopes(scope) -> tuple[str, ...]:
    """The scope values this provider understands; OIDC Core 3.1.2.1 ignores the rest."""
    return tuple(value for value in scope if value in SCOPES)


@dataclass(frozen=True)
class User:
    sub: str
    email: str
    email_verified: bool
    password: str
    factors: tuple[str, ...]

    def can_reach(self, acr: str) -> bool:
        return acr == ACR_PASSWORD or (acr == ACR_MFA and bool(self.factors))

    @property
    def claims(self) -> dict:
        return {"email": self.email, "email_verified": self.email_verified}


@dataclass(frozen=True)
class Session:
    """A browser's sign-in. sid names it to clients; clients are those it issued codes to."""

    sub: str
    auth_time: int
    factors: tuple[str, ...]
    login_seq: int
    sid: str = ""
    clients: frozenset[str] = frozenset()

    @property
    def amr(self) -> tuple[str, ...]:
        """RFC 8176 method references; "mfa" is added once two distinct factors were used."""
        return (*self.factors, "mfa") if len(set(self.factors)) > 1 else self.factors

    @property
    def acr(self) -> str:
        return ACR_MFA if len(set(self.factors)) > 1 else ACR_PASSWORD


@dataclass(frozen=True)
class PendingLogin:
    """An authorization request waiting for a sign-in that happens after it."""

    fingerprint: tuple
    login_seq: int


@dataclass(frozen=True)
class Grant:
    grant_id: str
    client_id: str
    sub: str
    scope: tuple[str, ...]
    auth_time: int
    amr: tuple[str, ...]
    acr: str
    acr_requested: bool
    auth_time_included: bool
    id_token_claims: tuple[str, ...]
    userinfo_claims: tuple[str, ...]
    sid: str = ""


@dataclass(frozen=True)
class IssuedCode:
    grant: Grant
    redirect_uri: str
    nonce: str | None
    code_challenge: str | None
    issued_at: int


@dataclass(frozen=True)
class AccessToken:
    grant_id: str
    scope: tuple[str, ...]
    issued_at: int
    expires_at: int
