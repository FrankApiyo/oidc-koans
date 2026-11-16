"""A toy OpenID Provider mounted on a FakeNetwork at its issuer origin.

Endpoints: /.well-known/openid-configuration, /jwks, /authorize, /token, /userinfo
and /logout. /login is where sign_in drives the browser to receive a session cookie.
"""

import secrets
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from toy.auth_request import AuthRequest, parse_auth_request
from toy.client_auth import Client, header
from toy.clock import Clock
from toy.errors import InvalidToken, OAuthError
from toy.http import Browser, FakeNetwork, Request, Response, with_query
from toy.jose import jws_encode, jws_verify, jwks_of, public_jwk
from toy.keys import RSA_1, RSA_3
from toy.profile import SPEC, Profile
from toy.provider_state import (
    ACR_MFA,
    ACR_PASSWORD,
    ACR_VALUES,
    AccessToken,
    Grant,
    PendingLogin,
    Session,
    User,
)
from toy.token_endpoint import TokenEndpoint

__all__ = ["ACR_MFA", "ACR_PASSWORD", "ACR_VALUES", "SPEC", "Profile", "Provider"]

ISSUER = "https://id.example"
TOKEN_LIFETIME = 300
SESSION_COOKIE = "op_session"
PENDING_COOKIE = "op_pending_login"
PASSWORD = "pwd"


@dataclass(frozen=True)
class _LoginNeed:
    reason: str | None = None
    unmet: bool = False
    cookies: dict = field(default_factory=dict)


class Provider(TokenEndpoint):
    """A provider whose users sign in through sign_in(), with no login form.

    prompt=login and max_age=0 need a sign-in after the authorization request,
    and that freshness belongs to the request itself: start the login, receive
    the 401 login_required page, call sign_in(), then reload the same authorize
    URL (browser.history[-1].url) to receive the code. A new authorization
    request, with a new state, needs another sign-in.

    Discovery §3 says RS256 "MUST be included" among the ID token algorithms, so a
    provider whose signing_key is EC also holds an RSA key (rs256_key, RSA_3 unless
    given) and publishes it. A client gets ID tokens signed with the alg it was
    registered with, or with signing_key's alg if it was registered with none.
    """

    def __init__(
        self,
        issuer: str = ISSUER,
        *,
        clock: Clock,
        network: FakeNetwork,
        signing_key=RSA_1,
        kid: str = "k1",
        rs256_key=None,
        profile: Profile = SPEC,
    ):
        super().__init__()
        self.issuer = issuer
        self.profile = profile
        self._clock = clock
        self._alg = _alg_for(signing_key)
        self._signers = _signers(self._alg, signing_key, kid, rs256_key)
        self._clients: dict[str, Client] = {}
        self._users: dict[str, User] = {}
        self._sessions: dict[str, Session] = {}
        self._pending: dict[str, PendingLogin] = {}
        self._tickets: dict[str, tuple[str, tuple[str, ...]]] = {}
        self._login_seq = 0
        network.mount(issuer, self)

    # --- set-up and test oracles ------------------------------------------

    def register_client(
        self,
        client_id: str,
        redirect_uris: list[str],
        secret: bytes | None = None,
        jwks: dict | None = None,
        *,
        extra_audiences: tuple[str, ...] = (),
        post_logout_redirect_uris: list[str] = (),
        id_token_signed_response_alg: str | None = None,
    ) -> None:
        alg = id_token_signed_response_alg
        if alg is not None and alg not in self._signers:
            raise ValueError(f"{self.issuer} cannot sign ID tokens with {alg!r}")
        client = Client(
            client_id, tuple(redirect_uris), secret, jwks,
            tuple(extra_audiences), tuple(post_logout_redirect_uris), alg,
        )
        self._clients = {**self._clients, client_id: client}

    def add_user(
        self, sub: str, email: str, email_verified: bool, password: str,
        factors: tuple[str, ...] = (),
    ) -> None:
        user = User(sub, email, email_verified, password, tuple(factors))
        self._users = {**self._users, sub: user}

    def sign_in(self, browser: Browser, sub: str, factors: tuple[str, ...]) -> None:
        """The user authenticates now with these factors; the browser gets a session cookie."""
        user = self._users.get(sub)
        factors = tuple(factors)
        if user is None:
            raise ValueError(f"no user {sub!r}")
        if not factors or any(f not in (PASSWORD, *user.factors) for f in factors):
            raise ValueError(f"{sub!r} cannot sign in with {factors!r}")
        ticket = secrets.token_urlsafe(16)
        self._tickets = {**self._tickets, ticket: (sub, factors)}
        landed = browser.get(with_query(f"{self.issuer}/login", {"ticket": ticket}))
        if landed.status != 200:
            raise RuntimeError(f"sign-in failed: {landed.body!r}")

    def introspect(self, token: str) -> dict:
        """RFC 7662 introspection, with acr and auth_time as RFC 9470 §6.2 describes."""
        active = self._active(token)
        if active is None:
            return {"active": False}
        record, grant = active
        return {
            "active": True, "iss": self.issuer, "sub": grant.sub, "client_id": grant.client_id,
            "scope": " ".join(record.scope), "token_type": "Bearer",
            "iat": record.issued_at, "exp": record.expires_at,
            "acr": grant.acr, "auth_time": grant.auth_time,
        }

    @property
    def jwks(self) -> dict:
        return jwks_of(*(public_jwk(key, kid) for key, kid in self._signers.values()))

    # --- routing ------------------------------------------------------------

    def __call__(self, request: Request) -> Response:
        routes = {
            "/.well-known/openid-configuration": self._discovery,
            "/jwks": lambda _: Response(200, {}, self.jwks),
            "/authorize": self._authorize,
            "/token": self._token,
            "/userinfo": self._userinfo,
            "/logout": self._logout,
            "/login": self._login,
        }
        handler = routes.get(request.path)
        if handler is None:
            return _page(404, "not_found", request.path)
        return handler(request)

    def _discovery(self, _request: Request) -> Response:
        return Response(200, {}, {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/authorize",
            "token_endpoint": f"{self.issuer}/token",
            "userinfo_endpoint": f"{self.issuer}/userinfo",
            "jwks_uri": f"{self.issuer}/jwks",
            "end_session_endpoint": f"{self.issuer}/logout",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": sorted(self._signers),
            "scopes_supported": ["openid", "email"],
            "claims_parameter_supported": True,
            "acr_values_supported": list(ACR_VALUES),
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic", "client_secret_post", "private_key_jwt", "none",
            ],
            "authorization_response_iss_parameter_supported": True,
        })

    def _login(self, request: Request) -> Response:
        ticket = request.query.get("ticket", "")
        if ticket not in self._tickets:
            return _page(400, "invalid_request", "unknown sign-in ticket")
        sub, factors = self._tickets[ticket]
        self._tickets = {k: v for k, v in self._tickets.items() if k != ticket}
        self._login_seq += 1
        session_id = secrets.token_urlsafe(16)
        replaced = request.cookies.get(SESSION_COOKIE)
        kept = {k: v for k, v in self._sessions.items() if k != replaced}
        session = Session(sub, self._clock.now(), factors, self._login_seq)
        self._sessions = {**kept, session_id: session}
        return Response(200, {}, {"signed_in": sub}, {SESSION_COOKIE: session_id})

    # --- /authorize -----------------------------------------------------------

    def _authorize(self, request: Request) -> Response:
        query = request.query
        client = self._clients.get(query.get("client_id", ""))
        if client is None or query.get("redirect_uri") not in client.redirect_uris:
            return _page(400, "invalid_request", "unknown client_id or unregistered redirect_uri")
        try:
            auth = parse_auth_request(query, public_client=client.is_public)
            return self._authenticate(request, client, auth)
        except OAuthError as error:
            failure = {"error": error.error, "error_description": error.description}
            return self._redirect(query["redirect_uri"], query.get("state"), failure)

    def _authenticate(self, request: Request, client: Client, auth: AuthRequest) -> Response:
        session = self._sessions.get(request.cookies.get(SESSION_COOKIE, ""))
        need = self._login_need(request, session, auth)
        if need.unmet:
            raise OAuthError("unmet_authentication_requirements", need.reason)
        if need.reason and "none" in auth.prompts:
            raise OAuthError("login_required", need.reason)
        if need.reason:
            body = {"error": "login_required", "error_description": need.reason}
            return Response(401, {}, body, need.cookies)
        code = self._issue_code(client, auth, session)
        return self._redirect(auth.redirect_uri, auth.state, {"code": code}, need.cookies)

    def _login_need(self, request, session, auth: AuthRequest) -> _LoginNeed:
        wants_fresh = self._wants_fresh_login(auth)
        reason, unmet = self._why_not_signed_in(request, session, auth, wants_fresh)
        pending_id = request.cookies.get(PENDING_COOKIE)
        if reason is None or unmet:
            done = {PENDING_COOKIE: None} if pending_id else {}
            self._pending = {k: v for k, v in self._pending.items() if k != pending_id}
            return _LoginNeed(reason, unmet, done)
        if not wants_fresh or "none" in auth.prompts:
            return _LoginNeed(reason)
        new_id = secrets.token_urlsafe(16)
        waiting = PendingLogin(auth.fingerprint, self._login_seq)
        self._pending = {
            **{k: v for k, v in self._pending.items() if k != pending_id}, new_id: waiting,
        }
        return _LoginNeed(reason, cookies={PENDING_COOKIE: new_id})

    def _wants_fresh_login(self, auth: AuthRequest) -> bool:
        return (
            ("login" in auth.prompts and self.profile.honours_prompt_login)
            or (auth.max_age == 0 and self.profile.honours_max_age)
            or (bool(auth.acr_values) and self.profile.acr_alone_reauthenticates)
        )

    def _why_not_signed_in(self, request, session, auth, wants_fresh) -> tuple[str | None, bool]:
        if session is None:
            return "nobody is signed in", False
        wanted = self._wanted_subject(auth)
        if wanted is not None and wanted != session.sub:
            return "the request names another user", False
        if wants_fresh and not self._signed_in_since(request, session, auth):
            return "a fresh sign-in is needed", False
        age = self._clock.now() - session.auth_time
        too_old = auth.max_age is not None and auth.max_age > 0 and age > auth.max_age
        if self.profile.honours_max_age and too_old:
            return "the sign-in is older than max_age", False
        return self._acr_shortfall(session, auth)

    def _signed_in_since(self, request, session, auth) -> bool:
        pending = self._pending.get(request.cookies.get(PENDING_COOKIE, ""))
        return (
            pending is not None
            and pending.fingerprint == auth.fingerprint
            and session.login_seq > pending.login_seq
        )

    def _acr_shortfall(self, session: Session, auth: AuthRequest) -> tuple[str | None, bool]:
        essential = auth.essential_acr_values
        wanted = essential or tuple(v for v in auth.acr_values if v in ACR_VALUES)
        if not wanted or session.acr in wanted:
            return None, False
        user = self._users[session.sub]
        if any(user.can_reach(acr) for acr in wanted):
            return "a stronger sign-in is needed", False
        if essential:
            return f"{session.sub!r} cannot reach {list(essential)!r}", True
        return None, False

    def _wanted_subject(self, auth: AuthRequest) -> str | None:
        hinted = None
        if auth.id_token_hint is not None:
            claims = self.verify_own(auth.id_token_hint)
            if claims is None:
                raise OAuthError("invalid_request", "id_token_hint was not issued here")
            hinted = claims.get("sub")
        named = auth.subject_value
        if hinted is not None and named is not None and hinted != named:
            raise OAuthError("invalid_request", "id_token_hint and the sub claim disagree")
        return hinted if hinted is not None else named

    def _issue_code(self, client: Client, auth: AuthRequest, session: Session) -> str:
        auth_time_dropped = (
            auth.max_age == 0
            and not self.profile.auth_time_when_max_age_zero
            and not auth.auth_time_essential
        )
        grant = Grant(
            grant_id=secrets.token_urlsafe(16),
            client_id=client.client_id,
            sub=session.sub,
            scope=auth.scope,
            auth_time=session.auth_time,
            amr=session.amr,
            acr=session.acr,
            acr_requested=auth.acr_requested,
            auth_time_included=not auth_time_dropped,
            id_token_claims=tuple(auth.id_token_claims),
            userinfo_claims=tuple(auth.userinfo_claims),
        )
        return self._store_code(grant, auth)

    def _redirect(self, uri: str, state: str | None, params: dict, cookies=None) -> Response:
        """OIDC Core 16.22 prefers 303 for redirects to the client; RFC 9207 adds iss."""
        with_state = {**params, **({"state": state} if state is not None else {})}
        location = with_query(uri, {**with_state, "iss": self.issuer})
        return Response(303, {"Location": location}, "", dict(cookies or {}))

    # --- ID tokens --------------------------------------------------------------

    def _id_token(self, grant: Grant, client: Client, nonce: str | None) -> str:
        now = self._clock.now()
        several = bool(client.extra_audiences)
        claims = {
            "iss": self.issuer,
            "sub": grant.sub,
            "aud": [client.client_id, *client.extra_audiences] if several else client.client_id,
            "exp": now + TOKEN_LIFETIME,
            "iat": now,
            **({"nonce": nonce} if nonce is not None else {}),
            **({"auth_time": grant.auth_time} if grant.auth_time_included else {}),
            "amr": list(grant.amr),
            **self._assurance(grant),
            **({"azp": client.client_id} if several else {}),
            **self._user_claims(grant.sub, grant.id_token_claims),
        }
        alg = client.id_token_signed_response_alg or self._alg
        key, kid = self._signers[alg]
        return jws_encode({"alg": alg, "kid": kid, "typ": "JWT"}, claims, key)

    def verify_own(self, token: str) -> dict | None:
        """The claims of a token this provider signed, expired or not; None otherwise."""
        try:
            claims = jws_verify(token, self.jwks, frozenset(self._signers))
        except InvalidToken:
            return None
        return claims if claims.get("iss") == self.issuer else None

    def _assurance(self, grant: Grant) -> dict:
        claim = self.profile.assurance_claim
        if not grant.acr_requested or claim == "amr":
            return {}
        return {claim: grant.acr}

    def _user_claims(self, sub: str, names) -> dict:
        claims = self._users[sub].claims
        return {name: claims[name] for name in names if name in claims}

    # --- /userinfo and /logout ----------------------------------------------------

    def _userinfo(self, request: Request) -> Response:
        scheme, _, token = (header(request.headers, "Authorization") or "").partition(" ")
        active = self._active(token) if scheme.lower() == "bearer" else None
        if active is None:
            challenge = 'Bearer error="invalid_token", error_description="not an active token"'
            return Response(401, {"WWW-Authenticate": challenge}, {"error": "invalid_token"})
        record, grant = active
        scoped = ("email", "email_verified") if "email" in record.scope else ()
        claims = self._user_claims(grant.sub, (*scoped, *grant.userinfo_claims))
        return Response(200, {}, {"sub": grant.sub, **claims})

    def _logout(self, request: Request) -> Response:
        params = request.form if request.method == "POST" else request.query
        session_id = request.cookies.get(SESSION_COOKIE)
        self._sessions = {k: v for k, v in self._sessions.items() if k != session_id}
        cleared = {SESSION_COOKIE: None} if session_id else {}
        target = params.get("post_logout_redirect_uri")
        if target is None:
            return Response(200, {}, {"signed_out": True}, cleared)
        client = self._logout_client(params)
        if client is None or target not in client.post_logout_redirect_uris:
            return Response(400, {}, _error("invalid_request", "cannot redirect there"), cleared)
        state = params.get("state")
        location = with_query(target, {"state": state}) if state is not None else target
        return Response(303, {"Location": location}, "", cleared)

    def _logout_client(self, params: dict) -> Client | None:
        """RP-Initiated Logout: the client named by a valid id_token_hint (and client_id)."""
        claims = self.verify_own(params.get("id_token_hint", ""))
        if claims is None:
            return None
        aud = claims.get("aud")
        audiences = [aud] if isinstance(aud, str) else list(aud or [])
        client_id = params.get("client_id", claims.get("azp", audiences[0] if audiences else None))
        return self._clients.get(client_id) if client_id in audiences else None

    def _active(self, token: str) -> tuple[AccessToken, Grant] | None:
        record = self._access.get(token)
        if record is None or record.grant_id in self._revoked:
            return None
        if not self._clock.now() < record.expires_at:
            return None
        return record, self._grants[record.grant_id]


def _signers(alg: str, signing_key, kid: str, rs256_key) -> dict[str, tuple]:
    """Each ID token alg this provider signs with, and its key and kid."""
    if alg == "RS256":
        if rs256_key is not None:
            raise ValueError("an RSA provider signs RS256 with its signing_key")
        return {alg: (signing_key, kid)}
    return {alg: (signing_key, kid), "RS256": (rs256_key or RSA_3, f"{kid}-rs256")}


def _alg_for(key) -> str:
    if isinstance(key, rsa.RSAPrivateKey):
        return "RS256"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return "ES256"
    raise ValueError("the toy provider signs with an RSA or P-256 key")


def _error(error: str, description: str) -> dict:
    return {"error": error, "error_description": description}


def _page(status: int, error: str, description: str) -> Response:
    return Response(status, {}, _error(error, description))
