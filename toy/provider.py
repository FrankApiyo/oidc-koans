"""A toy OpenID Provider mounted on a FakeNetwork at its issuer origin.

Endpoints: /.well-known/openid-configuration, /jwks, /authorize, /token, /userinfo
and /logout. /login is where sign_in drives the browser to receive a session cookie.
"""

import secrets
from dataclasses import dataclass, field, replace

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from toy.auth_request import AuthRequest, parse_auth_request
from toy.client_auth import Client, header
from toy.clock import Clock
from toy.errors import InvalidToken, OAuthError
from toy.http import Browser, FakeNetwork, Request, Response, with_query
from toy.jose import constant_time_equal, jws_encode, jws_verify, jwks_of, public_jwk
from toy.keys import RSA_1, RSA_3
from toy.logout import LOGOUT_EVENT, post_logout_target
from toy.profile import SPEC, Profile
from toy.provider_state import (
    ACR_MFA,
    ACR_PASSWORD,
    ACR_VALUES,
    SCOPES,
    AccessToken,
    Grant,
    PendingLogin,
    Session,
    User,
    known_scopes,
)
from toy.token_endpoint import TokenEndpoint

__all__ = ["ACR_MFA", "ACR_PASSWORD", "ACR_VALUES", "SPEC", "Profile", "Provider"]

ISSUER = "https://id.example"
TOKEN_LIFETIME = 300
LOGOUT_TOKEN_LIFETIME = 120
LOGOUT_CONFIRMATION_LIFETIME = 300
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
    That default is this toy's choice: Dynamic Client Registration §2 says of
    id_token_signed_response_alg, "The default, if omitted, is RS256."
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
        self._standby: dict[str, object] = {}
        self._clients: dict[str, Client] = {}
        self._users: dict[str, User] = {}
        self._sessions: dict[str, Session] = {}
        self._pending: dict[str, PendingLogin] = {}
        self._tickets: dict[str, tuple[str, tuple[str, ...]]] = {}
        self._logout_confirmations: dict[str, tuple[str, int]] = {}
        self._login_seq = 0
        self._network = network
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
        backchannel_logout_uri: str | None = None,
    ) -> None:
        """A client registered with a backchannel_logout_uri gets sid in its ID tokens."""
        alg = id_token_signed_response_alg
        if alg is not None and alg not in self._signers:
            raise ValueError(f"{self.issuer} cannot sign ID tokens with {alg!r}")
        client = Client(
            client_id, tuple(redirect_uris), secret, jwks,
            tuple(extra_audiences), tuple(post_logout_redirect_uris), alg, backchannel_logout_uri,
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
        published = (*self._signers.values(), *((key, kid) for kid, key in self._standby.items()))
        return jwks_of(*(public_jwk(key, kid) for key, kid in published))

    # --- key rotation (OIDC Core 10.1.1) ----------------------------------------

    def publish_key(self, key, kid: str) -> None:
        """Add a key to the JWK Set without signing with it yet."""
        if kid in self._kids():
            raise ValueError(f"{self.issuer} already publishes a key {kid!r}")
        _alg_for(key)
        self._standby = {**self._standby, kid: key}

    def sign_with(self, kid: str) -> None:
        """Sign ID tokens with a published key from now on; the key it replaces stays published."""
        key = self._standby.get(kid)
        if key is None:
            raise ValueError(f"publish {kid!r} before signing with it")
        alg = _alg_for(key)
        if alg not in self._signers:
            raise ValueError(f"{self.issuer} does not sign {alg} ID tokens")
        old_key, old_kid = self._signers[alg]
        self._signers = {**self._signers, alg: (key, kid)}
        kept = {k: v for k, v in self._standby.items() if k != kid}
        self._standby = {**kept, old_kid: old_key}

    def retire_key(self, kid: str) -> None:
        """Remove a key that no longer signs from the JWK Set."""
        if any(signing_kid == kid for _, signing_kid in self._signers.values()):
            raise ValueError(f"{kid!r} is in use: sign with another key first")
        if kid not in self._standby:
            raise ValueError(f"{self.issuer} publishes no key {kid!r}")
        self._standby = {k: v for k, v in self._standby.items() if k != kid}

    def _kids(self) -> frozenset[str]:
        return frozenset(kid for _, kid in self._signers.values()) | self._standby.keys()

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
            "scopes_supported": list(SCOPES),
            "claims_parameter_supported": True,
            "acr_values_supported": list(ACR_VALUES),
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic", "client_secret_post", "private_key_jwt", "none",
            ],
            "authorization_response_iss_parameter_supported": True,
            "backchannel_logout_supported": True,
            "backchannel_logout_session_supported": True,
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
        previous = self._sessions.get(replaced or "")
        if previous is not None and previous.sub == sub:
            session = replace(session, sid=previous.sid, clients=previous.clients)
        else:
            session = replace(session, sid=secrets.token_urlsafe(16))
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
        session_id = request.cookies[SESSION_COOKIE]
        joined = replace(session, clients=session.clients | {client.client_id})
        self._sessions = {**self._sessions, session_id: joined}
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
            scope=known_scopes(auth.scope),
            auth_time=session.auth_time,
            amr=session.amr,
            acr=session.acr,
            acr_requested=auth.acr_requested,
            auth_time_included=not auth_time_dropped,
            id_token_claims=tuple(auth.id_token_claims),
            userinfo_claims=tuple(auth.userinfo_claims),
            sid=session.sid,
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
            **({"sid": grant.sid} if client.backchannel_logout_uri else {}),
            **self._user_claims(grant.sub, grant.id_token_claims),
        }
        return self._sign(client, "JWT", claims)

    def logout_token(
        self, client_id: str, *, sub: str | None = None, sid: str | None = None
    ) -> str:
        """A Back-Channel Logout Token for this client, issued now, naming sub, sid or both."""
        now = self._clock.now()
        named = {name: value for name, value in (("sub", sub), ("sid", sid)) if value is not None}
        claims = {
            "iss": self.issuer, **named, "aud": client_id, "iat": now,
            "exp": now + LOGOUT_TOKEN_LIFETIME, "jti": secrets.token_urlsafe(16),
            "events": {LOGOUT_EVENT: {}},
        }
        return self._sign(self._clients[client_id], "logout+jwt", claims)

    def _sign(self, client: Client, typ: str, claims: dict) -> str:
        alg = client.id_token_signed_response_alg or self._alg
        key, kid = self._signers[alg]
        return jws_encode({"alg": alg, "kid": kid, "typ": typ}, claims, key)

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
        if scheme.lower() != "bearer" or not token:
            return Response(401, {"WWW-Authenticate": "Bearer"}, {})
        active = self._active(token)
        if active is None:
            challenge = 'Bearer error="invalid_token", error_description="not an active token"'
            return Response(401, {"WWW-Authenticate": challenge}, {"error": "invalid_token"})
        record, grant = active
        scoped = ("email", "email_verified") if "email" in record.scope else ()
        claims = self._user_claims(grant.sub, (*scoped, *grant.userinfo_claims))
        return Response(200, {}, {"sub": grant.sub, **claims})

    def _logout(self, request: Request) -> Response:
        """RP-Initiated Logout. RP-Initiated Logout §2: the OP MUST ask the user first when
        no id_token_hint was sent, or when the hint is not for this browser's session. This
        toy asks with a page carrying a confirmation; the user's yes is a POST of the same
        parameters plus that confirmation, from the same session, within
        LOGOUT_CONFIRMATION_LIFETIME seconds. Nothing ends before then."""
        params = request.form if request.method == "POST" else request.query
        session_id = request.cookies.get(SESSION_COOKIE) or ""
        session = self._sessions.get(session_id)
        if session is not None and not (
            self._hint_is_for(session, params) or self._confirmed(session_id, request)
        ):
            return self._ask_before_logout(session_id)
        self._logout_confirmations = {
            k: v for k, v in self._logout_confirmations.items() if k != session_id
        }
        self._sessions = {k: v for k, v in self._sessions.items() if k != session_id}
        cleared = {SESSION_COOKIE: None} if session_id else {}
        if session is not None:
            self._notify_logout(session)
        if "post_logout_redirect_uri" not in params:
            return Response(200, {}, {"signed_out": True}, cleared)
        registered = {cid: c.post_logout_redirect_uris for cid, c in self._clients.items()}
        target = post_logout_target(params, registered, self.verify_own)
        if target is None:
            return Response(400, {}, _error("invalid_request", "cannot redirect there"), cleared)
        state = params.get("state")
        location = with_query(target, {"state": state}) if state is not None else target
        return Response(303, {"Location": location}, "", cleared)

    def _hint_is_for(self, session: Session, params: dict) -> bool:
        """A hint this provider signed, for the session's user and, with a sid, that session."""
        claims = self.verify_own(params.get("id_token_hint", ""))
        if claims is None or claims.get("sub") != session.sub:
            return False
        return "sid" not in claims or claims["sid"] == session.sid

    def _confirmed(self, session_id: str, request: Request) -> bool:
        pending = self._logout_confirmations.get(session_id)
        offered = request.form.get("confirmation")
        if request.method != "POST" or pending is None or not isinstance(offered, str):
            return False
        expected, asked_at = pending
        in_time = self._clock.now() < asked_at + LOGOUT_CONFIRMATION_LIFETIME
        return in_time and constant_time_equal(offered.encode(), expected.encode())

    def _ask_before_logout(self, session_id: str) -> Response:
        confirmation = secrets.token_urlsafe(16)
        asked = {session_id: (confirmation, self._clock.now())}
        self._logout_confirmations = {**self._logout_confirmations, **asked}
        return Response(200, {}, {"confirm_logout": True, "confirmation": confirmation})

    def _notify_logout(self, session: Session) -> None:
        """Back-Channel Logout: POST a Logout Token to each of the session's clients that
        registered a backchannel_logout_uri. The answer changes nothing here."""
        for client_id in sorted(session.clients):
            uri = self._clients[client_id].backchannel_logout_uri
            if uri is not None:
                token = self.logout_token(client_id, sub=session.sub, sid=session.sid)
                self._network.send(Request("POST", uri, form={"logout_token": token}))

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
