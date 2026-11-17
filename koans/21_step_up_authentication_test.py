"""Step-up authentication (RFC 9470), and binding to the user.

Some actions need more than the sign-in a session began with. A resource
that wants a stronger or more recent sign-in answers 401 with
error="insufficient_user_authentication": "The authentication event
associated with the access token presented with the request does not meet
the authentication requirements of the protected resource". Its acr_values
and max_age say what would; max_age "has to represent a non-negative
integer". The client "SHOULD parse the WWW-Authenticate header for
acr_values and max_age and use them, if present, in constructing an
authorization request". RFC 9470 changes nothing in how the provider
handles those parameters.

To the client a step-up is a login of its own: its own state, nonce and
verifier, bound to the browser beside any other, kept with the session,
the action and its parameters. The answer counts only from the same user.
Core §5.7: iss and sub, "used together, are the only Claims that an RP can
rely upon as a stable identifier". That check is the app's job; RFC 9470
does not make it. The sign-in must also be fresh, auth_time after the
step-up began, at an acr read from the token, never from the request.

It buys a grant for one action with those parameters, for one user in one
session, for a short time. Spend it once: check and remove it in one step.

A common mistake: trusting whoever signs in during a step-up.

Read more:
  https://www.rfc-editor.org/rfc/rfc9470.html#section-3
  https://www.rfc-editor.org/rfc/rfc9470.html#section-4
  https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability
"""

import asyncio
import hashlib
import hmac
import secrets
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit

from conftest import __
from toy.client import (
    STATE_COOKIE,
    Transaction,
    bind_state,
    exchange_code,
    finish_login,
    parse_challenge,
    release_state,
    start_login,
)
from toy.clock import Clock
from toy.errors import FlowError, Forbidden, InvalidToken, OAuthError
from toy.http import Browser, FakeNetwork, Request, Response
from toy.id_token import numeric_date
from toy.keys import EC_1
from toy.provider import ACR_MFA, ACR_PASSWORD, Provider
from toy.resource import ResourceServer
from toy.step_up import PendingStepUp, StepUpGrant

ISSUER = "https://id.example"
OTHER_ISSUER = "https://other-id.example"
APP = "https://app.example"
API = "https://api.example"
REDIRECT_URI = f"{APP}/callback"
CLIENT_ID = "app"
SESSION_COOKIE = "session"
OP_SESSION_COOKIE = "op_session"
SIGN_IN_TAKES = 20
LEEWAY = 5
STEP_UP = {"acr_values": ACR_MFA, "max_age": 0}
PENDING_LIFETIME = 600
GRANT_LIFETIME = 300
TRANSFER = {"to": "bob", "amount": "10"}
ALICE = (ISSUER, "alice")


def check_same_user(claims: dict, user_key: tuple[str, str]) -> None:
    __()


def check_step_up(claims: dict, pending: PendingStepUp, now: int, leeway: int) -> None:
    __()


def grant_refusal(
    grant: StepUpGrant, *, user_key: tuple, session_id: str, action: str, params, now: int
) -> str | None:
    __()


def take_grant(
    grants: dict, grant_id: str, refusal: Callable[[StepUpGrant], str | None]
) -> tuple[StepUpGrant | None, str | None, dict]:
    __()


class Bank:
    """Moves money. A transfer waits once on the bank's systems before it is booked."""

    def __init__(self):
        self.transfers: tuple[dict, ...] = ()

    async def transfer(self, *, to: str, amount: str) -> None:
        await asyncio.sleep(0)
        self.transfers = (*self.transfers, {"to": to, "amount": amount})


class _TokenTap:
    """The network as finish_login sees it, keeping the ID token of the token response."""

    def __init__(self, network: FakeNetwork):
        self._network = network
        self.id_token = None

    def send(self, request: Request) -> Response:
        response = self._network.send(request)
        if isinstance(response.body, dict) and "id_token" in response.body:
            self.id_token = response.body["id_token"]
        return response


class App:
    """app.example, signed in through id.example, with server-side sessions of (iss, sub).

    GET /login starts a login. POST /step-up, with the session's csrf token (from GET
    /me) and a transfer's to and amount, starts a step-up: its own transaction, sending
    STEP_UP and the session's ID token as id_token_hint, kept for that session for
    PENDING_LIFETIME seconds. Each binds its state into STATE_COOKIE beside any other.
    /callback finds the transaction by state and acts on its stored purpose. A login
    signs the browser in under a new session id. A step-up must belong to the browser's
    session and be in time; finish_login, then your check_step_up, then a grant for its
    transfer, for GRANT_LIFETIME seconds. transfer() spends a grant.
    """

    def __init__(self, clock: Clock, network: FakeNetwork, bank: Bank):
        self.clock, self.bank, self._network = clock, bank, network
        discovery = Request("GET", f"{ISSUER}/.well-known/openid-configuration")
        self._config = network.send(discovery).body
        self._jwks = network.send(Request("GET", self._config["jwks_uri"])).body
        self._csrf_key = secrets.token_bytes(32)
        self._started: dict[str, Transaction | PendingStepUp] = {}
        self.sessions: dict[str, tuple[str, str]] = {}
        self.id_tokens: dict[str, str] = {}
        self.grants: dict[str, StepUpGrant] = {}

    def __call__(self, request: Request) -> Response:
        routes = {"/login": self._login, "/step-up": self._step_up,
                  "/callback": self._callback, "/me": self._me}
        route = routes.get(request.path)
        return route(request) if route else Response(404, {}, {"error": "not_found"})

    def csrf_ok(self, session_id: str, sent) -> bool:
        expected = hmac.new(self._csrf_key, session_id.encode(), hashlib.sha256).hexdigest()
        return isinstance(sent, str) and hmac.compare_digest(sent.encode(), expected.encode())

    def _me(self, request: Request) -> Response:
        session = request.cookies.get(SESSION_COOKIE, "")
        if session not in self.sessions:
            return Response(401, {}, {"error": "login_required"})
        csrf = hmac.new(self._csrf_key, session.encode(), hashlib.sha256).hexdigest()
        return Response(200, {}, {"sub": self.sessions[session][1], "csrf": csrf})

    def _begin(self, request: Request, extra: dict, record=None) -> Response:
        url, transaction = start_login(
            issuer_config=self._config, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI,
            now=self.clock.now(), extra=extra, purpose="login" if record is None else "step_up",
        )
        kept = record(transaction) if record else transaction
        self._started = {**self._started, transaction.state: kept}
        bound = bind_state(request.cookies.get(STATE_COOKIE), transaction.state)
        return Response(303, {"Location": url}, "", {STATE_COOKIE: bound})

    def _login(self, request: Request) -> Response:
        return self._begin(request, {})

    def _step_up(self, request: Request) -> Response:
        session = request.cookies.get(SESSION_COOKIE, "")
        if session not in self.sessions:
            return Response(401, {}, {"error": "login_required"})
        if not self.csrf_ok(session, request.form.get("csrf")):
            return Response(403, {}, {"error": "csrf"})
        params = {"to": request.form.get("to", ""), "amount": request.form.get("amount", "")}
        expires_at = self.clock.now() + PENDING_LIFETIME
        extra = {**STEP_UP, "id_token_hint": self.id_tokens[session]}
        return self._begin(request, extra, lambda transaction: PendingStepUp(
            transaction, self.sessions[session], session, "transfer", params,
            frozenset({ACR_MFA}), expires_at,
        ))

    def _callback(self, request: Request) -> Response:
        state = request.query.get("state", "")
        started = self._started.get(state)
        if started is None:
            return Response(401, {}, {"error": "state_mismatch"})
        self._started = {k: v for k, v in self._started.items() if k != state}
        cookies = {STATE_COOKIE: release_state(request.cookies.get(STATE_COOKIE), state)}
        session = request.cookies.get(SESSION_COOKIE, "")
        transaction = started.transaction if isinstance(started, PendingStepUp) else started
        pending = started if transaction.purpose == "step_up" else None
        if pending is not None and not (
            hmac.compare_digest(pending.session_id.encode(), session.encode())
            and session in self.sessions and self.clock.now() < pending.expires_at
        ):
            return Response(401, {}, {"error": "step_up_expired"}, cookies)
        tap = _TokenTap(self._network)
        try:
            claims = finish_login(
                transaction=transaction, callback=request,
                issuer_config=self._config, client_id=CLIENT_ID, jwks=self._jwks,
                network=tap, now=self.clock.now(),
            )
            if pending is not None:
                check_step_up(claims, pending, self.clock.now(), LEEWAY)
        except (FlowError, InvalidToken) as refused:
            return Response(401, {}, {"error": refused.reason}, cookies)
        except OAuthError as refused:
            return Response(401, {}, {"error": refused.error}, cookies)
        if pending is not None:
            return Response(200, {}, {"grant": self._grant(pending, claims)}, cookies)
        return self._sign_in(claims, session, tap.id_token, cookies)

    def _grant(self, pending: PendingStepUp, claims: dict) -> str:
        grant_id = secrets.token_urlsafe(16)
        grant = StepUpGrant(pending.user_key, pending.session_id, pending.action,
                            pending.params, claims["acr"], self.clock.now() + GRANT_LIFETIME)
        self.grants = {**self.grants, grant_id: grant}
        return grant_id

    def _sign_in(self, claims: dict, brought: str, id_token: str, cookies: dict) -> Response:
        session = secrets.token_urlsafe(16)
        self.sessions = {
            **{k: v for k, v in self.sessions.items() if k != brought},
            session: (claims["iss"], claims["sub"]),
        }
        self.id_tokens = {**{k: v for k, v in self.id_tokens.items() if k != brought},
                          session: id_token}
        self.grants = {k: v for k, v in self.grants.items() if v.session_id != brought}
        return Response(200, {}, {"sub": claims["sub"]}, {**cookies, SESSION_COOKIE: session})

    async def transfer(self, session_id: str, csrf: str, grant_id: str, transfer: dict) -> str:
        """Spend a grant on a transfer, through your take_grant and grant_refusal."""
        user_key = self.sessions.get(session_id)
        if user_key is None:
            raise Forbidden("user")
        if not self.csrf_ok(session_id, csrf):
            raise Forbidden("csrf")
        grant, reason, self.grants = take_grant(self.grants, grant_id, lambda grant: (
            grant_refusal(grant, user_key=user_key, session_id=session_id, action="transfer",
                          params=transfer, now=self.clock.now())
        ))
        if grant is None:
            raise Forbidden(reason)
        await self.bank.transfer(**transfer)
        return "ok"


@dataclass(frozen=True)
class World:
    clock: Clock
    network: FakeNetwork
    provider: Provider
    other: Provider
    app: App


def _world() -> World:
    """id.example, where alice and mallory each have a password and a one-time password,
    and other-id.example, where the account named alice belongs to someone else. app is a
    client of both; its pages sign in through id.example."""
    clock, network = Clock(), FakeNetwork()
    provider = Provider(ISSUER, clock=clock, network=network)
    other = Provider(OTHER_ISSUER, clock=clock, network=network, signing_key=EC_1, kid="o1")
    for op in (provider, other):
        op.register_client(CLIENT_ID, [REDIRECT_URI])
    provider.add_user("alice", "alice@example.com", True, "alice-password", factors=("otp",))
    provider.add_user("mallory", "mallory@example.com", True, "mallory-password", ("otp",))
    other.add_user("alice", "alice@example.com", False, "not-alices-password", ("otp",))
    app = App(clock, network, Bank())
    network.mount(APP, app)
    return World(clock, network, provider, other, app)


def _op(world: World, issuer: str) -> Provider:
    return world.provider if issuer == ISSUER else world.other


def _config(world: World, issuer: str) -> dict:
    return world.network.send(Request("GET", f"{issuer}/.well-known/openid-configuration")).body


def _signed_in(world: World, sub: str = "alice", factors=("pwd",)) -> Browser:
    """A browser in which sub signed in at id.example and to app an hour ago."""
    browser = Browser(world.network)
    world.provider.sign_in(browser, sub, factors)
    assert browser.get(f"{APP}/login").body == {"sub": sub}
    world.clock.advance(3600)
    return browser


def _sign_in_for(
    world: World, browser: Browser, sub: str, extra: dict, factors=("pwd",),
    issuer: str = ISSUER,
) -> tuple[dict, Transaction]:
    """A login like app's, finished here rather than at app's callback. When the
    provider asks for a sign-in, sub takes SIGN_IN_TAKES seconds with factors and the
    browser reloads the same authorize URL. Returns the claims and the transaction."""
    config = _config(world, issuer)
    url, transaction = start_login(
        issuer_config=config, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI,
        now=world.clock.now(), extra=extra, purpose="step_up",
    )
    if browser.get(url).status == 401:
        world.clock.advance(SIGN_IN_TAKES)
        _op(world, issuer).sign_in(browser, sub, factors)
        browser.get(url)
    bound = {STATE_COOKIE: bind_state(None, transaction.state)}
    claims = finish_login(
        transaction=transaction, callback=Request("GET", browser.history[-1].url, cookies=bound),
        issuer_config=config, client_id=CLIENT_ID,
        jwks=world.network.send(Request("GET", config["jwks_uri"])).body,
        network=world.network, now=world.clock.now(),
    )
    return claims, transaction


def _session(browser: Browser) -> tuple[str, str]:
    """The browser's app session id, and the csrf token app's pages post with it."""
    return browser.cookies(APP)[SESSION_COOKIE], browser.get(f"{APP}/me").body["csrf"]


def _start_step_up(browser: Browser, transfer: dict = TRANSFER) -> Response:
    """app's transfer page posts to /step-up; the browser follows to id.example."""
    return browser.post(f"{APP}/step-up", {"csrf": _session(browser)[1], **transfer})


def _granted(world: World, browser: Browser, transfer: dict = TRANSFER) -> str:
    """A step-up for transfer, with a fresh sign-in by password and one-time password."""
    assert _start_step_up(browser, transfer).status == 401
    sub = world.app.sessions[browser.cookies(APP)[SESSION_COOKIE]][1]
    return _answer(world, browser, browser.history[-1].url, sub).body["grant"]


def _answer(world: World, browser: Browser, url: str, sub: str) -> Response:
    """Open an authorize URL; when id.example asks for a sign-in, sub signs in with a
    password and a one-time password, taking SIGN_IN_TAKES seconds, and reloads it."""
    answer = browser.get(url)
    if answer.status == 401:
        world.clock.advance(SIGN_IN_TAKES)
        world.provider.sign_in(browser, sub, ("pwd", "otp"))
        answer = browser.get(url)
    return answer


def _edited(browser: Browser, without: str) -> str:
    """The authorize URL the browser last loaded, without one parameter."""
    url = urlsplit(browser.history[-1].url)
    query = {k: v for k, v in parse_qsl(url.query) if k != without}
    return f"{url.scheme}://{url.netloc}{url.path}?{urlencode(query)}"


def _without(claims: dict, name: str) -> dict:
    return {key: value for key, value in claims.items() if key != name}


def _reason(check: Callable) -> str | None:
    try:
        check()
    except InvalidToken as refused:
        return refused.reason
    return None


def _forbidden(attempt: Coroutine) -> str | None:
    try:
        asyncio.run(attempt)
    except Forbidden as refused:
        return refused.reason
    return None


def test_the_api_says_what_it_needs():
    """api.example demands MFA and a sign-in at most 60 seconds old, and asks id.example about each token (RFC 7662). alice's token is from a password sign-in two minutes ago. Write the challenge exactly as RFC 9470 §3 shapes it: quoted auth-params, separated by commas. The API checks the token first, so a made-up one learns nothing of its needs: §9 says a challenge before that check "will leak the required properties". What goes into app's next authorization request?"""
    world = _world()
    ResourceServer(API, network=world.network, clock=world.clock,
                   introspect=world.provider.introspect, acr_values=(ACR_MFA,), max_age=60)
    browser = Browser(world.network)
    world.provider.sign_in(browser, "alice", ("pwd",))
    url, transaction = start_login(issuer_config=_config(world, ISSUER), client_id=CLIENT_ID,
                                   redirect_uri=REDIRECT_URI, now=world.clock.now())
    answer = world.network.send(Request("GET", url, cookies=browser.cookies(ISSUER)))
    token = exchange_code(
        issuer_config=_config(world, ISSUER), client_id=CLIENT_ID, redirect_uri=REDIRECT_URI,
        code=Request("GET", answer.location).query["code"],
        code_verifier=transaction.code_verifier, network=world.network,
    )["access_token"]
    world.clock.advance(120)

    def call(bearer: str) -> Response:
        return world.network.send(Request("GET", f"{API}/statement",
                                          headers={"Authorization": f"Bearer {bearer}"}))

    weak = call(token)
    assert weak.status == __
    assert weak.headers["WWW-Authenticate"] == __
    challenge = parse_challenge(weak.headers["WWW-Authenticate"])
    assert challenge["max_age"] == __
    probe = parse_challenge(call("made-up").headers["WWW-Authenticate"])
    assert (probe["error"], "acr_values" in probe) == __
    asked = {name: challenge[name] for name in ("acr_values", "max_age") if name in challenge}
    assert asked == __


def test_accepts_the_same_user_signing_in_again():
    """Implement check_same_user above. user_key is the (iss, sub) of app's signed-in user. Raise InvalidToken("wrong_issuer") unless claims["iss"] is its iss, then InvalidToken("sub_mismatch") unless claims["sub"] is its sub. Core §5.7: a sub is "locally unique and never reassigned within the Issuer", so it means nothing without its issuer, and email "MUST NOT be used as unique identifiers for the End-User". alice signs in again at id.example; then, at other-id.example, the holder of the account named alice signs in, with alice's address on it."""
    world = _world()
    alice = _signed_in(world)
    again, _ = _sign_in_for(world, alice, "alice", {"max_age": 0})
    assert check_same_user(again, ALICE) is None
    elsewhere = Browser(world.network)
    namesake, _ = _sign_in_for(world, elsewhere, "alice", {}, issuer=OTHER_ISSUER)
    assert (namesake["sub"], namesake["email"]) == (again["sub"], again["email"])
    assert namesake["iss"] == __
    assert _reason(lambda: check_same_user(namesake, ALICE)) == __
    rows = [
        ({**again, "sub": "mallory"}, __),
        ({**again, "sub": "ALICE"}, "sub_mismatch"),
        ({**again, "sub": ""}, "sub_mismatch"),
        (_without(again, "sub"), "sub_mismatch"),
        ({**again, "iss": [ISSUER]}, "wrong_issuer"),
        ({**again, "iss": f"{ISSUER}/"}, "wrong_issuer"),
    ]
    for claims, reason in rows:
        assert _reason(lambda: check_same_user(claims, ALICE)) == reason


def test_accepts_a_fresh_step_up():
    """Implement check_step_up above, which app runs once finish_login has accepted a step-up's ID token: check_same_user against pending.user_key; then InvalidToken("nonce_mismatch") unless claims["nonce"] is a string equal to pending.transaction.nonce (compare with hmac.compare_digest); then auth_time, as chapter 20's check_fresh did, against pending.transaction.started_at; then InvalidToken("acr_not_met") unless the token's acr is a string in pending.required_acr. alice signed in with her password an hour ago. app sends STEP_UP: max_age=0, which Core §3.1.2.1 says "is equivalent to prompt=login", so id.example asks her to sign in and she reloads the same authorize URL. How long after the step-up began did she sign in, and at what level?"""
    world = _world()
    alice = _signed_in(world)
    claims, transaction = _sign_in_for(world, alice, "alice", STEP_UP, ("pwd", "otp"))
    pending = PendingStepUp(transaction, ALICE, "s1", "transfer", TRANSFER,
                            frozenset({ACR_MFA}), transaction.started_at + PENDING_LIFETIME)
    now = world.clock.now()
    assert claims["auth_time"] - transaction.started_at == __
    assert claims["acr"] == __
    assert check_step_up(claims, pending, now, LEEWAY) is None
    started = transaction.started_at
    for auth_time in (started, started - LEEWAY, now + LEEWAY, started + 0.5):
        assert check_step_up({**claims, "auth_time": auth_time}, pending, now, LEEWAY) is None


def test_refuses_a_step_up_answered_from_an_old_session():
    """mallory stole alice's id.example session cookie and her app session. alice signed in with both factors eight hours ago, so the provider's session is MFA. mallory asks app for a transfer and edits max_age out of the request her browser carries: with no fresh sign-in asked for, id.example answers from the session it has. What does app answer, and what grants are there? Then the rows. First, a login alice finishes in another tab after the step-up began: the same user, fresh and at MFA, and with this step-up's nonce it would pass; but it answers another request. Then no nonce, an empty one, no auth_time, the old sign-in's, a string, true, one from the future, and acr missing, which is what an edited-out acr_values gets from a password session."""
    world = _world()
    alice = _signed_in(world, factors=("pwd", "otp"))
    world.clock.advance(7 * 3600)
    mallory = Browser(world.network)
    mallory.set_cookie(ISSUER, OP_SESSION_COOKIE, alice.cookies(ISSUER)[OP_SESSION_COOKIE])
    mallory.set_cookie(APP, SESSION_COOKIE, alice.cookies(APP)[SESSION_COOKIE])
    assert _start_step_up(mallory).status == 401
    answer = mallory.get(_edited(mallory, "max_age"))
    assert (answer.status, answer.body) == __
    assert world.app.grants == __
    claims, transaction = _sign_in_for(world, alice, "alice", STEP_UP, ("pwd", "otp"))
    pending = PendingStepUp(transaction, ALICE, "s1", "transfer", TRANSFER,
                            frozenset({ACR_MFA}), transaction.started_at + PENDING_LIFETIME)
    login, _ = _sign_in_for(world, alice, "alice", {"acr_values": ACR_MFA}, ("pwd", "otp"))
    now, started = world.clock.now(), transaction.started_at
    assert check_step_up(claims, pending, now, LEEWAY) is None
    assert check_step_up({**login, "nonce": transaction.nonce}, pending, now, LEEWAY) is None
    rows = [
        (login, __),
        (_without(claims, "nonce"), "nonce_mismatch"),
        ({**claims, "nonce": ""}, "nonce_mismatch"),
        (_without(claims, "auth_time"), __),
        ({**claims, "auth_time": started - 8 * 3600}, __),
        ({**claims, "auth_time": started - LEEWAY - 1}, "stale_auth_time"),
        ({**claims, "auth_time": str(started)}, __),
        ({**claims, "auth_time": True}, "malformed"),
        ({**claims, "auth_time": now + LEEWAY + 1}, __),
        (_without(claims, "acr"), __),
        ({**claims, "acr": ACR_PASSWORD}, "acr_not_met"),
        ({**claims, "acr": ""}, "acr_not_met"),
    ]
    for tampered, reason in rows:
        assert _reason(lambda: check_step_up(tampered, pending, now, LEEWAY)) == reason


def test_refuses_another_user_who_steps_up():
    """mallory hijacked alice's app session, but not her second factor. She asks for a transfer and signs in at id.example as herself, with her own one-time password. app's step-up carries alice's ID token as id_token_hint, and Core §3.1.2.1 says the provider answers positively only if that user is logged in; "otherwise, it MUST return an error, such as login_required". So she edits the hint out. Her sign-in is fresh and at MFA: what does app answer, and is there a grant? Would a hint alone have been enough?"""
    world = _world()
    alice = _signed_in(world)
    mallory = Browser(world.network)
    mallory.set_cookie(APP, SESSION_COOKIE, alice.cookies(APP)[SESSION_COOKIE])
    assert _start_step_up(mallory).status == 401
    hinted = _answer(world, mallory, mallory.history[-1].url, "mallory")
    assert (hinted.status, hinted.body["error"]) == __
    answer = _answer(world, mallory, _edited(mallory, "id_token_hint"), "mallory")
    assert (answer.status, answer.body) == __
    assert world.app.grants == __
    honest = _granted(world, alice)
    assert world.app.grants[honest].user_key == ALICE


def test_accepts_a_grant_for_exactly_what_was_approved():
    """Implement grant_refusal above: why grant cannot pay for this request, or None. "user" unless user_key is the grant's and session_id, a string, is its session id (compare with hmac.compare_digest: a session id is a secret); then "action" unless action and params are the grant's; then "expired" unless now is before its expires_at. alice steps up for TRANSFER. What does app's grant hold? Does key order in the parameters matter?"""
    world = _world()
    alice = _signed_in(world)
    grant_id = _granted(world, alice)
    grant = world.app.grants[grant_id]
    session, _ = _session(alice)
    assert (grant.user_key, grant.action, grant.params) == __
    assert grant.acr == __
    request = {"user_key": ALICE, "session_id": session, "action": "transfer",
               "params": TRANSFER, "now": world.clock.now()}
    assert grant_refusal(grant, **request) is None
    assert grant_refusal(grant, **{**request, "params": {"amount": "10", "to": "bob"}}) is __
    late = {**request, "now": grant.expires_at - 1}
    assert grant_refusal(grant, **late) is None


def test_refuses_a_grant_for_another_action_or_user():
    """A grant that says only "stepped up" lets a step-up for one thing pay for another. Each row changes one thing about alice's request: her grant presented from mallory's session, or by alice of other-id.example, or with a missing session; another action; a bigger amount, the amount as a number, no parameters, an extra one; then the moment the grant lapses. Which reason does each get?"""
    world = _world()
    alice, mallory = _signed_in(world), _signed_in(world, "mallory")
    grant_id = _granted(world, alice)
    grant = world.app.grants[grant_id]
    session, _ = _session(alice)
    honest = {"user_key": ALICE, "session_id": session, "action": "transfer",
              "params": TRANSFER, "now": world.clock.now()}
    assert grant_refusal(grant, **honest) is None
    rows = [
        ({"user_key": (ISSUER, "mallory"), "session_id": _session(mallory)[0]}, __),
        ({"session_id": _session(mallory)[0]}, "user"),
        ({"user_key": (OTHER_ISSUER, "alice")}, __),
        ({"session_id": ""}, "user"),
        ({"session_id": None}, "user"),
        ({"action": "close_account"}, __),
        ({"params": {**TRANSFER, "amount": "10000"}}, __),
        ({"params": {**TRANSFER, "amount": 10}}, "action"),
        ({"params": {}}, "action"),
        ({"params": {**TRANSFER, "memo": "rent"}}, "action"),
        ({"now": grant.expires_at}, __),
    ]
    for changes, reason in rows:
        assert grant_refusal(grant, **{**honest, **changes}) == reason


async def careless_transfer(app: App, session_id: str, csrf: str, grant_id: str,
                            transfer: dict) -> str:
    """Another team's transfer, spending a step-up grant. Every field is checked."""
    user_key = app.sessions.get(session_id)
    if user_key is None:
        raise Forbidden("user")
    if not app.csrf_ok(session_id, csrf):
        raise Forbidden("csrf")
    grant = app.grants.get(grant_id)
    if grant is None:
        raise Forbidden("grant")
    same_session = hmac.compare_digest(grant.session_id.encode(), session_id.encode())
    if grant.user_key != user_key or not same_session:
        raise Forbidden("user")
    if grant.action != "transfer" or grant.params != transfer:
        raise Forbidden("action")
    if not app.clock.now() < grant.expires_at:
        raise Forbidden("expired")
    await app.bank.transfer(**transfer)
    app.grants = {key: value for key, value in app.grants.items() if key != grant_id}
    return "ok"


async def mallorys_requests(spend: Callable[[], Coroutine]) -> list:
    return __


def test_spot_the_bug_in_careless_transfer():
    """Spot the bug: read careless_transfer. One spend works, and a second, sent after it, is refused. But a server runs many requests at once: while one waits on the bank at an await, others run. mallory holds alice's session and has seen the id of the grant alice just earned. Make mallorys_requests run spend twice at the same time and return both outcomes, so that one approval moves money twice."""
    world = _world()
    alice = _signed_in(world)
    session, csrf = _session(alice)
    once = _granted(world, alice)
    assert asyncio.run(careless_transfer(world.app, session, csrf, once, TRANSFER)) == "ok"
    again = careless_transfer(world.app, session, csrf, once, TRANSFER)
    assert _forbidden(again) == "grant"
    assert len(world.app.bank.transfers) == 1
    grant_id = _granted(world, alice)
    outcomes = asyncio.run(mallorys_requests(
        lambda: careless_transfer(world.app, session, csrf, grant_id, TRANSFER)
    ))
    assert isinstance(outcomes, list), "mallorys_requests returns what each request gave"
    assert outcomes == ["ok", "ok"]
    assert len(world.app.bank.transfers) == 3


def test_refuses_a_grant_spent_twice():
    """Implement take_grant above, the fix. Check and remove the grant in one step, with no await between: grants.get(grant_id) is None gives (None, "grant", grants); a reason from refusal(grant) gives (None, that reason, grants), and the grant stays; else (grant, None, grants without it). Leave grants itself unchanged. app.transfer calls it before it waits on the bank. Your mallorys_requests runs against app.transfer, and so do hidden ones: mallory's own session with alice's grant id; alice with the wrong amount; each must leave alice's grant for alice. How many transfers happen?"""
    assert take_grant({}, "made-up", lambda grant: None) == (None, "grant", {})
    world = _world()
    alice, mallory = _signed_in(world), _signed_in(world, "mallory")
    session, csrf = _session(alice)
    grant_id = _granted(world, alice)
    outcomes = asyncio.run(mallorys_requests(
        lambda: world.app.transfer(session, csrf, grant_id, TRANSFER)
    ))
    assert outcomes.count("ok") == __
    refused = [outcome.reason for outcome in outcomes if isinstance(outcome, Forbidden)]
    assert refused == __
    assert len(world.app.bank.transfers) == __
    grant_id = _granted(world, alice)
    theirs = world.app.transfer(*_session(mallory), grant_id, TRANSFER)
    assert _forbidden(theirs) == __
    bigger = world.app.transfer(session, csrf, grant_id, {**TRANSFER, "amount": "10000"})
    assert _forbidden(bigger) == __
    assert _forbidden(world.app.transfer(session, csrf, grant_id, TRANSFER)) is __
    assert _forbidden(world.app.transfer(session, csrf, grant_id, TRANSFER)) == "grant"
    assert world.app.bank.transfers == __


def test_step_up_runs_beside_the_login():
    """First, pages that are not app's post to /step-up from alice's browser: with no csrf token, an empty one, mallory's. Then alice opens two transfer pages at once: 10 to bob, 5 to carol. Each step-up is a login with its own state and nonce, so app's state cookie binds both, and her sign-ins answer each one. Which grant pays for which transfer? The step-up callback, replayed, is refused: its state was used. Then alice signs in to app again. That login is answered silently from her provider session. A login is not a step-up, and a sign-in is a privilege change: the session gets a new id, and grants made for the old one go. What can her first grant do now, and a step-up she began before signing in again? One finished PENDING_LIFETIME seconds after it began?"""
    world = _world()
    mallory, alice = _signed_in(world, "mallory"), _signed_in(world)
    to_carol = {"to": "carol", "amount": "5"}
    forged = [{**TRANSFER}, {**TRANSFER, "csrf": ""}, {**TRANSFER, "csrf": _session(mallory)[1]}]
    refused = [alice.post(f"{APP}/step-up", form) for form in forged]
    assert [(answer.status, answer.body) for answer in refused] == __
    assert STATE_COOKIE not in alice.cookies(APP)
    assert _start_step_up(alice).status == 401
    to_bob_url = alice.history[-1].url
    assert _start_step_up(alice, to_carol).status == 401
    to_carol_url = alice.history[-1].url
    states = [dict(parse_qsl(urlsplit(url).query))["state"] for url in (to_bob_url, to_carol_url)]
    assert alice.cookies(APP)[STATE_COOKIE] == __
    sent = dict(parse_qsl(urlsplit(to_bob_url).query))
    assert (sent["acr_values"], sent["max_age"]) == __
    assert "id_token_hint" in sent
    bob_grant = _answer(world, alice, to_bob_url, "alice").body["grant"]
    callback = alice.history[-1].url
    assert alice.cookies(APP)[STATE_COOKIE] == __
    carol_grant = _answer(world, alice, to_carol_url, "alice").body["grant"]
    assert STATE_COOKIE not in alice.cookies(APP)
    assert world.app.grants[carol_grant].params == __
    assert alice.get(callback).body == __
    session, csrf = _session(alice)
    theirs = world.app.transfer(session, _session(mallory)[1], bob_grant, TRANSFER)
    assert _forbidden(theirs) == __
    wrong = world.app.transfer(session, csrf, bob_grant, to_carol)
    assert _forbidden(wrong) == __
    assert _forbidden(world.app.transfer(session, csrf, bob_grant, TRANSFER)) is None
    assert _start_step_up(alice, {"to": "dave", "amount": "7"}).status == 401
    to_dave_url = alice.history[-1].url
    assert alice.get(f"{APP}/login").body == {"sub": "alice"}
    late = _answer(world, alice, to_dave_url, "alice")
    assert (late.status, late.body) == __
    new_session, new_csrf = _session(alice)
    old = world.app.transfer(session, csrf, carol_grant, to_carol)
    assert _forbidden(old) == __
    moved = world.app.transfer(new_session, new_csrf, carol_grant, to_carol)
    assert _forbidden(moved) == __
    assert world.app.grants == __
    assert _start_step_up(alice).status == 401
    world.clock.advance(PENDING_LIFETIME)
    lapsed = _answer(world, alice, alice.history[-1].url, "alice")
    assert lapsed.body == __
