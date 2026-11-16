"""Sessions and logout.

A login leaves three things: the app's session, the provider's session
(its cookie in the browser) and the tokens. Ending one ends neither of the
others. Signing in raises a session's privilege, so the app gives it a new
id then: an id known before the sign-in must name nothing after it.

RP-Initiated Logout sends the browser to the provider's
end_session_endpoint with an id_token_hint (RECOMMENDED), client_id,
post_logout_redirect_uri and state. That URI "MUST have been previously
registered" and match one exactly. The provider "MUST ask the End-User"
before logging out "if an id_token_hint was not provided or if the
supplied ID Token does not belong to the current OP session". Logout
requests "are intended to be idempotent": logging out twice is no error.

Back-Channel Logout has the provider POST a Logout Token to each app the
user signed in to. It is signed like an ID token and carries an events
claim with the member http://schemas.openid.net/event/backchannel-logout,
a sub, a sid or both, and never a nonce: "A nonce Claim MUST NOT be
present", so that it cannot pass for an ID token. With no sid, all of that
user's sessions at the app end.

A common mistake: deleting the app's cookie and calling the user logged out.

Read more:
  https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
  https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RedirectionAfterLogout
  https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
"""

import hashlib
import hmac
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from conftest import __
from toy.client import (
    STATE_COOKIE,
    Transaction,
    bind_state,
    exchange_code,
    finish_login,
    release_state,
    start_login,
)
from toy.clock import Clock
from toy.errors import FlowError, InvalidToken, OAuthError
from toy.http import Browser, FakeNetwork, Request, Response
from toy.id_token import numeric_date
from toy.jose import jws_encode, jws_split, jws_verify
from toy.keys import ATTACKER_RSA, RSA_1
from toy.logout import LOGOUT_EVENT, logout_url
from toy.provider import Provider

ISSUER = "https://id.example"
OTHER_ISSUER = "https://other-id.example"
APP = "https://app.example"
QUIZ = "https://quiz.example"
SUITE = "https://suite.example"
APP_AFTER = f"{APP}/signed-out"
QUIZ_AFTER = f"{QUIZ}/signed-out"
SUITE_AFTER = f"{SUITE}/signed-out"
REGISTERED = {"app": (APP_AFTER,), "quiz": (QUIZ_AFTER,), "suite": (SUITE_AFTER,)}
SESSION_COOKIE = "session"
ALGS = frozenset({"RS256"})


def check_logout_claims(claims: dict) -> None:
    __()


def validate_logout_token(token: str, *, client_id: str, jwks: dict, now: int) -> dict:
    """Back-Channel Logout §2.6: what a Logout Token shares with an ID token, then the rest."""
    claims = jws_verify(token, jwks, ALGS)
    if claims.get("iss") != ISSUER:
        raise InvalidToken("wrong_issuer")
    aud = claims.get("aud")
    if aud != client_id and not (isinstance(aud, list) and client_id in aud):
        raise InvalidToken("wrong_audience")
    if "iat" not in claims or "exp" not in claims:
        raise InvalidToken("malformed")
    if not numeric_date(claims, "iat") <= now < numeric_date(claims, "exp"):
        raise InvalidToken("expired")
    check_logout_claims(claims)
    return claims


def sessions_to_end(sessions: dict, claims: dict) -> frozenset[str]:
    __()


def sign_in_session(
    sessions: dict, cookie: str | None, record: tuple, new_id: str
) -> tuple[str, dict]:
    __()


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
    """A client app, signed in through id.example, with server-side sessions.

    /login starts a code flow and binds its state to the browser. /callback
    finishes it with toy finish_login and keeps (iss, sub, sid) and the ID
    token in a session named by the SESSION_COOKIE cookie, through
    sign_in_session. GET /me names the session's user and gives its pages a
    csrf token bound to the session. POST /logout refuses a signed-in
    session's request without that token; else it ends the session, and with
    "here_only" in the form that is all, else it sends the browser to
    id.example's end_session_endpoint with the ID token as hint. POST
    /backchannel-logout takes a Logout Token from id.example and ends the
    sessions it names, or answers 400. Only /callback starts a session.
    """

    def __init__(self, clock: Clock, network: FakeNetwork, client_id: str, origin: str):
        self._clock, self._network = clock, network
        self._client_id, self._origin = client_id, origin
        discovery = Request("GET", f"{ISSUER}/.well-known/openid-configuration")
        self._config = network.send(discovery).body
        self._jwks = network.send(Request("GET", self._config["jwks_uri"])).body
        self._started: dict[str, Transaction] = {}
        self._csrf_key = secrets.token_bytes(32)
        self.sessions: dict[str, tuple[str, str, str | None]] = {}
        self.id_tokens: dict[str, str] = {}

    def __call__(self, request: Request) -> Response:
        routes = {
            "/login": self._login, "/callback": self._callback, "/me": self._me,
            "/logout": self._logout, "/signed-out": self._signed_out,
            "/backchannel-logout": self._backchannel_logout,
        }
        route = routes.get(request.path)
        return route(request) if route else Response(404, {}, {"error": "not_found"})

    def _login(self, request: Request) -> Response:
        url, transaction = start_login(
            issuer_config=self._config, client_id=self._client_id,
            redirect_uri=f"{self._origin}/callback", now=self._clock.now(),
        )
        self._started = {**self._started, transaction.state: transaction}
        bound = bind_state(request.cookies.get(STATE_COOKIE), transaction.state)
        return Response(303, {"Location": url}, "", {STATE_COOKIE: bound})

    def _callback(self, request: Request) -> Response:
        state = request.query.get("state", "")
        transaction = self._started.get(state)
        if transaction is None:
            return Response(401, {}, {"error": "state_mismatch"})
        self._started = {k: v for k, v in self._started.items() if k != state}
        tap = _TokenTap(self._network)
        try:
            claims = finish_login(
                transaction=transaction, callback=request, issuer_config=self._config,
                client_id=self._client_id, jwks=self._jwks, network=tap, now=self._clock.now(),
            )
        except (FlowError, InvalidToken) as refused:
            return Response(401, {}, {"error": refused.reason})
        except OAuthError as refused:
            return Response(401, {}, {"error": refused.error})
        brought = request.cookies.get(SESSION_COOKIE)
        record = (claims["iss"], claims["sub"], claims.get("sid"))
        session, self.sessions = sign_in_session(
            self.sessions, brought, record, secrets.token_urlsafe(16)
        )
        kept = {k: v for k, v in self.id_tokens.items() if k != brought}
        self.id_tokens = {**kept, session: tap.id_token}
        released = release_state(request.cookies.get(STATE_COOKIE), state)
        cookies = {STATE_COOKIE: released, SESSION_COOKIE: session}
        return Response(200, {}, {"sub": claims["sub"]}, cookies)

    def _me(self, request: Request) -> Response:
        cookie = request.cookies.get(SESSION_COOKIE, "")
        session = self.sessions.get(cookie)
        if session is None:
            return Response(401, {}, {"error": "login_required"})
        return Response(200, {}, {"sub": session[1], "csrf": self._csrf_token(cookie)})

    def _csrf_token(self, session: str) -> str:
        return hmac.new(self._csrf_key, session.encode(), hashlib.sha256).hexdigest()

    def _logout(self, request: Request) -> Response:
        session = request.cookies.get(SESSION_COOKIE, "")
        sent = request.form.get("csrf", "").encode()
        if session in self.sessions and not hmac.compare_digest(
            sent, self._csrf_token(session).encode()
        ):
            return Response(403, {}, {"error": "csrf"})
        id_token = self.id_tokens.get(session)
        self._end(frozenset({session}))
        cleared = {SESSION_COOKIE: None}
        if id_token is None or "here_only" in request.form:
            return Response(200, {}, {"signed_out": self._origin}, cleared)
        url = logout_url(
            issuer_config=self._config, id_token=id_token, client_id=self._client_id,
            post_logout_redirect_uri=f"{self._origin}/signed-out",
        )
        return Response(303, {"Location": url}, "", cleared)

    def _signed_out(self, _request: Request) -> Response:
        return Response(200, {}, {"signed_out": "everywhere"})

    def _backchannel_logout(self, request: Request) -> Response:
        try:
            claims = validate_logout_token(
                request.form.get("logout_token", ""), client_id=self._client_id,
                jwks=self._jwks, now=self._clock.now(),
            )
        except InvalidToken as refused:
            return Response(400, {}, {"error": "invalid_request", "reason": refused.reason})
        ended = sessions_to_end(self.sessions, claims)
        self._end(ended)
        return Response(200, {}, {"ended": len(ended)})

    def _end(self, ended: frozenset[str]) -> None:
        self.sessions = {k: v for k, v in self.sessions.items() if k not in ended}
        self.id_tokens = {k: v for k, v in self.id_tokens.items() if k not in ended}


@dataclass(frozen=True)
class World:
    clock: Clock
    network: FakeNetwork
    provider: Provider
    config: dict
    app: App
    quiz: App


def _world() -> World:
    """id.example, where alice and mallory have accounts, and its clients app and quiz.

    A third client, suite, gets ID tokens whose aud also lists quiz, with azp suite.
    """
    clock, network = Clock(), FakeNetwork()
    provider = Provider(ISSUER, clock=clock, network=network)
    for client_id, origin in (("app", APP), ("quiz", QUIZ)):
        provider.register_client(
            client_id, [f"{origin}/callback"], post_logout_redirect_uris=[f"{origin}/signed-out"],
            backchannel_logout_uri=f"{origin}/backchannel-logout",
        )
    provider.register_client(
        "suite", [f"{SUITE}/callback"], extra_audiences=("quiz",),
        post_logout_redirect_uris=[SUITE_AFTER],
    )
    provider.add_user("alice", "alice@example.com", True, "alice-password")
    provider.add_user("mallory", "mallory@example.com", True, "mallory-password")
    config = network.send(Request("GET", f"{ISSUER}/.well-known/openid-configuration")).body
    app, quiz = App(clock, network, "app", APP), App(clock, network, "quiz", QUIZ)
    network.mount(APP, app)
    network.mount(QUIZ, quiz)
    return World(clock, network, provider, config, app, quiz)


def _signed_in(world: World, sub: str = "alice") -> Browser:
    """A browser in which sub has just signed in at id.example."""
    browser = Browser(world.network)
    world.provider.sign_in(browser, sub, ("pwd",))
    return browser


def _me(world: World, browser: Browser, origin: str = APP) -> int:
    request = Request("GET", f"{origin}/me", cookies=browser.cookies(origin))
    return world.network.send(request).status


def _csrf(browser: Browser, origin: str = APP) -> str:
    """The token app's pages post with /logout, as /me hands it to them."""
    return browser.get(f"{origin}/me").body["csrf"]


def _id_token(world: World, sub: str = "alice", client_id: str = "app") -> str:
    """An ID token id.example issues client_id for sub, in a browser of its own."""
    origin = {"app": APP, "quiz": QUIZ, "suite": SUITE}[client_id]
    browser = _signed_in(world, sub)
    url, transaction = start_login(
        issuer_config=world.config, client_id=client_id, redirect_uri=f"{origin}/callback",
        now=world.clock.now(),
    )
    answer = world.network.send(Request("GET", url, cookies=browser.cookies(ISSUER)))
    return exchange_code(
        issuer_config=world.config, client_id=client_id, redirect_uri=f"{origin}/callback",
        code=Request("GET", answer.location).query["code"],
        code_verifier=transaction.code_verifier, network=world.network,
    )["id_token"]


def _reason(check: Callable) -> str | None:
    try:
        check()
    except InvalidToken as refused:
        return refused.reason
    return None


ALICE = (ISSUER, "alice", "s1")


def test_accepts_a_new_session_id_at_sign_in():
    """Implement sign_in_session above, which app's /callback calls once id.example has vouched for the user. sessions maps app's session ids to records; cookie is the session id the browser brought, or None; record is the new session's; new_id is a fresh random id. Return new_id and the sessions with record under new_id and nothing under cookie, leaving sessions itself unchanged. Signing in raises the session's privilege, so its id changes then. alice signs in to app twice in one browser: what does her first session id name afterwards?"""
    sessions = {"bob": (ISSUER, "bob", "s3")}
    assert sign_in_session(sessions, None, ALICE, "n1") == __
    assert sign_in_session(sessions, "bob", ALICE, "n2") == __
    assert sign_in_session(sessions, "gone", ALICE, "n3")[1] == {**sessions, "n3": ALICE}
    assert sessions == {"bob": (ISSUER, "bob", "s3")}
    world = _world()
    alice = _signed_in(world)
    assert alice.get(f"{APP}/login").body == {"sub": "alice"}
    first = alice.cookies(APP)[SESSION_COOKIE]
    assert alice.get(f"{APP}/login").body == {"sub": "alice"}
    second = alice.cookies(APP)[SESSION_COOKIE]
    assert (first in world.app.sessions, second in world.app.sessions) == __


def test_refuses_a_session_id_planted_before_sign_in():
    """Session fixation. mallory signs in to app as herself and keeps her session id. A page of hers on a sibling subdomain writes it into alice's browser as app's session cookie, then alice signs in to app. An app that kept the id it was brought would make mallory's copy name alice's session, and so would one that issued a new id but left the old one valid. A made-up id goes the same way. What does app answer each copy?"""
    world = _world()
    mallory = _signed_in(world, "mallory")
    assert mallory.get(f"{APP}/login").body == {"sub": "mallory"}
    planted = mallory.cookies(APP)[SESSION_COOKIE]
    alice = _signed_in(world)
    alice.set_cookie(APP, SESSION_COOKIE, planted)
    assert alice.cookies(APP) == {SESSION_COOKIE: planted}
    assert alice.get(f"{APP}/login").body == {"sub": "alice"}
    assert alice.get(f"{APP}/me").body["sub"] == "alice"
    assert (alice.cookies(APP)[SESSION_COOKIE] == planted) is __
    as_mallory = mallory.get(f"{APP}/me")
    assert (as_mallory.status, as_mallory.body) == __
    kiosk = _signed_in(world)
    kiosk.set_cookie(APP, SESSION_COOKIE, "chosen-by-mallory")
    assert kiosk.get(f"{APP}/login").body == {"sub": "alice"}
    chosen = Request("GET", f"{APP}/me", cookies={SESSION_COOKIE: "chosen-by-mallory"})
    assert world.network.send(chosen).status == __


def test_refuses_a_logout_posted_from_another_site():
    """alice is signed in to app. A page of mallory's makes her browser POST to app's /logout, and the browser sends her cookies along. Without a check any site could sign her out, a first step towards planting a login of mallory's own. So /me gives app's pages a token derived from the session id under a key only app holds, and /logout compares the one it is sent using hmac.compare_digest, whose time does not depend on how much matches. Which posts does app refuse?"""
    world = _world()
    alice, mallory = _signed_in(world), _signed_in(world, "mallory")
    assert alice.get(f"{APP}/login").body == {"sub": "alice"}
    assert mallory.get(f"{APP}/login").body == {"sub": "mallory"}
    token = _csrf(alice)
    forms = [{}, {"csrf": ""}, {"csrf": _csrf(mallory)}, {"csrf": token[:-1]}, {"here_only": "1"}]
    answers = [alice.post(f"{APP}/logout", form) for form in forms]
    assert [answer.status for answer in answers] == __
    assert _me(world, alice) == __
    out = alice.post(f"{APP}/logout", {"csrf": token, "here_only": "1"})
    assert out.body == __
    assert _me(world, alice) == 401


def test_logout_starts_at_the_end_session_endpoint():
    """alice signs in to app, then presses its log out button. Where does app send her browser, with which parameters, and whose ID token is the hint? RP-Initiated Logout §2 makes id_token_hint RECOMMENDED; app sends no state, which is OPTIONAL."""
    world = _world()
    alice = _signed_in(world)
    assert alice.get(f"{APP}/login").body == {"sub": "alice"}
    assert world.config["end_session_endpoint"] == __
    leaving = world.network.send(Request(
        "POST", f"{APP}/logout", form={"csrf": _csrf(alice)}, cookies=alice.cookies(APP)
    ))
    url = urlsplit(leaving.location)
    assert (leaving.status, f"{url.scheme}://{url.netloc}{url.path}") == (303, f"{ISSUER}/logout")
    params = dict(parse_qsl(url.query))
    assert sorted(params) == __
    assert params["post_logout_redirect_uri"] == __
    hint = jws_split(params["id_token_hint"])[1]
    assert (hint["sub"], hint["aud"]) == __


def post_logout_target(
    params: dict, registered: dict, verify_own: Callable[[str], dict | None]
) -> str | None:
    __()


def test_accepts_a_registered_post_logout_uri():
    """Implement post_logout_target above, id.example's check before it redirects after logout. params is the logout request. verify_own(token) returns the claims of a token id.example signed, or None. Return params["post_logout_redirect_uri"] only if: verify_own accepts params["id_token_hint"]; the hint was issued to a client, its aud when that names one client (a string, or a list of one), else its azp, which must be one of its audiences; params["client_id"], if sent, is that client; and the target is exactly one of registered[client]. Else None. RP-Initiated Logout §2: the provider "SHOULD accept ID Tokens" for a recent session "even when the exp time has passed"."""
    world = _world()
    hint = _id_token(world)
    verify = world.provider.verify_own
    sent = {"id_token_hint": hint, "post_logout_redirect_uri": APP_AFTER}
    assert post_logout_target(sent, REGISTERED, verify) == __
    assert post_logout_target({**sent, "client_id": "app"}, REGISTERED, verify) == APP_AFTER
    world.clock.advance(3600)
    assert jws_split(hint)[1]["exp"] < world.clock.now()
    assert post_logout_target(sent, REGISTERED, verify) == __
    assert post_logout_target({"id_token_hint": hint}, REGISTERED, verify) is __
    suite_hint = _id_token(world, client_id="suite")
    assert jws_split(suite_hint)[1]["aud"] == ["suite", "quiz"]
    to_suite = {"id_token_hint": suite_hint, "post_logout_redirect_uri": SUITE_AFTER}
    assert post_logout_target(to_suite, REGISTERED, verify) == __
    assert post_logout_target({**to_suite, "client_id": "suite"}, REGISTERED, verify) == SUITE_AFTER
    page = Browser(world.network).get(logout_url(
        issuer_config=world.config, id_token=hint, client_id="app",
        post_logout_redirect_uri=APP_AFTER, state="bye",
    ))
    assert page.body == __


def test_refuses_a_post_logout_uri_that_only_looks_registered():
    """mallory signs in to app herself, so her ID token is a perfectly good hint. She builds logout links that send whoever opens them somewhere app never registered: a longer path, a query for an open redirect in app, quiz's page. A provider matching by prefix, or against every client's URIs, would follow them. What does post_logout_target return for each, and what does id.example answer?"""
    world = _world()
    hint = _id_token(world, "mallory")
    targets = [
        f"{APP_AFTER}/", f"{APP_AFTER}?next=https://mallory.example", f"{APP_AFTER}/../evil",
        APP, QUIZ_AFTER, "https://mallory.example/signed-out", "",
    ]
    chosen = [
        post_logout_target(
            {"id_token_hint": hint, "post_logout_redirect_uri": target}, REGISTERED,
            world.provider.verify_own,
        )
        for target in targets
    ]
    assert chosen == __
    page = Browser(world.network).get(logout_url(
        issuer_config=world.config, id_token=hint, client_id="app",
        post_logout_redirect_uri=f"{APP_AFTER}?next=https://mallory.example",
    ))
    assert (page.status, page.location) == __


def test_refuses_a_logout_hint_for_another_client():
    """Now mallory keeps app's registered URI and plays with the hint. No hint at all; an empty one; alice's token re-signed with mallory's own key under id.example's kid; her quiz token sent with client_id app, or alone; alice's app token with client_id quiz, or an empty client_id; her suite token, whose aud also lists quiz, with client_id quiz; and two copies of it that id.example signs with quiz listed first, or with azp suite outside aud. When both are sent, the provider "MUST verify that the Client Identifier matches the one used when issuing the ID Token" (§2). What does post_logout_target return each time?"""
    world = _world()
    app_token, quiz_token = _id_token(world), _id_token(world, "mallory", "quiz")
    suite_token = _id_token(world, "mallory", "suite")
    assert jws_split(app_token)[0]["kid"] == "k1"
    forged = jws_encode({"alg": "RS256", "kid": "k1"}, jws_split(app_token)[1], ATTACKER_RSA)
    suite_claims = jws_split(suite_token)[1]
    quiz_first, azp_elsewhere = (
        jws_encode({"alg": "RS256", "kid": "k1"}, {**suite_claims, **odd}, RSA_1)
        for odd in ({"aud": ["quiz", "suite"]}, {"aud": ["app", "quiz"]})
    )
    to_app = {"post_logout_redirect_uri": APP_AFTER}
    requests = [
        {**to_app, "client_id": "app"},
        {**to_app, "client_id": "app", "id_token_hint": ""},
        {**to_app, "client_id": "app", "id_token_hint": forged},
        {**to_app, "client_id": "app", "id_token_hint": quiz_token},
        {**to_app, "id_token_hint": quiz_token},
        {"post_logout_redirect_uri": QUIZ_AFTER, "client_id": "quiz", "id_token_hint": app_token},
        {**to_app, "client_id": "", "id_token_hint": app_token},
        {"post_logout_redirect_uri": QUIZ_AFTER, "client_id": "quiz", "id_token_hint": suite_token},
        {"post_logout_redirect_uri": QUIZ_AFTER, "id_token_hint": quiz_first},
        {"post_logout_redirect_uri": SUITE_AFTER, "id_token_hint": azp_elsewhere},
    ]
    chosen = [post_logout_target(r, REGISTERED, world.provider.verify_own) for r in requests]
    assert chosen == __
    honest = {**to_app, "id_token_hint": app_token}
    assert post_logout_target(honest, REGISTERED, world.provider.verify_own) == APP_AFTER


def test_refuses_an_id_token_as_a_logout_token():
    """Implement check_logout_claims above, the checks Back-Channel Logout §2.6 adds once validate_logout_token's shared ones pass. sub, sid or both must be present, each a non-empty string, else InvalidToken("malformed"). events must be an object whose member LOGOUT_EVENT is itself an object, and nonce must be absent, else InvalidToken("wrong_typ"). An ID token rides in every logout URL as id_token_hint, so it turns up in browser history and logs. mallory finds alice's and posts it to app's back-channel endpoint: signed by id.example, for app, in date. What does app answer, and is alice still signed in?"""
    world = _world()
    logout = jws_split(world.provider.logout_token("app", sub="alice", sid="s1"))[1]
    assert check_logout_claims(logout) is None
    assert check_logout_claims({**logout, "sub": "alice"}) is None
    assert check_logout_claims({k: v for k, v in logout.items() if k != "sub"}) is None
    rows = [
        ({k: v for k, v in logout.items() if k not in ("sub", "sid")}, __),
        ({**logout, "sid": ""}, "malformed"),
        ({**logout, "sub": None}, "malformed"),
        ({**logout, "events": LOGOUT_EVENT}, __),
        ({**logout, "events": [LOGOUT_EVENT]}, "wrong_typ"),
        ({**logout, "events": {LOGOUT_EVENT: True}}, "wrong_typ"),
        ({**logout, "events": {}}, "wrong_typ"),
        ({**logout, "nonce": "n-1"}, __),
        ({**logout, "nonce": ""}, "wrong_typ"),
        ({**logout, "nonce": None}, "wrong_typ"),
    ]
    for claims, reason in rows:
        assert _reason(lambda: check_logout_claims(claims)) == reason
    alice = _signed_in(world)
    assert alice.get(f"{APP}/login").body == {"sub": "alice"}
    id_token = world.app.id_tokens[alice.cookies(APP)[SESSION_COOKIE]]
    answer = world.network.send(
        Request("POST", f"{APP}/backchannel-logout", form={"logout_token": id_token})
    )
    assert (answer.status, answer.body["reason"]) == __
    assert _me(world, alice) == __


SESSIONS = {
    "laptop": (ISSUER, "alice", "s1"),
    "phone": (ISSUER, "alice", "s2"),
    "tablet": (ISSUER, "alice", None),
    "bob": (ISSUER, "bob", "s3"),
    "other-alice": (OTHER_ISSUER, "alice", "s1"),
}


def test_accepts_a_logout_without_sid_for_every_session_of_that_user():
    """Implement sessions_to_end above. sessions maps app's session ids to (iss, sub, sid), sid None when the ID token had none. claims are a valid Logout Token's. Return the frozenset of ids whose iss is the token's iss, and: if the token has a sid, whose sid is that sid, and whose sub is the token's sub when it has one; if it has no sid, whose sub is the token's sub. "If a sid Claim is not present, the intent is that all sessions at the RP for the End-User identified by the iss and sub Claims be logged out" (§2.4)."""
    every_alice = sessions_to_end(SESSIONS, {"iss": ISSUER, "sub": "alice"})
    assert every_alice == __
    assert sessions_to_end(SESSIONS, {"iss": ISSUER, "sub": "bob"}) == __
    assert sessions_to_end(SESSIONS, {"iss": ISSUER, "sid": "s2"}) == __


def test_refuses_to_end_sessions_the_token_does_not_name():
    """A sid names one browser's session, and "The sid value need only be unique in the context of a particular issuer" (§2.4), so other-id.example may use "s1" too. alice signs out on her laptop only. Which sessions does each token end?"""
    rows = [
        ({"iss": ISSUER, "sid": "s1"}, __),
        ({"iss": ISSUER, "sub": "alice", "sid": "s1"}, {"laptop"}),
        ({"iss": ISSUER, "sub": "bob", "sid": "s1"}, __),
        ({"iss": ISSUER, "sid": "s9"}, set()),
        ({"iss": ISSUER, "sub": "carol"}, set()),
        ({"iss": OTHER_ISSUER, "sid": "s1"}, __),
        ({"iss": "https://mallory.example", "sub": "alice"}, set()),
    ]
    for claims, ended in rows:
        assert sessions_to_end(SESSIONS, claims) == frozenset(ended)


def test_accepts_a_logout_token_from_the_provider():
    """alice is signed in to app and quiz on her laptop, through one id.example session, and to app on her phone, through another. On the laptop she logs out of app. id.example ends its session there and POSTs a Logout Token, with that session's sid, to app and quiz. Where does the laptop land, and who is still signed in where? Can the laptop sign in to app again without signing in at id.example?"""
    world = _world()
    laptop, phone = _signed_in(world), _signed_in(world)
    for browser, origin in ((laptop, APP), (laptop, QUIZ), (phone, APP)):
        assert browser.get(f"{origin}/login").body == {"sub": "alice"}
    laptop_sid = world.quiz.sessions[laptop.cookies(QUIZ)[SESSION_COOKIE]][2]
    assert laptop_sid == world.app.sessions[laptop.cookies(APP)[SESSION_COOKIE]][2]
    landed = laptop.post(f"{APP}/logout", {"csrf": _csrf(laptop)})
    assert (laptop.history[-1].url, landed.body) == __
    still = [_me(world, browser, origin) for browser, origin in
             ((laptop, APP), (laptop, QUIZ), (phone, APP))]
    assert still == __
    assert laptop.get(f"{APP}/login").status == __


def test_logging_out_twice_is_not_an_error():
    """Anyone can link to id.example's logout. RP-Initiated Logout §2: "the OP MUST ask the End-User this question if an id_token_hint was not provided or if the supplied ID Token does not belong to the current OP session with the RP and/or currently logged in End-User". id.example asks with a page carrying a confirmation and ends nothing until the browser POSTs it back. §4: "it is explicitly not an error for an RP to request that a logout be performed when the OP does not consider that the End-User is logged in", and Back-Channel Logout §2.7 says the same of the app. What does each request get?"""
    world = _world()
    alice = _signed_in(world)
    assert alice.get(f"{APP}/login").body == {"sub": "alice"}
    hint = world.app.id_tokens[alice.cookies(APP)[SESSION_COOKIE]]
    no_hint = alice.get(f"{ISSUER}/logout")
    mallorys = _id_token(world, "mallory")
    mallorys_hint = alice.get(
        logout_url(issuer_config=world.config, id_token=mallorys, client_id="app")
    )
    asked = [page.body.get("confirm_logout") for page in (no_hint, mallorys_hint)]
    assert asked == __
    assert _me(world, alice) == __
    yes = alice.post(f"{ISSUER}/logout", {"confirmation": mallorys_hint.body["confirmation"]})
    assert yes.body == __
    assert _me(world, alice) == __
    again = alice.get(logout_url(
        issuer_config=world.config, id_token=hint, client_id="app",
        post_logout_redirect_uri=APP_AFTER,
    ))
    assert again.body == __
    assert alice.post(f"{APP}/logout", {}).body == __
    token = world.provider.logout_token("app", sub="alice")
    answer = world.network.send(
        Request("POST", f"{APP}/backchannel-logout", form={"logout_token": token})
    )
    assert (answer.status, answer.body) == __


def test_refuses_an_old_session_cookie_after_logout():
    """alice uses app's "log out of app only" button. Her old session cookie, if someone kept a copy, must now name nothing, so app ends the session on its server, not just in her browser. id.example still has its session: does her next login need a password? Then she logs out everywhere and tries once more."""
    world = _world()
    alice = _signed_in(world)
    assert alice.get(f"{APP}/login").body == {"sub": "alice"}
    kept = alice.cookies(APP)[SESSION_COOKIE]
    here_only = {"here_only": "1", "csrf": _csrf(alice)}
    assert alice.post(f"{APP}/logout", here_only).body == {"signed_out": APP}
    replayed = world.network.send(Request("GET", f"{APP}/me", cookies={SESSION_COOKIE: kept}))
    assert replayed.status == __
    again = alice.get(f"{APP}/login")
    assert (again.status, again.body) == __
    alice.post(f"{APP}/logout", {"csrf": _csrf(alice)})
    after = alice.get(f"{APP}/login")
    assert (after.status, after.body["error"]) == __
