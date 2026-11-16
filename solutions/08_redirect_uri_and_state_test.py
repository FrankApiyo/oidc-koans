"""redirect_uri exact matching and state.

The code goes wherever redirect_uri says, so the provider checks it. OIDC
Core §3.1.2.1 says it "MUST exactly match" a registered value, by simple
string comparison (RFC 3986 §6.2.1). RFC 9700 §2.1 allows one exception,
the port of a localhost redirect URI for a native app; this toy provider
has no native clients. A failing URI gets an error page, never a redirect
(RFC 6749 §4.1.2.1), and the token request repeats the same redirect_uri.

state ties the callback to the browser that started the login. Without it,
mallory starts a login as herself, stops at the callback, and gets alice's
browser to load that URL: alice is now signed in to the client as mallory
(login CSRF). RFC 9700 §2.1 asks for state values that are one-time use and
"securely bound to the user agent". This client keeps each pending state
in a cookie, so one browser can have several logins pending, and drops a
state once it is used. The same section lets PKCE or the OIDC nonce stand
in for state under conditions chapter 09 covers; this client checks state.

A client must not be an open redirector either. RFC 9700 §2.1: clients
"MUST NOT expose URLs that forward the user's browser to arbitrary URIs".

A common mistake: comparing state with !=. A callback with no state, in a
browser with no pending login, compares None with None and passes.

Read more:
  https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
  https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1
  https://www.rfc-editor.org/rfc/rfc9700.html#section-4.1.3
  https://www.rfc-editor.org/rfc/rfc6749.html#section-10.12
"""

import hmac
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

import pytest

from conftest import __
from toy.client import (
    STATE_COOKIE,
    Transaction,
    account_key,
    bind_state,
    exchange_code,
    release_state,
    start_login,
    validate_id_token,
)
from toy.clock import Clock
from toy.errors import FlowError, InvalidToken, OAuthError
from toy.http import Browser, FakeNetwork, Request, Response, with_query
from toy.provider import Provider

ISSUER = "https://id.example"
APP = "https://app.example"
REDIRECT_URI = f"{APP}/callback"
SECOND_REDIRECT_URI = f"{APP}/welcome"
REGISTERED = (REDIRECT_URI, SECOND_REDIRECT_URI)
EVIL = "https://evil.example"
CLIENT_ID = "app"
CLIENT_SECRET = b"app-secret-of-at-least-32-octets"
SESSION_COOKIE = "app_session"
LOOKALIKES = [
    "https://app.example/callback/",
    "https://app.example/callback?next=https://evil.example",
    "https://app.example/callback#f",
    "https://app.example/callback/../logout",
    "https://app.example/%63allback",
    "https://app.example:443/callback",
    "https://APP.example/callback",
    "http://app.example/callback",
    "https://app.example.evil.example/callback",
    "https://app.example@evil.example/callback",
    "https://evil.example/https://app.example/callback",
]


@dataclass(frozen=True)
class Pending:
    transaction: Transaction
    landing: str


class App:
    """The client at https://app.example, a confidential client.

    /login starts a login, keeps it in pending under its state with the page to
    land on afterwards, and binds the state to the browser. /callback runs
    handle_callback with this app's state check. Any other page shows who is
    signed in.
    """

    def __init__(self, clock, network, config, jwks, check: Callable):
        self.clock, self.network, self.config, self.jwks = clock, network, config, jwks
        self.check = check
        self.pending: dict[str, Pending] = {}
        self.sessions: dict[str, tuple[str, str]] = {}

    def __call__(self, request: Request) -> Response:
        routes = {"/login": self._login, "/callback": self._callback}
        return routes.get(request.path, self._page)(request)

    def _login(self, request: Request) -> Response:
        url, transaction = start_login(
            issuer_config=self.config, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI,
            now=self.clock.now(),
        )
        landing = same_site_path(request.query.get("next"))
        self.pending = {**self.pending, transaction.state: Pending(transaction, landing)}
        bound = bind_state(request.cookies.get(STATE_COOKIE), transaction.state)
        return Response(303, {"Location": url}, "", {STATE_COOKIE: bound})

    def _callback(self, request: Request) -> Response:
        try:
            user, landing = handle_callback(self, request)
        except (FlowError, InvalidToken, OAuthError) as refused:
            return Response(401, {}, {"error": getattr(refused, "reason", None) or refused.error})
        session_id = secrets.token_urlsafe(16)
        self.sessions = {**self.sessions, session_id: user}
        released = release_state(request.cookies.get(STATE_COOKIE), request.query.get("state"))
        cookies = {SESSION_COOKIE: session_id, STATE_COOKIE: released}
        return Response(303, {"Location": landing}, "", cookies)

    def _page(self, request: Request) -> Response:
        user = self.sessions.get(request.cookies.get(SESSION_COOKIE, ""))
        return Response(200, {}, {"page": request.path, "user": list(user) if user else None})


def handle_callback(app: App, callback: Request) -> tuple[tuple[str, str], str]:
    """The client's callback: who signed in, and the page to land on."""
    params = callback.query
    pending = app.pending.get(params.get("state"))
    transaction = pending.transaction if pending else None
    expected = transaction.state if transaction else None
    app.check(callback, expected)
    app.pending = {state: kept for state, kept in app.pending.items() if state != expected}
    if "error" in params:
        raise OAuthError(params["error"], params.get("error_description", ""))
    tokens = exchange_code(
        issuer_config=app.config, client_id=CLIENT_ID, code=params.get("code"),
        redirect_uri=REDIRECT_URI, client_secret=CLIENT_SECRET, network=app.network,
        code_verifier=transaction.code_verifier if transaction else None,
    )
    claims = validate_id_token(
        tokens["id_token"], issuer=app.config["issuer"], client_id=CLIENT_ID, jwks=app.jwks,
        now=app.clock.now(), nonce=transaction.nonce if transaction else None,
    )
    return account_key(claims), pending.landing if pending else "/"


def compare_states(callback: Request, expected: str | None) -> None:
    if callback.query.get("state") != expected:
        raise FlowError("state_mismatch")


def same_site_path(value: str | None) -> str:
    """value if it is a path on this site, else "/". Browsers read // and \\ as another host."""
    if not value or not value.startswith("/") or value.startswith("//"):
        return "/"
    if any(char == "\\" or char.isspace() or not char.isprintable() for char in value):
        return "/"
    return value


class Site:
    """Some other site; it keeps the URLs it was asked for."""

    def __init__(self):
        self.requested: tuple[str, ...] = ()

    def __call__(self, request: Request) -> Response:
        self.requested = (*self.requested, request.url)
        return Response(200, {}, "welcome to evil.example")


@dataclass(frozen=True)
class World:
    clock: Clock
    network: FakeNetwork
    provider: Provider
    config: dict
    app: App
    evil: Site


def _world(check: Callable | None = None) -> World:
    """id.example and its client app, whose callback checks state with check (check_state by default)."""
    clock, network = Clock(), FakeNetwork()
    provider = Provider(ISSUER, clock=clock, network=network)
    provider.register_client(CLIENT_ID, list(REGISTERED), secret=CLIENT_SECRET)
    provider.add_user("alice", "alice@example.com", True, "alice-password")
    provider.add_user("mallory", "mallory@example.com", True, "mallory-password")
    config = network.send(Request("GET", f"{ISSUER}/.well-known/openid-configuration")).body
    jwks = network.send(Request("GET", config["jwks_uri"])).body
    app = App(clock, network, config, jwks, check or check_state)
    evil = Site()
    network.mount(APP, app)
    network.mount(EVIL, evil)
    return World(clock, network, provider, config, app, evil)


def _browser(world: World, sub: str | None = None) -> Browser:
    browser = Browser(world.network)
    if sub is not None:
        world.provider.sign_in(browser, sub, ("pwd",))
    return browser


def _authorize(world: World, browser: Browser, params: dict) -> Response:
    """The provider's answer to the browser's /authorize request, before the browser follows it."""
    url = with_query(world.config["authorization_endpoint"], params)
    return world.network.send(Request("GET", url, cookies=browser.cookies(ISSUER)))


def _request_params(world: World, redirect_uri: str = REDIRECT_URI) -> tuple[dict, Transaction]:
    url, transaction = start_login(
        issuer_config=world.config, client_id=CLIENT_ID, redirect_uri=redirect_uri,
        now=world.clock.now(),
    )
    return dict(parse_qsl(urlsplit(url).query)), transaction


def _stop_at_callback(world: World, browser: Browser) -> str:
    """Start a login at the app as browser's user, and return the callback URL unvisited."""
    started = world.network.send(Request("GET", f"{APP}/login"))
    answer = world.network.send(Request("GET", started.location, cookies=browser.cookies(ISSUER)))
    return answer.location


def _bare_code(world: World, browser: Browser) -> str:
    """A code for app from a request with no state, no nonce and no PKCE."""
    params = {
        "response_type": "code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI,
        "scope": "openid email",
    }
    return Request("GET", _authorize(world, browser, params).location).query["code"]


def _user(browser: Browser) -> list | None:
    return browser.get(f"{APP}/").body["user"]


def test_an_unregistered_redirect_uri_gets_an_error_page():
    """RFC 6749 §4.1.2.1: the provider "MUST NOT automatically redirect the user-agent to the invalid redirection URI". A trailing slash is enough to make a URI unregistered."""
    world = _world()
    params, _ = _request_params(world)
    with_slash = {**params, "redirect_uri": f"{REDIRECT_URI}/"}
    answer = _authorize(world, _browser(world, "alice"), with_slash)
    assert answer.status == 400
    assert answer.location == None
    assert answer.body["error"] == "invalid_request"


def redirect_uri_allowed(registered: tuple[str, ...], uri: str | None) -> bool:
    return uri in registered


def test_accepts_each_registered_redirect_uri():
    """Implement redirect_uri_allowed above, the provider's check. Return True only if uri is, character for character, one of the registered strings. Parse nothing and normalise nothing."""
    assert redirect_uri_allowed(REGISTERED, REDIRECT_URI) is True
    assert redirect_uri_allowed(REGISTERED, SECOND_REDIRECT_URI) is True
    assert redirect_uri_allowed(REGISTERED, None) is False


def test_refuses_a_redirect_uri_that_only_looks_registered():
    """Each lookalike starts with, contains, or means the same as the registered URI. A provider that redirects to any of them may hand alice's code to someone else (RFC 6749 §10.6)."""
    world = _world()
    assert all("app.example" in uri.lower() for uri in LOOKALIKES)
    accepted = [uri for uri in LOOKALIKES if redirect_uri_allowed(REGISTERED, uri)]
    assert accepted == []
    params, _ = _request_params(world)
    alice = _browser(world, "alice")
    answers = [_authorize(world, alice, {**params, "redirect_uri": uri}) for uri in LOOKALIKES]
    assert {answer.status for answer in answers} == {400}


def test_the_token_request_repeats_the_redirect_uri():
    """RFC 6749 §4.1.3: the token request's redirect_uri and the authorization request's "MUST be identical". Both URIs here are registered; only the one the code was issued for will do."""
    world = _world()
    params, transaction = _request_params(world, REDIRECT_URI)
    answer = _authorize(world, _browser(world, "alice"), params)
    with pytest.raises(OAuthError) as refused:
        exchange_code(
            issuer_config=world.config, client_id=CLIENT_ID,
            code=Request("GET", answer.location).query["code"],
            redirect_uri=SECOND_REDIRECT_URI, code_verifier=transaction.code_verifier,
            network=world.network, client_secret=CLIENT_SECRET,
        )
    assert refused.value.error == "invalid_grant"


def test_spot_the_bug_in_compare_states():
    """Spot the bug: this app checks state with compare_states, in handle_callback. Read both. mallory asks for a code for app with no state, nonce or PKCE. Write the callback URL that signs alice's fresh browser in as mallory. It works partly because validate_id_token reads nonce=None as "no nonce was sent"."""
    world = _world(check=compare_states)
    code = _bare_code(world, _browser(world, "mallory"))
    alice = _browser(world)
    exploit = f"{REDIRECT_URI}?code={code}"
    assert urlsplit(exploit).netloc == "app.example"
    alice.get(exploit)
    assert _user(alice) == ["https://id.example", "mallory"]


def check_state(callback: Request, expected: str | None) -> None:
    returned = callback.query.get("state")
    if not returned:
        raise FlowError("missing_state")
    bound = callback.cookies.get(STATE_COOKIE)
    if not isinstance(expected, str) or not isinstance(bound, str):
        raise FlowError("state_mismatch")
    pending_here = expected in bound.split(".")
    if not (hmac.compare_digest(returned.encode(), expected.encode()) and pending_here):
        raise FlowError("state_mismatch")


def test_accepts_two_tabs_in_one_browser():
    """Implement check_state above; expected is the state of the pending login the callback's state names, or None. 1. No state in the callback: FlowError("missing_state"). 2. expected or the STATE_COOKIE cookie missing: FlowError("state_mismatch"). 3. The cookie holds the browser's pending states, joined by ".". Require the state to equal expected, and expected to be one of them, or raise "state_mismatch". hmac.compare_digest on bytes is a good habit here."""
    world = _world()
    alice = _browser(world)
    tabs = [alice.get(f"{APP}/login") for _ in range(2)]
    assert [tab.body["error"] for tab in tabs] == ["login_required", "login_required"]
    first, second = (request.url for request in alice.history if request.path == "/authorize")
    assert first != second
    world.provider.sign_in(alice, "alice", ("pwd",))
    assert alice.get(second).body["user"] == ["https://id.example", "alice"]
    assert alice.get(first).body["user"] == ["https://id.example", "alice"]
    assert (STATE_COOKIE in alice.cookies(APP)) == False


def test_refuses_a_login_planted_in_another_browser():
    """Login CSRF. mallory's callback URLs, loaded in alice's browser, must fail on state: one with no state, and one carrying mallory's own pending state. A state that is almost right is wrong too, and so is a cookie that merely contains the state."""
    world = _world()
    mallory = _browser(world, "mallory")
    with_her_state = _stop_at_callback(world, mallory)
    without_state = f"{REDIRECT_URI}?code={_bare_code(world, mallory)}"
    assert Request("GET", with_her_state).query["state"] in world.app.pending
    fresh, waiting = _browser(world), _browser(world)
    waiting.get(f"{APP}/login")
    planted = [
        (fresh, without_state, "missing_state"),
        (fresh, with_her_state, "state_mismatch"),
        (waiting, with_her_state, "state_mismatch"),
    ]
    for alice, url, reason in planted:
        assert alice.get(url).body["error"] == reason
        assert _user(alice) is None
    state = Request("GET", with_her_state).query["state"]
    near_misses = [
        (state[:-1], state), (state.swapcase(), state), (f"{state}x", state), ("other", state),
        (state, f"x{state}"), (state, f"{state}x"), (state, f"{state[:-1]}.x"),
    ]
    for returned, cookie in near_misses:
        url = f"{REDIRECT_URI}?state={returned}"
        with pytest.raises(FlowError) as refused:
            check_state(Request("GET", url, cookies={STATE_COOKIE: cookie}), state)
        assert refused.value.reason == "state_mismatch"


def test_refuses_a_callback_replayed_after_it_succeeded():
    """RFC 9700 §2.1: state is "one-time use". Once alice's login finishes, the app forgets its state, so loading the same callback URL again is refused, and her session is untouched."""
    world = _world()
    alice = _browser(world, "alice")
    alice.get(f"{APP}/login")
    callback = next(request.url for request in alice.history if request.path == "/callback")
    session = alice.cookies(APP)[SESSION_COOKIE]
    assert _user(alice) == ["https://id.example", "alice"]
    assert alice.get(callback).body["error"] == "state_mismatch"
    assert alice.cookies(APP)[SESSION_COOKIE] == session


def test_lands_only_on_its_own_pages():
    """/login?next=... says where to land after login. The app keeps next with the pending login, never reads it from the callback, and keeps it only if it is a path on its own site. Where does each login land?"""
    world = _world()
    alice = _browser(world, "alice")
    assert alice.get(f"{APP}/login?next=/settings").body["page"] == "/settings"
    off_site = ["//evil.example", "/\\evil.example", "https://evil.example", "/\t/evil.example"]
    for next_page in off_site:
        landed = alice.get(with_query(f"{APP}/login", {"next": next_page}))
        assert landed.body["page"] == "/"
    assert world.evil.requested == ()
