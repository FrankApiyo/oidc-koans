"""The authorization code flow, end to end.

OIDC Core §3.1.1 lists the steps. The client sends the browser to the
provider's authorization endpoint with response_type=code, scope=openid,
its client_id and its redirect_uri. The provider signs the user in and
sends the browser back to the redirect_uri with a code. The client posts
that code to the token endpoint itself, and the JSON response carries an ID
token and an access token. The client validates the ID token and reads
from it who signed in.

The browser carries only the code. A code is single-use and short-lived:
RFC 6749 §4.1.2 recommends 10 minutes at most, and this provider allows 60
seconds. Tokens travel on the back channel, in a response marked
Cache-Control: no-store. When the provider cannot issue a code, it sends
the browser back to a valid redirect_uri with an error parameter instead.

Each token has its own reader. The ID token is a statement to the client,
and its aud names the client. The access token is for an API such as
UserInfo, which answers the same whichever client the token was issued to.
RFC 6749 §10.16 describes the attack in the implicit flow: an access token
issued to an attacker's client, handed to another client as a login.

A common mistake: signing someone in because their access token works at
UserInfo. Sign in only from a validated ID token whose aud is you.

Read more:
  https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowSteps
  https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
  https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1
  https://www.rfc-editor.org/rfc/rfc6749.html#section-10.16
"""

import secrets
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from conftest import __
from toy.client import (
    STATE_COOKIE,
    Transaction,
    account_key,
    bind_state,
    fetch_userinfo,
    finish_login,
    start_login,
    validate_id_token,
)
from toy.clock import Clock
from toy.errors import FlowError, InvalidToken, OAuthError
from toy.http import Browser, FakeNetwork, Request, Response, with_query
from toy.jose import jws_encode
from toy.keys import ATTACKER_RSA
from toy.provider import Provider

ISSUER = "https://id.example"
APP = "https://app.example"
REDIRECT_URI = f"{APP}/callback"
CLIENT_ID = "app"
QUIZ = "https://quiz.example"
QUIZ_REDIRECT_URI = f"{QUIZ}/callback"
SESSION_COOKIE = "app_session"


class App:
    """The client at https://app.example.

    /login starts a login and binds its state to the browser. /callback finishes
    it with toy finish_login and starts a session. /token-login signs in a user
    of the app's mobile build from the tokens it posts, through signed_in_user.
    Any other page shows who is signed in.
    """

    def __init__(self, clock: Clock, network: FakeNetwork, config: dict, jwks: dict):
        self._clock, self._network, self._config, self._jwks = clock, network, config, jwks
        self.pending: dict[str, Transaction] = {}
        self.sessions: dict[str, tuple[str, str]] = {}

    def __call__(self, request: Request) -> Response:
        routes = {"/login": self._login, "/callback": self._callback, "/token-login": self._token}
        return routes.get(request.path, self._page)(request)

    def _login(self, request: Request) -> Response:
        url, transaction = start_login(
            issuer_config=self._config, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI,
            now=self._clock.now(),
        )
        self.pending = {**self.pending, transaction.state: transaction}
        bound = bind_state(request.cookies.get(STATE_COOKIE), transaction.state)
        return Response(303, {"Location": url}, "", {STATE_COOKIE: bound})

    def _callback(self, request: Request) -> Response:
        transaction = self.pending.get(request.query.get("state", ""))
        if transaction is None:
            return Response(400, {}, {"error": "no login is pending"})
        self.pending = {k: v for k, v in self.pending.items() if k != transaction.state}
        try:
            claims = finish_login(
                transaction=transaction, callback=request, issuer_config=self._config,
                client_id=CLIENT_ID, jwks=self._jwks, network=self._network,
                now=self._clock.now(),
            )
        except (FlowError, InvalidToken, OAuthError) as refused:
            return _refused(refused)
        return self._sign_in(account_key(claims))

    def _token(self, request: Request) -> Response:
        try:
            user = signed_in_user(
                request.form, issuer_config=self._config, jwks=self._jwks,
                now=self._clock.now(),
            )
        except InvalidToken as refused:
            return _refused(refused)
        return self._sign_in(user)

    def _sign_in(self, user: tuple[str, str]) -> Response:
        session_id = secrets.token_urlsafe(16)
        self.sessions = {**self.sessions, session_id: user}
        return Response(200, {}, {"user": list(user)}, {SESSION_COOKIE: session_id})

    def _page(self, request: Request) -> Response:
        user = self.sessions.get(request.cookies.get(SESSION_COOKIE, ""))
        return Response(200, {}, {"page": request.path, "user": list(user) if user else None})


@dataclass(frozen=True)
class World:
    clock: Clock
    network: FakeNetwork
    provider: Provider
    config: dict
    jwks: dict
    app: App


def _refused(error: Exception) -> Response:
    return Response(401, {}, {"error": getattr(error, "reason", None) or error.error})


def _world() -> World:
    """id.example with two clients, app and quiz; alice and mallory have accounts there."""
    clock, network = Clock(), FakeNetwork()
    provider = Provider(ISSUER, clock=clock, network=network)
    provider.register_client(CLIENT_ID, [REDIRECT_URI])
    provider.register_client("quiz", [QUIZ_REDIRECT_URI])
    provider.add_user("alice", "alice@example.com", True, "alice-password")
    provider.add_user("mallory", "mallory@example.com", True, "mallory-password")
    config = network.send(Request("GET", f"{ISSUER}/.well-known/openid-configuration")).body
    jwks = network.send(Request("GET", config["jwks_uri"])).body
    world = World(clock, network, provider, config, jwks, App(clock, network, config, jwks))
    network.mount(APP, world.app)
    network.mount(QUIZ, lambda request: Response(200, {}, "callback reached"))
    return world


def _browser(world: World, sub: str | None = None) -> Browser:
    browser = Browser(world.network)
    if sub is not None:
        world.provider.sign_in(browser, sub, ("pwd",))
    return browser


def _redirect(world, browser, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI, edit=dict, **extra):
    """The provider's answer to the browser's /authorize request, before the browser follows it.

    edit may change the request's parameters. Returns the answer and the transaction.
    """
    url, transaction = start_login(
        issuer_config=world.config, client_id=client_id, redirect_uri=redirect_uri,
        now=world.clock.now(), extra=extra or None,
    )
    params = edit(dict(parse_qsl(urlsplit(url).query)))
    authorize = with_query(world.config["authorization_endpoint"], params)
    answer = world.network.send(Request("GET", authorize, cookies=browser.cookies(ISSUER)))
    return answer, transaction


def _code(world, browser, **options) -> tuple[str, Transaction]:
    answer, transaction = _redirect(world, browser, **options)
    return Request("GET", answer.location).query["code"], transaction


def _redeem(world, code, transaction, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI):
    form = {
        "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
        "code_verifier": transaction.code_verifier, "client_id": client_id,
    }
    return world.network.send(Request("POST", world.config["token_endpoint"], form=form))


def _without_nonce(params: dict) -> dict:
    return {name: value for name, value in params.items() if name != "nonce"}


def _as_implicit(params: dict) -> dict:
    return {**params, "response_type": "token"}


def test_one_trip_through_the_browser_signs_alice_in():
    """alice is signed in at the provider and opens the client's /login. Her browser follows two redirects, and the client signs her in under the issuer and her subject."""
    world = _world()
    alice = _browser(world, "alice")
    before = len(alice.history)
    landed = alice.get(f"{APP}/login")
    visited = [(request.origin, request.path) for request in alice.history[before:]]
    assert visited == __
    assert landed.body["user"] == __
    assert alice.get(f"{APP}/").body["user"] == ["https://id.example", "alice"]


def test_the_client_asks_for_a_code():
    """OIDC Core §3.1.2.1: response_type picks the flow, and scope must hold openid for this to be an OpenID Connect request. redirect_uri says where the browser comes back."""
    world = _world()
    alice = _browser(world, "alice")
    alice.get(f"{APP}/login")
    authorize = next(request for request in alice.history if request.path == "/authorize")
    assert authorize.query["response_type"] == __
    assert "openid" in authorize.query["scope"].split()
    assert authorize.query["redirect_uri"] == __
    assert authorize.query["client_id"] == __


def test_a_code_is_not_an_access_token():
    """The code is a one-time grant for the token endpoint. Call UserInfo with it as a bearer token and see what an API makes of it."""
    world = _world()
    code, _ = _code(world, _browser(world, "alice"))
    request = Request(
        "GET", world.config["userinfo_endpoint"], headers={"Authorization": f"Bearer {code}"}
    )
    answer = world.network.send(request)
    assert answer.status == __
    assert answer.body["error"] == __


def test_the_client_redeems_the_code_on_the_back_channel():
    """OIDC Core §3.1.3.3: a token response "MUST include" Cache-Control with no-store, so nothing caches the tokens. token_type names the kind of access token, and is case-insensitive."""
    world = _world()
    code, transaction = _code(world, _browser(world, "alice"))
    answer = _redeem(world, code, transaction)
    assert answer.status == 200
    assert {"access_token", "id_token", "token_type"} <= set(answer.body)
    assert answer.headers["Cache-Control"] == __
    assert answer.body["token_type"].lower() == __


def test_a_code_works_once_and_not_for_long():
    """RFC 6749 §4.1.2: "The client MUST NOT use the authorization code more than once." This provider also lets a code live for 60 seconds. Both mistakes get the same error code (RFC 6749 §5.2)."""
    world = _world()
    alice = _browser(world, "alice")
    code, transaction = _code(world, alice)
    assert _redeem(world, code, transaction).status == 200
    assert _redeem(world, code, transaction).body["error"] == __
    late_code, late_transaction = _code(world, alice)
    world.clock.advance(60)
    assert _redeem(world, late_code, late_transaction).body["error"] == __


def test_errors_come_back_to_the_redirect_uri():
    """response_type=token asks for tokens in the redirect itself (the implicit flow). This provider speaks only the code flow, so it sends the browser back with an error (RFC 6749 §4.1.2.1), the state, and neither a code nor a token."""
    world = _world()
    answer, transaction = _redirect(world, _browser(world, "alice"), edit=_as_implicit)
    returned = Request("GET", answer.location).query
    assert answer.location.startswith(REDIRECT_URI)
    assert returned["error"] == __
    assert returned["state"] == __
    assert {"code", "access_token", "id_token"} & set(returned) == __


def test_prompt_none_never_shows_a_login_page():
    """OIDC Core §3.1.2.1: with prompt=none the provider "MUST NOT display any authentication or consent user interface pages". Nobody is signed in in this browser, so it answers with an error from §3.1.2.6."""
    world = _world()
    answer, _ = _redirect(world, _browser(world), prompt="none")
    returned = Request("GET", answer.location).query
    assert answer.location.startswith(REDIRECT_URI)
    assert returned["error"] == __
    assert "code" not in returned


def signed_in_user(form: dict, *, issuer_config: dict, jwks: dict, now: int) -> tuple[str, str]:
    __()


def _mobile_login(world: World, browser: Browser) -> dict:
    """The tokens the app's mobile build gets from its own login. It sends no nonce."""
    code, transaction = _code(world, browser, edit=_without_nonce)
    return _redeem(world, code, transaction).body


def test_accepts_an_id_token_issued_to_this_client():
    """Implement signed_in_user above; /token-login calls it with the form the mobile build posts. 1. Pass form.get("id_token") to validate_id_token, with issuer_config["issuer"], CLIENT_ID, jwks, now and nonce=None, since the mobile build sent no nonce. 2. Return account_key(claims). Never read the access token: with no id_token, validate_id_token refuses None as malformed. The cost of nonce=None: a leaked mobile ID token replays here until it expires; chapter 09's nonce ties a token to one login."""
    world = _world()
    alice = _browser(world, "alice")
    tokens = _mobile_login(world, alice)
    landed = alice.post(f"{APP}/token-login", tokens)
    assert landed.status == 200
    assert landed.body["user"] == __
    assert alice.get(f"{APP}/").body["user"] == ["https://id.example", "alice"]


def test_refuses_an_access_token_as_proof_of_identity():
    """quiz is mallory's app at the same provider, and alice once signed in to it, so mallory holds alice's tokens issued to quiz. They work at UserInfo, and still say nothing about a login to app. Nor does an ID token mallory signed herself, or one from app's own web login posted with its nonce: that nonce belongs to alice's browser, not to whoever posts it."""
    world = _world()
    alice = _browser(world, "alice")
    code, transaction = _code(world, alice, client_id="quiz", redirect_uri=QUIZ_REDIRECT_URI)
    quiz = _redeem(world, code, transaction, "quiz", QUIZ_REDIRECT_URI).body
    userinfo = fetch_userinfo(
        issuer_config=world.config, access_token=quiz["access_token"], network=world.network
    )
    assert userinfo["sub"] == "alice"
    now = world.clock.now()
    forged = jws_encode(
        {"alg": "RS256", "kid": "k1"},
        {"iss": ISSUER, "sub": "alice", "aud": CLIENT_ID, "exp": now + 300, "iat": now},
        ATTACKER_RSA,
    )
    web_code, web_login = _code(world, alice)
    web = _redeem(world, web_code, web_login).body
    mallory = _browser(world)
    attempts = [
        ({"access_token": quiz["access_token"]}, __),
        ({**quiz}, __),
        ({"id_token": forged}, __),
        ({"id_token": web["id_token"], "nonce": web_login.nonce}, __),
    ]
    for form, reason in attempts:
        refused = mallory.post(f"{APP}/token-login", form)
        assert (refused.status, refused.body["error"]) == (401, reason)
    assert world.app.sessions == {}
    assert SESSION_COOKIE not in mallory.cookies(APP)
