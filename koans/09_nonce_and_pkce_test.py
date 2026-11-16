"""nonce and PKCE.

Each binds something state does not. nonce binds the ID token to the
browser session that asked for it. The client sends a fresh, unguessable
value in the authorization request and keeps it with the pending login.
The provider copies it into the ID token, and OIDC Core §2 says clients
"MUST verify" that the claim equals the value sent. Sending a nonce is
OPTIONAL in the code flow; once one is sent, the claim must come back.

PKCE (RFC 7636) binds the code to the client instance that asked for it.
The client makes a code_verifier of 43 to 128 unreserved characters, sends
code_challenge = BASE64URL(SHA256(ASCII(code_verifier))) with method S256,
and redeems the code with the verifier. A client able to use S256 "MUST
use" it: with plain, the challenge is the verifier, so whoever sees the
request has it. RFC 9700 §2.1.1 says "Public clients MUST use PKCE", and
§4.8.2 has the provider refuse a verifier for a code issued with no challenge.

Can they replace state? RFC 9700 §2.1 says a client that has made sure the
provider supports PKCE "MAY rely on" it against CSRF, and "In OpenID
Connect flows, the nonce parameter provides CSRF protection"; otherwise
state must be used. Against code injection, §2.1.1 lets confidential OIDC
clients use nonce instead of PKCE. Public clients still need PKCE.

A common mistake: checking nonce only when the ID token happens to carry one.

Read more:
  https://www.rfc-editor.org/rfc/rfc7636.html#section-4.2
  https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.1
  https://www.rfc-editor.org/rfc/rfc9700.html#section-4.8.2
  https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
"""

import hashlib
import hmac
import secrets
import string
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
    finish_login,
    release_state,
    start_login,
)
from toy.clock import Clock
from toy.errors import FlowError, InvalidToken, OAuthError
from toy.http import Browser, FakeNetwork, Request, Response, with_query
from toy.jose import b64url_encode, jws_verify
from toy.provider import Provider

ISSUER = "https://id.example"
APP = "https://app.example"
REDIRECT_URI = f"{APP}/callback"
CLIENT_ID = "app"
SESSION_COOKIE = "app_session"
ALGS = frozenset({"RS256"})
UNRESERVED = frozenset(string.ascii_letters + string.digits + "-._~")
APPENDIX_B_OCTETS = bytes([
    116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
    187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121,
])
APPENDIX_B_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
APPENDIX_B_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


class App:
    """The client at https://app.example, a public client: it has no secret.

    /login starts a login and binds its state to the browser. /callback finishes
    it with toy finish_login, which sends the verifier and checks the nonce. Any
    other page shows who is signed in.
    """

    def __init__(self, clock: Clock, network: FakeNetwork, config: dict, jwks: dict):
        self._clock, self._network, self._config, self._jwks = clock, network, config, jwks
        self.pending: dict[str, Transaction] = {}
        self.sessions: dict[str, tuple[str, str]] = {}

    def __call__(self, request: Request) -> Response:
        routes = {"/login": self._login, "/callback": self._callback}
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
        state = request.query.get("state", "")
        transaction = self.pending.get(state)
        if transaction is None:
            return Response(401, {}, {"error": "state_mismatch"})
        self.pending = {k: v for k, v in self.pending.items() if k != state}
        try:
            claims = finish_login(
                transaction=transaction, callback=request, issuer_config=self._config,
                client_id=CLIENT_ID, jwks=self._jwks, network=self._network,
                now=self._clock.now(),
            )
        except (FlowError, InvalidToken, OAuthError) as refused:
            return Response(401, {}, {"error": getattr(refused, "reason", None) or refused.error})
        session_id = secrets.token_urlsafe(16)
        self.sessions = {**self.sessions, session_id: account_key(claims)}
        released = release_state(request.cookies.get(STATE_COOKIE), state)
        cookies = {SESSION_COOKIE: session_id, STATE_COOKIE: released}
        return Response(200, {}, {"user": list(account_key(claims))}, cookies)

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


def _world() -> World:
    """id.example and its public client app; alice, bob and mallory have accounts."""
    clock, network = Clock(), FakeNetwork()
    provider = Provider(ISSUER, clock=clock, network=network)
    provider.register_client(CLIENT_ID, [REDIRECT_URI])
    for user in ("alice", "bob", "mallory"):
        provider.add_user(user, f"{user}@example.com", True, f"{user}-password")
    config = network.send(Request("GET", f"{ISSUER}/.well-known/openid-configuration")).body
    jwks = network.send(Request("GET", config["jwks_uri"])).body
    app = App(clock, network, config, jwks)
    network.mount(APP, app)
    return World(clock, network, provider, config, jwks, app)


def _browser(world: World, sub: str | None = None) -> Browser:
    browser = Browser(world.network)
    if sub is not None:
        world.provider.sign_in(browser, sub, ("pwd",))
    return browser


def _authorize(world: World, browser: Browser, params: dict) -> Response:
    """The provider's answer to the browser's /authorize request, before the browser follows it."""
    url = with_query(world.config["authorization_endpoint"], params)
    return world.network.send(Request("GET", url, cookies=browser.cookies(ISSUER)))


def _request_params(world: World) -> tuple[dict, Transaction]:
    url, transaction = start_login(
        issuer_config=world.config, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI,
        now=world.clock.now(),
    )
    return dict(parse_qsl(urlsplit(url).query)), transaction


def _token_request(world: World, code: str, verifier: str | None) -> Response:
    form = {
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
    }
    form = form if verifier is None else {**form, "code_verifier": verifier}
    return world.network.send(Request("POST", world.config["token_endpoint"], form=form))


def _start(world: World, browser: Browser) -> str:
    """Start a login at the app in a browser nobody has signed in to yet.

    The provider answers 401 login_required; returns the authorize URL to reload after sign_in.
    """
    started = browser.get(f"{APP}/login")
    assert started.body["error"] == "login_required"
    return browser.history[-1].url


def _callback_url(world: World, browser: Browser, sub: str) -> str:
    """A login at the app in browser, signed in as sub and stopped before the callback."""
    authorize = _start(world, browser)
    world.provider.sign_in(browser, sub, ("pwd",))
    return _authorize(world, browser, Request("GET", authorize).query).location


def _id_claims(world: World, browser: Browser, edit=dict) -> tuple[dict, Transaction]:
    """A login by hand, edit changing the request; the ID token's signature-checked claims."""
    params, transaction = _request_params(world)
    code = Request("GET", _authorize(world, browser, edit(params)).location).query["code"]
    tokens = _token_request(world, code, transaction.code_verifier).body
    return jws_verify(tokens["id_token"], world.jwks, ALGS), transaction


def _without_nonce(params: dict) -> dict:
    return {name: value for name, value in params.items() if name != "nonce"}


def s256(verifier: str) -> str:
    __()


def test_s256_matches_rfc_7636_appendix_b():
    """Implement s256 above. RFC 7636 §4.2: code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier))). Hash the verifier's ASCII bytes, not the octets it was made from, and use toy.jose's b64url_encode, which drops the padding."""
    assert b64url_encode(APPENDIX_B_OCTETS) == APPENDIX_B_VERIFIER
    assert s256(APPENDIX_B_VERIFIER) == APPENDIX_B_CHALLENGE
    assert len(s256(APPENDIX_B_VERIFIER)) == __


def test_a_verifier_is_43_to_128_unreserved_characters():
    """RFC 7636 §4.1 fixes the verifier's length. This provider refuses a verifier outside it, even one whose S256 challenge matches. The toy client makes its verifiers from 32 random octets, as §4.1 recommends."""
    world = _world()
    alice = _browser(world, "alice")

    def redeems(verifier: str) -> bool:
        params, _ = _request_params(world)
        answer = _authorize(world, alice, {**params, "code_challenge": s256(verifier)})
        code = Request("GET", answer.location).query["code"]
        return _token_request(world, code, verifier).status == 200

    outcomes = {length: redeems("v" * length) for length in (42, 43, 128, 129)}
    assert outcomes == __
    _, transaction = _request_params(world)
    assert len(transaction.code_verifier) == __
    assert set(transaction.code_verifier) <= UNRESERVED


def test_plain_gives_the_verifier_away():
    """With method plain, the challenge is the verifier itself, so whoever reads the authorization request can redeem the code. RFC 7636 §7.2: "Clients MUST NOT downgrade to "plain" after trying the "S256" method." This provider accepts S256 only, and says so in its metadata."""
    world = _world()
    params, transaction = _request_params(world)
    plain = {
        **params, "code_challenge": transaction.code_verifier, "code_challenge_method": "plain",
    }
    answer = _authorize(world, _browser(world, "alice"), plain)
    assert world.config["code_challenge_methods_supported"] == __
    assert Request("GET", answer.location).query["error"] == __


def check_pkce(challenge: str | None, verifier: str | None) -> None:
    __()


def test_accepts_the_verifier_that_made_the_challenge():
    """Implement check_pkce above, the token endpoint's check; challenge is what the code was issued with. 1. No challenge: accept only a request that sends no verifier at all (RFC 9700 §4.8.2). 2. Otherwise the verifier must be 43 to 128 characters, all in UNRESERVED, with s256(verifier) equal to the challenge (RFC 7636 §4.6). Refuse with OAuthError("invalid_grant")."""
    verifier = secrets.token_urlsafe(32)
    assert check_pkce(s256(verifier), verifier) is __
    assert check_pkce(s256(APPENDIX_B_VERIFIER), APPENDIX_B_VERIFIER) is None
    assert check_pkce(None, None) is None


def test_refuses_a_downgraded_or_mismatched_verifier():
    """Each row is a code's challenge and the verifier sent for it. The fourth is the downgrade of RFC 9700 §4.8: a code issued without a challenge, redeemed with a verifier. The fifth is a plain challenge, under this provider's S256-only rule. The last differs from the right challenge in one character."""
    verifier, other = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    short, long, reserved = "s" * 42, "l" * 129, "+" * 43
    rows = [
        (s256(verifier), other),
        (s256(verifier), None),
        (s256(verifier), verifier[:-1]),
        (None, verifier),
        (verifier, verifier),
        (s256(short), short),
        (s256(long), long),
        (s256(reserved), reserved),
        (f"{APPENDIX_B_CHALLENGE[:-1]}N", APPENDIX_B_VERIFIER),
    ]
    for challenge, sent in rows:
        with pytest.raises(OAuthError) as refused:
            check_pkce(challenge, sent)
        assert refused.value.error == __


def test_refuses_a_stolen_code_without_its_verifier():
    """alice's callback URL leaks, code and all, before her browser loads it. mallory first redeems the code herself. Then she injects it into a login of her own: her browser, her state, and alice's code. State passes; PKCE does not."""
    world = _world()
    leaked = Request("GET", _callback_url(world, _browser(world), "alice")).query["code"]
    assert _token_request(world, leaked, None).body["error"] == __
    second_leak = Request("GET", _callback_url(world, _browser(world), "alice")).query["code"]
    mallory = _browser(world)
    her_callback = Request("GET", _callback_url(world, mallory, "mallory")).query
    injected = with_query(REDIRECT_URI, {**her_callback, "code": second_leak})
    assert her_callback["state"] in world.app.pending
    assert her_callback["state"] == mallory.cookies(APP)[STATE_COOKIE]
    assert mallory.get(injected).body["error"] == __
    assert world.app.sessions == {}
    alice = _browser(world, "alice")
    assert alice.get(f"{APP}/login").body["user"] == ["https://id.example", "alice"]


def test_each_login_keeps_its_own_verifier():
    """RFC 9700 §2.1.1: the challenge "MUST be transaction-specific". alice starts, bob starts, alice finishes, bob finishes. Each login keeps its verifier with its own pending record, and never puts it in the URL."""
    world = _world()
    alice, bob = _browser(world), _browser(world)
    pages = {browser: _start(world, browser) for browser in (alice, bob)}
    for browser, authorize in pages.items():
        transaction = world.app.pending[Request("GET", authorize).query["state"]]
        assert Request("GET", authorize).query["code_challenge"] == s256(transaction.code_verifier)
        assert (transaction.code_verifier in authorize) == __
    for browser, sub in ((alice, "alice"), (bob, "bob")):
        world.provider.sign_in(browser, sub, ("pwd",))
        assert browser.get(pages[browser]).body["user"] == __


def check_nonce(claims: dict, expected: str | None) -> None:
    __()


def test_accepts_the_nonce_this_login_sent():
    """Implement check_nonce above; expected is the nonce this login sent, or None. 1. If none was sent and the claims have no nonce, accept. 2. Otherwise the nonce claim must be a string equal to expected, or raise InvalidToken("nonce_mismatch")."""
    world = _world()
    alice = _browser(world, "alice")
    claims, transaction = _id_claims(world, alice)
    assert claims["nonce"] == __
    assert check_nonce(claims, transaction.nonce) is None
    without, _ = _id_claims(world, alice, _without_nonce)
    assert ("nonce" in without) == __
    assert check_nonce(without, None) is None


def test_refuses_an_id_token_without_this_logins_nonce():
    """OIDC Core §3.1.3.7 step 11: "If a nonce value was sent in the Authentication Request, a nonce Claim MUST be present" and equal. mallory's genuine token carries her own nonce. A token from a login that sent none carries none. A finished login's nonce is spent. And Core §2 says "The nonce value is a case-sensitive string", so a null one is no match for "nothing was sent"."""
    world = _world()
    alice, mallory = _browser(world, "alice"), _browser(world, "mallory")
    _, pending = _request_params(world)
    hers, her_login = _id_claims(world, mallory)
    no_nonce, _ = _id_claims(world, mallory, _without_nonce)
    assert hers["nonce"] == her_login.nonce
    finished, spent = _id_claims(world, alice)
    for claims, expected in [
        (hers, pending.nonce),
        (no_nonce, pending.nonce),
        ({**hers, "nonce": pending.nonce.swapcase()}, pending.nonce),
        ({**hers, "nonce": pending.nonce[:-1]}, pending.nonce),
        (finished, None),
        ({**no_nonce, "nonce": None}, None),
    ]:
        with pytest.raises(InvalidToken) as refused:
            check_nonce(claims, expected)
        assert refused.value.reason == __
    assert check_nonce(finished, spent.nonce) is None
