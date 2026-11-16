"""Parity for chapters 07 to 10: each solved function agrees with its toy/ counterpart."""

from functools import cache
from urllib.parse import parse_qsl, urlsplit

import pytest

from tests.parity_support import ID, OTHER, _outcome, _solved
from toy import client, client_auth, id_token, jose, token_endpoint
from toy.clock import Clock
from toy.errors import FlowError, OAuthError
from toy.http import Browser, FakeNetwork, Request, Response, with_query
from toy.keys import ATTACKER_RSA, RSA_1
from toy.provider import Provider


APP_ORIGIN, QUIZ_ORIGIN = "https://app.example", "https://quiz.example"


def _code_flow_world():
    """One provider with clients app and quiz, alice signed in, and the discovery document."""
    clock, network = Clock(), FakeNetwork()
    provider = Provider(clock=clock, network=network)
    for origin, client_id in ((APP_ORIGIN, "app"), (QUIZ_ORIGIN, "quiz")):
        provider.register_client(client_id, [f"{origin}/callback"])
        network.mount(origin, lambda request: Response(200, {}, "callback reached"))
    provider.add_user("alice", "alice@example.com", True, "alice-password")
    browser = Browser(network)
    provider.sign_in(browser, "alice", ("pwd",))
    config = network.send(Request("GET", f"{ID}/.well-known/openid-configuration")).body
    return clock, network, browser, config


def _flow_tokens(world, client_id: str, with_nonce: bool = True) -> dict:
    clock, network, browser, config = world
    redirect_uri = f"https://{client_id}.example/callback"
    url, transaction = client.start_login(
        issuer_config=config, client_id=client_id, redirect_uri=redirect_uri, now=clock.now()
    )
    params = {k: v for k, v in parse_qsl(urlsplit(url).query) if with_nonce or k != "nonce"}
    authorize = with_query(config["authorization_endpoint"], params)
    answer = network.send(Request("GET", authorize, cookies=browser.cookies(ID)))
    code = Request("GET", answer.location).query["code"]
    return client.exchange_code(
        issuer_config=config, client_id=client_id, code=code, redirect_uri=redirect_uri,
        code_verifier=transaction.code_verifier, network=network,
    )


@cache
def _token_login_cases():
    world = _code_flow_world()
    clock, _, _, config = world
    app, quiz = _flow_tokens(world, "app", with_nonce=False), _flow_tokens(world, "quiz")
    with_nonce = _flow_tokens(world, "app")
    now = clock.now()
    forged_claims = {"iss": ID, "sub": "alice", "aud": "app", "exp": now + 300, "iat": now}
    forged = jose.jws_encode({"alg": "RS256", "kid": "k1"}, forged_claims, ATTACKER_RSA)
    forms = {
        "app": {"id_token": app["id_token"]},
        "app-all-tokens": app,
        "app-with-nonce": {"id_token": with_nonce["id_token"]},
        "app-with-nonce-posted": {
            "id_token": with_nonce["id_token"],
            "nonce": jose.jws_split(with_nonce["id_token"])[1]["nonce"],
        },
        "empty": {},
        "access-token-only": {"access_token": quiz["access_token"]},
        "quiz": quiz,
        "forged": {"id_token": forged},
        "not-a-string": {"id_token": 5},
        "blank": {"id_token": ""},
    }
    jwks = jose.jwks_of(jose.public_jwk(RSA_1, "k1"))
    return forms, config, jwks, now


def _toy_token_login(form, config, jwks, now):
    def sign_in():
        claims = client.validate_id_token(
            form.get("id_token"), issuer=config["issuer"], client_id="app", jwks=jwks, now=now,
            nonce=None,
        )
        return client.account_key(claims)

    return _outcome(sign_in)


def test_token_login_cases_hold_both_accepted_and_refused_inputs():
    forms, config, jwks, now = _token_login_cases()
    outcomes = {_toy_token_login(form, config, jwks, now)[0] for form in forms.values()}
    assert outcomes == {"value", "refused"}


@pytest.mark.parametrize("late", [0, 300], ids=["now", "expired"])
@pytest.mark.parametrize("form_name", list(_token_login_cases()[0]))
def test_chapter_07_signed_in_user_matches_toy(form_name, late):
    signed_in_user = _solved("07_authorization_code_flow_test.py").signed_in_user
    forms, config, jwks, now = _token_login_cases()
    form = forms[form_name]
    solved = _outcome(
        lambda: signed_in_user(form, issuer_config=config, jwks=jwks, now=now + late)
    )
    assert solved == _toy_token_login(form, config, jwks, now + late)


REGISTERED_URIS = (f"{APP_ORIGIN}/callback", f"{APP_ORIGIN}/welcome")
CANDIDATE_URIS = [
    *REGISTERED_URIS,
    f"{APP_ORIGIN}/callback/", f"{APP_ORIGIN}/callback?x=1", f"{APP_ORIGIN}/callback#f",
    f"{APP_ORIGIN}/callback/../logout", f"{APP_ORIGIN}/%63allback",
    "https://app.example:443/callback",
    "https://APP.example/callback", "http://app.example/callback", f"{APP_ORIGIN}/Callback",
    "https://app.example.evil.example/callback", "https://app.example@evil.example/callback",
    "https://evil.example/https://app.example/callback", f"{APP_ORIGIN}/callbackx",
    f"{APP_ORIGIN}/", APP_ORIGIN, "", None,
]


def _provider_allows(uri: str | None) -> bool:
    """Whether the toy provider redirects to uri, or answers with its error page."""
    network = FakeNetwork()
    provider = Provider(clock=Clock(), network=network)
    provider.register_client("app", list(REGISTERED_URIS))
    params = {"response_type": "code", "client_id": "app", "scope": "openid"}
    if uri is not None:
        params = {**params, "redirect_uri": uri}
    answer = network.send(Request("GET", with_query(f"{ID}/authorize", params)))
    return answer.status != 400


def test_redirect_uri_candidates_hold_both_allowed_and_refused_inputs():
    assert {_provider_allows(uri) for uri in CANDIDATE_URIS} == {True, False}


@pytest.mark.parametrize("uri", CANDIDATE_URIS)
def test_chapter_08_redirect_uri_allowed_matches_toy(uri):
    redirect_uri_allowed = _solved("08_redirect_uri_and_state_test.py").redirect_uri_allowed
    assert redirect_uri_allowed(REGISTERED_URIS, uri) is _provider_allows(uri)


STATE_A, STATE_B = "a" * 20 + "Q-_9" * 5 + "b" * 3, "z" * 43
STATE_RETURNED = [None, "", STATE_A, STATE_A.upper(), STATE_A[:-1], f"{STATE_A}x", STATE_B, "é"]
STATE_COOKIES = [
    None, "", ".", STATE_A, STATE_B, f"{STATE_A}.{STATE_B}", f"{STATE_B}.{STATE_A}",
    f"x{STATE_A}", f"{STATE_A}x", f"{STATE_A}.", f"{STATE_A[:-1]}.{STATE_B}",
]
STATE_EXPECTED = [None, "", STATE_A, STATE_B]


def _flow_outcome(function):
    try:
        function()
        return ("value", None)
    except FlowError as refused:
        return ("refused", refused.reason)


def _state_callback(returned, cookie) -> Request:
    query = {} if returned is None else {"state": returned}
    cookies = {} if cookie is None else {client.STATE_COOKIE: cookie}
    return Request("GET", with_query(f"{APP_ORIGIN}/callback", query), cookies=cookies)


def _toy_state_outcome(returned, cookie, expected):
    transaction = client.Transaction(expected, "n", "v", f"{APP_ORIGIN}/callback", 0)
    callback = _state_callback(returned, cookie)
    return _flow_outcome(lambda: client._check_state(transaction, callback))


def test_state_cases_hold_both_accepted_and_refused_inputs():
    outcomes = {
        _toy_state_outcome(returned, cookie, expected)
        for returned in STATE_RETURNED for cookie in STATE_COOKIES for expected in STATE_EXPECTED
    }
    assert {"value", "refused"} == {kind for kind, _ in outcomes}
    assert {reason for _, reason in outcomes} == {None, "missing_state", "state_mismatch"}


@pytest.mark.parametrize("expected", STATE_EXPECTED)
@pytest.mark.parametrize("cookie", STATE_COOKIES)
@pytest.mark.parametrize("returned", STATE_RETURNED)
def test_chapter_08_check_state_matches_toy(returned, cookie, expected):
    check_state = _solved("08_redirect_uri_and_state_test.py").check_state
    callback = _state_callback(returned, cookie)
    solved = _flow_outcome(lambda: check_state(callback, expected))
    assert solved == _toy_state_outcome(returned, cookie, expected)


B_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
VERIFIERS = [B_VERIFIER, "v" * 43, "w" * 128, "~._-" * 11, "", "+" * 43, "v" * 42, "x" * 129]


@pytest.mark.parametrize("verifier", VERIFIERS)
def test_chapter_09_s256_matches_toy(verifier):
    s256 = _solved("09_nonce_and_pkce_test.py").s256
    assert s256(verifier) == client.s256(verifier)


def _grant_outcome(function):
    try:
        function()
        return ("value", None)
    except OAuthError as refused:
        return ("refused", refused.error)


PKCE_CHALLENGES = [
    None, client.s256(B_VERIFIER), f"{client.s256(B_VERIFIER)[:-1]}N", B_VERIFIER,
    client.s256("v" * 42), client.s256("x" * 129), client.s256("+" * 43), client.s256("~._-" * 11),
]
PKCE_VERIFIERS = [None, *VERIFIERS, B_VERIFIER[:-1], f"{B_VERIFIER}\n", f"{B_VERIFIER} "]


def test_pkce_cases_hold_both_accepted_and_refused_inputs():
    outcomes = {
        _grant_outcome(lambda: token_endpoint._check_verifier(challenge, verifier))[0]
        for challenge in PKCE_CHALLENGES for verifier in PKCE_VERIFIERS
    }
    assert outcomes == {"value", "refused"}


@pytest.mark.parametrize("verifier", PKCE_VERIFIERS)
@pytest.mark.parametrize("challenge", PKCE_CHALLENGES)
def test_chapter_09_check_pkce_matches_toy(challenge, verifier):
    check_pkce = _solved("09_nonce_and_pkce_test.py").check_pkce
    expected = _grant_outcome(lambda: token_endpoint._check_verifier(challenge, verifier))
    assert _grant_outcome(lambda: check_pkce(challenge, verifier)) == expected


NONCE = "n" * 20 + "Q-_9" * 5 + "m" * 3
NONCE_CLAIMS = [
    {}, {"nonce": NONCE}, {"nonce": NONCE.upper()}, {"nonce": NONCE[:-1]}, {"nonce": f"{NONCE}x"},
    {"nonce": None}, {"nonce": ""}, {"nonce": 1}, {"nonce": [NONCE]}, {"nonce": "é"},
]
NONCE_EXPECTED = [None, NONCE, "other", ""]


def test_nonce_cases_hold_both_accepted_and_refused_inputs():
    outcomes = {
        _outcome(lambda: id_token._check_nonce(claims, expected))[0]
        for claims in NONCE_CLAIMS for expected in NONCE_EXPECTED
    }
    assert outcomes == {"value", "refused"}


@pytest.mark.parametrize("expected", NONCE_EXPECTED)
@pytest.mark.parametrize("claims", NONCE_CLAIMS, ids=repr)
def test_chapter_09_check_nonce_matches_toy(claims, expected):
    check_nonce = _solved("09_nonce_and_pkce_test.py").check_nonce
    toy = _outcome(lambda: id_token._check_nonce(claims, expected))
    assert _outcome(lambda: check_nonce(claims, expected)) == toy


BASIC_CREDENTIALS = [
    ("s6BhdRkqt3", b"7Fjfp0ZBr1KtDRbnfVdmIw"), ("https://app.example/client", b"p:ss%2B w+rd"),
    ("a b+c", b"&=?/#"), ("zo\u00eb", "\u00e9".encode()), ("", b""), ("app", b"~-._*"),
    ("100%", b"%%"), ("app", b":"), ("a:b", b"c:d"), ("app", b"\xff\x00"),
]


@pytest.mark.parametrize(("client_id", "secret"), BASIC_CREDENTIALS)
def test_chapter_10_basic_authorization_matches_toy(client_id, secret):
    solved = _solved("10_token_endpoint_and_client_auth_test.py").basic_authorization
    assert solved(client_id, secret) == client.basic_authorization(client_id, secret)


NO_AUD = object()
ASSERTION_AUDIENCES = [
    ID, [ID], f"{ID}/token", [f"{ID}/token"], [ID, f"{ID}/token"], [ID, ID], [ID, OTHER], OTHER,
    f"{ID}/", "https://ID.example", f"{ID}.evil.example", "https://id.exampl", "", None, [],
    [[ID]], 5, {"aud": ID}, (ID,), NO_AUD,
]


def _toy_accepts_assertion_audience(aud) -> bool:
    claims = {"iss": "c", "sub": "c", "jti": "j", "exp": 100}
    if aud is not NO_AUD:
        claims = {**claims, "aud": aud}
    try:
        client_auth._check_assertion(claims, "c", {}, ID, 0, frozenset())
    except OAuthError:
        return False
    return True


def test_assertion_audiences_hold_both_accepted_and_refused_inputs():
    assert {_toy_accepts_assertion_audience(aud) for aud in ASSERTION_AUDIENCES} == {True, False}


@pytest.mark.parametrize("aud", ASSERTION_AUDIENCES, ids=repr)
def test_chapter_10_audience_is_issuer_matches_toy(aud):
    solved = _solved("10_token_endpoint_and_client_auth_test.py").audience_is_issuer
    given = None if aud is NO_AUD else aud
    assert solved(given, ID) is _toy_accepts_assertion_audience(aud)
