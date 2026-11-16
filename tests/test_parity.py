"""Each chapter's solved function agrees with its toy/ counterpart, attack inputs included.

The solved functions are loaded from solutions/ by path, since chapter files
are not a package. Run from the repo root with: pytest tests/test_parity.py
"""

import hmac
import importlib.util
from functools import cache
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qsl, urlsplit

import pytest
from cryptography.hazmat.primitives import serialization

from toy import client, client_auth, id_token, jose, token_endpoint
from toy.clock import Clock
from toy.errors import FlowError, InvalidToken, OAuthError
from toy.http import Browser, FakeNetwork, Request, Response, with_query
from toy.keys import ATTACKER_RSA, EC_1, HMAC_SECRET, RSA_1, RSA_2
from toy.provider import Provider

ROOT = Path(__file__).resolve().parent.parent


@cache
def _solved(filename: str):
    path = ROOT / "solutions" / filename
    spec = importlib.util.spec_from_file_location(f"solved_{path.stem}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _outcome(function, *args):
    try:
        return ("value", function(*args))
    except InvalidToken as refused:
        return ("refused", refused.reason)


B64URL_TEXTS = [
    "", "YQ", "YR", "YWI", "YWJj", "-_8", "AAECAwQ",
    "YQ==", "YQ=", "+/8", "+/8=", "-_8=junk", "Y", "YWJjZ",
    "Y Q", " YQ", "YQ ", "YQ\n", "YQ\r\n", "YQ\t", "Zm9v.", "ë", None, b"YQ",
]


def test_b64url_texts_hold_both_honest_and_malformed_inputs():
    outcomes = {_outcome(jose.b64url_decode, text)[0] for text in B64URL_TEXTS}
    assert outcomes == {"value", "refused"}


@pytest.mark.parametrize("text", B64URL_TEXTS)
def test_chapter_02_b64url_decode_matches_toy(text):
    solved = _solved("02_base64url_and_json_test.py").b64url_decode
    assert _outcome(solved, text) == _outcome(jose.b64url_decode, text)


SIGNERS = {"HS256": HMAC_SECRET, "RS256": RSA_1, "ES256": EC_1}
SIGNER_JWKS = jose.jwks_of(*(jose.public_jwk(key, alg) for alg, key in SIGNERS.items()))
SIGNED_PAYLOAD = {"iss": "https://id.example", "sub": "alice"}
ALL_ALGS = frozenset({"HS256", "RS256", "ES256"})
ALG_HEADERS = [
    {"alg": "HS256"}, {"alg": "RS256"}, {"alg": "ES256"},
    {"alg": "none"}, {"alg": "None"}, {"alg": "NONE"}, {"alg": "nOnE"}, {},
    {"alg": None}, {"alg": ["HS256"]}, {"alg": "hs256"}, {"alg": "HS256 "}, {"alg": "HS512"},
]
ALLOWED_SETS = [
    frozenset({"HS256"}), frozenset({"RS256", "ES256"}), frozenset(),
    frozenset({"none"}), frozenset({"HS256", "none"}), frozenset({"HS512"}),
]


def _token_for(header: dict) -> str:
    """Honest headers are signed with a published key; any other header gets no signature."""
    signer = SIGNERS.get(header.get("alg")) if isinstance(header.get("alg"), str) else None
    if signer is None:
        return f"{jose.json_segment(header)}.{jose.json_segment(SIGNED_PAYLOAD)}."
    return jose.jws_encode({**header, "kid": header["alg"]}, SIGNED_PAYLOAD, signer)


def _toy_alg_outcome(header: dict, allowed: frozenset[str]):
    outcome = _outcome(jose.jws_verify, _token_for(header), SIGNER_JWKS, allowed)
    return ("value", header["alg"]) if outcome == ("value", SIGNED_PAYLOAD) else outcome


def test_alg_headers_hold_both_allowed_and_refused_inputs():
    outcomes = {
        _toy_alg_outcome(header, allowed)[0] for header in ALG_HEADERS for allowed in ALLOWED_SETS
    }
    assert outcomes == {"value", "refused"}


@pytest.mark.parametrize("allowed", ALLOWED_SETS, ids=lambda algs: "+".join(sorted(algs)))
@pytest.mark.parametrize("header", ALG_HEADERS, ids=repr)
def test_chapter_03_check_alg_matches_toy(header, allowed):
    solved = _solved("03_jws_and_jwt_test.py").check_alg
    assert _outcome(solved, header, allowed) == _toy_alg_outcome(header, allowed)


OTHER_HS256_SECRET = b"another-secret-of-32-octets-long"
HS256_HONEST = jose.jws_encode({"alg": "HS256", "kid": "s1"}, SIGNED_PAYLOAD, HMAC_SECRET)
HS256_HEADER, HS256_PAYLOAD, HS256_SIGNATURE = HS256_HONEST.split(".")
HS256_TOKENS = [
    HS256_HONEST,
    f"{HS256_HEADER}.{jose.json_segment({**SIGNED_PAYLOAD, 'sub': 'admin'})}.{HS256_SIGNATURE}",
    f"{HS256_HEADER}.{HS256_PAYLOAD}.{HS256_SIGNATURE[:22]}",
    f"{HS256_HEADER}.{HS256_PAYLOAD}.{HS256_SIGNATURE}AA",
    f"{HS256_HEADER}.{HS256_PAYLOAD}.{jose.b64url_encode(jose.b64url_decode(HS256_SIGNATURE) + b'extra')}",
    f"{HS256_HEADER}.{HS256_PAYLOAD}.",
    f"{HS256_HEADER}.{HS256_PAYLOAD}.{HS256_SIGNATURE}=",
    f"{HS256_HEADER}.{HS256_PAYLOAD}",
    jose.jws_encode({"alg": "HS256", "kid": "s1"}, SIGNED_PAYLOAD, OTHER_HS256_SECRET),
]
HS256_SECRETS = [HMAC_SECRET, OTHER_HS256_SECRET]


def _toy_hs256_outcome(token: str, secret: bytes):
    jwks = jose.jwks_of(jose.public_jwk(secret, "s1"))
    return _outcome(jose.jws_verify, token, jwks, frozenset({"HS256"}))


def test_hs256_tokens_hold_both_accepted_and_refused_inputs():
    outcomes = {
        _toy_hs256_outcome(token, secret)[0] for token in HS256_TOKENS for secret in HS256_SECRETS
    }
    assert outcomes == {"value", "refused"}


@pytest.mark.parametrize("secret", HS256_SECRETS, ids=["secret", "other"])
@pytest.mark.parametrize("token", HS256_TOKENS, ids=[f"token{i}" for i in range(len(HS256_TOKENS))])
def test_chapter_04_hs256_verify_matches_toy(token, secret):
    solved = _solved("04_hs256_test.py").hs256_verify
    assert _outcome(solved, token, secret) == _toy_hs256_outcome(token, secret)


@pytest.mark.parametrize("token", HS256_TOKENS[:2], ids=["honest", "edited"])
def test_chapter_04_hs256_verify_compares_with_compare_digest(token):
    solved = _solved("04_hs256_test.py").hs256_verify
    with mock.patch.object(hmac, "compare_digest", wraps=hmac.compare_digest) as spy:
        _outcome(solved, token, HMAC_SECRET)
    assert spy.call_count == 1


RSA_PUBLIC_PEM = RSA_1.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
)
KEY_TYPE_ALGS = ["HS256", "RS256", "ES256", "none", "HS512", "ES384", "rs256"]
KEY_TYPE_JWKS = {
    "rsa": jose.public_jwk(RSA_1, "k"),
    "ec": jose.public_jwk(EC_1, "k"),
    "oct": jose.public_jwk(HMAC_SECRET, "k"),
    "oct-no-alg": {"kty": "oct", "kid": "k", "k": jose.b64url_encode(HMAC_SECRET)},
    "rsa-no-alg": {k: v for k, v in jose.public_jwk(RSA_1, "k").items() if k != "alg"},
    "ec-es384": {**jose.public_jwk(EC_1, "k"), "alg": "ES384"},
    "oct-hs512": {**jose.public_jwk(HMAC_SECRET, "k"), "alg": "HS512"},
    "rsa-as-ec": {**jose.public_jwk(RSA_1, "k"), "kty": "EC"},
    "no-kty": {"kid": "k"},
}
KEY_TYPE_SIGNERS = {"HS256": RSA_PUBLIC_PEM, "RS256": RSA_1, "ES256": EC_1}


def _key_type_token(alg: str) -> str:
    signer = KEY_TYPE_SIGNERS.get(alg)
    if signer is None:
        return f"{jose.json_segment({'alg': alg, 'kid': 'k'})}.{jose.json_segment(SIGNED_PAYLOAD)}."
    return jose.jws_encode({"alg": alg, "kid": "k"}, SIGNED_PAYLOAD, signer)


def _toy_key_type_outcome(alg: str, jwk: dict):
    """Only alg_not_allowed is a key-type refusal; any later outcome means the key type passed."""
    outcome = _outcome(jose.jws_verify, _key_type_token(alg), jose.jwks_of(jwk), ALL_ALGS)
    return outcome if outcome == ("refused", "alg_not_allowed") else ("value", None)


def test_key_type_cases_hold_both_passing_and_refused_inputs():
    outcomes = {
        _toy_key_type_outcome(alg, jwk)[0]
        for alg in KEY_TYPE_ALGS
        for jwk in KEY_TYPE_JWKS.values()
    }
    assert outcomes == {"value", "refused"}


@pytest.mark.parametrize("jwk_name", KEY_TYPE_JWKS)
@pytest.mark.parametrize("alg", KEY_TYPE_ALGS)
def test_chapter_05_check_key_type_matches_toy(alg, jwk_name):
    solved = _solved("05_rs256_and_es256_test.py").check_key_type
    jwk = KEY_TYPE_JWKS[jwk_name]
    assert _outcome(solved, alg, jwk) == _toy_key_type_outcome(alg, jwk)


ASYMMETRIC_ALGS = frozenset({"RS256", "ES256"})
RSA_1_JWK, RSA_2_JWK = jose.public_jwk(RSA_1, "k1"), jose.public_jwk(RSA_2, "k2")
FIND_KEY_SETS = {
    "rollover": jose.jwks_of(RSA_1_JWK, RSA_2_JWK),
    "enc": jose.jwks_of(RSA_1_JWK, {**RSA_2_JWK, "use": "enc"}),
    "no-use": jose.jwks_of({k: v for k, v in RSA_2_JWK.items() if k != "use"}),
    "odd-use": jose.jwks_of({**RSA_2_JWK, "use": "SIG"}, {**RSA_1_JWK, "use": None}),
    "shared-kid": jose.jwks_of({**jose.public_jwk(RSA_1, "k2"), "use": "enc"}, RSA_2_JWK),
    "duplicate": jose.jwks_of(jose.public_jwk(RSA_1, "k2"), RSA_2_JWK),
    "no-kid": jose.jwks_of({k: v for k, v in RSA_1_JWK.items() if k != "kid"}),
    "empty": jose.jwks_of(),
}
FIND_KEY_TOKENS = {
    "k1": jose.jws_encode({"alg": "RS256", "kid": "k1"}, SIGNED_PAYLOAD, RSA_1),
    "k2": jose.jws_encode({"alg": "RS256", "kid": "k2"}, SIGNED_PAYLOAD, RSA_2),
    "no-kid": jose.jws_encode({"alg": "RS256"}, SIGNED_PAYLOAD, RSA_1),
    "empty-kid": jose.jws_encode({"alg": "RS256", "kid": ""}, SIGNED_PAYLOAD, RSA_1),
    "K1": jose.jws_encode({"alg": "RS256", "kid": "K1"}, SIGNED_PAYLOAD, RSA_1),
    "path-kid": jose.jws_encode({"alg": "RS256", "kid": "../k1"}, SIGNED_PAYLOAD, RSA_1),
    "list-kid": jose.jws_encode({"alg": "RS256", "kid": ["k1"]}, SIGNED_PAYLOAD, RSA_1),
    "carried-jwk": jose.jws_encode(
        {"alg": "RS256", "kid": "k1", "jwk": jose.public_jwk(ATTACKER_RSA, "k1")},
        SIGNED_PAYLOAD, ATTACKER_RSA,
    ),
    "carried-jwk-no-kid": jose.jws_encode(
        {"alg": "RS256", "jwk": jose.public_jwk(ATTACKER_RSA, "k1")}, SIGNED_PAYLOAD, ATTACKER_RSA
    ),
    "jku": jose.jws_encode(
        {"alg": "RS256", "kid": "m1", "jku": "https://attacker.example/jwks"},
        SIGNED_PAYLOAD, ATTACKER_RSA,
    ),
}


def _toy_find_key_outcome(token: str, jwks: dict):
    """The key toy.jose.jws_verify would check this token with, or why it would refuse."""
    return _outcome(jose._find_by_kid, jwks, jose.jws_split(token)[0].get("kid"))


def test_find_key_cases_hold_both_accepted_and_refused_inputs():
    outcomes = {
        _toy_find_key_outcome(token, jwks)[0]
        for token in FIND_KEY_TOKENS.values()
        for jwks in FIND_KEY_SETS.values()
    }
    assert outcomes == {"value", "refused"}


@pytest.mark.parametrize("set_name", FIND_KEY_SETS)
@pytest.mark.parametrize("token_name", FIND_KEY_TOKENS)
def test_chapter_06_find_key_matches_toy(token_name, set_name):
    find_key = _solved("06_jwk_and_jwks_test.py").find_key
    token, jwks = FIND_KEY_TOKENS[token_name], FIND_KEY_SETS[set_name]
    header = jose.jws_split(token)[0]
    assert _outcome(find_key, jwks, header) == _toy_find_key_outcome(token, jwks)


ISSUERS = {"https://id.example": (RSA_1, "k1"), "https://other-id.example": (EC_1, "o1")}


def _issuer_world():
    clock, network = Clock(), FakeNetwork()
    providers = {
        issuer: Provider(issuer, clock=clock, network=network, signing_key=key, kid=kid)
        for issuer, (key, kid) in ISSUERS.items()
    }
    attacker_keys = jose.jwks_of(jose.public_jwk(ATTACKER_RSA, "m1"))
    network.mount("https://attacker.example", lambda request: Response(200, {}, attacker_keys))
    trusted = {
        issuer: network.send(Request("GET", f"{issuer}/.well-known/openid-configuration")).body
        for issuer in ISSUERS
    }
    return network, trusted, providers


def _issuer_token(header: dict, iss: str, key) -> str:
    return jose.jws_encode(header, {**SIGNED_PAYLOAD, "iss": iss}, key)


ID, OTHER = "https://id.example", "https://other-id.example"
ISSUER_TOKENS = {
    "id": _issuer_token({"alg": "RS256", "kid": "k1"}, ID, RSA_1),
    "id-own-jku": _issuer_token({"alg": "RS256", "kid": "k1", "jku": f"{ID}/jwks"}, ID, RSA_1),
    "other": _issuer_token({"alg": "ES256", "kid": "o1"}, OTHER, EC_1),
    "other-key-claims-id": _issuer_token({"alg": "ES256", "kid": "o1"}, ID, EC_1),
    "jku": _issuer_token(
        {"alg": "RS256", "kid": "m1", "jku": "https://attacker.example/jwks"}, ID, ATTACKER_RSA
    ),
    "x5u": _issuer_token(
        {"alg": "RS256", "kid": "m1", "x5u": "https://attacker.example/jwks"}, ID, ATTACKER_RSA
    ),
    "jwk": _issuer_token(
        {"alg": "RS256", "kid": "k1", "jwk": jose.public_jwk(ATTACKER_RSA, "k1")}, ID, ATTACKER_RSA
    ),
}


@pytest.mark.parametrize("issuer", ISSUERS)
@pytest.mark.parametrize("token_name", ISSUER_TOKENS)
def test_chapter_06_verify_from_matches_toy(token_name, issuer):
    verify_from = _solved("06_jwk_and_jwks_test.py").verify_from
    network, trusted, providers = _issuer_world()
    token = ISSUER_TOKENS[token_name]
    expected = _outcome(jose.jws_verify, token, providers[issuer].jwks, ASYMMETRIC_ALGS)
    assert _outcome(verify_from, token, issuer, trusted, network) == expected


def test_issuer_tokens_hold_both_accepted_and_refused_inputs():
    _, _, providers = _issuer_world()
    outcomes = {
        _outcome(jose.jws_verify, token, providers[issuer].jwks, ASYMMETRIC_ALGS)[0]
        for token in ISSUER_TOKENS.values()
        for issuer in ISSUERS
    }
    assert outcomes == {"value", "refused"}


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
