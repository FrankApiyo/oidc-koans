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

from toy import client, client_auth, id_token, jose, key_cache, token_endpoint
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


CHAPTER_11 = "11_id_token_validation_iss_aud_azp_test.py"
TYP_HEADERS = [
    {}, {"typ": "JWT"}, {"typ": "jwt"}, {"typ": "application/jwt"}, {"typ": "Application/JWT"},
    {"typ": None}, {"typ": "at+jwt"}, {"typ": "application/at+jwt"}, {"typ": "logout+jwt"},
    {"typ": "JWT "}, {"typ": 7}, {"typ": ["JWT"]}, {"typ": ""},
]
TYP_PAYLOADS = [{"sub": "alice"}, {"sub": "alice", "events": {}}, {"events": None}]


def test_typ_cases_hold_both_accepted_and_refused_inputs():
    outcomes = {
        _outcome(id_token._check_type, header, payload)[0]
        for header in TYP_HEADERS for payload in TYP_PAYLOADS
    }
    assert outcomes == {"value", "refused"}


@pytest.mark.parametrize("payload", TYP_PAYLOADS, ids=repr)
@pytest.mark.parametrize("header", TYP_HEADERS, ids=repr)
def test_chapter_11_check_type_matches_toy(header, payload):
    solved = _solved(CHAPTER_11).check_type
    assert _outcome(solved, header, payload) == _outcome(id_token._check_type, header, payload)


NO_CLAIM = object()
ISS_VALUES = [
    ID, f"{ID}/", "https://ID.example", "http://id.example", f"{ID}.evil.example", "https://id.exampl",
    OTHER, [ID], "", None, 7, NO_CLAIM,
]


def _with(name: str, value) -> dict:
    return {"sub": "alice"} if value is NO_CLAIM else {"sub": "alice", name: value}


@pytest.mark.parametrize("iss", ISS_VALUES, ids=repr)
def test_chapter_11_check_issuer_matches_toy(iss):
    solved = _solved(CHAPTER_11).check_issuer
    claims = _with("iss", iss)
    assert _outcome(solved, claims, ID) == _outcome(id_token._check_issuer, claims, ID)


AUD_VALUES = [
    "app", ["app"], ["app", "api"], ["api", "app"], ["app", "app"], ["app", "quiz"], "webapp",
    "APP", "app ", ["webapp"], [], NO_CLAIM, None, 7, ["app", 7], ["quiz", 7], {"app": True},
    "quiz", ["quiz", "app"], "",
]
TRUSTED_SETS = [frozenset(), frozenset({"api"}), frozenset({"quiz", "api"})]


def test_audience_cases_hold_both_accepted_and_refused_inputs():
    outcomes = {
        _outcome(id_token._check_audience, _with("aud", aud), "app", trusted)
        for aud in AUD_VALUES for trusted in TRUSTED_SETS
    }
    assert {kind for kind, _ in outcomes} == {"value", "refused"}
    assert {reason for _, reason in outcomes} >= {None, "wrong_audience", "malformed"}


@pytest.mark.parametrize("trusted", TRUSTED_SETS, ids=lambda t: "+".join(sorted(t)) or "none")
@pytest.mark.parametrize("aud", AUD_VALUES, ids=repr)
def test_chapter_11_check_audience_matches_toy(aud, trusted):
    solved = _solved(CHAPTER_11).check_audience
    claims = _with("aud", aud)
    expected = _outcome(id_token._check_audience, claims, "app", trusted)
    assert _outcome(solved, claims, "app", trusted) == expected


WELL_FORMED_AUDS = ["app", ["app"], ["app", "api"], ["api", "app"], ["quiz", "app", "api"]]
AZP_VALUES = [NO_CLAIM, None, "app", "quiz", "APP", "", ["app"]]


@pytest.mark.parametrize("azp_extension", [False, True])
@pytest.mark.parametrize("azp", AZP_VALUES, ids=repr)
@pytest.mark.parametrize("aud", WELL_FORMED_AUDS, ids=repr)
def test_chapter_11_check_authorized_party_matches_toy(aud, azp, azp_extension):
    """aud has already passed the audience check when azp is checked, so it is well formed."""
    solved = _solved(CHAPTER_11).check_authorized_party
    claims = {**_with("azp", azp), "aud": aud}
    expected = _outcome(id_token._check_authorized_party, claims, "app", azp_extension)
    assert _outcome(solved, claims, "app", azp_extension) == expected


VT_NOW = 1_800_000_000
VT_JWKS = jose.jwks_of(jose.public_jwk(RSA_1, "k1"), jose.public_jwk(EC_1, "o1"))
VT_EVENTS = {"http://schemas.openid.net/event/backchannel-logout": {}}


def _vt(header: dict | None = None, key=RSA_1, **changes) -> str:
    """A token for client app from id.example, honest unless changed; None drops a claim."""
    claims = {
        "iss": ID, "sub": "alice", "aud": "app", "exp": VT_NOW + 300, "iat": VT_NOW,
        "nonce": "n-1", "auth_time": VT_NOW - 60, "acr": "urn:toy:acr:pwd",
    }
    claims = {k: v for k, v in {**claims, **changes}.items() if v is not NO_CLAIM}
    alg = "ES256" if key is EC_1 else "RS256"
    kid = "o1" if key is EC_1 else "k1"
    return jose.jws_encode({"alg": alg, "kid": kid, **(header or {})}, claims, key)


MFA = frozenset({"urn:toy:acr:mfa"})
VALIDATION_CASES = {
    "honest": (_vt(), {}),
    "es256": (_vt(key=EC_1), {}),
    "typ-at": (_vt({"typ": "at+jwt"}), {}),
    "events": (_vt(events=VT_EVENTS), {}),
    "typ-int": (_vt({"typ": 7}), {}),
    "forged": (_vt(key=ATTACKER_RSA), {}),
    "unknown-kid": (_vt({"kid": "k9"}), {}),
    "es256-not-allowed": (_vt(key=EC_1), {"allowed_algs": frozenset({"RS256"})}),
    "no-sub": (_vt(sub=NO_CLAIM), {}),
    "sub-int": (_vt(sub=42), {}),
    "iss-slash": (_vt(iss=f"{ID}/"), {}),
    "no-iss": (_vt(iss=NO_CLAIM), {}),
    "aud-webapp": (_vt(aud="webapp"), {}),
    "aud-extra": (_vt(aud=["app", "api"]), {}),
    "aud-extra-trusted": (_vt(aud=["app", "api"]), {"trusted_audiences": frozenset({"api"})}),
    "aud-int": (_vt(aud=7), {}),
    "no-aud": (_vt(aud=NO_CLAIM), {}),
    "aud-odd-item": (_vt(aud=["quiz", 7]), {}),
    "azp-ignored": (_vt(azp="quiz"), {}),
    "azp-ext": (_vt(azp="quiz"), {"azp_extension": True}),
    "azp-missing-ext": (
        _vt(aud=["app", "api"]),
        {"azp_extension": True, "trusted_audiences": frozenset({"api"})},
    ),
    "azp-ok-ext": (
        _vt(aud=["app", "api"], azp="app"),
        {"azp_extension": True, "trusted_audiences": frozenset({"api"})},
    ),
    "exp-now": (_vt(exp=VT_NOW), {}),
    "exp-minus-one": (_vt(exp=VT_NOW + 1), {}),
    "exp-leeway-ok": (_vt(exp=VT_NOW - 4), {"leeway": 5}),
    "exp-leeway-out": (_vt(exp=VT_NOW - 5), {"leeway": 5}),
    "exp-float": (_vt(exp=VT_NOW + 0.5), {}),
    "no-exp": (_vt(exp=NO_CLAIM), {}),
    "exp-true": (_vt(exp=True), {}),
    "exp-string": (_vt(exp="1800000300"), {}),
    "exp-nan": (_vt(exp=float("nan")), {}),
    "exp-inf": (_vt(exp=float("inf")), {}),
    "exp-null": (_vt(exp=None), {}),
    "iat-future": (_vt(iat=VT_NOW + 1), {}),
    "iat-leeway-ok": (_vt(iat=VT_NOW + 5), {"leeway": 5}),
    "iat-leeway-out": (_vt(iat=VT_NOW + 6), {"leeway": 5}),
    "iat-true": (_vt(iat=True), {}),
    "no-iat": (_vt(iat=NO_CLAIM), {}),
    "nbf-future": (_vt(nbf=VT_NOW + 1), {}),
    "nbf-string": (_vt(nbf="0"), {}),
    "nonce-wrong": (_vt(nonce="n-2"), {}),
    "nonce-missing": (_vt(nonce=NO_CLAIM), {}),
    "nonce-unsent": (_vt(), {"nonce": None}),
    "nonce-none-both": (_vt(nonce=NO_CLAIM), {"nonce": None}),
    "max-age-no-auth-time": (_vt(auth_time=NO_CLAIM), {"max_age": 300}),
    "no-auth-time": (_vt(auth_time=NO_CLAIM), {}),
    "auth-time-stale": (_vt(auth_time=VT_NOW - 301), {"max_age": 300}),
    "auth-time-edge": (_vt(auth_time=VT_NOW - 300), {"max_age": 300}),
    "auth-time-leeway": (_vt(auth_time=VT_NOW - 305), {"max_age": 300, "leeway": 5}),
    "auth-time-future": (_vt(auth_time=VT_NOW + 1), {}),
    "auth-time-string": (_vt(auth_time="0"), {}),
    "auth-time-true": (_vt(auth_time=True), {"max_age": 300}),
    "acr-weak": (_vt(), {"required_acr": MFA}),
    "acr-int": (_vt(acr=2), {"required_acr": frozenset({"2"})}),
    "acr-true": (_vt(acr=True), {"required_acr": frozenset({"1"})}),
    "acr-ok": (_vt(acr="urn:toy:acr:mfa"), {"required_acr": MFA}),
    "acr-missing": (_vt(acr=NO_CLAIM), {"required_acr": MFA}),
    "acr-list": (_vt(acr=["urn:toy:acr:mfa"]), {"required_acr": MFA}),
    "logout-and-forged": (_vt({"typ": "logout+jwt"}, ATTACKER_RSA, iss=OTHER), {}),
    "forged-and-iss": (_vt(key=ATTACKER_RSA, iss=OTHER, aud="quiz"), {}),
    "no-sub-and-iss": (_vt(sub=NO_CLAIM, iss=OTHER), {}),
    "iss-and-aud": (_vt(iss=OTHER, aud="quiz"), {}),
    "aud-and-azp": (_vt(aud=["quiz", "api"], azp="quiz"), {"azp_extension": True}),
    "aud-and-expired": (_vt(aud="quiz", exp=VT_NOW), {}),
    "azp-and-expired": (_vt(azp="quiz", exp=VT_NOW), {"azp_extension": True}),
    "expired-and-iat-future": (_vt(exp=VT_NOW, iat=VT_NOW + 1), {}),
    "expired-and-iat-string": (_vt(exp=VT_NOW, iat="x"), {}),
    "no-exp-and-iat-future": (_vt(exp=NO_CLAIM, iat=VT_NOW + 1), {}),
    "iat-future-and-nonce": (_vt(iat=VT_NOW + 1, nonce="n-2"), {}),
    "nbf-and-nonce": (_vt(nbf=VT_NOW + 1, nonce="n-2"), {}),
    "expired-and-nonce": (_vt(exp=VT_NOW, nonce="n-2"), {}),
    "nonce-and-no-auth-time": (_vt(nonce="n-2", auth_time=NO_CLAIM), {"max_age": 300}),
    "stale-and-acr": (_vt(auth_time=VT_NOW - 301), {"max_age": 300, "required_acr": MFA}),
    "future-auth-time-and-acr": (_vt(auth_time=VT_NOW + 1), {"required_acr": MFA}),
    "expired-and-stale": (_vt(exp=VT_NOW, auth_time=VT_NOW - 999), {"max_age": 300}),
}
SIGNED_PART_OPTIONS = ("allowed_algs", "trusted_audiences", "azp_extension")
SIGNED_PART_REASONS = frozenset({
    "malformed", "wrong_typ", "alg_not_allowed", "unknown_kid", "bad_signature",
    "wrong_issuer", "wrong_audience", "azp_mismatch",
})


def _toy_validation(token: str, options: dict):
    full = {"nonce": "n-1", **options}
    return _outcome(lambda: id_token.validate_id_token(
        token, issuer=ID, client_id="app", jwks=VT_JWKS, now=VT_NOW, **full
    ))


LATER_REASONS = frozenset({
    "expired", "issued_in_future", "not_yet_valid", "nonce_mismatch", "auth_time_missing",
    "stale_auth_time", "acr_not_met",
})


def test_validation_cases_cover_every_reason_in_the_validator():
    outcomes = [_toy_validation(token, options) for token, options in VALIDATION_CASES.values()]
    reasons = {reason for kind, reason in outcomes if kind == "refused"}
    assert "value" in {kind for kind, _ in outcomes}
    assert reasons == SIGNED_PART_REASONS | LATER_REASONS


@pytest.mark.parametrize("case", VALIDATION_CASES)
def test_chapter_11_validate_signed_part_matches_toy(case):
    """Where chapter 11's part refuses, it gives toy's reason; where it passes, toy either passes
    or refuses for a reason chapter 12 checks."""
    token, options = VALIDATION_CASES[case]
    signed_part = {k: v for k, v in options.items() if k in SIGNED_PART_OPTIONS}
    solved = _outcome(lambda: _solved(CHAPTER_11).validate_signed_part(
        token, issuer=ID, client_id="app", jwks=VT_JWKS, **signed_part
    ))
    toy = _toy_validation(token, options)
    if solved[0] == "refused":
        assert solved == toy
    elif toy[0] == "refused":
        later_malformed = toy[1] == "malformed" and not _malformed_before_dates(token)
        assert toy[1] in LATER_REASONS or later_malformed


def _malformed_before_dates(token: str) -> bool:
    """Whether toy's malformed comes from the signed part: an unparseable token, sub or aud."""
    claims = jose.jws_split(token)[1]
    aud = claims.get("aud", [])
    bad_aud = not isinstance(aud, str) and (
        not isinstance(aud, list) or not all(isinstance(a, str) for a in aud)
    )
    return not isinstance(claims.get("sub"), str) or not claims.get("sub") or bad_aud


CHAPTER_12 = "12_id_token_validation_time_nonce_acr_test.py"
DATE_VALUES = [
    VT_NOW, VT_NOW + 0.5, 0, -1, True, False, "1800000000", None, float("nan"), float("inf"),
    float("-inf"), [VT_NOW], {"t": VT_NOW}, 10**20,
]


@pytest.mark.parametrize("value", DATE_VALUES, ids=repr)
def test_chapter_12_numeric_date_matches_toy(value):
    solved = _solved(CHAPTER_12).numeric_date
    claims = {"exp": value}
    assert _outcome(solved, claims, "exp") == _outcome(id_token.numeric_date, claims, "exp")


DATE_CLAIMS = [
    {"exp": VT_NOW + 300, "iat": VT_NOW},
    {"exp": VT_NOW, "iat": VT_NOW - 300},
    {"exp": VT_NOW + 1, "iat": VT_NOW},
    {"exp": VT_NOW - 5, "iat": VT_NOW - 300},
    {"exp": VT_NOW - 4.5, "iat": VT_NOW - 300},
    {"exp": VT_NOW + 300, "iat": VT_NOW + 1},
    {"exp": VT_NOW + 300, "iat": VT_NOW + 5},
    {"exp": VT_NOW + 300, "iat": VT_NOW + 6},
    {"exp": VT_NOW + 300, "iat": VT_NOW, "nbf": VT_NOW},
    {"exp": VT_NOW + 300, "iat": VT_NOW, "nbf": VT_NOW + 5},
    {"exp": VT_NOW + 300, "iat": VT_NOW, "nbf": VT_NOW + 6},
    {"exp": VT_NOW + 300, "iat": VT_NOW, "nbf": "0"},
    {"iat": VT_NOW},
    {"exp": VT_NOW + 300},
    {},
    {"exp": True, "iat": VT_NOW},
    {"exp": VT_NOW + 300, "iat": True},
    {"exp": VT_NOW, "iat": "x"},
    {"exp": "x", "iat": VT_NOW + 9},
    {"exp": VT_NOW, "iat": VT_NOW + 9},
    {"exp": float("nan"), "iat": VT_NOW},
    {"exp": None, "iat": VT_NOW},
]
LEEWAYS = [0, 5, 300]


def test_date_cases_hold_every_date_reason():
    outcomes = {
        _outcome(id_token._check_dates, claims, VT_NOW, leeway)
        for claims in DATE_CLAIMS for leeway in LEEWAYS
    }
    assert {reason for _, reason in outcomes} == {
        None, "malformed", "expired", "issued_in_future", "not_yet_valid",
    }


@pytest.mark.parametrize("leeway", LEEWAYS)
@pytest.mark.parametrize("claims", DATE_CLAIMS, ids=repr)
def test_chapter_12_check_dates_matches_toy(claims, leeway):
    solved = _solved(CHAPTER_12).check_dates
    expected = _outcome(id_token._check_dates, claims, VT_NOW, leeway)
    assert _outcome(solved, claims, VT_NOW, leeway) == expected


AUTH_TIMES = [NO_CLAIM, VT_NOW, VT_NOW - 300, VT_NOW - 301, VT_NOW - 305, VT_NOW - 306, VT_NOW + 1,
              VT_NOW + 5, VT_NOW - 0.5, "0", True, None, float("nan")]
MAX_AGES = [None, 0, 300]


def test_auth_time_cases_hold_every_auth_time_reason():
    outcomes = {
        _outcome(id_token._check_auth_time, _with("auth_time", at), VT_NOW, leeway, max_age, None)
        for at in AUTH_TIMES for leeway in (0, 5) for max_age in MAX_AGES
    }
    assert {reason for _, reason in outcomes} == {
        None, "malformed", "auth_time_missing", "issued_in_future", "stale_auth_time",
    }


@pytest.mark.parametrize("max_age", MAX_AGES)
@pytest.mark.parametrize("leeway", [0, 5])
@pytest.mark.parametrize("auth_time", AUTH_TIMES, ids=repr)
def test_chapter_12_check_auth_time_matches_toy(auth_time, leeway, max_age):
    solved = _solved(CHAPTER_12).check_auth_time
    claims = _with("auth_time", auth_time)
    expected = _outcome(id_token._check_auth_time, claims, VT_NOW, leeway, max_age, None)
    assert _outcome(solved, claims, VT_NOW, leeway, max_age) == expected


ACR_VALUES = [
    "2", 2, True, None, ["2"], "02", " 2", "1", "0", "urn:toy:acr:mfa", "URN:TOY:ACR:MFA",
    "urn:toy:acr:pwd", NO_CLAIM,
]
REQUIRED_ACRS = [frozenset({"2"}), frozenset({"1"}), MFA, frozenset({"urn:toy:acr:pwd", "2"})]


@pytest.mark.parametrize("required", REQUIRED_ACRS, ids=lambda r: "+".join(sorted(r)))
@pytest.mark.parametrize("acr", ACR_VALUES, ids=repr)
def test_chapter_12_check_acr_matches_toy(acr, required):
    solved = _solved(CHAPTER_12).check_acr
    claims = _with("acr", acr)
    assert _outcome(solved, claims, required) == _outcome(id_token.check_acr, claims, required)


@pytest.mark.parametrize("case", VALIDATION_CASES)
def test_chapters_11_and_12_together_match_toy_validate_id_token(case):
    """Chapter 11's signed part, then chapter 12's claim checks, give toy's answer, multi-defect
    tokens included."""
    token, options = VALIDATION_CASES[case]
    signed_part = {k: v for k, v in options.items() if k in SIGNED_PART_OPTIONS}
    later = {k: v for k, v in {"nonce": "n-1", **options}.items() if k not in SIGNED_PART_OPTIONS}

    def course_validator():
        claims = _solved(CHAPTER_11).validate_signed_part(
            token, issuer=ID, client_id="app", jwks=VT_JWKS, **signed_part
        )
        return _solved(CHAPTER_12).check_claims(claims, now=VT_NOW, **later)

    assert _outcome(course_validator) == _toy_validation(token, options)


CHAPTER_13 = "13_access_tokens_and_userinfo_test.py"
USERINFO_CASES = [
    ("alice", {"sub": "alice"}),
    ("alice", {"sub": "alice", "email": "alice@example.com"}),
    ("123", {"sub": "123"}),
    ("alice", {"sub": "Alice"}),
    ("alice", {"sub": "alice "}),
    ("alice", {"sub": " alice"}),
    ("alice", {"sub": "mallory"}),
    ("alice", {"sub": ["alice"]}),
    ("alice", {"sub": None}),
    ("alice", {"sub": ""}),
    ("alice", {}),
    ("123", {"sub": 123}),
    ("1", {"sub": True}),
    ("ä", {"sub": "ä"}),
]


def test_userinfo_cases_hold_both_outcomes():
    outcomes = {
        _outcome(client.check_userinfo_subject, {"sub": id_sub}, userinfo)
        for id_sub, userinfo in USERINFO_CASES
    }
    assert outcomes == {("value", None), ("refused", "sub_mismatch")}


@pytest.mark.parametrize(("id_sub", "userinfo"), USERINFO_CASES, ids=repr)
def test_chapter_13_check_userinfo_subject_matches_toy(id_sub, userinfo):
    solved = _solved(CHAPTER_13).check_userinfo_subject
    id_claims = {"sub": id_sub}
    expected = _outcome(client.check_userinfo_subject, id_claims, userinfo)
    assert _outcome(solved, id_claims, userinfo) == expected


CHAPTER_14 = "14_claims_and_scopes_test.py"
ESSENTIAL_REQUESTS = [
    {"email": {"essential": True}},
    {"email": {"essential": True}, "phone_number": {"essential": True}},
    {"email": None, "name": {}, "nickname": {"essential": False}},
    {"locale": {"essential": "true"}, "picture": {"essential": 1}, "zoneinfo": {"essential": 0}},
    {"sub": {"value": "alice", "essential": True}, "acr": {"essential": True, "values": ["1"]}},
    {"email_verified": {"essential": True}, "address": {"essential": True}},
    {},
]
RETURNED_CLAIMS = [
    {}, {"sub": "alice", "email": "alice@example.com"}, {"email": None},
    {"email_verified": False, "email": ""}, {"acr": "1", "phone_number": "+1"},
]


@pytest.mark.parametrize("requested", ESSENTIAL_REQUESTS, ids=repr)
@pytest.mark.parametrize("claims", RETURNED_CLAIMS, ids=repr)
def test_chapter_14_missing_essential_claims_matches_toy(claims, requested):
    solved = _solved(CHAPTER_14).missing_essential_claims
    assert solved(claims, requested) == client.missing_essential_claims(claims, requested)


CHAPTER_15 = "15_discovery_and_mix_up_test.py"
ACME = f"{ID}/acme"


def _flow_outcome(function, *args, **kwargs):
    try:
        return ("value", function(*args, **kwargs))
    except FlowError as refused:
        return ("refused", refused.reason)


def _discovery_document(issuer: str | None) -> dict:
    document = _solved(CHAPTER_15)._metadata(issuer or ID)
    return document if issuer else {k: v for k, v in document.items() if k != "issuer"}


DISCOVERY_HOSTS = {
    "honest": {"": ID, "/acme": ACME, "/zeta": f"{ID}/zeta/"},
    "slashes-differ": {"": f"{ID}/", "/acme": f"{ACME}/", "/zeta": f"{ID}/zeta"},
    "names-another": {"": ACME, "/acme": OTHER, "/zeta": ID},
    "no-issuer": {"": None, "/acme": None},
    "empty": {},
}
DISCOVERY_ISSUERS = [ID, f"{ID}/", f"{ID}//", ACME, f"{ACME}/", f"{ID}/zeta/", f"{ID}/zeta"]


def _discovery_host(named: dict):
    host = _solved(CHAPTER_15).TenantHost(
        {tenant: _discovery_document(issuer) for tenant, issuer in named.items()}
    )
    network = FakeNetwork()
    network.mount(ID, host)
    return network, host


def test_discovery_cases_hold_both_outcomes():
    outcomes = set()
    for named in DISCOVERY_HOSTS.values():
        for issuer in DISCOVERY_ISSUERS:
            network, _ = _discovery_host(named)
            outcomes.add(_flow_outcome(client.discover, issuer=issuer, network=network)[0])
    assert outcomes == {"value", "refused"}


@pytest.mark.parametrize("issuer", DISCOVERY_ISSUERS)
@pytest.mark.parametrize("host_name", DISCOVERY_HOSTS)
def test_chapter_15_discover_matches_toy(host_name, issuer):
    solved = _solved(CHAPTER_15).discover
    network, host = _discovery_host(DISCOVERY_HOSTS[host_name])
    toy_network, toy_host = _discovery_host(DISCOVERY_HOSTS[host_name])
    expected = _flow_outcome(client.discover, issuer=issuer, network=toy_network)
    assert _flow_outcome(solved, issuer=issuer, network=network) == expected
    assert host.asked == toy_host.asked


RESPONSE_PARAMS = [
    {"code": "c", "state": "s", "iss": ID},
    {"code": "c", "state": "s"},
    {"error": "access_denied", "state": "s"},
    {"error": "access_denied", "state": "s", "iss": OTHER},
    {"error": "access_denied", "state": "s", "iss": ID},
    {"code": "c", "state": "s", "iss": f"{ID}/"},
    {"code": "c", "state": "s", "iss": "https://ID.example"},
    {"code": "c", "state": "s", "iss": f"{ID}.evil.example"},
    {"code": "c", "state": "s", "iss": ACME},
    {"code": "c", "state": "s", "iss": "https%3A%2F%2Fid.example"},
    {"code": "c", "state": "s", "iss": ""},
]
ISS_CONFIGS = {
    "advertised": {"issuer": ID, "authorization_response_iss_parameter_supported": True},
    "not-advertised": {"issuer": ID, "authorization_response_iss_parameter_supported": False},
    "silent": {"issuer": ID},
}


@pytest.mark.parametrize("config_name", ISS_CONFIGS)
@pytest.mark.parametrize("params", RESPONSE_PARAMS, ids=repr)
def test_chapter_15_check_response_issuer_matches_toy(params, config_name):
    solved = _solved(CHAPTER_15).check_response_issuer
    config = ISS_CONFIGS[config_name]
    expected = _flow_outcome(client._check_response_issuer, params, config)
    assert _flow_outcome(solved, params, config) == expected


def test_response_issuer_cases_hold_both_outcomes():
    outcomes = {
        _flow_outcome(client._check_response_issuer, params, config)
        for params in RESPONSE_PARAMS for config in ISS_CONFIGS.values()
    }
    assert outcomes == {("value", None), ("refused", "issuer_mismatch")}


CHAPTER_16 = "16_jwks_key_rotation_test.py"
CACHE_NOW = 1_800_000_000
FETCHED_SET = jose.jwks_of(jose.public_jwk(RSA_2, "k2"))
CACHED_SETS = {
    "k1": jose.jwks_of(jose.public_jwk(RSA_1, "k1")),
    "k1+k2": jose.jwks_of(jose.public_jwk(RSA_1, "k1"), jose.public_jwk(RSA_2, "k2")),
    "kidless": {"keys": [{k: v for k, v in jose.public_jwk(RSA_1, "k1").items() if k != "kid"}]},
    "empty": {"keys": []},
}
KIDS = ["k1", "k2", "K1", "k1 ", "", None, 7, ["k1"]]
AGES = [
    None, 0, 1, key_cache.REFETCH_COOLDOWN - 1, key_cache.REFETCH_COOLDOWN,
    key_cache.CACHE_LIFETIME - 1, key_cache.CACHE_LIFETIME, key_cache.CACHE_LIFETIME + 1,
]


def _cache_outcome(function, set_name: str, kid, age):
    fetches = 0

    def fetch():
        nonlocal fetches
        fetches += 1
        return FETCHED_SET

    entry = None if age is None else key_cache.CachedKeys(CACHED_SETS[set_name], CACHE_NOW - age)
    result = function(entry, kid, CACHE_NOW, fetch)
    return fetches, result, result is entry


def test_cache_cases_hold_every_outcome():
    outcomes = {
        _cache_outcome(key_cache.cached_keys, set_name, kid, age)[0::2]
        for set_name in CACHED_SETS for kid in KIDS for age in AGES
    }
    assert outcomes == {(0, True), (1, False)}


@pytest.mark.parametrize("age", AGES)
@pytest.mark.parametrize("kid", KIDS, ids=repr)
@pytest.mark.parametrize("set_name", CACHED_SETS)
def test_chapter_16_cached_keys_matches_toy(set_name, kid, age):
    solved = _solved(CHAPTER_16).cached_keys
    expected = _cache_outcome(key_cache.cached_keys, set_name, kid, age)
    assert _cache_outcome(solved, set_name, kid, age) == expected
