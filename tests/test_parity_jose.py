"""Parity for chapters 02 to 06: each solved function agrees with its toy/ counterpart."""

import hmac
from unittest import mock

import pytest
from cryptography.hazmat.primitives import serialization

from tests.parity_support import ID, OTHER, _outcome, _solved
from toy import jose
from toy.clock import Clock
from toy.http import FakeNetwork, Request, Response
from toy.keys import ATTACKER_RSA, EC_1, HMAC_SECRET, RSA_1, RSA_2
from toy.provider import Provider


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
