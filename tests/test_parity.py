"""Each chapter's solved function agrees with its toy/ counterpart, attack inputs included.

The solved functions are loaded from solutions/ by path, since chapter files
are not a package. Run from the repo root with: pytest tests/test_parity.py
"""

import importlib.util
from functools import cache
from pathlib import Path

import pytest

from toy import jose
from toy.errors import InvalidToken
from toy.keys import EC_1, HMAC_SECRET, RSA_1

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
