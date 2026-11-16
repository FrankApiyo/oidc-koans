"""Parity for chapters 16 to 18: each solved function agrees with its toy/ counterpart."""

import pytest

from tests.parity_support import ID, OTHER, _outcome, _solved
from toy import client, jose, key_cache, token_endpoint
from toy.keys import ATTACKER_RSA, RSA_1, RSA_2


CHAPTER_16 = "16_jwks_key_rotation_test.py"
CACHE_NOW = 1_800_000_000
FETCHED_SET = jose.jwks_of(jose.public_jwk(RSA_2, "k2"))
CACHED_SETS = {
    "k1": jose.jwks_of(jose.public_jwk(RSA_1, "k1")),
    "k1+k2": jose.jwks_of(jose.public_jwk(RSA_1, "k1"), jose.public_jwk(RSA_2, "k2")),
    "kidless": {"keys": [{k: v for k, v in jose.public_jwk(RSA_1, "k1").items() if k != "kid"}]},
    "empty": {"keys": []},
}
CACHE_JWKS_URI = f"{ID}/jwks"
NAMED_SET = jose.jwks_of(jose.public_jwk(ATTACKER_RSA, "k2"))
KIDS = ["k1", "k2", "K1", "k1 ", "", None, 7, ["k1"]]
CACHE_HEADERS = {
    **{f"kid={kid!r}": {"kid": kid} for kid in KIDS},
    "no-kid": {},
    "jku": {"kid": "k2", "jku": "https://mallory.example/jwks"},
    "x5u": {"kid": "k2", "x5u": "https://mallory.example/cert"},
    "jwk": {"kid": "k2", "jwk": jose.public_jwk(ATTACKER_RSA, "k2")},
    "known-kid-jku": {"kid": "k1", "jku": "https://mallory.example/jwks"},
}
AGES = [
    None, 0, 1, key_cache.REFETCH_COOLDOWN - 1, key_cache.REFETCH_COOLDOWN,
    key_cache.CACHE_LIFETIME - 1, key_cache.CACHE_LIFETIME, key_cache.CACHE_LIFETIME + 1,
]


def _cache_outcome(function, set_name: str, header: dict, age):
    urls = ()

    def get(url):
        nonlocal urls
        urls = (*urls, url)
        return FETCHED_SET if url == CACHE_JWKS_URI else NAMED_SET

    entry = None if age is None else key_cache.CachedKeys(CACHED_SETS[set_name], CACHE_NOW - age)
    result = function(entry, header, CACHE_NOW, get, CACHE_JWKS_URI)
    return urls, result, result is entry


def test_cache_cases_hold_every_outcome():
    outcomes = {
        _cache_outcome(key_cache.cached_keys, set_name, header, age)[0::2]
        for set_name in CACHED_SETS for header in CACHE_HEADERS.values() for age in AGES
    }
    assert outcomes == {((), True), ((CACHE_JWKS_URI,), False)}


@pytest.mark.parametrize("age", AGES)
@pytest.mark.parametrize("header_name", CACHE_HEADERS)
@pytest.mark.parametrize("set_name", CACHED_SETS)
def test_chapter_16_cached_keys_matches_toy(set_name, header_name, age):
    solved = _solved(CHAPTER_16).cached_keys
    header = CACHE_HEADERS[header_name]
    expected = _cache_outcome(key_cache.cached_keys, set_name, header, age)
    assert _cache_outcome(solved, set_name, header, age) == expected


CHAPTER_17 = "17_sub_vs_email_test.py"
SUBJECT_CLAIMS = [
    {"iss": ID, "sub": "alice"}, {"iss": OTHER, "sub": "alice"}, {"iss": ID, "sub": "Alice"},
    {"iss": f"{ID}/", "sub": "alice"}, {"iss": ID, "sub": " alice"}, {"iss": ID, "sub": "a" * 255},
    {"iss": ID, "sub": "alice", "email": "alice@example.com"}, {"sub": "alice"}, {"iss": ID},
    {}, {"iss": ID, "sub": ""}, {"iss": "", "sub": "alice"}, {"iss": ID, "sub": None},
    {"iss": ID, "sub": 123}, {"iss": ID, "sub": ["alice"]}, {"iss": ID, "sub": True},
    {"iss": [ID], "sub": "alice"},
]


def test_subject_cases_hold_both_outcomes():
    outcomes = {_outcome(client.account_key, claims)[0] for claims in SUBJECT_CLAIMS}
    assert outcomes == {"value", "refused"}


@pytest.mark.parametrize("claims", SUBJECT_CLAIMS, ids=repr)
def test_chapter_17_account_key_matches_toy(claims):
    solved = _solved(CHAPTER_17).account_key
    assert _outcome(solved, claims) == _outcome(client.account_key, claims)


DROP_CLAIM = object()
EMAIL_CLAIMS = [
    {"email": email, **({} if verified is DROP_CLAIM else {"email_verified": verified})}
    for email in ["alice@example.com", "Alice@Example.com", "", None, ["alice@example.com"], 7]
    for verified in [True, False, None, "true", "false", 1, 1.0, 0, [True], {}, DROP_CLAIM]
] + [{"email_verified": True}, {}]


def test_email_cases_hold_both_outcomes():
    outcomes = {client.verified_email(claims) is None for claims in EMAIL_CLAIMS}
    assert outcomes == {True, False}


@pytest.mark.parametrize("claims", EMAIL_CLAIMS, ids=repr)
def test_chapter_17_verified_email_matches_toy(claims):
    solved = _solved(CHAPTER_17).verified_email
    assert solved(claims) == client.verified_email(claims)


CHAPTER_18 = "18_refresh_tokens_and_rotation_test.py"
ORIGINAL_CLAIMS = {"iss": ID, "sub": "alice", "aud": "app", "iat": 1, "auth_time": 1, "nonce": "n"}
REFRESH_CHANGES = [
    {}, {"iat": 9}, {"auth_time": 9}, {"nonce": DROP_CLAIM}, {"iss": OTHER}, {"iss": DROP_CLAIM},
    {"iss": OTHER, "sub": "mallory"}, {"sub": "mallory"}, {"sub": "Alice"}, {"sub": ""},
    {"sub": DROP_CLAIM}, {"sub": None}, {"aud": "quiz"}, {"aud": ["app"]}, {"aud": ["app", "quiz"]},
    {"aud": DROP_CLAIM}, {"nonce": "other"}, {"nonce": ""}, {"nonce": None},
    {"sub": "mallory", "aud": "quiz", "nonce": "x"},
]
ORIGINALS = [ORIGINAL_CLAIMS, {k: v for k, v in ORIGINAL_CLAIMS.items() if k != "nonce"}]


def _refreshed(original: dict, changes: dict) -> dict:
    return {k: v for k, v in {**original, **changes}.items() if v is not DROP_CLAIM}


def test_refreshed_token_cases_hold_every_reason():
    reasons = {
        _outcome(client.check_refreshed_id_token, original, _refreshed(original, changes))
        for original in ORIGINALS for changes in REFRESH_CHANGES
    }
    assert {outcome for outcome in reasons} == {
        ("value", None), ("refused", "wrong_issuer"), ("refused", "sub_mismatch"),
        ("refused", "wrong_audience"), ("refused", "nonce_mismatch"),
    }


@pytest.mark.parametrize("changes", REFRESH_CHANGES, ids=repr)
@pytest.mark.parametrize("original", ORIGINALS, ids=["with-nonce", "without-nonce"])
def test_chapter_18_check_refreshed_id_token_matches_toy(original, changes):
    solved = _solved(CHAPTER_18).check_refreshed_id_token
    refreshed = _refreshed(original, changes)
    expected = _outcome(client.check_refreshed_id_token, original, refreshed)
    assert _outcome(solved, original, refreshed) == expected


LEDGERS = {
    "fresh": token_endpoint.RefreshLedger(),
    "one-grant": token_endpoint.RefreshLedger({"rt-2": "g1"}, {"rt-1": "g1"}),
    "two-grants": token_endpoint.RefreshLedger(
        {"rt-2": "g1", "rt-3": "g2"}, {"rt-1": "g1", "rt-0": "g2"}
    ),
    "revoked": token_endpoint.RefreshLedger(
        {"rt-2": "g1", "rt-3": "g2"}, {"rt-1": "g1"}, frozenset({"g1"})
    ),
}
PRESENTED = ["rt-0", "rt-1", "rt-2", "rt-3", "rt-9", "", "RT-2", "rt-2 "]


def test_ledger_cases_hold_every_outcome():
    outcomes = {
        (grant is None, after == ledger)
        for ledger in LEDGERS.values() for token in PRESENTED
        for grant, after in [token_endpoint.spend_refresh_token(ledger, token)]
    }
    assert outcomes == {(False, False), (True, True), (True, False)}


@pytest.mark.parametrize("token", PRESENTED)
@pytest.mark.parametrize("name", LEDGERS)
def test_chapter_18_spend_refresh_token_matches_toy(name, token):
    solved = _solved(CHAPTER_18).spend_refresh_token
    ledger = LEDGERS[name]
    assert solved(ledger, token) == token_endpoint.spend_refresh_token(ledger, token)
