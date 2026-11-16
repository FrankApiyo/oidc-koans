"""Parity for chapters 19 and 20: each solved function agrees with its toy/ counterpart."""

import itertools

import pytest

from tests.parity_support import ID, OTHER, _outcome, _solved
from toy import assurance, id_token, logout, rp_session
from toy.provider import ACR_MFA, ACR_PASSWORD

CHAPTER_19 = "19_sessions_and_logout_test.py"
CHAPTER_20 = "20_authentication_context_test.py"
AFTER, QUIZ_AFTER = "https://app.example/signed-out", "https://quiz.example/signed-out"
REGISTERED = {"app": (AFTER,), "quiz": (QUIZ_AFTER,), "empty": ()}
HINTS = {
    "app": {"aud": "app"},
    "quiz": {"aud": "quiz"},
    "listed": {"aud": ["app"]},
    "both": {"aud": ["quiz", "app"], "azp": "app"},
    "both-no-azp": {"aud": ["quiz", "app"]},
    "azp-outside": {"aud": ["quiz", "app"], "azp": "mallory"},
    "odd-azp": {"aud": ["quiz", "app"], "azp": ["app"]},
    "none-listed": {"aud": []},
    "no-aud": {},
    "odd-aud": {"aud": 7},
}
TARGETS = [None, AFTER, f"{AFTER}/", f"{AFTER}?next=x", "https://app.example", QUIZ_AFTER, ""]
CLIENT_IDS = [None, "app", "quiz", "", "empty", "APP"]
HINT_NAMES = [None, "", "forged", *HINTS]


def _params(hint, client_id, target):
    given = {"id_token_hint": hint, "client_id": client_id, "post_logout_redirect_uri": target}
    return {name: value for name, value in given.items() if value is not None}


@pytest.mark.parametrize("hint, client_id, target", list(
    itertools.product(HINT_NAMES, CLIENT_IDS, TARGETS)
))
def test_chapter_19_post_logout_target_matches_toy(hint, client_id, target):
    solved = _solved(CHAPTER_19).post_logout_target
    params = _params(hint, client_id, target)
    expected = logout.post_logout_target(params, REGISTERED, HINTS.get)
    assert solved(params, REGISTERED, HINTS.get) == expected


def test_chapter_19_post_logout_cases_hold_both_outcomes():
    outcomes = {
        logout.post_logout_target(_params(*case), REGISTERED, HINTS.get)
        for case in itertools.product(HINT_NAMES, CLIENT_IDS, TARGETS)
    }
    assert outcomes == {None, AFTER, QUIZ_AFTER}


EVENTS = {logout.LOGOUT_EVENT: {}}
LOGOUT_CLAIMS = [
    {"sub": "alice", "events": EVENTS},
    {"sid": "s1", "events": EVENTS},
    {"sub": "alice", "sid": "s1", "events": EVENTS},
    {"sub": "alice", "sid": "s1", "events": {logout.LOGOUT_EVENT: {"a": 1}, "other": []}},
    {"events": EVENTS},
    {"sub": "", "events": EVENTS},
    {"sid": "", "events": EVENTS},
    {"sub": "alice", "sid": "", "events": EVENTS},
    {"sub": None, "sid": "s1", "events": EVENTS},
    {"sub": ["alice"], "events": EVENTS},
    {"sid": 1, "events": EVENTS},
    {"sub": "alice"},
    {"sub": "alice", "events": None},
    {"sub": "alice", "events": logout.LOGOUT_EVENT},
    {"sub": "alice", "events": [logout.LOGOUT_EVENT]},
    {"sub": "alice", "events": {}},
    {"sub": "alice", "events": {logout.LOGOUT_EVENT: True}},
    {"sub": "alice", "events": {logout.LOGOUT_EVENT: []}},
    {"sub": "alice", "events": {logout.LOGOUT_EVENT: None}},
    {"sub": "alice", "events": {"http://schemas.openid.net/event/backchannel-logout/": {}}},
    {"sub": "alice", "events": EVENTS, "nonce": "n-1"},
    {"sub": "alice", "events": EVENTS, "nonce": ""},
    {"sub": "alice", "events": EVENTS, "nonce": None},
    {"sid": "", "events": [logout.LOGOUT_EVENT], "nonce": "n"},
]


@pytest.mark.parametrize("claims", LOGOUT_CLAIMS)
def test_chapter_19_check_logout_claims_matches_toy(claims):
    solved = _solved(CHAPTER_19).check_logout_claims
    assert _outcome(solved, claims) == _outcome(logout.check_logout_claims, claims)


def test_chapter_19_logout_claims_hold_every_outcome():
    outcomes = {_outcome(logout.check_logout_claims, claims) for claims in LOGOUT_CLAIMS}
    assert outcomes == {("value", None), ("refused", "malformed"), ("refused", "wrong_typ")}


SESSIONS = {
    "laptop": (ID, "alice", "s1"),
    "phone": (ID, "alice", "s2"),
    "tablet": (ID, "alice", None),
    "bob": (ID, "bob", "s3"),
    "other-alice": (OTHER, "alice", "s1"),
    "other-bob": (OTHER, "bob", None),
}
NAMING = [
    {"sub": "alice"}, {"sub": "bob"}, {"sub": "carol"}, {"sid": "s1"}, {"sid": "s3"},
    {"sid": "s9"}, {"sub": "alice", "sid": "s1"}, {"sub": "bob", "sid": "s1"},
    {"sub": "alice", "sid": "s3"},
]


@pytest.mark.parametrize("issuer", [ID, OTHER, "https://mallory.example"])
@pytest.mark.parametrize("named", NAMING)
def test_chapter_19_sessions_to_end_matches_toy(issuer, named):
    solved = _solved(CHAPTER_19).sessions_to_end
    claims = {"iss": issuer, **named}
    assert solved(SESSIONS, claims) == logout.sessions_to_end(SESSIONS, claims)


@pytest.mark.parametrize("cookie", [None, "", "laptop", "bob", "unknown", "fresh"])
def test_chapter_19_sign_in_session_matches_toy(cookie):
    solved = _solved(CHAPTER_19).sign_in_session
    record = (ID, "alice", "s9")
    before = dict(SESSIONS)
    assert solved(SESSIONS, cookie, record, "fresh") == rp_session.sign_in_session(
        SESSIONS, cookie, record, "fresh"
    )
    assert SESSIONS == before


AMRS = [
    ["pwd", "otp", "mfa"], ["otp", "pwd"], ["otp"], ["pwd", "mfa"], ["OTP"], ["hotp"], [],
    "otp", "pwd otp", ("otp",), ["pwd", ["otp"]], ["otp", 7], {"otp": True}, None, 0, "",
]


@pytest.mark.parametrize("method", ["otp", "mfa", "pwd", "hwk", ""])
@pytest.mark.parametrize("amr", AMRS)
def test_chapter_20_amr_includes_matches_toy(amr, method):
    solved = _solved(CHAPTER_20).amr_includes
    for claims in ({"amr": amr}, {}):
        assert solved(claims, method) is assurance.amr_includes(claims, method)


STARTED, NOW = 1_800_000_000, 1_800_000_030
AUTH_TIMES = [
    STARTED - 61, STARTED - 60, STARTED - 1, STARTED, STARTED + 0.5, NOW, NOW + 59, NOW + 60,
    NOW + 61, 0, -1, True, False, None, str(STARTED), float("nan"), float("inf"), [STARTED],
]


def _toy_fresh(claims, started_at, now, leeway):
    id_token._check_auth_time(claims, now, leeway, None, started_at - leeway)


@pytest.mark.parametrize("leeway", [0, 1, 60])
@pytest.mark.parametrize("auth_time", AUTH_TIMES)
def test_chapter_20_check_fresh_matches_toy(auth_time, leeway):
    solved = _solved(CHAPTER_20).check_fresh
    for claims in ({"auth_time": auth_time}, {}):
        args = (claims, STARTED, NOW, leeway)
        assert _outcome(solved, *args) == _outcome(_toy_fresh, *args)


def test_chapter_20_fresh_cases_hold_every_outcome():
    outcomes = {
        _outcome(_toy_fresh, {"auth_time": auth_time}, STARTED, NOW, leeway)[1]
        for auth_time in AUTH_TIMES for leeway in (0, 1, 60)
    }
    assert outcomes == {None, "stale_auth_time", "issued_in_future", "malformed"}


POLICY = {
    ID: {"mfa": frozenset({ACR_MFA}), "any": frozenset({ACR_PASSWORD, ACR_MFA})},
    OTHER: {"any": frozenset({ACR_PASSWORD, ACR_MFA})},
}
ACRS = [ACR_MFA, ACR_PASSWORD, ACR_MFA.upper(), "urn:toy:acr:hwk", "0", "", None, 2, True,
        [ACR_MFA], "missing"]


@pytest.mark.parametrize("level", ["mfa", "any", "hwk", ""])
@pytest.mark.parametrize("issuer", [ID, OTHER, "https://mallory.example", None, [ID], "missing"])
@pytest.mark.parametrize("acr", ACRS)
def test_chapter_20_check_level_matches_toy(acr, issuer, level):
    solved = _solved(CHAPTER_20).check_level
    given = {"iss": issuer, "acr": acr}
    claims = {name: value for name, value in given.items() if value != "missing"}
    args = (claims, POLICY, level)
    assert _outcome(solved, *args) == _outcome(assurance.check_level, *args)
