"""Parity for chapters 19 and 20: each solved function agrees with its toy/ counterpart."""

import itertools

import pytest

from tests.parity_support import ID, OTHER, _outcome, _solved
from toy import logout

CHAPTER_19 = "19_sessions_and_logout_test.py"
AFTER, QUIZ_AFTER = "https://app.example/signed-out", "https://quiz.example/signed-out"
REGISTERED = {"app": (AFTER,), "quiz": (QUIZ_AFTER,), "empty": ()}
HINTS = {
    "app": {"aud": "app"},
    "quiz": {"aud": "quiz"},
    "listed": {"aud": ["app"]},
    "both": {"aud": ["quiz", "app"], "azp": "app"},
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
