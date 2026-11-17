"""Parity for chapter 21: each solved function agrees with its toy/ counterpart."""

import itertools

import pytest

from tests.parity_support import ID, OTHER, _outcome, _solved
from toy import step_up
from toy.client import Transaction
from toy.provider import ACR_MFA, ACR_PASSWORD

CHAPTER_21 = "21_step_up_authentication_test.py"
ALICE = (ID, "alice")
STARTED, NOW = 1_800_000_000, 1_800_000_030
TRANSFER = {"to": "bob", "amount": "10"}
PENDING = step_up.PendingStepUp(
    Transaction("s", "n", "v", "https://app.example/callback", STARTED, "step_up"),
    ALICE, "session-1", "transfer", TRANSFER, frozenset({ACR_MFA}), STARTED + 600,
)
MISSING = object()
ISSUERS = [ID, OTHER, f"{ID}/", "", None, [ID], MISSING]
SUBS = ["alice", "mallory", "ALICE", "", None, ["alice"], 7, MISSING]


def _claims(**given):
    return {name: value for name, value in given.items() if value is not MISSING}


@pytest.mark.parametrize("iss, sub", list(itertools.product(ISSUERS, SUBS)))
def test_chapter_21_check_same_user_matches_toy(iss, sub):
    solved = _solved(CHAPTER_21).check_same_user
    claims = _claims(iss=iss, sub=sub, email="alice@example.com")
    assert _outcome(solved, claims, ALICE) == _outcome(step_up.check_same_user, claims, ALICE)


AUTH_TIMES = [
    STARTED - 3600, STARTED - 6, STARTED - 5, STARTED - 1, STARTED, STARTED + 0.5, STARTED + 20,
    NOW, NOW + 5, NOW + 6, 0, True, False, None, str(STARTED), float("nan"), [STARTED], MISSING,
]
ACRS = [ACR_MFA, ACR_PASSWORD, ACR_MFA.upper(), "", "0", None, 2, True, [ACR_MFA], MISSING]


@pytest.mark.parametrize("leeway", [0, 5])
@pytest.mark.parametrize("acr", ACRS)
@pytest.mark.parametrize("auth_time", AUTH_TIMES)
@pytest.mark.parametrize("who", [ALICE, (OTHER, "alice"), (ID, "mallory")])
def test_chapter_21_check_step_up_matches_toy(who, auth_time, acr, leeway):
    solved = _solved(CHAPTER_21).check_step_up
    claims = _claims(iss=who[0], sub=who[1], auth_time=auth_time, acr=acr)
    args = (claims, PENDING, NOW, leeway)
    assert _outcome(solved, *args) == _outcome(step_up.check_step_up, *args)


def test_chapter_21_step_up_cases_hold_every_outcome():
    outcomes = {
        _outcome(step_up.check_step_up, _claims(iss=who[0], sub=who[1], auth_time=t, acr=a),
                 PENDING, NOW, 5)
        for who in (ALICE, (OTHER, "alice"), (ID, "mallory"))
        for t in AUTH_TIMES for a in ACRS
    }
    assert {reason for _, reason in outcomes} == {
        None, "wrong_issuer", "sub_mismatch", "auth_time_missing", "malformed",
        "issued_in_future", "stale_auth_time", "acr_not_met",
    }


GRANT = step_up.StepUpGrant(ALICE, "session-1", "transfer", TRANSFER, ACR_MFA, NOW + 300)
USER_KEYS = [ALICE, (ID, "mallory"), (OTHER, "alice"), ("alice", ID), ()]
SESSIONS = ["session-1", "session-2", "", None, "session-11"]
ACTIONS = ["transfer", "close_account", "", None]
PARAMS = [TRANSFER, {"amount": "10", "to": "bob"}, {**TRANSFER, "amount": "10000"},
          {**TRANSFER, "amount": 10}, {}, None, {**TRANSFER, "memo": "x"}]
TIMES = [NOW, NOW + 299, NOW + 300, NOW + 301]


@pytest.mark.parametrize("now", TIMES)
@pytest.mark.parametrize("params", PARAMS)
@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize("session_id", SESSIONS)
@pytest.mark.parametrize("user_key", USER_KEYS)
def test_chapter_21_grant_refusal_matches_toy(user_key, session_id, action, params, now):
    solved = _solved(CHAPTER_21).grant_refusal
    request = {"user_key": user_key, "session_id": session_id, "action": action,
               "params": params, "now": now}
    assert solved(GRANT, **request) == step_up.grant_refusal(GRANT, **request)


GRANTS = {"g1": GRANT, "g2": GRANT}


@pytest.mark.parametrize("reason", [None, "user", "action", "expired"])
@pytest.mark.parametrize("grant_id", ["g1", "g2", "g3", ""])
def test_chapter_21_take_grant_matches_toy(grant_id, reason):
    solved = _solved(CHAPTER_21).take_grant
    before = dict(GRANTS)
    seen = []

    def refusal(grant):
        seen.append(grant)
        return reason

    expected = step_up.take_grant(GRANTS, grant_id, refusal)
    toy_seen, seen[:] = list(seen), []
    assert solved(GRANTS, grant_id, refusal) == expected
    assert seen == toy_seen
    assert GRANTS == before
