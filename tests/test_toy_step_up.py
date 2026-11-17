import pytest

from toy.client import Transaction
from toy.errors import FORBIDDEN_REASONS, Forbidden, InvalidToken
from toy.provider import ACR_MFA, ACR_PASSWORD
from toy.step_up import (
    PendingStepUp,
    StepUpGrant,
    check_same_user,
    check_step_up,
    grant_refusal,
    take_grant,
)

ID, OTHER = "https://id.example", "https://other-id.example"
ALICE = (ID, "alice")
STARTED, NOW = 1_800_000_000, 1_800_000_030
TRANSFER = {"to": "bob", "amount": 10}
PENDING = PendingStepUp(
    Transaction("s", "n", "v", "https://app.example/callback", STARTED, "step_up"),
    ALICE, "session-1", "transfer", TRANSFER, frozenset({ACR_MFA}), STARTED + 600,
)
GRANT = StepUpGrant(ALICE, "session-1", "transfer", TRANSFER, ACR_MFA, NOW + 300)


def _reason(check, *args, **kwargs):
    try:
        check(*args, **kwargs)
    except InvalidToken as refused:
        return refused.reason
    return None


def test_forbidden_takes_only_known_reasons():
    assert Forbidden("grant").reason == "grant"
    assert FORBIDDEN_REASONS == {"grant", "user", "action", "expired", "csrf"}
    with pytest.raises(ValueError):
        Forbidden("nope")


def test_same_user_is_the_same_iss_and_sub():
    assert check_same_user({"iss": ID, "sub": "alice"}, ALICE) is None


@pytest.mark.parametrize("claims, reason", [
    ({"iss": OTHER, "sub": "alice"}, "wrong_issuer"),
    ({"iss": ID, "sub": "mallory"}, "sub_mismatch"),
    ({"iss": ID, "sub": "ALICE"}, "sub_mismatch"),
    ({"iss": ID, "sub": ""}, "sub_mismatch"),
    ({"iss": ID}, "sub_mismatch"),
    ({"sub": "alice"}, "wrong_issuer"),
    ({"iss": [ID], "sub": "alice"}, "wrong_issuer"),
    ({"iss": ID, "sub": "mallory", "email": "alice@example.com"}, "sub_mismatch"),
])
def test_another_user_is_refused(claims, reason):
    assert _reason(check_same_user, claims, ALICE) == reason


def test_a_fresh_mfa_sign_in_by_the_same_user_answers_the_step_up():
    claims = {"iss": ID, "sub": "alice", "auth_time": STARTED + 20, "acr": ACR_MFA}
    assert check_step_up(claims, PENDING, NOW) is None
    assert check_step_up({**claims, "auth_time": STARTED - 5}, PENDING, NOW, 5) is None
    assert check_step_up({**claims, "auth_time": NOW + 5}, PENDING, NOW, 5) is None


@pytest.mark.parametrize("changes, leeway, reason", [
    ({"sub": "mallory"}, 0, "sub_mismatch"),
    ({"iss": OTHER}, 0, "wrong_issuer"),
    ({"auth_time": STARTED - 1}, 0, "stale_auth_time"),
    ({"auth_time": STARTED - 3600}, 0, "stale_auth_time"),
    ({"auth_time": STARTED - 6}, 5, "stale_auth_time"),
    ({"auth_time": NOW + 1}, 0, "issued_in_future"),
    ({"auth_time": True}, 0, "malformed"),
    ({"auth_time": str(STARTED)}, 0, "malformed"),
    ({"auth_time": None}, 0, "malformed"),
    ({"acr": ACR_PASSWORD}, 0, "acr_not_met"),
    ({"acr": ""}, 0, "acr_not_met"),
    ({"acr": [ACR_MFA]}, 0, "acr_not_met"),
    ({"acr": "missing"}, 0, "acr_not_met"),
    ({"auth_time": "missing"}, 0, "auth_time_missing"),
])
def test_a_step_up_answer_is_refused(changes, leeway, reason):
    given = {"iss": ID, "sub": "alice", "auth_time": STARTED + 20, "acr": ACR_MFA, **changes}
    claims = {name: value for name, value in given.items() if value != "missing"}
    assert _reason(check_step_up, claims, PENDING, NOW, leeway) == reason


def _refusal(**changes):
    request = {"user_key": ALICE, "session_id": "session-1", "action": "transfer",
               "params": TRANSFER, "now": NOW, **changes}
    return grant_refusal(GRANT, **request)


def test_a_grant_is_spent_only_on_what_it_approved():
    assert _refusal() is None
    assert _refusal(params={"amount": 10, "to": "bob"}) is None
    assert _refusal(now=NOW + 299) is None


@pytest.mark.parametrize("changes, reason", [
    ({"user_key": (ID, "mallory")}, "user"),
    ({"user_key": (OTHER, "alice")}, "user"),
    ({"session_id": "session-2"}, "user"),
    ({"session_id": ""}, "user"),
    ({"session_id": None}, "user"),
    ({"action": "close_account"}, "action"),
    ({"params": {"to": "bob", "amount": 10000}}, "action"),
    ({"params": {"to": "bob", "amount": "10"}}, "action"),
    ({"params": {}}, "action"),
    ({"params": {**TRANSFER, "memo": "x"}}, "action"),
    ({"now": NOW + 300}, "expired"),
])
def test_a_grant_is_refused_for_anything_else(changes, reason):
    assert _refusal(**changes) == reason


def test_take_grant_removes_the_grant_it_returns():
    grants = {"g1": GRANT, "g2": GRANT}
    taken, reason, after = take_grant(grants, "g1", lambda grant: None)
    assert (taken, reason, after) == (GRANT, None, {"g2": GRANT})
    assert grants == {"g1": GRANT, "g2": GRANT}


def test_take_grant_keeps_a_grant_it_refuses():
    grants = {"g1": GRANT}
    assert take_grant(grants, "g1", lambda grant: "user") == (None, "user", grants)
    assert take_grant(grants, "g9", lambda grant: None) == (None, "grant", grants)
    assert take_grant({}, "", lambda grant: None) == (None, "grant", {})
