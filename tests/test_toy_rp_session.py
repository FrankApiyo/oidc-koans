import pytest

from toy.rp_session import sign_in_session

ANONYMOUS = (None, None, None)
ALICE = ("https://id.example", "alice", "s1")
SESSIONS = {"planted": ANONYMOUS, "bob": ("https://id.example", "bob", "s2")}


@pytest.mark.parametrize("cookie", ["planted", "bob", "unknown", "", None])
def test_sign_in_gives_a_new_id_and_forgets_the_one_brought(cookie):
    session_id, after = sign_in_session(SESSIONS, cookie, ALICE, "fresh")
    assert session_id == "fresh"
    assert after["fresh"] == ALICE
    assert cookie not in after
    assert {k: v for k, v in after.items() if k != "fresh"} == {
        k: v for k, v in SESSIONS.items() if k != cookie
    }


def test_sign_in_leaves_the_sessions_it_was_given_alone():
    before = dict(SESSIONS)
    sign_in_session(SESSIONS, "planted", ALICE, "fresh")
    assert SESSIONS == before
