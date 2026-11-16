from toy.token_endpoint import RefreshLedger, spend_refresh_token

LEDGER = RefreshLedger(active={"rt-1": "g1", "rt-9": "g9"}, spent={"rt-0": "g1"})


def test_a_refresh_token_is_good_once():
    grant, after = spend_refresh_token(LEDGER, "rt-1")
    assert grant == "g1"
    assert after == RefreshLedger({"rt-9": "g9"}, {"rt-0": "g1", "rt-1": "g1"}, frozenset())
    assert spend_refresh_token(after, "rt-1")[0] is None


def test_a_spent_token_presented_again_revokes_its_grant():
    grant, after = spend_refresh_token(LEDGER, "rt-0")
    assert grant is None
    assert after == RefreshLedger(LEDGER.active, LEDGER.spent, frozenset({"g1"}))
    assert spend_refresh_token(after, "rt-1") == (None, after)
    assert spend_refresh_token(after, "rt-9")[0] == "g9"


def test_an_unknown_token_changes_nothing():
    for token in ("rt-2", "", "RT-1", "rt-1 "):
        assert spend_refresh_token(LEDGER, token) == (None, LEDGER)
