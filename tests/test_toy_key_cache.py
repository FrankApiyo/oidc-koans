import pytest

from toy.jose import jwks_of, public_jwk
from toy.key_cache import CACHE_LIFETIME, REFETCH_COOLDOWN, CachedKeys, cached_keys
from toy.keys import RSA_1, RSA_2

NOW = 1_800_000_000
OLD_SET = jwks_of(public_jwk(RSA_1, "k1"))
NEW_SET = jwks_of(public_jwk(RSA_2, "k2"))


class Fetcher:
    def __init__(self, jwks):
        self._jwks = jwks
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return self._jwks


def test_the_first_lookup_fetches():
    fetch = Fetcher(OLD_SET)
    assert cached_keys(None, "k1", NOW, fetch) == CachedKeys(OLD_SET, NOW)
    assert fetch.calls == 1


@pytest.mark.parametrize("age", [0, REFETCH_COOLDOWN, CACHE_LIFETIME - 1])
def test_a_known_kid_never_fetches_while_the_set_is_fresh(age):
    entry, fetch = CachedKeys(OLD_SET, NOW), Fetcher(NEW_SET)
    assert cached_keys(entry, "k1", NOW + age, fetch) is entry
    assert fetch.calls == 0


@pytest.mark.parametrize("kid", ["k1", "k2", None])
def test_a_set_fetched_a_cache_lifetime_ago_is_fetched_again(kid):
    entry, fetch = CachedKeys(OLD_SET, NOW), Fetcher(NEW_SET)
    later = NOW + CACHE_LIFETIME
    assert cached_keys(entry, kid, later, fetch) == CachedKeys(NEW_SET, later)
    assert fetch.calls == 1


def test_an_unknown_kid_fetches_once_the_cooldown_has_passed():
    entry, fetch = CachedKeys(OLD_SET, NOW), Fetcher(NEW_SET)
    assert cached_keys(entry, "k2", NOW + REFETCH_COOLDOWN - 1, fetch) is entry
    assert fetch.calls == 0
    later = NOW + REFETCH_COOLDOWN
    assert cached_keys(entry, "k2", later, fetch) == CachedKeys(NEW_SET, later)
    assert fetch.calls == 1


def test_a_fetched_set_replaces_the_old_one():
    fetch = Fetcher(NEW_SET)
    refreshed = cached_keys(CachedKeys(OLD_SET, NOW), "k2", NOW + REFETCH_COOLDOWN, fetch)
    assert [jwk["kid"] for jwk in refreshed.jwks["keys"]] == ["k2"]


@pytest.mark.parametrize("kid", [None, "", 7, ["k2"]])
def test_a_missing_or_odd_kid_never_fetches(kid):
    entry, fetch = CachedKeys(OLD_SET, NOW), Fetcher(NEW_SET)
    assert cached_keys(entry, kid, NOW + REFETCH_COOLDOWN, fetch) is entry
    assert fetch.calls == 0


def test_a_kid_matches_exactly():
    entry, fetch = CachedKeys(OLD_SET, NOW), Fetcher(NEW_SET)
    assert cached_keys(entry, "K1", NOW + REFETCH_COOLDOWN, fetch).jwks == NEW_SET
    assert fetch.calls == 1
