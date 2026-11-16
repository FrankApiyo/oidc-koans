import pytest

from toy.jose import jwks_of, public_jwk
from toy.key_cache import CACHE_LIFETIME, REFETCH_COOLDOWN, CachedKeys, cached_keys
from toy.keys import ATTACKER_RSA, RSA_1, RSA_2

NOW = 1_800_000_000
JWKS_URI = "https://id.example/jwks"
OLD_SET = jwks_of(public_jwk(RSA_1, "k1"))
NEW_SET = jwks_of(public_jwk(RSA_2, "k2"))
ATTACKER_SET = jwks_of(public_jwk(ATTACKER_RSA, "k2"))


class Getter:
    """Serves jwks at JWKS_URI and ATTACKER_SET anywhere else, and keeps each URL asked for."""

    def __init__(self, jwks):
        self._jwks = jwks
        self.urls: tuple[str, ...] = ()

    def __call__(self, url):
        self.urls = (*self.urls, url)
        return self._jwks if url == JWKS_URI else ATTACKER_SET

    @property
    def calls(self):
        return len(self.urls)


def _lookup(entry, header, now, get):
    return cached_keys(entry, header, now, get, JWKS_URI)


def test_the_first_lookup_fetches_the_jwks_uri():
    get = Getter(OLD_SET)
    assert _lookup(None, {"kid": "k1"}, NOW, get) == CachedKeys(OLD_SET, NOW)
    assert get.urls == (JWKS_URI,)


@pytest.mark.parametrize("age", [0, REFETCH_COOLDOWN, CACHE_LIFETIME - 1])
def test_a_known_kid_never_fetches_while_the_set_is_fresh(age):
    entry, get = CachedKeys(OLD_SET, NOW), Getter(NEW_SET)
    assert _lookup(entry, {"kid": "k1"}, NOW + age, get) is entry
    assert get.calls == 0


@pytest.mark.parametrize("header", [{"kid": "k1"}, {"kid": "k2"}, {}])
def test_a_set_fetched_a_cache_lifetime_ago_is_fetched_again(header):
    entry, get = CachedKeys(OLD_SET, NOW), Getter(NEW_SET)
    later = NOW + CACHE_LIFETIME
    assert _lookup(entry, header, later, get) == CachedKeys(NEW_SET, later)
    assert get.calls == 1


def test_an_unknown_kid_fetches_once_the_cooldown_has_passed():
    entry, get = CachedKeys(OLD_SET, NOW), Getter(NEW_SET)
    assert _lookup(entry, {"kid": "k2"}, NOW + REFETCH_COOLDOWN - 1, get) is entry
    assert get.calls == 0
    later = NOW + REFETCH_COOLDOWN
    assert _lookup(entry, {"kid": "k2"}, later, get) == CachedKeys(NEW_SET, later)
    assert get.calls == 1


def test_a_fetched_set_replaces_the_old_one():
    get = Getter(NEW_SET)
    refreshed = _lookup(CachedKeys(OLD_SET, NOW), {"kid": "k2"}, NOW + REFETCH_COOLDOWN, get)
    assert [jwk["kid"] for jwk in refreshed.jwks["keys"]] == ["k2"]


@pytest.mark.parametrize("header", [{}, {"kid": None}, {"kid": ""}, {"kid": 7}, {"kid": ["k2"]}])
def test_a_missing_or_odd_kid_never_fetches(header):
    entry, get = CachedKeys(OLD_SET, NOW), Getter(NEW_SET)
    assert _lookup(entry, header, NOW + REFETCH_COOLDOWN, get) is entry
    assert get.calls == 0


def test_a_kid_matches_exactly():
    entry, get = CachedKeys(OLD_SET, NOW), Getter(NEW_SET)
    assert _lookup(entry, {"kid": "K1"}, NOW + REFETCH_COOLDOWN, get).jwks == NEW_SET
    assert get.calls == 1


@pytest.mark.parametrize("age", [REFETCH_COOLDOWN, CACHE_LIFETIME])
@pytest.mark.parametrize("named", [
    {"jku": "https://mallory.example/jwks"},
    {"x5u": "https://mallory.example/cert"},
    {"jwk": public_jwk(ATTACKER_RSA, "k2")},
    {"jku": JWKS_URI.upper()},
], ids=["jku", "x5u", "jwk", "jku-lookalike"])
def test_keys_the_header_names_are_never_used(named, age):
    entry, get = CachedKeys(OLD_SET, NOW), Getter(NEW_SET)
    later = NOW + age
    assert _lookup(entry, {"kid": "k2", **named}, later, get) == CachedKeys(NEW_SET, later)
    assert get.urls == (JWKS_URI,)
