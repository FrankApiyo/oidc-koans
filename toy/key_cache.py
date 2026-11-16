"""A relying party's cached copy of one issuer's JWK Set (OIDC Core §10.1.1).

A set is fetched again once it is CACHE_LIFETIME seconds old. An unfamiliar
kid sends the cache back to the jwks_uri, but not within REFETCH_COOLDOWN
seconds of the last fetch, and the set it fetches replaces the old one. Both
numbers are this toy's choice: the specs set neither.
"""

from collections.abc import Callable
from dataclasses import dataclass

CACHE_LIFETIME = 3600
REFETCH_COOLDOWN = 60


@dataclass(frozen=True)
class CachedKeys:
    jwks: dict
    fetched_at: int


def cached_keys(
    entry: CachedKeys | None, kid, now: int, fetch: Callable[[], dict]
) -> CachedKeys:
    """The entry to look kid up in: entry itself, or a set fetch() returns now.

    A missing or non-string kid is not an unfamiliar kid, so it never fetches.
    """
    if entry is None or now - entry.fetched_at >= CACHE_LIFETIME:
        return CachedKeys(fetch(), now)
    if not isinstance(kid, str) or not kid or _holds(entry.jwks, kid):
        return entry
    if now - entry.fetched_at < REFETCH_COOLDOWN:
        return entry
    return CachedKeys(fetch(), now)


def _holds(jwks: dict, kid: str) -> bool:
    return any(jwk.get("kid") == kid for jwk in jwks.get("keys", []))
