"""JWKS key rotation.

A provider changes its signing key from time to time, and at once if a key
leaks. OIDC Core §10.1.1: it publishes its keys as a JWK Set at its
jwks_uri, and the kid in each token's header names the key that signed it.
It adds new keys to the set first, then "can begin using a new key at its
discretion". The verifier "knows to go back to the jwks_uri location to
re-retrieve the keys when it sees an unfamiliar kid value", and the set
"SHOULD retain recently decommissioned signing keys for a reasonable period
of time". With several keys in a set, a kid "MUST be provided" (§10.1).

So a client keeps a copy of each issuer's set, and fetches it again when
the copy is too old, or when a token names a kid the copy lacks. Anyone can
send a token with a made-up kid, so that second fetch is rate-limited: at
most once per cooldown, per issuer. The new set replaces the old, so a key
the provider dropped stops working. The specs set neither number; this
course uses an hour for the copy and a minute for the cooldown.

For a rotation no client notices, the provider publishes the new key,
waits one cache lifetime, signs with it, and retires the old key once
every token it signed has expired.

A common mistake: fetching the set for every token or every unknown kid,
or keeping a key forever.

Read more:
  https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys
  https://openid.net/specs/openid-connect-core-1_0.html#Signing
  https://www.rfc-editor.org/rfc/rfc7517.html#section-5
"""

from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from conftest import __
from toy.client import exchange_code, start_login
from toy.clock import Clock
from toy.errors import InvalidToken
from toy.http import Browser, FakeNetwork, Request, Response
from toy.jose import jws_encode, jws_split, jws_verify, jwks_of, public_jwk
from toy.key_cache import CACHE_LIFETIME, REFETCH_COOLDOWN, CachedKeys
from toy.keys import ATTACKER_RSA, RSA_1, RSA_2
from toy.provider import TOKEN_LIFETIME, Provider

ISSUER = "https://id.example"
APP = "https://app.example"
REDIRECT_URI = f"{APP}/callback"
CLIENT_ID = "app"
MALLORY = "https://mallory.example"
ALGS = frozenset({"RS256"})


class Recorder:
    """Passes each request on to app, and keeps the path of each one."""

    def __init__(self, app: Callable[[Request], Response]):
        self._app = app
        self.paths: tuple[str, ...] = ()

    def __call__(self, request: Request) -> Response:
        self.paths = (*self.paths, request.path)
        return self._app(request)

    @property
    def jwks_fetches(self) -> int:
        return self.paths.count("/jwks")


def _claims(token: str, jwks: dict, issuer: str) -> dict:
    claims = jws_verify(token, jwks, ALGS)
    if claims.get("iss") != issuer:
        raise InvalidToken("wrong_issuer")
    return claims


class CarelessCache:
    """Another team's key cache for app. It keeps one entry per issuer."""

    def __init__(self, network: FakeNetwork, jwks_uris: dict[str, str]):
        self._network, self._jwks_uris = network, dict(jwks_uris)
        self.entries: dict[str, dict] = {}

    def verify(self, token: str, issuer: str, now: int) -> dict:
        header = jws_split(token)[0]
        kid = header.get("kid")
        entry = self.entries.get(issuer)
        stale = entry is None or now - entry["fetched_at"] >= CACHE_LIFETIME
        unknown = entry is not None and kid not in entry["keys"]
        if stale or (unknown and now - entry["fetched_at"] >= REFETCH_COOLDOWN):
            url = header.get("jku") or self._jwks_uris[issuer]
            jwks = self._network.send(Request("GET", url)).body
            entry = {"keys": {jwk["kid"]: jwk for jwk in jwks["keys"]}, "fetched_at": now}
            self.entries = {**self.entries, issuer: entry}
        key = entry["keys"].get(kid)
        if key is None:
            raise InvalidToken("unknown_kid")
        return _claims(token, jwks_of(key), issuer)


def cached_keys(
    entry: CachedKeys | None, kid, now: int, fetch: Callable[[], dict]
) -> CachedKeys:
    # >>> answer
    if entry is None or now - entry.fetched_at >= CACHE_LIFETIME:
        return CachedKeys(fetch(), now)
    known = any(jwk.get("kid") == kid for jwk in entry.jwks["keys"])
    if known or not isinstance(kid, str) or not kid:
        return entry
    if now - entry.fetched_at < REFETCH_COOLDOWN:
        return entry
    return CachedKeys(fetch(), now)
    # <<<


class KeyCache:
    """app's key cache, built on your cached_keys. It keeps one entry per issuer.

    verify takes only the kid from the token's header, and gives cached_keys a
    fetch that always asks the jwks_uri app was configured with for that issuer.
    """

    def __init__(self, network: FakeNetwork, jwks_uris: dict[str, str]):
        self._network, self._jwks_uris = network, dict(jwks_uris)
        self.entries: dict[str, CachedKeys] = {}

    def verify(self, token: str, issuer: str, now: int) -> dict:
        kid = jws_split(token)[0].get("kid")
        entry = cached_keys(self.entries.get(issuer), kid, now, lambda: self._fetch(issuer))
        self.entries = {**self.entries, issuer: entry}
        return _claims(token, entry.jwks, issuer)

    def _fetch(self, issuer: str) -> dict:
        return self._network.send(Request("GET", self._jwks_uris[issuer])).body


class KeyHost:
    """mallory's server: one JWK Set at every path, and the URL of each request."""

    def __init__(self, jwks: dict):
        self._jwks = jwks
        self.requested: tuple[str, ...] = ()

    def __call__(self, request: Request) -> Response:
        self.requested = (*self.requested, request.url)
        return Response(200, {}, self._jwks)


@dataclass(frozen=True)
class World:
    clock: Clock
    network: FakeNetwork
    provider: Provider
    recorder: Recorder
    mallory: KeyHost
    config: dict

    def cache(self) -> KeyCache:
        return KeyCache(self.network, {ISSUER: self.config["jwks_uri"]})


def _world() -> World:
    """id.example signing with k1, alice and bob with accounts there, and mallory's key host.

    The recorder sits in front of id.example and counts what app asks it for.
    """
    clock, network = Clock(), FakeNetwork()
    provider = Provider(ISSUER, clock=clock, network=network)
    provider.register_client(CLIENT_ID, [REDIRECT_URI])
    provider.add_user("alice", "alice@example.com", True, "alice-password")
    provider.add_user("bob", "bob@example.com", True, "bob-password")
    recorder = Recorder(provider)
    network.mount(ISSUER, recorder)
    network.mount(APP, lambda request: Response(200, {}, "callback reached"))
    mallory = KeyHost(jwks_of(public_jwk(ATTACKER_RSA, "m1")))
    network.mount(MALLORY, mallory)
    config = network.send(Request("GET", f"{ISSUER}/.well-known/openid-configuration")).body
    return World(clock, network, provider, recorder, mallory, config)


def _id_token(world: World, sub: str = "alice") -> str:
    """The ID token id.example issues app now, after sub signs in."""
    browser = Browser(world.network)
    world.provider.sign_in(browser, sub, ("pwd",))
    url, transaction = start_login(
        issuer_config=world.config, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI,
        now=world.clock.now(),
    )
    answer = world.network.send(Request("GET", url, cookies=browser.cookies(ISSUER)))
    return exchange_code(
        issuer_config=world.config, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI,
        code=Request("GET", answer.location).query["code"],
        code_verifier=transaction.code_verifier, network=world.network,
    )["id_token"]


def _token(world: World, header: dict, key=ATTACKER_RSA, sub: str = "admin") -> str:
    """A token for app in id.example's name, issued now and signed with key."""
    now = world.clock.now()
    claims = {"iss": ISSUER, "sub": sub, "aud": CLIENT_ID, "iat": now, "exp": now + TOKEN_LIFETIME}
    return jws_encode({"alg": "RS256", **header}, claims, key)


def _reason(check: Callable) -> str | None:
    try:
        check()
    except InvalidToken as refused:
        return refused.reason
    return None


def test_a_provider_publishes_more_keys_than_it_signs_with():
    """id.example publishes k2 ahead of using it. Which kids does its set hold, and which signs today's tokens? Core §10.1: "If there are multiple keys in the referenced JWK Set document, a kid value MUST be provided in the JOSE Header." The toy verifier refuses a token with no kid, even when the set holds a single key: that is the toy's choice."""
    world = _world()
    world.provider.publish_key(RSA_2, "k2")
    published = world.network.send(Request("GET", world.config["jwks_uri"])).body
    assert [jwk["kid"] for jwk in published["keys"]] == _a(["k1", "k2"])
    assert jws_split(_id_token(world))[0]["kid"] == _a("k1")
    unnamed = _token(world, {}, key=RSA_1, sub="alice")
    assert _reason(lambda: jws_verify(unnamed, published, ALGS)) == _a("unknown_kid")


def mallorys_header() -> dict:
    return _a({"alg": "RS256", "kid": "m1", "jku": f"{MALLORY}/jwks"})


def test_spot_the_bug_in_careless_cache():
    """Spot the bug: another team wrote CarelessCache for app. Read it. mallory serves a JWK Set at https://mallory.example/jwks with one key, kid "m1", whose private half is ATTACKER_RSA. app has held id.example's set for a minute. Make mallorys_header return a header that gets her token, signed with ATTACKER_RSA, accepted as id.example's admin, and leaves app trusting her key for tokens that name no URL at all."""
    world = _world()
    careless = CarelessCache(world.network, {ISSUER: world.config["jwks_uri"]})
    assert careless.verify(_id_token(world), ISSUER, world.clock.now())["sub"] == "alice"
    world.clock.advance(REFETCH_COOLDOWN)
    header = mallorys_header()
    assert careless.verify(_token(world, header), ISSUER, world.clock.now())["sub"] == "admin"
    plain = _token(world, {"kid": header["kid"]})
    assert careless.verify(plain, ISSUER, world.clock.now())["sub"] == "admin"
    assert [urlsplit(url).netloc for url in world.mallory.requested] == ["mallory.example"]


def test_accepts_a_known_kid_without_fetching_again():
    """Implement cached_keys above, the fix. entry is app's copy of one issuer's set, or None, and fetch() GETs that issuer's jwks_uri: you never see the header, only its kid. 1. No entry, or one CACHE_LIFETIME seconds old or older: return CachedKeys(fetch(), now). 2. A kid that names a key in entry.jwks["keys"], or one that is not a non-empty string: return entry. 3. Any other kid: return CachedKeys(fetch(), now) once REFETCH_COOLDOWN seconds have passed since entry.fetched_at, else entry. A fetched set replaces the old one; never merge them."""
    world = _world()
    cache = world.cache()
    assert cache.verify(_id_token(world), ISSUER, world.clock.now())["sub"] == "alice"
    assert world.recorder.jwks_fetches == _a(1)
    world.clock.advance(REFETCH_COOLDOWN)
    for sub in ("alice", "bob", "alice"):
        assert cache.verify(_id_token(world, sub), ISSUER, world.clock.now())["sub"] == sub
    for header in ({}, {"kid": ""}):
        unnamed = _token(world, header, key=RSA_1)
        assert _reason(lambda: cache.verify(unnamed, ISSUER, world.clock.now())) == "unknown_kid"
    assert world.recorder.jwks_fetches == _a(1)
    world.clock.advance(CACHE_LIFETIME - REFETCH_COOLDOWN)
    assert cache.verify(_id_token(world), ISSUER, world.clock.now())["sub"] == "alice"
    assert world.recorder.jwks_fetches == _a(2)


def test_refuses_a_key_set_the_token_names():
    """The fix in place: KeyCache hands your cached_keys the kid alone, and its fetch always goes to the jwks_uri app was configured with. Your header and the hidden ones get nowhere, mallory's server hears nothing, and a token naming no URL finds no key of hers. What does app say to each?"""
    world = _world()
    cache = world.cache()
    assert cache.verify(_id_token(world), ISSUER, world.clock.now())["sub"] == "alice"
    world.clock.advance(REFETCH_COOLDOWN)
    headers = [
        mallorys_header(),
        {"kid": "m1", "jku": f"{MALLORY}/jwks"},
        {"kid": "m2", "jku": f"{MALLORY}/m2"},
        {"kid": "m1", "x5u": f"{MALLORY}/jwks"},
        {"kid": "m1", "jku": f"{MALLORY}/jwks", "jwk": public_jwk(ATTACKER_RSA, "m1")},
        {"kid": "k1", "jku": f"{MALLORY}/jwks"},
        {"kid": "m1"},
    ]
    reasons = [
        _reason(lambda: cache.verify(_token(world, header), ISSUER, world.clock.now()))
        for header in headers
    ]
    assert reasons[:5] == _a(["unknown_kid"] * 5)
    assert reasons[5:] == _a(["bad_signature", "unknown_kid"])
    assert world.mallory.requested == _a(())
    assert cache.verify(_id_token(world), ISSUER, world.clock.now())["sub"] == "alice"


def test_accepts_a_new_kid_after_one_refetch():
    """id.example rotates in a hurry: a minute after app's first fetch it publishes k2 and signs with it at once. bob's token names a kid app has never seen. How many times has app fetched the set once it has checked bob's token twice? The new set still holds k1, so alice's token from before the switch still passes."""
    world = _world()
    cache = world.cache()
    alices = _id_token(world)
    assert cache.verify(alices, ISSUER, world.clock.now())["sub"] == "alice"
    world.clock.advance(REFETCH_COOLDOWN)
    world.provider.publish_key(RSA_2, "k2")
    world.provider.sign_with("k2")
    bobs = _id_token(world, "bob")
    assert jws_split(bobs)[0]["kid"] == "k2"
    assert cache.verify(bobs, ISSUER, world.clock.now())["sub"] == _a("bob")
    assert cache.verify(bobs, ISSUER, world.clock.now())["sub"] == "bob"
    assert world.recorder.jwks_fetches == _a(2)
    assert cache.verify(alices, ISSUER, world.clock.now())["sub"] == _a("alice")


def test_refuses_to_refetch_for_every_unknown_kid():
    """Anyone can send app a token with a kid made up on the spot. mallory sends a hundred in one second. A cache that fetched for each would send id.example a hundred requests on her behalf, and a provider may rate-limit app for that. Core §10.1.1 says when to go back, not how often: the cooldown is engineering practice. How many fetches does app make, now and after the next cooldown?"""
    world = _world()
    cache = world.cache()
    alices = _id_token(world)
    assert cache.verify(alices, ISSUER, world.clock.now())["sub"] == "alice"
    world.clock.advance(REFETCH_COOLDOWN)
    made_up = [_token(world, {"kid": f"made-up-{n}"}) for n in range(100)]
    reasons = {_reason(lambda: cache.verify(token, ISSUER, world.clock.now())) for token in made_up}
    assert reasons == _a({"unknown_kid"})
    assert world.recorder.jwks_fetches == _a(2)
    assert cache.verify(alices, ISSUER, world.clock.now())["sub"] == "alice"
    world.clock.advance(REFETCH_COOLDOWN)
    late = _token(world, {"kid": "made-up-100"})
    assert _reason(lambda: cache.verify(late, ISSUER, world.clock.now())) == "unknown_kid"
    assert world.recorder.jwks_fetches == _a(3)


def test_refuses_a_forgery_without_refetching():
    """A known kid whose signature does not verify is not a rotation. It is a forgery, and fetching the set again cannot change that. mallory signs with ATTACKER_RSA and names id.example's k1. What does app say, and how many fetches has it made?"""
    world = _world()
    cache = world.cache()
    assert cache.verify(_id_token(world), ISSUER, world.clock.now())["sub"] == "alice"
    world.clock.advance(REFETCH_COOLDOWN)
    forged = _token(world, {"kid": "k1"})
    assert _reason(lambda: cache.verify(forged, ISSUER, world.clock.now())) == _a("bad_signature")
    assert world.recorder.jwks_fetches == _a(1)


def test_refuses_a_retired_key_once_the_cache_expires():
    """k1's private key leaks, so id.example signs with k2 and drops k1 at once. mallory has k1 and signs tokens as anyone. Until app's copy of the set expires, hers pass: that is the price of a cache. Then app fetches again and the new set replaces the old. A cache that keeps keys forever, or merges what it fetches into what it had, would take her tokens for good."""
    world = _world()
    cache = world.cache()
    assert cache.verify(_id_token(world), ISSUER, world.clock.now())["sub"] == "alice"
    world.provider.publish_key(RSA_2, "k2")
    world.provider.sign_with("k2")
    world.provider.retire_key("k1")
    world.clock.advance(CACHE_LIFETIME - 1)
    leaked = _token(world, {"kid": "k1"}, key=RSA_1)
    assert cache.verify(leaked, ISSUER, world.clock.now())["sub"] == _a("admin")
    world.clock.advance(1)
    leaked = _token(world, {"kid": "k1"}, key=RSA_1)
    assert _reason(lambda: cache.verify(leaked, ISSUER, world.clock.now())) == _a("unknown_kid")
    assert world.recorder.jwks_fetches == _a(2)
    assert cache.verify(_id_token(world), ISSUER, world.clock.now())["sub"] == "alice"


def test_a_key_retired_too_early_breaks_live_tokens():
    """Nothing leaked, but id.example retires k1 the moment it signs with k2. bob's login sends app back for the new set, which replaces the old. alice's token, signed with k1 ninety seconds ago, is still in date. Core §10.1.1: the set "SHOULD retain recently decommissioned signing keys for a reasonable period of time". What does app say to alice's token now?"""
    world = _world()
    cache = world.cache()
    alices = _id_token(world)
    assert cache.verify(alices, ISSUER, world.clock.now())["sub"] == "alice"
    world.clock.advance(REFETCH_COOLDOWN)
    world.provider.publish_key(RSA_2, "k2")
    world.provider.sign_with("k2")
    world.provider.retire_key("k1")
    assert cache.verify(_id_token(world, "bob"), ISSUER, world.clock.now())["sub"] == "bob"
    world.clock.advance(30)
    assert world.clock.now() < jws_split(alices)[1]["exp"]
    assert _reason(lambda: cache.verify(alices, ISSUER, world.clock.now())) == _a("unknown_kid")


ROTATION_STEPS = frozenset({
    "publish k2", "sign with k2", "retire k1", "wait one cache lifetime", "wait one token lifetime",
})


def _rotation_failures(order) -> tuple[str, ...]:
    """Runs id.example's rotation steps in order.

    alice signs in at the start and after each step. Then app's cache, which has
    run since the start, and a new server's empty one check every token issued
    so far that is still in date. Each refusal is described.
    """
    world = _world()
    steps = {
        "publish k2": lambda: world.provider.publish_key(RSA_2, "k2"),
        "sign with k2": lambda: world.provider.sign_with("k2"),
        "retire k1": lambda: world.provider.retire_key("k1"),
        "wait one cache lifetime": lambda: world.clock.advance(CACHE_LIFETIME),
        "wait one token lifetime": lambda: world.clock.advance(TOKEN_LIFETIME),
    }
    app, tokens, failures = world.cache(), (), ()
    for step in ("start", *order):
        if step != "start":
            steps[step]()
        tokens = (*tokens, _id_token(world))
        now = world.clock.now()
        live = [token for token in tokens if now < jws_split(token)[1]["exp"]]
        for name, cache in (("app", app), ("new server", world.cache())):
            refused = [token for token in live if _reason(lambda: cache.verify(token, ISSUER, now))]
            failures = (*failures, *(
                f"after {step}: {name} refused {jws_split(token)[0]['kid']}" for token in refused
            ))
    return failures


def test_rotation_runs_in_this_order():
    """Put ROTATION_STEPS in the order id.example should follow, so that no in-date token is ever refused, by app or by a server that starts mid-way. Then: what goes wrong first if id.example signs with k2 the moment it publishes it?"""
    order = _a((
        "publish k2", "wait one cache lifetime", "sign with k2", "wait one token lifetime",
        "retire k1",
    ))
    assert set(order) == ROTATION_STEPS
    assert _rotation_failures(order) == ()
    hasty = ("publish k2", "sign with k2", "wait one token lifetime", "retire k1")
    assert _rotation_failures(hasty)[0] == _a("after sign with k2: app refused k2")
