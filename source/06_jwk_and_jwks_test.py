"""JWK, JWKS and kid.

A JWK (RFC 7517 §4) is a key written as a JSON object. kty names its type:
"RSA", "EC" or "oct". RSA keys have n and e, and EC keys have crv, x and y,
each an integer in base64url, big-endian. use says whether a key is for
"sig" or "enc". A JWK Set (§5) is {"keys": [...]}. A provider publishes its
set at the jwks_uri in its discovery document, and OIDC Discovery says that
set "MUST NOT contain private or symmetric key values".

A JWS header's kid names the key that signed it. RFC 7517 §4.5 says its
structure "is unspecified" and that it is "a case-sensitive string". Compare
it exactly with the keys you already hold, and never use it as a file path,
a query or a URL. Two issuers can both have a key called "k1", so look a
kid up only in the set of the issuer you expect.

A header can also carry a key (jwk, x5c) or point at one (jku, x5u), and
whoever wrote the token wrote the header. OIDC Core §2 says ID Tokens
"SHOULD NOT use" these fields, and RFC 8725 §3.8 says the keys must
"belong to the issuer".

A common mistake: verifying with the key the token brought, or fetching
the URL it named, which also lets anyone make your server send requests.

Read more:
  https://www.rfc-editor.org/rfc/rfc7517.html#section-4.5
  https://openid.net/specs/openid-connect-core-1_0.html#IDToken
  https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
  https://www.rfc-editor.org/rfc/rfc8725.html#section-3.8
"""

from dataclasses import dataclass

import pytest

from conftest import __
from toy.clock import Clock
from toy.errors import InvalidToken
from toy.http import FakeNetwork, Request, Response
from toy.jose import b64url_decode, jws_encode, jws_split, jws_verify, jwks_of, public_jwk
from toy.keys import ATTACKER_RSA, EC_1, HMAC_SECRET, RSA_1, RSA_2
from toy.provider import Provider

ISSUER = "https://id.example"
OTHER_ISSUER = "https://other-id.example"
ATTACKER = "https://attacker.example"
ALGS = frozenset({"RS256", "ES256"})
CLAIMS = {"iss": ISSUER, "sub": "alice", "aud": "app"}
ROLLOVER_KEYS = jwks_of(
    public_jwk(RSA_1, "k1"),
    {name: value for name, value in public_jwk(RSA_2, "k2").items() if name != "use"},
)
ATTACKER_KEYS = jwks_of(public_jwk(ATTACKER_RSA, "m1"))
SECRET_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "k"})


class KeyHost:
    """Serves one JWK Set at every path, and keeps the URLs it was asked for."""

    def __init__(self, jwks: dict):
        self._jwks = jwks
        self.requested: tuple[str, ...] = ()

    def __call__(self, request: Request) -> Response:
        self.requested = (*self.requested, request.url)
        return Response(200, {}, self._jwks)


@dataclass(frozen=True)
class World:
    network: FakeNetwork
    trusted: dict
    attacker: KeyHost


def _world() -> World:
    """Two providers the client trusts, each with its discovery document, and an attacker's key host."""
    clock, network = Clock(), FakeNetwork()
    Provider(ISSUER, clock=clock, network=network)
    Provider(OTHER_ISSUER, clock=clock, network=network, signing_key=EC_1, kid="o1")
    attacker = KeyHost(ATTACKER_KEYS)
    network.mount(ATTACKER, attacker)
    trusted = {
        issuer: network.send(Request("GET", f"{issuer}/.well-known/openid-configuration")).body
        for issuer in (ISSUER, OTHER_ISSUER)
    }
    return World(network, trusted, attacker)


def _fetch(world: World, url: str) -> dict:
    return world.network.send(Request("GET", url)).body


def test_an_rsa_jwk_holds_n_and_e():
    """RFC 7518 §6.3.1: n is the modulus and e the exponent, each as base64url of its big-endian bytes. Most RSA keys share one small, odd e."""
    jwk = public_jwk(RSA_1, "k1")
    numbers = RSA_1.public_key().public_numbers()
    assert int.from_bytes(b64url_decode(jwk["n"]), _a("big")) == numbers.n
    assert jwk["e"] == _a("AQAB")
    assert int.from_bytes(b64url_decode(jwk["e"]), "big") == _a(65537)


def test_an_ec_jwk_names_its_curve():
    """RFC 7518 §6.2.1: an EC key says which curve it is on, and gives the point as x and y, each as long as the curve's field."""
    jwk = public_jwk(EC_1, "e1")
    assert jwk["kty"] == _a("EC")
    assert jwk["crv"] == _a("P-256")
    assert len(b64url_decode(jwk["x"])) == _a(32)


def test_a_published_set_holds_no_secrets():
    """Fetch the provider's JWK Set from its jwks_uri. It holds public members only. An oct JWK's k is the secret itself, so a symmetric key never goes there."""
    world = _world()
    published = _fetch(world, world.trusted[ISSUER]["jwks_uri"])
    assert list(published) == _a(["keys"])
    assert {name for jwk in published["keys"] for name in jwk} & SECRET_MEMBERS == _a(set())
    assert b64url_decode(public_jwk(HMAC_SECRET, "s1")["k"]) == _a(HMAC_SECRET)


def find_key(jwks: dict, header: dict) -> dict:
    # >>> answer
    kid = header.get("kid")
    for jwk in jwks.get("keys", []):
        if kid and jwk.get("kid") == kid and jwk.get("use", "sig") == "sig":
            return jwk
    raise InvalidToken("unknown_kid", f"kid {kid!r}")
    # <<<


def _verified(token: str, jwks: dict) -> dict:
    """The claims, checked with the one key find_key chose from jwks."""
    return jws_verify(token, jwks_of(find_key(jwks, jws_split(token)[0])), ALGS)


def test_accepts_the_key_the_kid_names():
    """Implement find_key above. 1. Read kid from the header. 2. Return the first key in jwks["keys"] whose kid equals it exactly and whose use, if it has one, is "sig". 3. If the header has no kid, or no key matches, raise InvalidToken("unknown_kid"). Read nothing else from the header."""
    old = jws_encode({"alg": "RS256", "kid": "k1"}, CLAIMS, RSA_1)
    new = jws_encode({"alg": "RS256", "kid": "k2"}, CLAIMS, RSA_2)
    assert find_key(ROLLOVER_KEYS, jws_split(new)[0])["kid"] == _a("k2")
    assert _verified(old, ROLLOVER_KEYS)["sub"] == "alice"
    assert _verified(new, ROLLOVER_KEYS)["sub"] == "alice"
    carrying_its_own_key = jws_encode(
        {"alg": "RS256", "kid": "k1", "jwk": public_jwk(RSA_1, "k1")}, CLAIMS, RSA_1
    )
    assert _verified(carrying_its_own_key, ROLLOVER_KEYS)["sub"] == "alice"


def test_refuses_a_kid_that_matches_only_loosely():
    """RFC 7517 §4.5: a kid is "a case-sensitive string" with no structure you may rely on. "K1" is not "k1", and no key is called "../k1". A header with no kid matches nothing, not even a key with no kid, though None == None in Python. Core §10.1 needs a kid only when a set has several keys; this verifier always wants one."""
    without_kid = {name: value for name, value in public_jwk(RSA_1, "k1").items() if name != "kid"}
    keys = jwks_of(*ROLLOVER_KEYS["keys"], without_kid)
    assert find_key(keys, {"alg": "RS256", "kid": "k1"})["kid"] == "k1"
    for header in [{"kid": "K1"}, {"kid": "k1 "}, {"kid": "../k1"}, {}]:
        with pytest.raises(InvalidToken) as refused:
            find_key(keys, {"alg": "RS256", **header})
        assert refused.value.reason == _a("unknown_kid")


def test_refuses_a_key_carried_in_the_header():
    """RFC 8725 §3.8: the key must belong to the issuer. The attacker signs with their own key and puts its JWK in the header, under the provider's kid. That key checks out against itself, and means nothing."""
    carried = public_jwk(ATTACKER_RSA, "k1")
    header = {"alg": "RS256", "kid": "k1", "jwk": carried}
    attack = jws_encode(header, {**CLAIMS, "sub": "admin"}, ATTACKER_RSA)
    assert jws_verify(attack, jwks_of(jws_split(attack)[0]["jwk"]), ALGS)["sub"] == "admin"
    with pytest.raises(InvalidToken) as refused:
        _verified(attack, ROLLOVER_KEYS)
    assert refused.value.reason == _a("bad_signature")


def test_refuses_a_key_published_for_encryption():
    """RFC 7517 §4.2: use "enc" marks a key for encryption. OIDC Core §10.1 says a signing key's usage "MUST support signing". A set may also hold an encryption key and a signing key under one kid. Skip the encryption key and keep looking."""
    token = jws_encode({"alg": "RS256", "kid": "k2"}, CLAIMS, RSA_2)
    for_encryption = {**public_jwk(RSA_2, "k2"), "use": "enc"}
    unmarked = {name: value for name, value in for_encryption.items() if name != "use"}
    assert jws_verify(token, jwks_of(unmarked), ALGS)["sub"] == "alice"
    with pytest.raises(InvalidToken) as refused:
        find_key(jwks_of(public_jwk(RSA_1, "k1"), for_encryption), jws_split(token)[0])
    assert refused.value.reason == _a("unknown_kid")
    shared_kid = jwks_of({**public_jwk(RSA_1, "k2"), "use": "enc"}, public_jwk(RSA_2, "k2"))
    assert _verified(token, shared_kid)["sub"] == _a("alice")


def verify_from(token: str, issuer: str, trusted: dict, network: FakeNetwork) -> dict:
    # >>> answer
    jwks = network.send(Request("GET", trusted[issuer]["jwks_uri"])).body
    return jws_verify(token, jwks, ALGS)
    # <<<


def test_accepts_keys_from_the_expected_issuers_jwks_uri():
    """Implement verify_from above. issuer is the one this login expects, and trusted maps each issuer you trust to its discovery document. 1. GET trusted[issuer]["jwks_uri"] with network.send(Request(...)). 2. Return jws_verify(token, the response body, ALGS). Take no key and no URL from the token."""
    world = _world()
    own_jku = world.trusted[ISSUER]["jwks_uri"]
    from_id = jws_encode({"alg": "RS256", "kid": "k1", "jku": own_jku}, CLAIMS, RSA_1)
    from_other = jws_encode({"alg": "ES256", "kid": "o1"}, {**CLAIMS, "iss": OTHER_ISSUER}, EC_1)
    assert verify_from(from_id, ISSUER, world.trusted, world.network)["iss"] == _a(ISSUER)
    claims = verify_from(from_other, OTHER_ISSUER, world.trusted, world.network)
    assert claims["iss"] == _a(OTHER_ISSUER)


def test_refuses_a_jku_or_x5u_the_token_chose():
    """RFC 8725 §3.10 warns that following jku or x5u can be a server-side request forgery. The attacker hosts their own key set and points the header at it. Your verifier never asks for it."""
    for field in ["jku", "x5u"]:
        world = _world()
        header = {"alg": "RS256", "kid": "m1", field: f"{ATTACKER}/jwks"}
        attack = jws_encode(header, {**CLAIMS, "sub": "admin"}, ATTACKER_RSA)
        assert jws_verify(attack, ATTACKER_KEYS, ALGS)["sub"] == "admin"
        with pytest.raises(InvalidToken) as refused:
            verify_from(attack, ISSUER, world.trusted, world.network)
        assert refused.value.reason == _a("unknown_kid")
        assert world.attacker.requested == _a(())


def test_refuses_another_issuers_key():
    """The client trusts other-id too, and other-id's key is genuine. A token that claims to be from id.example, signed with other-id's key, must not pass a login that expects id.example. Nor may other-id's own token: the login, not the token, names the issuer."""
    world = _world()
    other_keys = _fetch(world, world.trusted[OTHER_ISSUER]["jwks_uri"])
    impersonation = jws_encode({"alg": "ES256", "kid": "o1"}, {**CLAIMS, "sub": "admin"}, EC_1)
    from_other = jws_encode({"alg": "ES256", "kid": "o1"}, {**CLAIMS, "iss": OTHER_ISSUER}, EC_1)
    assert jws_verify(impersonation, other_keys, ALGS)["iss"] == ISSUER
    for token in [impersonation, from_other]:
        with pytest.raises(InvalidToken) as refused:
            verify_from(token, ISSUER, world.trusted, world.network)
        assert refused.value.reason == _a("unknown_kid")
