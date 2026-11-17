"""RS256 and ES256: public-key signatures.

RS256 and ES256 split the key in two. The provider signs with a private
key, and anyone can verify with the public key it publishes. RS256 is
RSASSA-PKCS1-v1_5 with SHA-256 (RFC 7518 §3.3), which needs "A key of size
2048 bits or larger". It gives the same signature for the same input. OIDC
Core §3.1.3.7 says an ID token's alg "SHOULD be the default of RS256",
unless the client registered another one.

ES256 is ECDSA on P-256 with SHA-256 (RFC 7518 §3.4). Each signature
usually uses a fresh random number, so two signatures of one input differ
and both verify. Check one by verifying it, never by comparing bytes. In a JWS the
signature is R then S, each "32 octets long", 64 octets in all. The
cryptography package reads and writes ECDSA signatures as DER, so convert.

In algorithm confusion (RFC 8725 §2.1), an attacker turns "RS256" into
"HS256", and a verifier uses "the RSA public key as the HMAC shared
secret". That key is public, so the attacker can compute the MAC too. RFC
8725 §3.1 says "each key MUST be used with exactly one algorithm". Pin each
algorithm to one key type, and check the key you found against the alg.

A common mistake: handing "the key" to whatever the token's alg names,
without asking what kind of key it is.

Read more:
  https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4
  https://www.rfc-editor.org/rfc/rfc8725.html#section-2.1
  https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1
  https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
"""

import hashlib
import hmac

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from conftest import __
from toy.clock import Clock
from toy.errors import InvalidToken
from toy.http import FakeNetwork, Request
from toy.jose import (
    b64url_encode,
    jws_encode,
    jws_split,
    jws_verify,
    jwks_of,
    key_from_jwk,
    public_jwk,
)
from toy.keys import EC_1, HMAC_SECRET, RSA_1
from toy.provider import Provider

ISSUER = "https://id.example"
CLAIMS = {"iss": ISSUER, "sub": "alice", "aud": "app"}
RSA_JWK = public_jwk(RSA_1, "k1")
EC_JWK = public_jwk(EC_1, "e1")
RSA_JWK_WITHOUT_ALG = {name: value for name, value in RSA_JWK.items() if name != "alg"}
CLIENT_SECRET_JWK = {"kty": "oct", "kid": "s1", "k": b64url_encode(HMAC_SECRET)}
VERIFIER_KEYS = jwks_of(RSA_JWK, EC_JWK, CLIENT_SECRET_JWK)
ALL_ALGS = frozenset({"HS256", "RS256", "ES256"})
KTY_FOR_ALG = {"HS256": "oct", "RS256": "RSA", "ES256": "EC"}


def test_rs256_signatures_are_as_long_as_the_key():
    """RSA_1 is the provider's RSA key. An RS256 signature is one number modulo n, written in as many bytes as n takes."""
    token = jws_encode({"alg": "RS256", "kid": "k1"}, CLAIMS, RSA_1)
    signature = jws_split(token)[3]
    assert RSA_1.key_size == 2048
    assert len(signature) == 256
    assert jws_verify(token, VERIFIER_KEYS, ALL_ALGS)["sub"] == "alice"


def test_rs256_signs_the_same_input_the_same_way():
    """RSASSA-PKCS1-v1_5 has no randomness, so signing one input twice gives one signature."""
    header = {"alg": "RS256", "kid": "k1"}
    first, second = jws_encode(header, CLAIMS, RSA_1), jws_encode(header, CLAIMS, RSA_1)
    assert (first == second) is True


def test_an_es256_signature_is_r_then_s():
    """RFC 7518 §3.4: R and S are each 32 octets, big-endian, R first. Split the signature and rebuild the pair the cryptography package verifies."""
    token = jws_encode({"alg": "ES256", "kid": "e1"}, CLAIMS, EC_1)
    _, _, signing_input, signature = jws_split(token)
    half = 32
    r = int.from_bytes(signature[:half], "big")
    s = int.from_bytes(signature[half:], "big")
    assert len(signature) == 64
    assert jws_verify(token, VERIFIER_KEYS, ALL_ALGS)["sub"] == "alice"
    der = encode_dss_signature(r, s)
    key_from_jwk(EC_JWK).verify(der, signing_input, ec.ECDSA(hashes.SHA256()))


def test_a_der_signature_is_not_a_jws_signature():
    """The cryptography package signs ECDSA in DER. Put that in a token and a JWS verifier refuses it. Turn it into R then S first."""
    token = jws_encode({"alg": "ES256", "kid": "e1"}, CLAIMS, EC_1)
    signing_input = token.rsplit(".", 1)[0]
    der = EC_1.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    with pytest.raises(InvalidToken) as refused:
        jws_verify(f"{signing_input}.{b64url_encode(der)}", VERIFIER_KEYS, ALL_ALGS)
    assert refused.value.reason == "bad_signature"
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    assert jws_verify(f"{signing_input}.{b64url_encode(raw)}", VERIFIER_KEYS, ALL_ALGS)["sub"] == "alice"


def test_oidc_defaults_to_rs256():
    """OIDC Core §3.1.3.7: the ID token's alg SHOULD be the default, unless the client registered another. The toy provider signs with RSA_1 and says so in its discovery document."""
    network = FakeNetwork()
    Provider(ISSUER, clock=Clock(), network=network)
    config = network.send(Request("GET", f"{ISSUER}/.well-known/openid-configuration")).body
    assert config["id_token_signing_alg_values_supported"] == ["RS256"]


def test_the_public_key_is_public():
    """RSA_JWK is the provider's public key, published at its jwks_uri. Anyone can fetch it and write it out as PEM. An attacker has these bytes too."""
    pem = key_from_jwk(RSA_JWK).public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")


def check_key_type(alg: str, jwk: dict) -> None:
    if alg not in KTY_FOR_ALG or jwk.get("kty") != KTY_FOR_ALG[alg] or jwk.get("alg", alg) != alg:
        raise InvalidToken("alg_not_allowed", f"key {jwk.get('kid')!r} is not for {alg!r}")


def test_accepts_each_algorithm_with_its_own_key_type():
    """Implement check_key_type above. Raise InvalidToken("alg_not_allowed") unless all three hold: 1. alg is a key of KTY_FOR_ALG. 2. jwk.get("kty") is KTY_FOR_ALG[alg]. 3. jwk.get("alg"), if the key names one, equals alg. Otherwise return None."""
    tokens = [
        jws_encode({"alg": "RS256", "kid": "k1"}, CLAIMS, RSA_1),
        jws_encode({"alg": "ES256", "kid": "e1"}, CLAIMS, EC_1),
        jws_encode({"alg": "HS256", "kid": "s1"}, CLAIMS, HMAC_SECRET),
    ]
    for token, jwk in zip(tokens, [RSA_JWK, EC_JWK, CLIENT_SECRET_JWK]):
        alg = jws_split(token)[0]["alg"]
        assert check_key_type(alg, jwk) is None
        assert jws_verify(token, VERIFIER_KEYS, ALL_ALGS)["sub"] == "alice"
    assert KTY_FOR_ALG["HS256"] == "oct"
    assert ("alg" in CLIENT_SECRET_JWK) is False


def test_refuses_an_rsa_public_key_as_an_hmac_secret():
    """RFC 8725 §2.1: the attacker MACs a token with the provider's public key as the secret, and sets alg to HS256. A verifier that feeds "the key for k1" to HMAC finds the MAC correct. A JWK need not name its alg, so the key type must stop this on its own."""
    pem = key_from_jwk(RSA_JWK).public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    attack = jws_encode({"alg": "HS256", "kid": "k1"}, {**CLAIMS, "sub": "admin"}, pem)
    header, claims, signing_input, signature = jws_split(attack)
    assert hmac.compare_digest(hmac.new(pem, signing_input, hashlib.sha256).digest(), signature)
    assert claims["sub"] == "admin"
    with pytest.raises(InvalidToken) as refused:
        check_key_type(header["alg"], RSA_JWK_WITHOUT_ALG)
    assert refused.value.reason == "alg_not_allowed"
    with pytest.raises(InvalidToken) as toy_refused:
        jws_verify(attack, VERIFIER_KEYS, ALL_ALGS)
    assert toy_refused.value.reason == "alg_not_allowed"


def test_refuses_a_key_of_another_type_or_algorithm():
    """Algorithm confusion has more than one shape. Each key is for one key type and, if it names one, one alg. An alg the table does not know has no key type at all."""
    cases = [
        ("RS256", EC_JWK),
        ("ES256", RSA_JWK_WITHOUT_ALG),
        ("HS256", EC_JWK),
        ("ES256", {**EC_JWK, "alg": "ES384"}),
        ("HS256", {**CLIENT_SECRET_JWK, "alg": "HS512"}),
        ("HS512", {**CLIENT_SECRET_JWK, "alg": "HS512"}),
        ("none", {"kid": "k1"}),
    ]
    for alg, jwk in cases:
        with pytest.raises(InvalidToken) as refused:
            check_key_type(alg, jwk)
        assert refused.value.reason == "alg_not_allowed"
