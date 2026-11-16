"""HS256: MACs and shared secrets.

HS256 is HMAC with SHA-256 (RFC 7518 §3.2). The signer runs HMAC over the
JWS Signing Input with a secret key, and the 32-byte result, in base64url,
is the third segment. The verifier holds the same secret, computes the MAC
again and compares. A MAC can show "that whoever generated the MAC was in
possession of the MAC key". Both sides hold that key, so either side could
have made the token. A MAC is not a signature, and it cannot say who wrote it.

In OIDC the HS256 key is the client's own secret. OIDC Core §10.1 says "The
MAC key used is the octets of the UTF-8 representation of the client_secret
value." Symmetric signatures "MUST NOT be used by public (non-confidential)
Clients", which cannot keep a secret. RFC 7518 §3.2 wants a key "of the
same size as the hash output" or larger, and Core §16.19 says an HS256
client_secret "MUST contain at least 32 octets".

Compare the MAC in constant time. Python's == on bytes can return as soon
as it finds a difference, so its timing hints at how much of a guess was
right. An attacker who times many guesses can then build a valid MAC one
byte at a time. Python documents hmac.compare_digest as "designed to
prevent timing analysis". OIDC Core §16.12 asks verifiers to "continue
running until all the octets have been processed".

A common mistake: checking the MAC with ==, or keying it with a short,
guessable secret.

Read more:
  https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2
  https://openid.net/specs/openid-connect-core-1_0.html#Signing
  https://openid.net/specs/openid-connect-core-1_0.html#SymmetricKeyEntropy
"""

import hashlib
import hmac
from unittest import mock

import pytest

from conftest import __
from toy.errors import InvalidToken
from toy.jose import (
    b64url_decode,
    b64url_encode,
    json_segment,
    jws_encode,
    jws_split,
    jws_verify,
    jwks_of,
    public_jwk,
)
from toy.keys import HMAC_SECRET

A1_TOKEN = (
    "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
    ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)
A1_KEY = b64url_decode(
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
)
APP_SECRET = "app-secret-Zoë-7Qx2vN9pL4mR8sT1wY6kB3"
QUIZ_SECRET = "quiz-secret-H5jD0fG7cV2bN8mK4xZ9qW1eR6"
CLAIMS = {"iss": "https://id.example", "sub": "alice", "aud": "app"}


def _signed(claims: dict, key: bytes) -> str:
    return jws_encode({"alg": "HS256", "kid": "s1"}, claims, key)


def bytes_looked_at(guess: bytes, mac: bytes) -> int:
    """How many bytes a compare that stops at the first difference reads."""
    for count, (left, right) in enumerate(zip(guess, mac), 1):
        if left != right:
            return count
    return len(mac)


def test_hs256_is_hmac_with_sha256():
    """RFC 7515 A.1 is an HS256 token. HMAC its signing input with SHA-256 and the A.1 key, and you get its third segment. That is 32 bytes, written in base64url without padding."""
    header_segment, payload_segment, signature_segment = A1_TOKEN.split(".")
    mac = hmac.new(A1_KEY, f"{header_segment}.{payload_segment}".encode("ascii"), hashlib.sha256)
    assert b64url_encode(mac.digest()) == signature_segment
    assert len(mac.digest()) == _a(32)
    assert len(signature_segment) == _a(43)


def test_an_early_exit_compare_tells_how_much_was_right():
    """A compare that stops at the first difference reads one byte of a guess wrong at the start, and every byte of a guess wrong only at the end. The time it takes tells an attacker how many leading bytes they have right."""
    mac = hmac.new(HMAC_SECRET, b"header.payload", hashlib.sha256).digest()
    wrong_first = bytes([mac[0] ^ 1]) + mac[1:]
    wrong_last = mac[:-1] + bytes([mac[-1] ^ 1])
    assert bytes_looked_at(wrong_first, mac) == _a(1)
    assert bytes_looked_at(wrong_last, mac) == _a(32)


def test_the_client_secret_is_the_key():
    """OIDC Core §10.1: the HS256 key is "the octets of the UTF-8 representation of the client_secret value". The secret is text; turn it into the key the provider used."""
    token = _signed(CLAIMS, APP_SECRET.encode("utf-8"))
    key = _a(APP_SECRET.encode("utf-8"))
    assert jws_verify(token, jwks_of(public_jwk(key, "s1")), frozenset({"HS256"}))["sub"] == "alice"


def test_an_hs256_secret_has_at_least_32_octets():
    """RFC 7518 §3.2: the key is at least the size of the hash output, 256 bits for HS256. Core §16.19 counts it in octets. A short password does not make it."""
    minimum_octets = _a(32)
    assert minimum_octets * 8 == 256
    assert len(APP_SECRET.encode("utf-8")) >= minimum_octets
    assert (len("hunter2".encode("utf-8")) >= minimum_octets) is _a(False)


def hs256_verify(token: str, secret: bytes) -> dict:
    # >>> answer
    _, payload, signing_input, signature = jws_split(token)
    expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, signature):
        raise InvalidToken("bad_signature")
    return payload
    # <<<


def test_accepts_a_mac_made_with_the_shared_secret():
    """Implement hs256_verify above. 1. jws_split the token. 2. HMAC its signing input with secret and hashlib.sha256. 3. Unless hmac.compare_digest finds that MAC equal to the signature, raise InvalidToken("bad_signature"). 4. Return the payload. Chapter 03's alg check comes before this; here you check only the MAC."""
    assert hs256_verify(A1_TOKEN, A1_KEY)["iss"] == _a("joe")
    assert hs256_verify(_signed(CLAIMS, HMAC_SECRET), HMAC_SECRET)["sub"] == "alice"


def test_refuses_a_token_changed_after_it_was_signed():
    """The attacker keeps the MAC and edits the payload, cuts the MAC short, adds bytes after it, or drops it. None of these is the MAC of what arrived."""
    header_segment, _, signature_segment = _signed(CLAIMS, HMAC_SECRET).split(".")
    admin = json_segment({**CLAIMS, "sub": "admin"})
    payload_segment = json_segment(CLAIMS)
    signature = b64url_decode(signature_segment)
    for forged in [
        f"{header_segment}.{admin}.{signature_segment}",
        f"{header_segment}.{payload_segment}.{signature_segment[:22]}",
        f"{header_segment}.{payload_segment}.{b64url_encode(signature + b'extra')}",
        f"{header_segment}.{payload_segment}.",
    ]:
        with pytest.raises(InvalidToken) as refused:
            hs256_verify(forged, HMAC_SECRET)
        assert refused.value.reason == _a("bad_signature")


def test_compares_the_mac_with_compare_digest():
    """The koan cannot time your compare, so it swaps hmac.compare_digest for a spy that counts the calls. Call hmac.compare_digest once, by that name, and never ==."""
    token = _signed(CLAIMS, HMAC_SECRET)
    with mock.patch.object(hmac, "compare_digest", wraps=hmac.compare_digest) as spy:
        assert hs256_verify(token, HMAC_SECRET)["sub"] == "alice"
    assert spy.call_count == _a(1)


def test_anyone_with_the_secret_can_mint_a_token():
    """The client holds the secret too, so it can make a token that says the provider issued it, and the MAC checks out. A MAC proves the key, not the author."""
    key = APP_SECRET.encode("utf-8")
    minted_by_the_client = _signed({**CLAIMS, "sub": "admin"}, key)
    claims = hs256_verify(minted_by_the_client, key)
    assert claims["iss"] == _a("https://id.example")
    assert claims["sub"] == _a("admin")


def test_each_client_checks_with_its_own_secret():
    """Two clients of one provider have two secrets. A token MACed for quiz does not verify with app's secret."""
    for_quiz = _signed({**CLAIMS, "aud": "quiz"}, QUIZ_SECRET.encode("utf-8"))
    assert hs256_verify(for_quiz, QUIZ_SECRET.encode("utf-8"))["aud"] == "quiz"
    with pytest.raises(InvalidToken) as refused:
        hs256_verify(for_quiz, APP_SECRET.encode("utf-8"))
    assert refused.value.reason == _a("bad_signature")
