"""JWS compact serialization and JWT claims.

A JWS in compact form (RFC 7515 §7.1) is three base64url segments joined
by dots: a JOSE header, a payload and a signature. The header is JSON that
says how the token was signed: alg names the algorithm, typ the kind of
token, and kid hints at the key. The signature covers the JWS Signing Input,
ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS
Payload)). That is the encoded text as sent, never a re-serialized object.

A JWT (RFC 7519) is a JWS whose payload is a JSON claims set. The
registered claims have short names: iss, sub, aud, exp, nbf, iat and jti.
aud is "an array of case-sensitive strings", or a single string when the
JWT has one audience, so code that reads it must handle both.

A JWS is signed, not encrypted, so anyone can decode it. Decoding is not
verifying. To verify, the verifier picks the algorithms it accepts and
checks the signature with a key it already trusts. RFC 8725 §3.1 says libraries
"MUST enable the caller to specify a supported set of algorithms". An
Unsecured JWS has alg "none" and an empty signature. OIDC Core §2 says ID
Tokens "MUST NOT use none", unless the client asked for it at registration
and no ID token comes from the authorization endpoint.

A common mistake: letting the token's own alg decide how it is checked, so
a token that says "none" is checked by nothing.

Read more:
  https://www.rfc-editor.org/rfc/rfc7515.html#section-7.1
  https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1
  https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1
"""

import hashlib
import hmac
import json

import pytest

from conftest import __
from toy.clock import Clock
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
NOW = Clock().now()
CLAIMS = {
    "iss": "https://id.example",
    "sub": "alice",
    "aud": "app",
    "exp": NOW + 300,
    "nbf": NOW + 60,
    "iat": NOW,
    "jti": "token-1",
}
JWKS = jwks_of(public_jwk(HMAC_SECRET, "k1"))


def _signed(claims: dict) -> str:
    return jws_encode({"alg": "HS256", "kid": "k1"}, claims, HMAC_SECRET)


def test_the_header_says_how_it_was_signed():
    """RFC 7515 §7.1: base64url segments joined by dots, header first. RFC 7515 Appendix A.1's header says the token is a JWT, MACed with HMAC SHA-256."""
    parts = A1_TOKEN.split(".")
    header = json.loads(b64url_decode(parts[0]))
    assert len(parts) == __
    assert header["alg"] == __
    assert header["typ"] == __


def test_the_signature_covers_the_encoded_segments():
    """RFC 7515 §5.1: the signing input is the header segment, a dot, and the payload segment, in ASCII. Build it from the segments as sent."""
    header_segment, payload_segment, signature_segment = A1_TOKEN.split(".")
    signing_input = __.encode("ascii")
    mac = hmac.new(A1_KEY, signing_input, hashlib.sha256).digest()
    assert b64url_encode(mac) == signature_segment


def test_the_payload_was_signed_as_bytes_not_as_an_object():
    """The A.1 payload has CRLF line breaks inside its JSON. Parse it and write it out compactly: the same claims, other bytes, and the MAC no longer matches."""
    header_segment, payload_segment, signature_segment = A1_TOKEN.split(".")
    payload = b64url_decode(payload_segment)
    rewritten = json_segment(json.loads(payload))
    mac = hmac.new(A1_KEY, f"{header_segment}.{rewritten}".encode("ascii"), hashlib.sha256)
    assert b"\r\n" in payload
    assert json.loads(b64url_decode(rewritten)) == json.loads(payload)
    assert b64url_decode(rewritten) == __
    assert (b64url_encode(mac.digest()) == signature_segment) is __


def test_registered_claims_have_short_names():
    """RFC 7519 §4.1 registers seven claim names, each three letters long. Name the claim that holds each value."""
    claims = jws_split(_signed(CLAIMS))[1]
    issuer, subject, audience = __, __, __
    expires, not_before, issued_at, token_id = __, __, __, __
    assert claims.get(issuer) == "https://id.example"
    assert claims.get(subject) == "alice"
    assert claims.get(audience) == "app"
    assert claims.get(expires) == NOW + 300
    assert claims.get(not_before) == NOW + 60
    assert claims.get(issued_at) == NOW
    assert claims.get(token_id) == "token-1"


def test_aud_is_a_string_or_an_array():
    """RFC 7519 §4.1.3: aud is an array of strings, or one string. On a string, "in" finds substrings: "app" is in "webapp". Put a lone string in a list first."""
    one = jws_split(_signed({**CLAIMS, "aud": "webapp"}))[1]["aud"]
    many = jws_split(_signed({**CLAIMS, "aud": ["webapp", "api"]}))[1]["aud"]
    audiences = [one] if isinstance(one, str) else one
    assert ("app" in one) is __
    assert ("app" in many) is __
    assert ("app" in audiences) is __


def test_decoding_is_not_verifying():
    """A JWS is signed, not encrypted: anyone can decode one, and anyone can edit one. Swap in a payload that says sub is admin, keep the old signature."""
    header_segment, _, signature_segment = _signed(CLAIMS).split(".")
    forged = f"{header_segment}.{json_segment({**CLAIMS, 'sub': 'admin'})}.{signature_segment}"
    assert jws_split(forged)[1]["sub"] == __
    with pytest.raises(InvalidToken) as refused:
        jws_verify(forged, JWKS, frozenset({"HS256"}))
    assert refused.value.reason == __


def test_kid_lives_in_the_header():
    """kid is a header parameter, the signer's hint about which key to use. It is not a claim."""
    header, claims, _, _ = jws_split(_signed(CLAIMS))
    assert header.get("kid") == __
    assert claims.get("kid") == __


def check_alg(header: dict, allowed_algs: frozenset[str]) -> str:
    __()


def test_accepts_an_algorithm_the_verifier_chose():
    """Implement check_alg above. 1. Read alg from the header. 2. Unless it is a str in allowed_algs, raise InvalidToken("alg_not_allowed"). 3. Return alg."""
    token = _signed(CLAIMS)
    assert check_alg(jws_split(token)[0], frozenset({"HS256"})) == __
    assert jws_verify(token, JWKS, frozenset({"HS256"}))["sub"] == "alice"


def test_refuses_alg_none():
    """RFC 8725 §2.1: an attacker sets alg to "none" and drops the signature. The forged token decodes, and only the verifier's own list of algorithms stops it."""
    payload_segment = json_segment({**CLAIMS, "sub": "admin"})
    for header in [{"alg": "none"}, {"alg": "None"}, {"alg": "NONE"}, {"alg": "nOnE"}, {}]:
        forged = f"{json_segment(header)}.{payload_segment}."
        decoded, claims, _, signature = jws_split(forged)
        assert claims["sub"] == "admin" and signature == b""
        with pytest.raises(InvalidToken) as refused:
            check_alg(decoded, frozenset({"HS256"}))
        assert refused.value.reason == __


def test_refuses_an_alg_the_verifier_did_not_choose():
    """RFC 7515 §4.1.1: alg is case-sensitive. A check that refuses only "none" is a deny-list. An allow-list also refuses every algorithm, and every spelling, that nobody chose."""
    for alg in ["HS512", "hs256", "HS256 "]:
        with pytest.raises(InvalidToken) as refused:
            check_alg({"alg": alg}, frozenset({"HS256"}))
        assert refused.value.reason == __
