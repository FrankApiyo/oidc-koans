import json

import pytest
from cryptography.hazmat.primitives import serialization

from toy.errors import REASONS, InvalidToken
from toy.jose import (
    b64url_decode,
    b64url_encode,
    constant_time_equal,
    json_segment,
    jws_encode,
    jws_split,
    jws_verify,
    jwks_of,
    key_from_jwk,
    public_jwk,
    sign_input,
)
from toy.keys import ATTACKER_RSA, EC_1, HMAC_SECRET, RSA_1, RSA_2

ALL_ALGS = frozenset({"HS256", "RS256", "ES256"})
CLAIMS = {"iss": "https://id.example", "sub": "alice", "aud": "app"}

# RFC 7515 Appendix A.1, copied from the RFC text. The header and payload
# segments encode JSON with CRLFs and spaces, so they cannot be rebuilt with
# json_segment.
RFC_A1_HEADER = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
RFC_A1_PAYLOAD = (
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
)
RFC_A1_JWK = {
    "kty": "oct",
    "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
}
RFC_A1_SIGNATURE = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"


def reason_of(call):
    with pytest.raises(InvalidToken) as caught:
        call()
    return caught.value.reason


def provider_jwks():
    return jwks_of(public_jwk(RSA_1, "k1"), public_jwk(RSA_2, "k2"), public_jwk(EC_1, "e1"))


def forged(header, payload, signature=b""):
    return f"{json_segment(header)}.{json_segment(payload)}.{b64url_encode(signature)}"


def test_b64url_round_trips_without_padding():
    assert b64url_encode(b"\xfb\xff") == "-_8"
    assert b64url_decode("-_8") == b"\xfb\xff"


@pytest.mark.parametrize("text", ["-_8=", "+_8", "-/8", "-_ 8"])
def test_b64url_decode_rejects_padding_and_std_alphabet(text):
    assert b64url_decode("-_8") == b"\xfb\xff"
    assert reason_of(lambda: b64url_decode(text)) == "malformed"


def test_json_segment_keeps_utf8():
    segment = json_segment({"name": "Zoë"})
    raw = b64url_decode(segment)
    assert raw == '{"name":"Zoë"}'.encode()
    assert json.loads(raw) == {"name": "Zoë"}


def test_hs256_matches_rfc7515_appendix_a1():
    signing_input = f"{RFC_A1_HEADER}.{RFC_A1_PAYLOAD}".encode()
    key = key_from_jwk(RFC_A1_JWK)
    assert sign_input("HS256", key, signing_input) == b64url_decode(RFC_A1_SIGNATURE)
    header, payload, _, _ = jws_split(f"{RFC_A1_HEADER}.{RFC_A1_PAYLOAD}.{RFC_A1_SIGNATURE}")
    assert header == {"typ": "JWT", "alg": "HS256"}
    assert payload["http://example.com/is_root"] is True


def test_hs256_verifies_against_an_oct_jwk():
    token = jws_encode({"alg": "HS256", "kid": "s1"}, CLAIMS, HMAC_SECRET)
    jwks = jwks_of(public_jwk(HMAC_SECRET, "s1"))
    assert jws_verify(token, jwks, ALL_ALGS) == CLAIMS
    assert reason_of(lambda: jws_verify(token[:-2] + "AA", jwks, ALL_ALGS)) == "bad_signature"


def test_rs256_is_deterministic_and_verifies():
    header = {"alg": "RS256", "kid": "k1"}
    token = jws_encode(header, CLAIMS, RSA_1)
    assert token == jws_encode(header, CLAIMS, RSA_1)
    assert jws_verify(token, provider_jwks(), ALL_ALGS) == CLAIMS


def test_rs256_signed_by_another_key_is_bad_signature():
    token = jws_encode({"alg": "RS256", "kid": "k1"}, CLAIMS, RSA_2)
    assert reason_of(lambda: jws_verify(token, provider_jwks(), ALL_ALGS)) == "bad_signature"


def test_es256_verifies_but_bytes_differ():
    header = {"alg": "ES256", "kid": "e1"}
    first = jws_encode(header, CLAIMS, EC_1)
    second = jws_encode(header, CLAIMS, EC_1)
    assert first != second
    assert len(jws_split(first)[3]) == 64
    assert jws_verify(first, provider_jwks(), ALL_ALGS) == CLAIMS
    assert jws_verify(second, provider_jwks(), ALL_ALGS) == CLAIMS


def test_es256_refuses_wrong_length_signature():
    token = jws_encode({"alg": "ES256", "kid": "e1"}, CLAIMS, EC_1)
    signing_input, segment = token.rsplit(".", 1)
    signature = b64url_decode(segment)
    padded = signature[:32] + b"\x00" + signature[32:]
    assert len(signature) == 64
    assert jws_verify(token, provider_jwks(), ALL_ALGS) == CLAIMS
    for wrong in (padded, signature[:63]):
        tampered = f"{signing_input}.{b64url_encode(wrong)}"
        reason = reason_of(lambda: jws_verify(tampered, provider_jwks(), ALL_ALGS))
        assert reason == "bad_signature", len(wrong)


def test_verify_refuses_alg_none():
    token = jws_encode({"alg": "none", "kid": "k1"}, CLAIMS, None)
    assert token.endswith(".")
    everything = ALL_ALGS | {"none"}
    assert reason_of(lambda: jws_verify(token, provider_jwks(), everything)) == "alg_not_allowed"
    honest = jws_encode({"alg": "RS256", "kid": "k1"}, CLAIMS, RSA_1)
    assert jws_verify(honest, provider_jwks(), ALL_ALGS) == CLAIMS


def test_verify_refuses_an_alg_outside_the_allowed_set():
    token = jws_encode({"alg": "RS256", "kid": "k1"}, CLAIMS, RSA_1)
    only_es = frozenset({"ES256"})
    assert reason_of(lambda: jws_verify(token, provider_jwks(), only_es)) == "alg_not_allowed"


def test_verify_refuses_hs256_with_rsa_public_key_as_secret():
    public_pem = RSA_1.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    attack = jws_encode({"alg": "HS256", "kid": "k1"}, CLAIMS, public_pem)
    assert reason_of(lambda: jws_verify(attack, provider_jwks(), ALL_ALGS)) == "alg_not_allowed"
    honest = jws_encode({"alg": "RS256", "kid": "k1"}, CLAIMS, RSA_1)
    assert jws_verify(honest, provider_jwks(), ALL_ALGS) == CLAIMS


def test_verify_ignores_header_jwk():
    carried = public_jwk(ATTACKER_RSA, "k1")
    attack = jws_encode({"alg": "RS256", "kid": "k1", "jwk": carried}, CLAIMS, ATTACKER_RSA)
    assert reason_of(lambda: jws_verify(attack, provider_jwks(), ALL_ALGS)) == "bad_signature"
    honest = jws_encode({"alg": "RS256", "kid": "k1", "jwk": carried}, CLAIMS, RSA_1)
    assert jws_verify(honest, provider_jwks(), ALL_ALGS) == CLAIMS


def test_unknown_kid_is_unknown_kid():
    token = jws_encode({"alg": "RS256", "kid": "attacker"}, CLAIMS, ATTACKER_RSA)
    assert reason_of(lambda: jws_verify(token, provider_jwks(), ALL_ALGS)) == "unknown_kid"
    no_kid = jws_encode({"alg": "RS256"}, CLAIMS, RSA_1)
    assert reason_of(lambda: jws_verify(no_kid, provider_jwks(), ALL_ALGS)) == "unknown_kid"


def test_verify_refuses_a_jwk_pinned_to_another_alg():
    pinned = {**public_jwk(EC_1, "e1"), "alg": "ES384"}
    token = jws_encode({"alg": "ES256", "kid": "e1"}, CLAIMS, EC_1)
    jwks = jwks_of(pinned)
    assert jws_verify(token, provider_jwks(), ALL_ALGS) == CLAIMS
    assert reason_of(lambda: jws_verify(token, jwks, ALL_ALGS)) == "alg_not_allowed"


def test_verify_skips_a_jwk_whose_use_is_not_sig():
    token = jws_encode({"alg": "RS256", "kid": "k2"}, CLAIMS, RSA_2)
    signing = public_jwk(RSA_2, "k2")
    unmarked = {name: value for name, value in signing.items() if name != "use"}
    assert jws_verify(token, jwks_of(signing), ALL_ALGS) == CLAIMS
    assert jws_verify(token, jwks_of(unmarked), ALL_ALGS) == CLAIMS
    for use in ("enc", "SIG", None):
        jwks = jwks_of({**signing, "use": use})
        assert reason_of(lambda: jws_verify(token, jwks, ALL_ALGS)) == "unknown_kid", use
    encryption_first = jwks_of({**public_jwk(RSA_1, "k2"), "use": "enc"}, signing)
    assert jws_verify(token, encryption_first, ALL_ALGS) == CLAIMS


@pytest.mark.parametrize(
    "token",
    [
        "only.two",
        "a.b.c.d",
        f"{b64url_encode(b'not json')}.{json_segment(CLAIMS)}.",
        f"{json_segment({'alg': 'RS256'})}.{b64url_encode(b'[1]')}.",
        f"{b64url_encode(b'\xff')}.{json_segment(CLAIMS)}.",
    ],
)
def test_split_refuses_malformed_tokens(token):
    assert reason_of(lambda: jws_split(token)) == "malformed"


def test_split_returns_signing_input_and_signature():
    token = jws_encode({"alg": "HS256", "kid": "s1"}, CLAIMS, HMAC_SECRET)
    header, payload, signing_input, signature = jws_split(token)
    assert header == {"alg": "HS256", "kid": "s1"}
    assert payload == CLAIMS
    assert signing_input == token.rsplit(".", 1)[0].encode()
    assert signature == sign_input("HS256", HMAC_SECRET, signing_input)


def test_public_jwk_of_a_private_key_has_only_public_members():
    for key, kty in ((RSA_1, "RSA"), (EC_1, "EC")):
        jwk = public_jwk(key, "k")
        assert jwk["kty"] == kty
        assert not {"d", "p", "q", "dp", "dq", "qi"} & set(jwk)
    assert public_jwk(RSA_1, "k")["e"] == "AQAB"
    assert len(b64url_decode(public_jwk(EC_1, "k")["x"])) == 32


def test_key_from_jwk_round_trips_public_keys():
    for key in (RSA_1, EC_1):
        restored = key_from_jwk(public_jwk(key, "k"))
        assert restored.public_numbers() == key.public_key().public_numbers()
    assert key_from_jwk(public_jwk(HMAC_SECRET, "s")) == HMAC_SECRET


def test_published_and_attacker_keys_are_distinct():
    numbers = {k.public_key().public_numbers().n for k in (RSA_1, RSA_2, ATTACKER_RSA)}
    assert len(numbers) == 3
    assert len(HMAC_SECRET) >= 32


def test_constant_time_equal():
    assert constant_time_equal(b"abc", b"abc")
    assert not constant_time_equal(b"abc", b"abd")


def test_invalid_token_reasons_are_a_closed_set():
    assert InvalidToken("expired").reason == "expired"
    assert len(REASONS) == 16
    with pytest.raises(ValueError):
        InvalidToken("expird")
