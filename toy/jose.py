"""Compact JWS (RFC 7515) with HS256, RS256 and ES256, and the JWKs to verify it."""

import base64
import binascii
import hashlib
import hmac
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from toy.errors import InvalidToken

_B64URL = re.compile(r"[A-Za-z0-9_-]*")
_P256_BYTES = 32
_KTY_FOR_ALG = {"HS256": "oct", "RS256": "RSA", "ES256": "EC"}


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    if not isinstance(text, str) or not _B64URL.fullmatch(text) or len(text) % 4 == 1:
        raise InvalidToken("malformed", "not unpadded base64url")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except binascii.Error as error:
        raise InvalidToken("malformed", str(error)) from error


def json_segment(obj: dict) -> str:
    text = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    return b64url_encode(text.encode("utf-8"))


def constant_time_equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def sign_input(alg: str, key, signing_input: bytes) -> bytes:
    """The raw JWS signature of signing_input. alg "none" gives an empty signature."""
    if alg == "none":
        return b""
    if alg == "HS256":
        return hmac.new(key, signing_input, hashlib.sha256).digest()
    if alg == "RS256":
        return key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    if alg == "ES256":
        r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(_P256_BYTES, "big") + s.to_bytes(_P256_BYTES, "big")
    raise ValueError(f"toy.jose cannot sign with {alg!r}")


def jws_encode(header: dict, payload: dict, key) -> str:
    signing_input = f"{json_segment(header)}.{json_segment(payload)}"
    signature = sign_input(header["alg"], key, signing_input.encode("ascii"))
    return f"{signing_input}.{b64url_encode(signature)}"


def jws_split(token: str) -> tuple[dict, dict, bytes, bytes]:
    """Decode a compact JWS without verifying it."""
    parts = token.split(".") if isinstance(token, str) else []
    if len(parts) != 3:
        raise InvalidToken("malformed", "a compact JWS has three segments")
    header_segment, payload_segment, signature_segment = parts
    return (
        _json_object(header_segment),
        _json_object(payload_segment),
        f"{header_segment}.{payload_segment}".encode("ascii"),
        b64url_decode(signature_segment),
    )


def jws_verify(token: str, jwks: dict, allowed_algs: frozenset[str]) -> dict:
    """Return the payload of a JWS signed by a key in jwks, chosen by kid.

    Keys carried in the token (jwk, jku, x5u, x5c) are never used.
    """
    header, payload, signing_input, signature = jws_split(token)
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in allowed_algs or alg not in _KTY_FOR_ALG:
        raise InvalidToken("alg_not_allowed", f"alg {alg!r}")
    jwk = _find_by_kid(jwks, header.get("kid"))
    if jwk.get("kty") != _KTY_FOR_ALG[alg] or jwk.get("alg", alg) != alg:
        raise InvalidToken("alg_not_allowed", f"key {jwk.get('kid')!r} is not for {alg}")
    if not _signature_matches(alg, key_from_jwk(jwk), signing_input, signature):
        raise InvalidToken("bad_signature")
    return payload


def public_jwk(key, kid: str) -> dict:
    """The JWK to publish for key: public members only for RSA and EC, k for a secret."""
    if isinstance(key, bytes):
        return {"kty": "oct", "kid": kid, "use": "sig", "alg": "HS256", "k": b64url_encode(key)}
    if isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        key = key.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        numbers = key.public_numbers()
        return {
            "kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
            "n": _uint_segment(numbers.n), "e": _uint_segment(numbers.e),
        }
    if isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1):
        numbers = key.public_numbers()
        return {
            "kty": "EC", "kid": kid, "use": "sig", "alg": "ES256", "crv": "P-256",
            "x": b64url_encode(numbers.x.to_bytes(_P256_BYTES, "big")),
            "y": b64url_encode(numbers.y.to_bytes(_P256_BYTES, "big")),
        }
    raise ValueError(f"toy.jose has no JWK form for {type(key).__name__}")


def key_from_jwk(jwk: dict):
    """The verification key a JWK describes: bytes for oct, else a public key."""
    try:
        return _key_from_members(jwk)
    except (KeyError, ValueError) as error:
        raise InvalidToken("malformed", f"unusable JWK {jwk.get('kid')!r}") from error


def jwks_of(*jwks: dict) -> dict:
    return {"keys": [dict(jwk) for jwk in jwks]}


def _json_object(segment: str) -> dict:
    try:
        value = json.loads(b64url_decode(segment).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InvalidToken("malformed", "segment is not UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise InvalidToken("malformed", "segment is not a JSON object")
    return value


def _key_from_members(jwk: dict):
    kty = jwk.get("kty")
    if kty == "oct":
        return b64url_decode(jwk["k"])
    if kty == "RSA":
        n, e = (int.from_bytes(b64url_decode(jwk[name]), "big") for name in ("n", "e"))
        return rsa.RSAPublicNumbers(e, n).public_key()
    if kty == "EC" and jwk.get("crv") == "P-256":
        point = b"\x04" + b64url_decode(jwk["x"]) + b64url_decode(jwk["y"])
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    raise ValueError(f"unsupported JWK kty {kty!r}")


def _find_by_kid(jwks: dict, kid) -> dict:
    """The first signing key with this kid. A key whose use is present and not "sig" is skipped."""
    match = next(
        (
            jwk for jwk in jwks.get("keys", [])
            if kid and jwk.get("kid") == kid and jwk.get("use", "sig") == "sig"
        ),
        None,
    )
    if match is None:
        raise InvalidToken("unknown_kid", f"kid {kid!r}")
    return match


def _signature_matches(alg: str, key, signing_input: bytes, signature: bytes) -> bool:
    if alg == "HS256":
        return constant_time_equal(sign_input(alg, key, signing_input), signature)
    try:
        if alg == "RS256":
            key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        else:
            key.verify(_der_signature(signature), signing_input, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def _der_signature(raw: bytes) -> bytes:
    if len(raw) != 2 * _P256_BYTES:
        raise InvalidSignature
    r = int.from_bytes(raw[:_P256_BYTES], "big")
    s = int.from_bytes(raw[_P256_BYTES:], "big")
    return encode_dss_signature(r, s)


def _uint_segment(value: int) -> str:
    return b64url_encode(value.to_bytes((value.bit_length() + 7) // 8, "big"))
