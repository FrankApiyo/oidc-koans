"""ID token validation, in the order of OIDC Core 3.1.3.7 (errata set 2)."""

import math

from toy.errors import InvalidToken
from toy.jose import constant_time_equal, jws_split, jws_verify

MAX_LEEWAY = 300
DEFAULT_ALGS = frozenset({"RS256", "ES256"})
_ID_TOKEN_TYPES = frozenset({"jwt", "application/jwt"})


def validate_id_token(
    token: str,
    *,
    issuer: str,
    client_id: str,
    jwks: dict,
    now: int,
    nonce: str | None,
    allowed_algs: frozenset[str] = DEFAULT_ALGS,
    leeway: int = 0,
    max_age: int | None = None,
    required_acr: frozenset[str] | None = None,
    not_before: int | None = None,
    trusted_audiences: frozenset[str] = frozenset(),
    azp_extension: bool = False,
) -> dict:
    """Return the claims of a valid ID token, or raise InvalidToken.

    A token is in date iff iat - leeway <= now < exp + leeway. trusted_audiences
    are the other audiences this client accepts beside itself. azp is checked
    only when azp_extension says an extension that issues it is in use.
    """
    _check_options(now, leeway, max_age, not_before)
    header, payload, _, _ = jws_split(token)
    _check_type(header, payload)
    claims = jws_verify(token, jwks, allowed_algs)
    _check_subject(claims)
    _check_issuer(claims, issuer)
    _check_audience(claims, client_id, trusted_audiences)
    _check_authorized_party(claims, client_id, azp_extension)
    _check_dates(claims, now, leeway)
    _check_nonce(claims, nonce)
    _check_auth_time(claims, now, leeway, max_age, not_before)
    if required_acr is not None:
        check_acr(claims, required_acr)
    return claims


def check_acr(claims: dict, required: frozenset[str]) -> None:
    """acr must be one of the required strings, compared exactly and never ordered."""
    if not isinstance(required, frozenset) or not all(isinstance(v, str) for v in required):
        raise TypeError("required acr values are a frozenset of strings")
    acr = claims.get("acr")
    if not isinstance(acr, str) or acr not in required:
        raise InvalidToken("acr_not_met", f"acr {acr!r}")


def numeric_date(claims: dict, name: str):
    """A NumericDate claim (RFC 7519 §2): a finite JSON number, never a bool or a string."""
    value = claims[name]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise InvalidToken("malformed", f"{name} is not a NumericDate: {value!r}")
    return value


def _check_options(now, leeway, max_age, not_before) -> None:
    optional = {"max_age": max_age, "not_before": not_before}
    given = {"now": now, "leeway": leeway, **{k: v for k, v in optional.items() if v is not None}}
    for name, value in given.items():
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} counts whole seconds, not {value!r}")
    if not 0 <= leeway <= MAX_LEEWAY:
        raise ValueError(f"leeway must be 0 to {MAX_LEEWAY} seconds, not {leeway}")
    if max_age is not None and max_age < 0:
        raise ValueError(f"max_age must not be negative, not {max_age}")


def _check_type(header: dict, payload: dict) -> None:
    typ = header.get("typ")
    if typ is not None and (not isinstance(typ, str) or typ.lower() not in _ID_TOKEN_TYPES):
        raise InvalidToken("wrong_typ", f"typ {typ!r} is not an ID token")
    if "events" in payload:
        raise InvalidToken("wrong_typ", "a token with events is a logout or event token")


def _check_subject(claims: dict) -> None:
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub:
        raise InvalidToken("malformed", "sub must be a non-empty string")


def _check_issuer(claims: dict, issuer: str) -> None:
    if claims.get("iss") != issuer:
        raise InvalidToken("wrong_issuer", f"iss {claims.get('iss')!r}")


def _check_audience(claims: dict, client_id: str, trusted: frozenset[str]) -> None:
    audiences = _audiences(claims)
    if client_id not in audiences:
        raise InvalidToken("wrong_audience", f"aud {audiences!r} does not list {client_id!r}")
    untrusted = set(audiences) - {client_id} - trusted
    if untrusted:
        raise InvalidToken("wrong_audience", f"untrusted audiences {sorted(untrusted)!r}")


def _audiences(claims: dict) -> tuple[str, ...]:
    aud = claims.get("aud", ())
    if isinstance(aud, str):
        return (aud,)
    if not isinstance(aud, (list, tuple)) or not all(isinstance(a, str) for a in aud):
        raise InvalidToken("malformed", "aud is a string or an array of strings")
    return tuple(aud)


def _check_authorized_party(claims: dict, client_id: str, azp_extension: bool) -> None:
    if not azp_extension:
        return
    azp = claims.get("azp")
    if azp is None and len(_audiences(claims)) > 1:
        raise InvalidToken("azp_mismatch", "several audiences and no azp")
    if azp is not None and azp != client_id:
        raise InvalidToken("azp_mismatch", f"azp {azp!r}")


def _check_dates(claims: dict, now: int, leeway: int) -> None:
    for name in ("exp", "iat"):
        if name not in claims:
            raise InvalidToken("malformed", f"an ID token must carry {name}")
    if not now < numeric_date(claims, "exp") + leeway:
        raise InvalidToken("expired", f"exp {claims['exp']} at {now}")
    if not numeric_date(claims, "iat") - leeway <= now:
        raise InvalidToken("issued_in_future", f"iat {claims['iat']} at {now}")
    if "nbf" in claims and not numeric_date(claims, "nbf") - leeway <= now:
        raise InvalidToken("not_yet_valid", f"nbf {claims['nbf']} at {now}")


def _check_nonce(claims: dict, nonce: str | None) -> None:
    claimed = claims.get("nonce")
    if nonce is None and "nonce" not in claims:
        return
    if not isinstance(claimed, str) or nonce is None or not constant_time_equal(
        claimed.encode("utf-8"), nonce.encode("utf-8")
    ):
        raise InvalidToken("nonce_mismatch")


def _check_auth_time(claims, now, leeway, max_age, not_before) -> None:
    if "auth_time" not in claims:
        if max_age is not None or not_before is not None:
            raise InvalidToken("auth_time_missing")
        return
    auth_time = numeric_date(claims, "auth_time")
    if auth_time > now + leeway:
        raise InvalidToken("issued_in_future", f"auth_time {auth_time} at {now}")
    if max_age is not None and now - auth_time > max_age + leeway:
        raise InvalidToken("stale_auth_time", f"auth_time {auth_time} is over {max_age}s old")
    if not_before is not None and auth_time < not_before:
        raise InvalidToken("stale_auth_time", f"auth_time {auth_time} before {not_before}")
