"""Parity for chapters 11 and 12: each solved function agrees with its toy/ counterpart."""

import pytest

from tests.parity_support import ID, OTHER, _outcome, _solved
from toy import id_token, jose
from toy.keys import ATTACKER_RSA, EC_1, RSA_1


CHAPTER_11 = "11_id_token_validation_iss_aud_azp_test.py"
TYP_HEADERS = [
    {}, {"typ": "JWT"}, {"typ": "jwt"}, {"typ": "application/jwt"}, {"typ": "Application/JWT"},
    {"typ": None}, {"typ": "at+jwt"}, {"typ": "application/at+jwt"}, {"typ": "logout+jwt"},
    {"typ": "JWT "}, {"typ": 7}, {"typ": ["JWT"]}, {"typ": ""},
]
TYP_PAYLOADS = [{"sub": "alice"}, {"sub": "alice", "events": {}}, {"events": None}]


def test_typ_cases_hold_both_accepted_and_refused_inputs():
    outcomes = {
        _outcome(id_token._check_type, header, payload)[0]
        for header in TYP_HEADERS for payload in TYP_PAYLOADS
    }
    assert outcomes == {"value", "refused"}


@pytest.mark.parametrize("payload", TYP_PAYLOADS, ids=repr)
@pytest.mark.parametrize("header", TYP_HEADERS, ids=repr)
def test_chapter_11_check_type_matches_toy(header, payload):
    solved = _solved(CHAPTER_11).check_type
    assert _outcome(solved, header, payload) == _outcome(id_token._check_type, header, payload)


NO_CLAIM = object()
ISS_VALUES = [
    ID, f"{ID}/", "https://ID.example", "http://id.example", f"{ID}.evil.example", "https://id.exampl",
    OTHER, [ID], "", None, 7, NO_CLAIM,
]


def _with(name: str, value) -> dict:
    return {"sub": "alice"} if value is NO_CLAIM else {"sub": "alice", name: value}


@pytest.mark.parametrize("iss", ISS_VALUES, ids=repr)
def test_chapter_11_check_issuer_matches_toy(iss):
    solved = _solved(CHAPTER_11).check_issuer
    claims = _with("iss", iss)
    assert _outcome(solved, claims, ID) == _outcome(id_token._check_issuer, claims, ID)


AUD_VALUES = [
    "app", ["app"], ["app", "api"], ["api", "app"], ["app", "app"], ["app", "quiz"], "webapp",
    "APP", "app ", ["webapp"], [], NO_CLAIM, None, 7, ["app", 7], ["quiz", 7], {"app": True},
    "quiz", ["quiz", "app"], "",
]
TRUSTED_SETS = [frozenset(), frozenset({"api"}), frozenset({"quiz", "api"})]


def test_audience_cases_hold_both_accepted_and_refused_inputs():
    outcomes = {
        _outcome(id_token._check_audience, _with("aud", aud), "app", trusted)
        for aud in AUD_VALUES for trusted in TRUSTED_SETS
    }
    assert {kind for kind, _ in outcomes} == {"value", "refused"}
    assert {reason for _, reason in outcomes} >= {None, "wrong_audience", "malformed"}


@pytest.mark.parametrize("trusted", TRUSTED_SETS, ids=lambda t: "+".join(sorted(t)) or "none")
@pytest.mark.parametrize("aud", AUD_VALUES, ids=repr)
def test_chapter_11_check_audience_matches_toy(aud, trusted):
    solved = _solved(CHAPTER_11).check_audience
    claims = _with("aud", aud)
    expected = _outcome(id_token._check_audience, claims, "app", trusted)
    assert _outcome(solved, claims, "app", trusted) == expected


WELL_FORMED_AUDS = ["app", ["app"], ["app", "api"], ["api", "app"], ["quiz", "app", "api"]]
AZP_VALUES = [NO_CLAIM, None, "app", "quiz", "APP", "", ["app"]]


@pytest.mark.parametrize("azp_extension", [False, True])
@pytest.mark.parametrize("azp", AZP_VALUES, ids=repr)
@pytest.mark.parametrize("aud", WELL_FORMED_AUDS, ids=repr)
def test_chapter_11_check_authorized_party_matches_toy(aud, azp, azp_extension):
    """aud has already passed the audience check when azp is checked, so it is well formed."""
    solved = _solved(CHAPTER_11).check_authorized_party
    claims = {**_with("azp", azp), "aud": aud}
    expected = _outcome(id_token._check_authorized_party, claims, "app", azp_extension)
    assert _outcome(solved, claims, "app", azp_extension) == expected


VT_NOW = 1_800_000_000
VT_JWKS = jose.jwks_of(jose.public_jwk(RSA_1, "k1"), jose.public_jwk(EC_1, "o1"))
VT_EVENTS = {"http://schemas.openid.net/event/backchannel-logout": {}}


def _vt(header: dict | None = None, key=RSA_1, **changes) -> str:
    """A token for client app from id.example, honest unless changed; None drops a claim."""
    claims = {
        "iss": ID, "sub": "alice", "aud": "app", "exp": VT_NOW + 300, "iat": VT_NOW,
        "nonce": "n-1", "auth_time": VT_NOW - 60, "acr": "urn:toy:acr:pwd",
    }
    claims = {k: v for k, v in {**claims, **changes}.items() if v is not NO_CLAIM}
    alg = "ES256" if key is EC_1 else "RS256"
    kid = "o1" if key is EC_1 else "k1"
    return jose.jws_encode({"alg": alg, "kid": kid, **(header or {})}, claims, key)


MFA = frozenset({"urn:toy:acr:mfa"})
VALIDATION_CASES = {
    "honest": (_vt(), {}),
    "es256": (_vt(key=EC_1), {}),
    "typ-at": (_vt({"typ": "at+jwt"}), {}),
    "events": (_vt(events=VT_EVENTS), {}),
    "typ-int": (_vt({"typ": 7}), {}),
    "forged": (_vt(key=ATTACKER_RSA), {}),
    "unknown-kid": (_vt({"kid": "k9"}), {}),
    "es256-not-allowed": (_vt(key=EC_1), {"allowed_algs": frozenset({"RS256"})}),
    "no-sub": (_vt(sub=NO_CLAIM), {}),
    "sub-int": (_vt(sub=42), {}),
    "iss-slash": (_vt(iss=f"{ID}/"), {}),
    "no-iss": (_vt(iss=NO_CLAIM), {}),
    "aud-webapp": (_vt(aud="webapp"), {}),
    "aud-extra": (_vt(aud=["app", "api"]), {}),
    "aud-extra-trusted": (_vt(aud=["app", "api"]), {"trusted_audiences": frozenset({"api"})}),
    "aud-int": (_vt(aud=7), {}),
    "no-aud": (_vt(aud=NO_CLAIM), {}),
    "aud-odd-item": (_vt(aud=["quiz", 7]), {}),
    "azp-ignored": (_vt(azp="quiz"), {}),
    "azp-ext": (_vt(azp="quiz"), {"azp_extension": True}),
    "azp-missing-ext": (
        _vt(aud=["app", "api"]),
        {"azp_extension": True, "trusted_audiences": frozenset({"api"})},
    ),
    "azp-ok-ext": (
        _vt(aud=["app", "api"], azp="app"),
        {"azp_extension": True, "trusted_audiences": frozenset({"api"})},
    ),
    "exp-now": (_vt(exp=VT_NOW), {}),
    "exp-minus-one": (_vt(exp=VT_NOW + 1), {}),
    "exp-leeway-ok": (_vt(exp=VT_NOW - 4), {"leeway": 5}),
    "exp-leeway-out": (_vt(exp=VT_NOW - 5), {"leeway": 5}),
    "exp-float": (_vt(exp=VT_NOW + 0.5), {}),
    "no-exp": (_vt(exp=NO_CLAIM), {}),
    "exp-true": (_vt(exp=True), {}),
    "exp-string": (_vt(exp="1800000300"), {}),
    "exp-nan": (_vt(exp=float("nan")), {}),
    "exp-inf": (_vt(exp=float("inf")), {}),
    "exp-null": (_vt(exp=None), {}),
    "iat-future": (_vt(iat=VT_NOW + 1), {}),
    "iat-leeway-ok": (_vt(iat=VT_NOW + 5), {"leeway": 5}),
    "iat-leeway-out": (_vt(iat=VT_NOW + 6), {"leeway": 5}),
    "iat-true": (_vt(iat=True), {}),
    "no-iat": (_vt(iat=NO_CLAIM), {}),
    "nbf-future": (_vt(nbf=VT_NOW + 1), {}),
    "nbf-string": (_vt(nbf="0"), {}),
    "nonce-wrong": (_vt(nonce="n-2"), {}),
    "nonce-missing": (_vt(nonce=NO_CLAIM), {}),
    "nonce-unsent": (_vt(), {"nonce": None}),
    "nonce-none-both": (_vt(nonce=NO_CLAIM), {"nonce": None}),
    "max-age-no-auth-time": (_vt(auth_time=NO_CLAIM), {"max_age": 300}),
    "no-auth-time": (_vt(auth_time=NO_CLAIM), {}),
    "auth-time-stale": (_vt(auth_time=VT_NOW - 301), {"max_age": 300}),
    "auth-time-edge": (_vt(auth_time=VT_NOW - 300), {"max_age": 300}),
    "auth-time-leeway": (_vt(auth_time=VT_NOW - 305), {"max_age": 300, "leeway": 5}),
    "auth-time-future": (_vt(auth_time=VT_NOW + 1), {}),
    "auth-time-string": (_vt(auth_time="0"), {}),
    "auth-time-true": (_vt(auth_time=True), {"max_age": 300}),
    "acr-weak": (_vt(), {"required_acr": MFA}),
    "acr-int": (_vt(acr=2), {"required_acr": frozenset({"2"})}),
    "acr-true": (_vt(acr=True), {"required_acr": frozenset({"1"})}),
    "acr-ok": (_vt(acr="urn:toy:acr:mfa"), {"required_acr": MFA}),
    "acr-missing": (_vt(acr=NO_CLAIM), {"required_acr": MFA}),
    "acr-list": (_vt(acr=["urn:toy:acr:mfa"]), {"required_acr": MFA}),
    "logout-and-forged": (_vt({"typ": "logout+jwt"}, ATTACKER_RSA, iss=OTHER), {}),
    "forged-and-iss": (_vt(key=ATTACKER_RSA, iss=OTHER, aud="quiz"), {}),
    "no-sub-and-iss": (_vt(sub=NO_CLAIM, iss=OTHER), {}),
    "iss-and-aud": (_vt(iss=OTHER, aud="quiz"), {}),
    "aud-and-azp": (_vt(aud=["quiz", "api"], azp="quiz"), {"azp_extension": True}),
    "aud-and-expired": (_vt(aud="quiz", exp=VT_NOW), {}),
    "azp-and-expired": (_vt(azp="quiz", exp=VT_NOW), {"azp_extension": True}),
    "expired-and-iat-future": (_vt(exp=VT_NOW, iat=VT_NOW + 1), {}),
    "expired-and-iat-string": (_vt(exp=VT_NOW, iat="x"), {}),
    "no-exp-and-iat-future": (_vt(exp=NO_CLAIM, iat=VT_NOW + 1), {}),
    "iat-future-and-nonce": (_vt(iat=VT_NOW + 1, nonce="n-2"), {}),
    "nbf-and-nonce": (_vt(nbf=VT_NOW + 1, nonce="n-2"), {}),
    "expired-and-nonce": (_vt(exp=VT_NOW, nonce="n-2"), {}),
    "nonce-and-no-auth-time": (_vt(nonce="n-2", auth_time=NO_CLAIM), {"max_age": 300}),
    "stale-and-acr": (_vt(auth_time=VT_NOW - 301), {"max_age": 300, "required_acr": MFA}),
    "future-auth-time-and-acr": (_vt(auth_time=VT_NOW + 1), {"required_acr": MFA}),
    "expired-and-stale": (_vt(exp=VT_NOW, auth_time=VT_NOW - 999), {"max_age": 300}),
}
SIGNED_PART_OPTIONS = ("allowed_algs", "trusted_audiences", "azp_extension")
SIGNED_PART_REASONS = frozenset({
    "malformed", "wrong_typ", "alg_not_allowed", "unknown_kid", "bad_signature",
    "wrong_issuer", "wrong_audience", "azp_mismatch",
})


def _toy_validation(token: str, options: dict):
    full = {"nonce": "n-1", **options}
    return _outcome(lambda: id_token.validate_id_token(
        token, issuer=ID, client_id="app", jwks=VT_JWKS, now=VT_NOW, **full
    ))


LATER_REASONS = frozenset({
    "expired", "issued_in_future", "not_yet_valid", "nonce_mismatch", "auth_time_missing",
    "stale_auth_time", "acr_not_met",
})


def test_validation_cases_cover_every_reason_in_the_validator():
    outcomes = [_toy_validation(token, options) for token, options in VALIDATION_CASES.values()]
    reasons = {reason for kind, reason in outcomes if kind == "refused"}
    assert "value" in {kind for kind, _ in outcomes}
    assert reasons == SIGNED_PART_REASONS | LATER_REASONS


@pytest.mark.parametrize("case", VALIDATION_CASES)
def test_chapter_11_validate_signed_part_matches_toy(case):
    """Where chapter 11's part refuses, it gives toy's reason; where it passes, toy either passes
    or refuses for a reason chapter 12 checks."""
    token, options = VALIDATION_CASES[case]
    signed_part = {k: v for k, v in options.items() if k in SIGNED_PART_OPTIONS}
    solved = _outcome(lambda: _solved(CHAPTER_11).validate_signed_part(
        token, issuer=ID, client_id="app", jwks=VT_JWKS, **signed_part
    ))
    toy = _toy_validation(token, options)
    if solved[0] == "refused":
        assert solved == toy
    elif toy[0] == "refused":
        later_malformed = toy[1] == "malformed" and not _malformed_before_dates(token)
        assert toy[1] in LATER_REASONS or later_malformed


def _malformed_before_dates(token: str) -> bool:
    """Whether toy's malformed comes from the signed part: an unparseable token, sub or aud."""
    claims = jose.jws_split(token)[1]
    aud = claims.get("aud", [])
    bad_aud = not isinstance(aud, str) and (
        not isinstance(aud, list) or not all(isinstance(a, str) for a in aud)
    )
    return not isinstance(claims.get("sub"), str) or not claims.get("sub") or bad_aud


CHAPTER_12 = "12_id_token_validation_time_nonce_acr_test.py"
DATE_VALUES = [
    VT_NOW, VT_NOW + 0.5, 0, -1, True, False, "1800000000", None, float("nan"), float("inf"),
    float("-inf"), [VT_NOW], {"t": VT_NOW}, 10**20,
]


@pytest.mark.parametrize("value", DATE_VALUES, ids=repr)
def test_chapter_12_numeric_date_matches_toy(value):
    solved = _solved(CHAPTER_12).numeric_date
    claims = {"exp": value}
    assert _outcome(solved, claims, "exp") == _outcome(id_token.numeric_date, claims, "exp")


DATE_CLAIMS = [
    {"exp": VT_NOW + 300, "iat": VT_NOW},
    {"exp": VT_NOW, "iat": VT_NOW - 300},
    {"exp": VT_NOW + 1, "iat": VT_NOW},
    {"exp": VT_NOW - 5, "iat": VT_NOW - 300},
    {"exp": VT_NOW - 4.5, "iat": VT_NOW - 300},
    {"exp": VT_NOW + 300, "iat": VT_NOW + 1},
    {"exp": VT_NOW + 300, "iat": VT_NOW + 5},
    {"exp": VT_NOW + 300, "iat": VT_NOW + 6},
    {"exp": VT_NOW + 300, "iat": VT_NOW, "nbf": VT_NOW},
    {"exp": VT_NOW + 300, "iat": VT_NOW, "nbf": VT_NOW + 5},
    {"exp": VT_NOW + 300, "iat": VT_NOW, "nbf": VT_NOW + 6},
    {"exp": VT_NOW + 300, "iat": VT_NOW, "nbf": "0"},
    {"iat": VT_NOW},
    {"exp": VT_NOW + 300},
    {},
    {"exp": True, "iat": VT_NOW},
    {"exp": VT_NOW + 300, "iat": True},
    {"exp": VT_NOW, "iat": "x"},
    {"exp": "x", "iat": VT_NOW + 9},
    {"exp": VT_NOW, "iat": VT_NOW + 9},
    {"exp": float("nan"), "iat": VT_NOW},
    {"exp": None, "iat": VT_NOW},
]
LEEWAYS = [0, 5, 300]


def test_date_cases_hold_every_date_reason():
    outcomes = {
        _outcome(id_token._check_dates, claims, VT_NOW, leeway)
        for claims in DATE_CLAIMS for leeway in LEEWAYS
    }
    assert {reason for _, reason in outcomes} == {
        None, "malformed", "expired", "issued_in_future", "not_yet_valid",
    }


@pytest.mark.parametrize("leeway", LEEWAYS)
@pytest.mark.parametrize("claims", DATE_CLAIMS, ids=repr)
def test_chapter_12_check_dates_matches_toy(claims, leeway):
    solved = _solved(CHAPTER_12).check_dates
    expected = _outcome(id_token._check_dates, claims, VT_NOW, leeway)
    assert _outcome(solved, claims, VT_NOW, leeway) == expected


AUTH_TIMES = [NO_CLAIM, VT_NOW, VT_NOW - 300, VT_NOW - 301, VT_NOW - 305, VT_NOW - 306, VT_NOW + 1,
              VT_NOW + 5, VT_NOW - 0.5, "0", True, None, float("nan")]
MAX_AGES = [None, 0, 300]


def test_auth_time_cases_hold_every_auth_time_reason():
    outcomes = {
        _outcome(id_token._check_auth_time, _with("auth_time", at), VT_NOW, leeway, max_age, None)
        for at in AUTH_TIMES for leeway in (0, 5) for max_age in MAX_AGES
    }
    assert {reason for _, reason in outcomes} == {
        None, "malformed", "auth_time_missing", "issued_in_future", "stale_auth_time",
    }


@pytest.mark.parametrize("max_age", MAX_AGES)
@pytest.mark.parametrize("leeway", [0, 5])
@pytest.mark.parametrize("auth_time", AUTH_TIMES, ids=repr)
def test_chapter_12_check_auth_time_matches_toy(auth_time, leeway, max_age):
    solved = _solved(CHAPTER_12).check_auth_time
    claims = _with("auth_time", auth_time)
    expected = _outcome(id_token._check_auth_time, claims, VT_NOW, leeway, max_age, None)
    assert _outcome(solved, claims, VT_NOW, leeway, max_age) == expected


ACR_VALUES = [
    "2", 2, True, None, ["2"], "02", " 2", "1", "0", "urn:toy:acr:mfa", "URN:TOY:ACR:MFA",
    "urn:toy:acr:pwd", NO_CLAIM,
]
REQUIRED_ACRS = [frozenset({"2"}), frozenset({"1"}), MFA, frozenset({"urn:toy:acr:pwd", "2"})]


@pytest.mark.parametrize("required", REQUIRED_ACRS, ids=lambda r: "+".join(sorted(r)))
@pytest.mark.parametrize("acr", ACR_VALUES, ids=repr)
def test_chapter_12_check_acr_matches_toy(acr, required):
    solved = _solved(CHAPTER_12).check_acr
    claims = _with("acr", acr)
    assert _outcome(solved, claims, required) == _outcome(id_token.check_acr, claims, required)


@pytest.mark.parametrize("case", VALIDATION_CASES)
def test_chapters_11_and_12_together_match_toy_validate_id_token(case):
    """Chapter 11's signed part, then chapter 12's claim checks, give toy's answer, multi-defect
    tokens included."""
    token, options = VALIDATION_CASES[case]
    signed_part = {k: v for k, v in options.items() if k in SIGNED_PART_OPTIONS}
    later = {k: v for k, v in {"nonce": "n-1", **options}.items() if k not in SIGNED_PART_OPTIONS}

    def course_validator():
        claims = _solved(CHAPTER_11).validate_signed_part(
            token, issuer=ID, client_id="app", jwks=VT_JWKS, **signed_part
        )
        return _solved(CHAPTER_12).check_claims(claims, now=VT_NOW, **later)

    assert _outcome(course_validator) == _toy_validation(token, options)
