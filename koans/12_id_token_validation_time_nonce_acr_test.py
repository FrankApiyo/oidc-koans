"""ID token validation, part 2: time, nonce, acr and auth_time.

Once the signature, iss and aud hold, OIDC Core §3.1.3.7 items 9 to 13
remain. "The current time MUST be before the time represented by the exp
Claim", and Core §2 allows "some small leeway, usually no more than a few
minutes, to account for clock skew". With leeway L, this course accepts a
token iff iat - L <= now < exp + L, and checks nbf when present. Rejecting
an old iat is optional: "The acceptable range is Client specific."

exp, iat, nbf and auth_time are NumericDates (RFC 7519 §2): JSON numbers
of seconds, and "non-integer values can be represented". A string, a
boolean, null, NaN or Infinity is malformed; in Python, True is an int.

If a nonce was sent, "a nonce Claim MUST be present" and equal (chapter
09). If acr was requested, "the Client SHOULD check that the asserted
Claim Value is appropriate": acr values are strings with no order, so
check membership in the set you accept. A max_age request makes auth_time
"REQUIRED" (Core §2), and the client "SHOULD check the auth_time Claim
value and request re-authentication if it determines too much time has
elapsed". exp says nothing about when the user signed in.

A common mistake: refusing only when now > exp. At now == exp, the token
"MUST NOT be accepted".

Read more:
  https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
  https://openid.net/specs/openid-connect-core-1_0.html#IDToken
  https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4
  https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
"""

import hashlib
import hmac
import json
import math
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from conftest import __
from toy.client import Transaction, exchange_code, start_login
from toy.clock import Clock
from toy.errors import InvalidToken
from toy.http import Browser, FakeNetwork, Request, Response
from toy.id_token import MAX_LEEWAY
from toy.jose import b64url_encode, jws_verify
from toy.provider import ACR_MFA, ACR_PASSWORD, SPEC, Profile, Provider

ISSUER = "https://id.example"
APP = "https://app.example"
REDIRECT_URI = f"{APP}/callback"
CLIENT_ID = "app"
NONCE = "n" * 20 + "Q-_9" * 5 + "m" * 3
MFA = frozenset({ACR_MFA})
LAX = Profile(
    assurance_claim="acr", acr_alone_reauthenticates=False, auth_time_when_max_age_zero=False,
    honours_prompt_login=False, honours_max_age=False,
)
A3_ACCESS_TOKEN = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"
A3_AT_HASH = "77QmUPtjPfzWtF2AnpK9RQ"
A4_CODE = "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk"
A4_C_HASH = "LDktKdoQak3Pk0cnXxCltA"
DROP = object()


def check_nonce(claims: dict, nonce: str | None) -> None:
    """Chapter 09's check: the nonce this login sent, or no nonce if it sent none."""
    claimed = claims.get("nonce")
    if nonce is None and "nonce" not in claims:
        return
    if not isinstance(claimed, str) or nonce is None:
        raise InvalidToken("nonce_mismatch")
    if not hmac.compare_digest(claimed.encode("utf-8"), nonce.encode("utf-8")):
        raise InvalidToken("nonce_mismatch")


def check_claims(
    claims: dict,
    *,
    now: int,
    nonce: str | None,
    leeway: int = 0,
    max_age: int | None = None,
    required_acr: frozenset[str] | None = None,
) -> dict:
    """OIDC Core §3.1.3.7 items 9 to 13, in this course's order, once chapter 11's checks passed."""
    if isinstance(leeway, bool) or not isinstance(leeway, int):
        raise TypeError(f"leeway counts whole seconds, not {leeway!r}")
    if not 0 <= leeway <= MAX_LEEWAY:
        raise ValueError(f"leeway must be 0 to {MAX_LEEWAY} seconds, not {leeway}")
    check_dates(claims, now, leeway)
    check_nonce(claims, nonce)
    check_auth_time(claims, now, leeway, max_age)
    if required_acr is not None:
        check_acr(claims, required_acr)
    return claims


@dataclass(frozen=True)
class World:
    clock: Clock
    network: FakeNetwork
    provider: Provider
    config: dict


def _world(clock: Clock, profile: Profile = SPEC) -> World:
    """id.example, with this profile, and its public client app; alice has a password only."""
    network = FakeNetwork()
    provider = Provider(ISSUER, clock=clock, network=network, profile=profile)
    provider.register_client(CLIENT_ID, [REDIRECT_URI])
    provider.add_user("alice", "alice@example.com", True, "alice-password")
    network.mount(APP, lambda request: Response(200, {}, "callback reached"))
    config = network.send(Request("GET", f"{ISSUER}/.well-known/openid-configuration")).body
    return World(clock, network, provider, config)


def _signed_in(world: World) -> Browser:
    browser = Browser(world.network)
    world.provider.sign_in(browser, "alice", ("pwd",))
    return browser


def _login(world: World, browser: Browser, **extra) -> tuple[dict, Transaction]:
    """The claims of the ID token app gets when browser logs in with these extra parameters."""
    url, transaction = start_login(
        issuer_config=world.config, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI,
        now=world.clock.now(), extra=extra or None,
    )
    answer = world.network.send(Request("GET", url, cookies=browser.cookies(ISSUER)))
    tokens = exchange_code(
        issuer_config=world.config, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI,
        code=dict(parse_qsl(urlsplit(answer.location).query))["code"],
        code_verifier=transaction.code_verifier, network=world.network,
    )
    return jws_verify(tokens["id_token"], world.provider.jwks, frozenset({"RS256"})), transaction


def _claims(clock: Clock, **changes) -> dict:
    """An ID token's claims, issued now and good for 300 seconds, with changes."""
    now = clock.now()
    claims = {
        "iss": ISSUER, "sub": "alice", "aud": CLIENT_ID, "exp": now + 300, "iat": now,
        "nonce": NONCE, "auth_time": now - 60, "acr": ACR_PASSWORD,
    }
    return {k: v for k, v in {**claims, **changes}.items() if v is not DROP}


def _reason(check) -> str | None:
    try:
        check()
    except InvalidToken as refused:
        return refused.reason
    return None


def numeric_date(claims: dict, name: str):
    __()


def test_refuses_a_date_that_is_not_a_number(clock):
    """Implement numeric_date above: return claims[name] if it is a NumericDate, an int or a float; else raise InvalidToken("malformed"). RFC 8259 §6 says numbers "such as Infinity and NaN" "are not permitted" in JSON, yet Python's json reads them. And is True an int?"""
    now = clock.now()
    assert numeric_date({"exp": now + 300}, "exp") == now + 300
    assert numeric_date({"exp": now + 0.5}, "exp") == now + 0.5
    assert isinstance(True, int) is __
    assert math.isnan(json.loads('{"exp": NaN}')["exp"]) is __
    for value in (True, False, str(now + 300), None, math.nan, math.inf, -math.inf, [now]):
        assert _reason(lambda: numeric_date({"exp": value}, "exp")) == __


def check_dates(claims: dict, now: int, leeway: int) -> None:
    __()


def test_accepts_a_token_inside_its_window(clock):
    """Implement check_dates above, in this order. exp and iat must both be present, or InvalidToken("malformed"). exp: now < exp + leeway, or "expired". iat: iat - leeway <= now, or "issued_in_future". nbf, if present: nbf - leeway <= now, or "not_yet_valid". Read each with numeric_date. Each token here is at its last good second."""
    claims = _claims(clock)
    clock.advance(299)
    assert check_dates(claims, clock.now(), 0) is None
    clock.advance(5)
    assert check_dates(claims, clock.now(), 5) is None
    early = _claims(clock, iat=clock.now() + 5, nbf=clock.now() + 5)
    assert check_dates(early, clock.now(), 5) is None
    assert check_dates(_claims(clock, nbf=clock.now()), clock.now(), 0) is None
    assert check_dates(_claims(clock, exp=clock.now() + 0.5), clock.now(), 0) is None


def test_refuses_a_token_outside_its_window(clock):
    """A replayed token past its exp, one minted ahead of time, one that says nothing of when it ends. Which reason does each get? The second row is at exp exactly."""
    issued = clock.now()
    claims = _claims(clock)
    clock.advance(300)
    now = clock.now()
    rows = [
        (claims, now - 1, 0, None),
        (claims, now, 0, __),
        (claims, now + 4, 5, None),
        (claims, now + 5, 5, "expired"),
        (_claims(clock, exp=now - 0.5), now, 0, "expired"),
        (_claims(clock, iat=now + 1), now, 0, __),
        (_claims(clock, iat=now + 6), now, 5, "issued_in_future"),
        (_claims(clock, nbf=now + 600), now, 60, __),
        (_claims(clock, exp=DROP), now, 0, __),
        (_claims(clock, iat=DROP), now, 0, "malformed"),
        (_claims(clock, exp=True), now, 0, "malformed"),
        (_claims(clock, iat=True), now, 0, "malformed"),
    ]
    assert claims["exp"] == issued + 300 == now
    for token_claims, at, leeway, reason in rows:
        assert _reason(lambda: check_dates(token_claims, at, leeway)) == reason


def check_auth_time(claims: dict, now: int, leeway: int, max_age: int | None) -> None:
    __()


def test_accepts_a_sign_in_within_max_age(clock):
    """Implement check_auth_time above. No auth_time claim is fine, unless max_age was sent: then InvalidToken("auth_time_missing"). Otherwise read it with numeric_date. An auth_time after now + leeway is "issued_in_future". With max_age, now - auth_time may be at most max_age + leeway, or "stale_auth_time"."""
    now = clock.now()
    assert check_auth_time({}, now, 0, None) is None
    assert check_auth_time({"auth_time": now - 300}, now, 0, 300) is None
    assert check_auth_time({"auth_time": now - 305}, now, 5, 300) is None
    assert check_auth_time({"auth_time": now}, now, 0, 0) is None
    assert check_auth_time({"auth_time": now + 5}, now, 5, None) is None
    assert check_auth_time({"auth_time": now - 86_400}, now, 0, None) is None


def test_refuses_a_sign_in_older_than_max_age(clock):
    """Core §3.1.2.1: past max_age the provider "MUST attempt to actively re-authenticate". "Attempt": this lax provider replays alice's session instead, and drops auth_time under max_age=0. What does check_claims say? alice signing in afresh is the honest twin."""
    world = _world(clock, LAX)
    alice = _signed_in(world)
    signed_in_at = clock.now()
    clock.advance(400)
    claims, transaction = _login(world, alice, max_age=300)
    assert clock.now() - claims["auth_time"] == 400
    stale = claims, transaction.nonce
    claims, transaction = _login(world, alice, max_age=0)
    assert "auth_time" not in claims
    missing = claims, transaction.nonce
    for (token_claims, nonce), max_age, reason in [
        (stale, 300, __),
        (missing, 0, __),
    ]:
        check = lambda: check_claims(token_claims, now=clock.now(), nonce=nonce, max_age=max_age)
        assert _reason(check) == reason
    rows = [
        ({"auth_time": clock.now() - 301}, 300, "stale_auth_time"),
        ({"auth_time": clock.now() + 1}, None, __),
        ({"auth_time": str(signed_in_at)}, 300, __),
        ({"auth_time": True}, 300, "malformed"),
        ({}, 300, "auth_time_missing"),
    ]
    for token_claims, max_age, reason in rows:
        assert _reason(lambda: check_auth_time(token_claims, clock.now(), 0, max_age)) == reason
    world.provider.sign_in(alice, "alice", ("pwd",))
    claims, transaction = _login(world, alice, max_age=300)
    assert check_claims(claims, now=clock.now(), nonce=transaction.nonce, max_age=300) == claims


def check_acr(claims: dict, required: frozenset[str]) -> None:
    __()


def test_refuses_an_acr_that_only_looks_enough(clock):
    """Implement check_acr above: acr must be a string and one of the required values, compared exactly, or InvalidToken("acr_not_met"). Levels have no order, and neither 2 nor True is "2". acr_values is a request, not a promise: what acr does alice, who has no second factor, get back when app asks for MFA?"""
    assert check_acr({"acr": ACR_MFA}, MFA) is None
    assert check_acr({"acr": "2"}, frozenset({"2"})) is None
    assert check_acr({"acr": ACR_PASSWORD}, frozenset({ACR_PASSWORD, ACR_MFA})) is None
    near_misses = [
        ({"acr": 2}, frozenset({"2"})), ({"acr": True}, frozenset({"1"})),
        ({"acr": " 2"}, frozenset({"2"})), ({"acr": "3"}, frozenset({"2"})),
        ({"acr": ACR_PASSWORD}, MFA), ({"acr": ACR_MFA.upper()}, MFA), ({"acr": "0"}, MFA),
        ({"acr": [ACR_MFA]}, MFA), ({"acr": None}, MFA), ({}, MFA),
    ]
    for claims, required in near_misses:
        assert _reason(lambda: check_acr(claims, required)) == __
    world = _world(clock)
    claims, _ = _login(world, _signed_in(world), acr_values=ACR_MFA)
    assert claims["acr"] == __
    assert _reason(lambda: check_acr(claims, MFA)) == "acr_not_met"


def test_allows_a_few_minutes_of_leeway_at_most(clock):
    """RFC 7519 §4.1.4 allows "some small leeway, usually no more than a few minutes". check_claims above takes 0 to 300 whole seconds and refuses any other leeway. id.example's clock runs 30 seconds fast, so its token's iat is 30 seconds in your future. What happens with each leeway?"""
    claims = _claims(clock, iat=clock.now() + 30)

    def outcome(leeway) -> str:
        try:
            check_claims(claims, now=clock.now(), nonce=NONCE, leeway=leeway)
        except InvalidToken as refused:
            return refused.reason
        except (TypeError, ValueError):
            return "bad leeway"
        return "accepted"

    leeways = (0, 29, 30, 300, 301, 86_400, 300_000, 1.5)
    assert {leeway: outcome(leeway) for leeway in leeways} == __


def test_reports_the_first_check_that_fails(clock):
    """check_claims runs dates, then nonce, then auth_time, then acr, the order of toy validate_id_token after aud and azp. A token with several defects gets the reason of the first check it fails. Which one is it each time?"""
    now = clock.now()

    def reason(token_claims, **options):
        return _reason(lambda: check_claims(token_claims, now=now, nonce=NONCE, **options))

    assert reason(_claims(clock, exp=now, iat=now + 1)) == __
    assert reason(_claims(clock, exp=now, iat="soon")) == __
    assert reason(_claims(clock, exp=DROP, nonce="other")) == __
    assert reason(_claims(clock, iat=now + 1, nonce="other")) == __
    wrong_nonce_no_auth_time = _claims(clock, nonce="other", auth_time=DROP)
    assert reason(wrong_nonce_no_auth_time, max_age=300) == __
    stale_and_weak = _claims(clock, auth_time=now - 301)
    assert reason(stale_and_weak, max_age=300, required_acr=MFA) == __
    assert reason(_claims(clock), required_acr=MFA) == __


def test_at_hash_ties_an_access_token_to_its_id_token(clock):
    """Core §3.1.3.6: at_hash is the base64url of "the left-most half of the hash" of the access token's ASCII, with the hash of the ID token's alg: SHA-256 for RS256. c_hash is the same for a code. They matter when a code or token rides the browser next to an ID token, as in hybrid flows: a swapped code fails c_hash. The vectors are Core Appendix A.3 and A.4."""

    def left_half(value: str) -> str:
        digest = hashlib.sha256(value.encode("ascii")).digest()
        return b64url_encode(digest[: __])

    assert left_half(A3_ACCESS_TOKEN) == A3_AT_HASH
    assert left_half(A4_CODE) == A4_C_HASH
    assert (left_half("a-code-mallory-swapped-in") == A4_C_HASH) is __
    world = _world(clock)
    claims, _ = _login(world, _signed_in(world))
    assert ("at_hash" in claims) is __
