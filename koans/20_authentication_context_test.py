"""Authentication context: acr, amr, auth_time, max_age, prompt, acr_values.

An ID token can say how and when the user signed in. auth_time is when
they last actively authenticated. amr is a "JSON array of strings that are
identifiers for authentication methods" (RFC 8176 names pwd, otp, hwk, mfa
and more); mfa says several factors were used, not which. acr is a
case-sensitive string naming an authentication context class; "Parties
using this claim will need to agree upon the meanings".

The request asks and the token answers. Past max_age the provider "MUST
attempt to actively re-authenticate", and the token "MUST include an
auth_time Claim Value"; "max_age=0 is equivalent to prompt=login". With
prompt=login it "MUST reauthenticate the End-User even if the End-User is
already authenticated", and "If it cannot reauthenticate the End-User, it
MUST return an error"; auth_time comes only if asked for. prompt=none
"MUST NOT display any authentication or consent user interface pages".
acr_values asks for acr "as a Voluntary Claim", and an unmet one SHOULD
get the session's current acr. Only an Essential acr request with values
turns an unmet level into a failed sign-in.

So check what came back. A sign-in made for your request has auth_time >=
the time you sent it, less leeway. An acr counts only if you agreed its
meaning with that issuer: there is no global order to rank it by.

A common mistake: assuming max_age, prompt or acr_values were honoured.

Read more:
  https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
  https://openid.net/specs/openid-connect-core-1_0.html#acrSemantics
  https://www.rfc-editor.org/rfc/rfc8176.html#section-2
"""

import hmac
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit

from conftest import __
from toy.client import STATE_COOKIE, Transaction, bind_state, finish_login, start_login
from toy.clock import Clock
from toy.errors import InvalidToken
from toy.http import Browser, FakeNetwork, Request, Response
from toy.id_token import numeric_date
from toy.keys import EC_1
from toy.provider import ACR_MFA, ACR_PASSWORD, SPEC, Profile, Provider

ISSUER = "https://id.example"
OTHER_ISSUER = "https://other-id.example"
APP = "https://app.example"
REDIRECT_URI = f"{APP}/callback"
CLIENT_ID = "app"
SIGN_IN_TAKES = 20
LAX = Profile(
    assurance_claim="acr", acr_alone_reauthenticates=False, auth_time_when_max_age_zero=False,
    honours_prompt_login=False, honours_max_age=False,
)
FRESH_MFA = {"acr_values": ACR_MFA, "max_age": 0}
POLICY = {
    ISSUER: {"mfa": frozenset({ACR_MFA}), "any": frozenset({ACR_PASSWORD, ACR_MFA})},
    OTHER_ISSUER: {"any": frozenset({ACR_PASSWORD, ACR_MFA})},
}
ACR_RANK = {ACR_PASSWORD: 1, ACR_MFA: 2}
MFA_RANK = 2
RFC_8176 = {
    "face": "Biometric authentication using facial recognition.",
    "fpt": "Biometric authentication using a fingerprint.",
    "hwk": "Proof-of-Possession (PoP) of a hardware-secured key.",
    "kba": "Knowledge-based authentication.",
    "mfa": "Multiple-factor authentication.",
    "otp": "One-time password.",
    "pwd": "Password-based authentication.",
    "sms": "Confirmation using SMS text message to the user at a registered number.",
    "swk": "Proof-of-Possession (PoP) of a software-secured key.",
}


@dataclass(frozen=True)
class World:
    clock: Clock
    network: FakeNetwork
    providers: dict


def _world(profile: Profile = SPEC) -> World:
    """id.example, with this profile, and other-id.example, each with app as a client.

    At both, alice has a password and a one-time password; at id.example,
    mallory has a password only.
    """
    clock, network = Clock(), FakeNetwork()
    provider = Provider(ISSUER, clock=clock, network=network, profile=profile)
    other = Provider(OTHER_ISSUER, clock=clock, network=network, signing_key=EC_1, kid="o1")
    for op in (provider, other):
        op.register_client(CLIENT_ID, [REDIRECT_URI])
        op.add_user("alice", "alice@example.com", True, "alice-password", factors=("otp",))
    provider.add_user("mallory", "mallory@example.com", True, "mallory-password")
    network.mount(APP, lambda request: Response(200, {}, "callback reached"))
    return World(clock, network, {ISSUER: provider, OTHER_ISSUER: other})


def _signed_in(world: World, sub: str, factors=("pwd",), issuer: str = ISSUER) -> Browser:
    """A browser in which sub signed in at issuer an hour ago; the clock is now."""
    browser = Browser(world.network)
    world.providers[issuer].sign_in(browser, sub, factors)
    world.clock.advance(3600)
    return browser


def _config(world: World, issuer: str) -> dict:
    return world.network.send(Request("GET", f"{issuer}/.well-known/openid-configuration")).body


def _authorize(world: World, browser: Browser, extra: dict, edit=None, issuer: str = ISSUER):
    """app starts a login with extra parameters; the browser opens the URL, after edit(query).

    Returns the browser's last response and app's transaction.
    """
    url, transaction = start_login(
        issuer_config=_config(world, issuer), client_id=CLIENT_ID, redirect_uri=REDIRECT_URI,
        now=world.clock.now(), extra=extra,
    )
    query = dict(parse_qsl(urlsplit(url).query))
    sent = f"{issuer}/authorize?{urlencode(edit(query) if edit else query)}"
    return browser.get(sent), transaction


def _sign_in_for(
    world: World, browser: Browser, sub: str, extra: dict, factors=("pwd",), edit=None,
    issuer: str = ISSUER,
) -> tuple[dict, Transaction]:
    """A login with these parameters. When the provider asks for a sign-in, sub takes
    SIGN_IN_TAKES seconds to sign in with factors, and the browser reloads the same
    authorize URL. Returns the claims finish_login gives app, and app's transaction."""
    answer, transaction = _authorize(world, browser, extra, edit, issuer)
    if answer.status == 401:
        same_request = browser.history[-1].url
        world.clock.advance(SIGN_IN_TAKES)
        world.providers[issuer].sign_in(browser, sub, factors)
        answer = browser.get(same_request)
    assert answer.body == "callback reached", answer.body
    bound = {STATE_COOKIE: bind_state(None, transaction.state)}
    callback = Request("GET", browser.history[-1].url, cookies=bound)
    config = _config(world, issuer)
    claims = finish_login(
        transaction=transaction, callback=callback, issuer_config=config, client_id=CLIENT_ID,
        jwks=world.network.send(Request("GET", config["jwks_uri"])).body,
        network=world.network, now=world.clock.now(),
    )
    return claims, transaction


def _callback_query(browser: Browser) -> dict:
    return dict(parse_qsl(urlsplit(browser.history[-1].url).query))


def _reason(check: Callable) -> str | None:
    try:
        check()
    except InvalidToken as refused:
        return refused.reason
    return None


def test_amr_names_methods_and_mfa_hides_which():
    """RFC 8176 §2 gives each method a short name; RFC_8176 above holds some of them, with the RFC's descriptions less their citations. Which names are a password, a one-time password, a hardware-secured key and several factors? alice signs in to id.example with her password and her one-time password; app asks for acr with acr_values. What amr and acr does app get?"""
    assert RFC_8176[__] == "Password-based authentication."
    assert RFC_8176[__] == "One-time password."
    assert RFC_8176[__] == "Proof-of-Possession (PoP) of a hardware-secured key."
    assert RFC_8176[__] == "Multiple-factor authentication."
    world = _world()
    alice = _signed_in(world, "alice")
    claims, _ = _sign_in_for(world, alice, "alice", FRESH_MFA, factors=("pwd", "otp"))
    assert claims["amr"] == __
    assert claims["acr"] == __


def amr_includes(claims: dict, method: str) -> bool:
    __()


def test_accepts_a_method_listed_in_amr():
    """Implement amr_includes above: True when claims["amr"] is a list of strings that contains method, compared exactly; else False. Core §2: amr is a "JSON array of strings", and "The amr value is an array of case-sensitive strings". Nothing gives the array an order, so look for the name, not a position."""
    world = _world()
    alice = _signed_in(world, "alice")
    claims, _ = _sign_in_for(world, alice, "alice", FRESH_MFA, factors=("otp", "pwd"))
    assert claims["amr"] == ["otp", "pwd", "mfa"]
    assert amr_includes(claims, "otp") is __
    assert amr_includes({"amr": ["pwd", "otp"]}, "otp") is True
    assert amr_includes({"amr": ["hwk"]}, "hwk") is True
    assert amr_includes(claims, "hwk") is __


def test_refuses_an_amr_that_only_looks_like_it():
    """app lets a sign-in approve a payment only when amr lists otp. Some providers send just "mfa"; RFC 8176 says "specific authentication methods used may also be included", so may, not must. Others send a string, or nest a list. Which of these list otp?"""
    shapes = [
        ["pwd", "mfa"], "pwd otp", "otp", ["OTP"], ["hotp"], ["pwd", ["otp"]], ["otp", 7],
        {"otp": True}, [], None,
    ]
    assert [amr_includes({"amr": amr}, "otp") for amr in shapes] == __
    assert amr_includes({}, "otp") is __
    assert amr_includes({"amr": ["pwd", "otp", "mfa"]}, "otp") is True


def check_fresh(claims: dict, started_at: int, now: int, leeway: int) -> None:
    __()


def test_accepts_a_sign_in_made_after_the_request():
    """Implement check_fresh above: a sign-in made after app sent its request at started_at. No auth_time: InvalidToken("auth_time_missing"). Read it with numeric_date (malformed for anything but a number). Later than now + leeway: "issued_in_future". Earlier than started_at - leeway: "stale_auth_time". alice signed in an hour ago; app sends max_age=0 and she takes SIGN_IN_TAKES seconds to sign in again. Chapter 12's check, now - auth_time <= max_age + leeway, refuses her a second later: why does started_at work where now does not?"""
    world = _world()
    alice = _signed_in(world, "alice")
    claims, transaction = _sign_in_for(world, alice, "alice", {"max_age": 0})
    started_at = transaction.started_at
    assert claims["auth_time"] - started_at == __
    world.clock.advance(1)
    now = world.clock.now()
    assert check_fresh(claims, started_at, now, 0) is None
    assert (now - claims["auth_time"] <= 0) is __
    assert check_fresh({"auth_time": started_at}, started_at, now, 0) is None
    assert check_fresh({"auth_time": started_at - 5}, started_at, now, 5) is None
    assert check_fresh({"auth_time": now + 5}, started_at, now, 5) is None
    assert check_fresh({"auth_time": started_at + 0.5}, started_at, now, 0) is None


def test_refuses_a_session_from_before_the_request():
    """This id.example is lax: it ignores prompt=login and max_age, replaying alice's hour-old session, and drops auth_time under max_age=0. Both break a MUST: under prompt=login the provider "MUST reauthenticate the End-User even if the End-User is already authenticated" (Core §3.1.2.3), and past max_age the token "MUST include an auth_time Claim Value". Clients still meet providers that do both. app asks with prompt=login and auth_time as an essential claim, then with max_age=0 alone. What does check_fresh say each time, and to each row?"""
    world = _world(LAX)
    alice = _signed_in(world, "alice")
    essential = {"id_token": {"auth_time": {"essential": True}}}
    login = {"prompt": "login", "claims": essential}
    replayed, transaction = _sign_in_for(world, alice, "alice", login)
    started_at, now = transaction.started_at, world.clock.now()
    assert started_at - replayed["auth_time"] == __
    assert _reason(lambda: check_fresh(replayed, started_at, now, 0)) == __
    dropped, transaction = _sign_in_for(world, alice, "alice", {"max_age": 0})
    assert "auth_time" not in dropped
    missing = _reason(lambda: check_fresh(dropped, transaction.started_at, now, 0))
    assert missing == __
    rows = [
        ({"auth_time": started_at - 6}, 5, "stale_auth_time"),
        ({"auth_time": started_at - 1}, 0, "stale_auth_time"),
        ({"auth_time": 0}, 0, "stale_auth_time"),
        ({"auth_time": now + 6}, 5, __),
        ({"auth_time": True}, 0, __),
        ({"auth_time": str(now)}, 0, "malformed"),
        ({"auth_time": None}, 0, "malformed"),
        ({}, 0, "auth_time_missing"),
    ]
    for claims, leeway, reason in rows:
        assert _reason(lambda: check_fresh(claims, started_at, now, leeway)) == reason


def test_prompt_none_never_shows_a_page():
    """app checks for a session without disturbing the user: prompt=none. Core §3.1.2.1: the provider "MUST NOT display any authentication or consent user interface pages". "An error is returned if an End-User is not already authenticated", and "The error code will typically be login_required, interaction_required, or another code defined in Section 3.1.2.6". If the parameter "contains none with any other value, an error is returned", without naming the code, so the second error is id.example's choice. What does each browser bring back to app's callback?"""
    world = _world()
    nobody, alice = Browser(world.network), _signed_in(world, "alice")
    answer, _ = _authorize(world, nobody, {"prompt": "none"})
    assert [request.url.split("?")[0] for request in nobody.history] == [
        f"{ISSUER}/authorize", REDIRECT_URI,
    ]
    assert _callback_query(nobody)["error"] == __
    answer, _ = _authorize(world, alice, {"prompt": "none"})
    assert sorted(_callback_query(alice)) == __
    answer, _ = _authorize(world, alice, {"prompt": "none login"})
    assert _callback_query(alice)["error"] == __


def test_acr_values_is_a_request_not_a_promise():
    """mallory has only a password. app asks for MFA with acr_values, which requests acr "as a Voluntary Claim". Then it asks again with acr as an essential claim with values: Core §5.5.1.1 says that if this "requirement cannot be met, then the Authorization Server MUST treat that outcome as a failed authentication attempt". Core names no error code for it, but a later OpenID spec says its code "SHALL be used" in exactly this case. What comes back each time? Which acr values does id.example advertise?"""
    world = _world()
    assert _config(world, ISSUER)["acr_values_supported"] == __
    mallory = _signed_in(world, "mallory")
    claims, _ = _sign_in_for(world, mallory, "mallory", {"acr_values": ACR_MFA})
    assert claims["acr"] == __
    essential = {"id_token": {"acr": {"essential": True, "values": [ACR_MFA]}}}
    answer, _ = _authorize(world, mallory, {"claims": essential})
    assert _callback_query(mallory)["error"] == __


def careless_payment_check(claims: dict, payer: str, transaction: Transaction, now: int) -> None:
    """Another team's check before a sign-in may approve a payment at app. payer is the
    sub of app's signed-in user; transaction is the login app started for this payment."""
    if claims.get("iss") != ISSUER:
        raise InvalidToken("wrong_issuer")
    if claims.get("sub") != payer:
        raise InvalidToken("sub_mismatch")
    nonce = claims.get("nonce")
    if not isinstance(nonce, str) or not hmac.compare_digest(
        nonce.encode(), transaction.nonce.encode()
    ):
        raise InvalidToken("nonce_mismatch")
    auth_time = claims.get("auth_time")
    if isinstance(auth_time, bool) or not isinstance(auth_time, int):
        raise InvalidToken("malformed")
    if auth_time < transaction.started_at or auth_time > now:
        raise InvalidToken("stale_auth_time")
    achieved = ACR_RANK.get(claims.get("acr"), MFA_RANK)
    if achieved < MFA_RANK:
        raise InvalidToken("acr_not_met")


def mallorys_query(query: dict) -> dict:
    return __


def test_spot_the_bug_in_careless_payment_check():
    """Spot the bug: app sends FRESH_MFA, acr_values for MFA and max_age=0, and checks the answer with careless_payment_check. Read it. mallory has only a password, so app's own request gets her a token she cannot pay with. But the request crosses her browser, which can change it. Make mallorys_query return the query her browser sends in place of app's, so that a fresh sign-in with her password passes."""
    edited = mallorys_query({"acr_values": ACR_MFA, "max_age": "0", "state": "s"})
    assert isinstance(edited, dict), "mallorys_query returns the query her browser sends: a dict"
    world = _world()
    mallory = _signed_in(world, "mallory")
    honest, transaction = _sign_in_for(world, mallory, "mallory", FRESH_MFA)
    now = world.clock.now()
    assert _reason(lambda: careless_payment_check(honest, "mallory", transaction, now)) == (
        "acr_not_met"
    )
    world.clock.advance(60)
    claims, transaction = _sign_in_for(world, mallory, "mallory", FRESH_MFA, edit=mallorys_query)
    assert claims["amr"] == ["pwd"] and claims.get("acr") not in ACR_RANK
    assert careless_payment_check(claims, "mallory", transaction, world.clock.now()) is None


def check_level(claims: dict, policy: dict, level: str) -> None:
    __()


def payment_check(claims: dict, payer: str, transaction: Transaction, now: int) -> None:
    """careless_payment_check with its auth_time checks replaced by your check_fresh and
    its acr check by your check_level."""
    if claims.get("iss") != ISSUER:
        raise InvalidToken("wrong_issuer")
    if claims.get("sub") != payer:
        raise InvalidToken("sub_mismatch")
    nonce = claims.get("nonce")
    if not isinstance(nonce, str) or not hmac.compare_digest(
        nonce.encode(), transaction.nonce.encode()
    ):
        raise InvalidToken("nonce_mismatch")
    check_fresh(claims, transaction.started_at, now, 0)
    check_level(claims, POLICY, "mfa")


def test_accepts_the_level_app_agreed_with_each_issuer():
    """Implement check_level above, the fix. policy maps each issuer to app's levels, and each level to the exact acr strings that meet it there. Raise InvalidToken("acr_not_met") unless claims["acr"] is a string in policy[claims["iss"]][level]; an issuer or level the policy does not list meets nothing. alice pays with her one-time password; at other-id.example a password is all app needs for "any"."""
    world = _world()
    alice = _signed_in(world, "alice")
    claims, transaction = _sign_in_for(world, alice, "alice", FRESH_MFA, factors=("pwd", "otp"))
    assert payment_check(claims, "alice", transaction, world.clock.now()) is None
    assert check_level(claims, POLICY, "any") is None
    elsewhere = _signed_in(world, "alice", issuer=OTHER_ISSUER)
    asked = {"acr_values": ACR_PASSWORD}
    other, _ = _sign_in_for(world, elsewhere, "alice", asked, issuer=OTHER_ISSUER)
    assert (other["iss"], other["acr"]) == __
    assert check_level(other, POLICY, "any") is None


def test_refuses_a_level_app_never_agreed_to():
    """Your fix against mallory's edited request, and hidden ones: acr "0", which Core §2 says "SHOULD NOT be used to authorize access to any resource of any monetary value"; an acr id.example never defined; acr as a number, a boolean, a list or in capitals. Then alice's real MFA sign-in at other-id.example: app agreed nothing about what its acr means, so it is not app's mfa. What does each get?"""
    world = _world()
    mallory = _signed_in(world, "mallory")
    claims, transaction = _sign_in_for(world, mallory, "mallory", FRESH_MFA, edit=mallorys_query)
    now = world.clock.now()
    assert "acr" not in claims
    assert _reason(lambda: payment_check(claims, "mallory", transaction, now)) == __
    for acr in ("0", "urn:toy:acr:hwk", 2, True, [ACR_MFA], ACR_MFA.upper(), "", None):
        tampered = {**claims, "acr": acr}
        assert _reason(lambda: payment_check(tampered, "mallory", transaction, now)) == (
            "acr_not_met"
        )
    elsewhere = _signed_in(world, "alice", issuer=OTHER_ISSUER)
    other, _ = _sign_in_for(
        world, elsewhere, "alice", FRESH_MFA, factors=("pwd", "otp"), issuer=OTHER_ISSUER,
    )
    assert other["acr"] == ACR_MFA
    assert _reason(lambda: check_level(other, POLICY, "mfa")) == __
    assert _reason(lambda: check_level({**other, "iss": [ISSUER]}, POLICY, "mfa")) == (
        "acr_not_met"
    )
