"""Assurance in the wild: how providers report it differently.

Core gives three channels, acr, amr and auth_time, and leaves meaning to
agreement: for acr, "Parties using this claim will need to agree upon the
meanings of the values used". Providers fill them in differently. As of
November 2026 (vendors change this; check your provider):

- Keycloak puts the level in acr, mapped from a level of authentication,
  and sends auth_time by default; amr needs an opt-in mapper.
- WSO2 Identity Server sends acr, set by an adaptive script, and amr of
  authenticator names like BasicAuthenticator and totp unless mapped to RFC
  8176 values; yet its 7.3.0 ID token table lists neither acr nor auth_time.
- Azure AD B2C names the policy that ran, in tfp by default (acr "is only
  provided for backward-compatibility"): a flow, not a level. No amr listed.
- Microsoft Entra ID v2.0 ID tokens have no acr; auth_time is optional, and
  its pages disagree on whether amr (rsa, ngcmfa, pwd, mfa...) comes unasked.
  Step-up runs on an auth-context claim, acrs, and insufficient_claims.

Only prompt=login is documented as forcing a sign-in at all four (WSO2's
up to 6.1.0). Only Keycloak documents max_age; where docs are silent, check
your provider. A client keeps a rule per issuer, which claim carries a
level there and which values count, and takes anything else as nothing.

A common mistake: reading acr from every provider as if it meant the same.

Read more:
  https://www.keycloak.org/docs/latest/server_admin/index.html#_step-up-flow
  https://is.docs.wso2.com/en/7.3.0/guides/authentication/conditional-auth/acr-and-amr/
  https://learn.microsoft.com/en-us/azure/active-directory-b2c/tokens-overview#claims
  https://learn.microsoft.com/en-us/entra/identity-platform/claims-challenge
"""

import base64
import json
from dataclasses import dataclass

from conftest import __
from toy.client import STATE_COOKIE, bind_state, finish_login, parse_challenge, start_login
from toy.clock import Clock
from toy.http import Browser, FakeNetwork, Request, Response
from toy.keys import EC_1
from toy.provider import ACR_MFA, ACR_PASSWORD, Profile, Provider

ISSUER = "https://id.example"
OTHER_ISSUER = "https://other-id.example"
APP = "https://app.example"
REDIRECT_URI = f"{APP}/callback"
CLIENT_ID = "app"
SIGN_IN_TAKES = 20
B2C_FLOW = "B2C_1_signin"
# Each profile plays one configuration its provider's docs describe, as of November 2026.
# Fields those docs leave open keep the toy's spec behaviour, and no koan asserts them:
# PROMISED and SENT below say where to check your provider.
KEYCLOAK = Profile(
    assurance_claim="acr", acr_alone_reauthenticates=False, auth_time_when_max_age_zero=True,
    honours_prompt_login=True, honours_max_age=True, assurance_unasked=True, amr_names=None,
)
WSO2 = Profile(
    assurance_claim="acr", acr_alone_reauthenticates=False, auth_time_when_max_age_zero=True,
    honours_prompt_login=True, honours_max_age=True, assurance_unasked=True,
    amr_names=(("pwd", "BasicAuthenticator"), ("otp", "totp")),
)
B2C = Profile(
    assurance_claim="tfp", acr_alone_reauthenticates=False, auth_time_when_max_age_zero=True,
    honours_prompt_login=True, honours_max_age=True, assurance_unasked=True,
    fixed_assurance=B2C_FLOW, amr_names=None,
)
ENTRA = Profile(
    assurance_claim="amr", acr_alone_reauthenticates=False, auth_time_when_max_age_zero=True,
    honours_prompt_login=True, honours_max_age=True,
    amr_names=(("pwd", "pwd"), ("otp", "totp"), ("mfa", "mfa")), auth_time_unasked=False,
)
FORCES, CHECK = "forces a sign-in", "check your provider"
DEFAULT, CONFIGURED, ABSENT = "sent by default", "only when configured", "not sent"
# What each provider's docs say, as of November 2026: a request that re-authenticates an
# hour-old password session, and what a plain sign-in's ID token carries.
PROMISED = {
    "Keycloak": {"prompt=login": FORCES, "max_age": FORCES, "acr_values": FORCES},
    "WSO2 Identity Server": {"prompt=login": FORCES, "max_age": CHECK, "acr_values": CHECK},
    "Azure AD B2C": {"prompt=login": FORCES, "max_age": CHECK, "acr_values": CHECK},
    "Microsoft Entra ID": {"prompt=login": FORCES, "max_age": CHECK, "acr_values": CHECK},
}
SENT = {
    "Keycloak": {"acr": DEFAULT, "amr": CONFIGURED, "auth_time": DEFAULT},
    "WSO2 Identity Server": {"acr": CHECK, "amr": DEFAULT, "auth_time": CHECK},
    "Azure AD B2C": {"acr": CHECK, "amr": CHECK, "auth_time": DEFAULT},
    "Microsoft Entra ID": {"acr": ABSENT, "amr": CHECK, "auth_time": CONFIGURED},
}
PROFILES = {
    "Keycloak": KEYCLOAK, "WSO2 Identity Server": WSO2, "Azure AD B2C": B2C,
    "Microsoft Entra ID": ENTRA,
}
RFC_8176 = frozenset({
    "face", "fpt", "geo", "hwk", "iris", "kba", "mca", "mfa", "otp", "pin", "pwd", "rba",
    "retina", "sc", "sms", "swk", "tel", "user", "vbm", "wia",
})
ENTRA_AMR = ("pwd", "rsa", "otp", "fed", "wia", "mfa", "ngcmfa", "wiaormfa", "none")
RULES = {
    ISSUER: {"mfa": ("acr", frozenset({ACR_MFA}))},
    OTHER_ISSUER: {"mfa": ("amr", frozenset({"mfa"}))},
}


def meets(claims: dict, rules: dict, level: str) -> bool:
    __()


@dataclass(frozen=True)
class World:
    clock: Clock
    network: FakeNetwork
    providers: dict


def _world(profile: Profile, other: Profile | None = None) -> World:
    """id.example playing profile, and other-id.example playing other if given, each with
    app as a client and alice, who has a password and a one-time password, as a user."""
    clock, network = Clock(), FakeNetwork()
    providers = {ISSUER: Provider(ISSUER, clock=clock, network=network, profile=profile)}
    if other is not None:
        providers = {**providers, OTHER_ISSUER: Provider(
            OTHER_ISSUER, clock=clock, network=network, signing_key=EC_1, kid="o1",
            profile=other,
        )}
    for op in providers.values():
        op.register_client(CLIENT_ID, [REDIRECT_URI])
        op.add_user("alice", "alice@example.com", True, "alice-password", factors=("otp",))
    network.mount(APP, lambda request: Response(200, {}, "callback reached"))
    return World(clock, network, providers)


def _config(world: World, issuer: str) -> dict:
    return world.network.send(Request("GET", f"{issuer}/.well-known/openid-configuration")).body


def _browser(world: World, factors=("pwd",), issuer: str = ISSUER) -> Browser:
    """A browser in which alice has just signed in at issuer with factors."""
    browser = Browser(world.network)
    world.providers[issuer].sign_in(browser, "alice", factors)
    return browser


def _start(world: World, browser: Browser, extra: dict, issuer: str):
    url, transaction = start_login(
        issuer_config=_config(world, issuer), client_id=CLIENT_ID, redirect_uri=REDIRECT_URI,
        now=world.clock.now(), extra=extra,
    )
    return browser.get(url), url, transaction


def _sign_in_for(world: World, extra: dict = None, factors=("pwd", "otp"),
                 issuer: str = ISSUER) -> dict:
    """alice signs in at issuer with factors, then app logs in with extra parameters. If
    the provider asks for a sign-in, she gives it the same factors and reloads the same
    authorize URL. Returns the claims finish_login gives app."""
    browser = _browser(world, factors, issuer)
    answer, url, transaction = _start(world, browser, extra or {}, issuer)
    if answer.status == 401:
        world.clock.advance(SIGN_IN_TAKES)
        world.providers[issuer].sign_in(browser, "alice", factors)
        browser.get(url)
    config = _config(world, issuer)
    bound = {STATE_COOKIE: bind_state(None, transaction.state)}
    return finish_login(
        transaction=transaction, callback=Request("GET", browser.history[-1].url, cookies=bound),
        issuer_config=config, client_id=CLIENT_ID,
        jwks=world.network.send(Request("GET", config["jwks_uri"])).body,
        network=world.network, now=world.clock.now(),
    )


def _asks_to_sign_in(profile: Profile, extra: dict) -> bool:
    """alice signed in with her password an hour ago. Does app's request with extra get a
    sign-in page (True) or a code at once (False)?"""
    world = _world(profile)
    browser = _browser(world)
    world.clock.advance(3600)
    answer, _, _ = _start(world, browser, extra, ISSUER)
    return answer.status == 401


def _reported(claims: dict, names=("acr", "amr", "tfp", "auth_time")) -> dict:
    return {name: claims[name] for name in names if name in claims}


def test_each_provider_reports_assurance_its_own_way():
    """alice signs in with her password and a one-time password, and app asks for MFA with acr_values. Each provider is played in one configuration its docs describe, as of November 2026: Keycloak's default client scopes; WSO2 as its ACR and AMR guide has it; B2C with tfp, the default its token reference names; Entra with amr asked for as an optional claim. What does each put in acr, amr or tfp? At which can app see, in a standard claim, that a second factor was used?"""
    asked = {"acr_values": ACR_MFA}
    reported = {
        name: _reported(_sign_in_for(_world(profile), asked), ("acr", "amr", "tfp"))
        for name, profile in PROFILES.items()
    }
    assert reported == __
    standard = sorted(
        name for name, claims in reported.items()
        if claims.get("acr") == ACR_MFA or "mfa" in claims.get("amr", [])
    )
    assert standard == __


def test_a_flow_name_is_not_a_level():
    """B2C's tfp is "The name of the policy that was used to acquire the ID token", and "The value of acr is only provided for backward-compatibility". Whether that policy asked for a second factor is set in the policy, not in the token. alice signs in once with her password alone and once with both factors. Can app tell the two apart from tfp?"""
    world = _world(B2C)
    weak = _sign_in_for(world, factors=("pwd",))
    strong = _sign_in_for(world, factors=("pwd", "otp"))
    assert (weak["tfp"], strong["tfp"]) == __
    assert (weak["tfp"] == strong["tfp"]) is __
    assert ("acr" in weak, "amr" in weak) == __


def test_amr_names_outside_rfc_8176():
    """RFC_8176 holds the method names RFC 8176 §2 registers. WSO2 reports its authenticators' own names unless an admin maps them; Entra documents ENTRA_AMR, among others. Which names are not registered? Entra's wiaormfa is its own value, not RFC 8176's mfa: does a check for "mfa" in the list count it, and one for "mfa" in the joined text?"""
    wso2 = _sign_in_for(_world(WSO2))["amr"]
    assert sorted(set(wso2) - RFC_8176) == __
    assert sorted(set(ENTRA_AMR) - RFC_8176) == __
    assert ("mfa" in ["pwd", "wiaormfa"]) is __
    assert ("mfa" in " ".join(["pwd", "wiaormfa"])) is __


def test_what_forces_a_fresh_sign_in():
    """alice signed in with her password an hour ago, and app wants a fresh sign-in. PROMISED says what each provider's docs say three requests do then: prompt=login; max_age, which only Keycloak documents; acr_values for a level above the session's. Which request may app rely on at all four? What may it assume about max_age at Entra? Then the request at a toy Keycloak, whose docs promise all three: which get a sign-in page? Wherever a sign-in is not promised, the check of chapter 20 still decides: auth_time against the time app sent its request."""
    everywhere = [request for request in PROMISED["Keycloak"]
                  if all(promised[request] == FORCES for promised in PROMISED.values())]
    assert everywhere == __
    assert PROMISED["Microsoft Entra ID"]["max_age"] == __
    requests = [{"prompt": "login"}, {"max_age": 60}, {"acr_values": ACR_MFA}]
    asked = [_asks_to_sign_in(KEYCLOAK, extra) for extra in requests]
    assert asked == __


def test_what_goes_missing():
    """SENT says what each provider's docs say a plain sign-in's ID token carries. WSO2's guide puts acr in the ID token but its 7.3.0 claims table does not, so that is check your provider. So are B2C's acr, whose pages disagree on tfp against acr, B2C's amr, which its claims table leaves out, and Entra's amr, whose pages disagree. Entra's v2.0 tokens document no acr. Where may app count on auth_time without configuring anything? Where on amr? Then a toy Entra configured to send amr: alice signs in with both factors. Its auth_time is an optional claim; asking for it as an essential claim stands in here for configuring it. Does a token without acr mean no second factor was used?"""
    with_auth_time = [name for name, sent in SENT.items() if sent["auth_time"] == DEFAULT]
    assert with_auth_time == __
    with_amr = [name for name, sent in SENT.items() if sent["amr"] == DEFAULT]
    assert with_amr == __
    entra = _sign_in_for(_world(ENTRA))
    assert sorted(_reported(entra)) == __
    essential = {"claims": {"id_token": {"auth_time": {"essential": True}}}}
    assert "auth_time" in _sign_in_for(_world(ENTRA), essential)
    assert ("acr" in entra, "mfa" in entra["amr"]) == __


def test_accepts_mfa_however_each_issuer_reports_it():
    """Implement meets above: True when claims show level by the rule app keeps for claims["iss"]. rules[iss][level] is (claim, accepted). For "amr", the claim must be a list of strings holding one of accepted; for any other claim, a string that is one of accepted. An issuer or level the rules do not list shows nothing. id.example is played as Keycloak, other-id.example as Entra. alice signs in at each with both factors, then with her password alone."""
    world = _world(KEYCLOAK, ENTRA)
    keycloak = _sign_in_for(world, {"acr_values": ACR_MFA})
    entra = _sign_in_for(world, issuer=OTHER_ISSUER)
    assert (keycloak["iss"], keycloak["acr"]) == __
    assert meets(keycloak, RULES, "mfa") is True
    assert meets(entra, RULES, "mfa") is __
    weak_keycloak = _sign_in_for(world, {"acr_values": ACR_PASSWORD}, ("pwd",))
    weak_entra = _sign_in_for(world, factors=("pwd",), issuer=OTHER_ISSUER)
    assert meets(weak_keycloak, RULES, "mfa") is __
    assert meets(weak_entra, RULES, "mfa") is __


def test_refuses_assurance_an_issuer_never_promised():
    """Each row is something a token could carry. The rules say Keycloak's level is in acr and Entra's in amr. Keycloak can send acr "0" once a session's level has lapsed; Entra's wiaormfa is not the value mfa; B2C's flow name is no level; an issuer with no rule shows nothing, however strong its claim looks. Which rows meet "mfa"? If a Keycloak realm names a level "2", does the number 2 meet it?"""
    rows = [
        {"iss": OTHER_ISSUER, "amr": ["pwd", "wiaormfa"]},
        {"iss": OTHER_ISSUER, "amr": "mfa"},
        {"iss": OTHER_ISSUER, "amr": ["pwd", "MFA"]},
        {"iss": OTHER_ISSUER, "amr": []},
        {"iss": OTHER_ISSUER, "amr": ["pwd", ["mfa"]]},
        {"iss": OTHER_ISSUER, "amr": ["mfa", 7]},
        {"iss": OTHER_ISSUER, "acr": ACR_MFA, "amr": ["pwd"]},
        {"iss": ISSUER, "amr": ["pwd", "otp", "mfa"]},
        {"iss": ISSUER, "acr": "0"},
        {"iss": ISSUER, "acr": ""},
        {"iss": ISSUER, "acr": [ACR_MFA]},
        {"iss": ISSUER, "acr": {"value": ACR_MFA}},
        {"iss": ISSUER, "tfp": B2C_FLOW},
        {"iss": "https://mallory.example", "acr": ACR_MFA, "amr": ["mfa"]},
        {"acr": ACR_MFA},
        {"iss": [ISSUER], "acr": ACR_MFA},
    ]
    assert [meets(claims, RULES, "mfa") for claims in rows] == __
    numbered = {ISSUER: {"gold": ("acr", frozenset({"2"}))}}
    assert meets({"iss": ISSUER, "acr": 2}, numbered, "gold") is __
    assert meets({"iss": ISSUER, "acr": "2"}, numbered, "gold") is True
    assert meets({"iss": ISSUER, "acr": ACR_MFA}, RULES, "hwk") is False
    assert meets({"iss": ISSUER, "acr": ACR_MFA}, RULES, "mfa") is True
    assert meets({"iss": OTHER_ISSUER, "amr": ["wiaormfa", "mfa"]}, RULES, "mfa") is True


def test_a_step_up_challenge_that_is_not_rfc_9470():
    """Entra's step-up is a claims challenge: a 401 whose error "Must be "insufficient_claims" when a claims challenge should be generated", with a base64 claims request, sent only to clients that declare the "cp1" capability. This one keeps only the error and claims auth-params of such a challenge. Would a client that waits for RFC 9470's error step up? What does it ask for, and in which token?"""
    request = {"access_token": {"acrs": {"essential": True, "value": "c1"}}}
    encoded = base64.b64encode(json.dumps(request, separators=(",", ":")).encode()).decode()
    challenge = parse_challenge(f'Bearer error="insufficient_claims", claims="{encoded}"')
    assert challenge["error"] == __
    rfc_9470 = challenge["error"] == "insufficient_user_authentication" or "acr_values" in challenge
    assert rfc_9470 is __
    asked = json.loads(base64.b64decode(challenge["claims"]))
    assert asked == __
    assert sorted(asked) == __
