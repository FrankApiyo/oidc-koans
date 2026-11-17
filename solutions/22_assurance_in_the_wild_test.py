"""Assurance in the wild: how providers report it differently.

Core gives three channels, acr, amr and auth_time, and leaves meaning to
agreement: for acr, "Parties using this claim will need to agree upon the
meanings of the values used". Providers fill them in differently. As of
November 2026 (vendors change this; check your provider):

- Keycloak puts the level in acr, mapped from a level of authentication,
  and sends auth_time by default; amr comes only from an opt-in mapper.
- WSO2 Identity Server sends acr, set by an adaptive script, and amr of
  authenticator names like BasicAuthenticator and totp unless mapped to RFC
  8176 values; yet its 7.3.0 ID token table lists neither acr nor auth_time.
- Azure AD B2C names the policy that ran, in tfp by default, keeping acr
  "only for backward-compatibility": a flow's name, not a level. No amr.
- Microsoft Entra ID v2.0 ID tokens have no acr; auth_time is optional, and
  its pages disagree on whether amr (rsa, ngcmfa, pwd, mfa...) comes unasked.
  Step-up runs on an auth-context claim, acrs, and insufficient_claims.

All four document prompt=login as forcing a sign-in (WSO2 up to 6.1.0).
Only Keycloak documents max_age. B2C and Entra do not document
acr_values. So a client keeps a rule per issuer: which claim carries a
level there and which values count. Anything else shows nothing.

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
# Each profile plays its provider as its documentation stood in November 2026. Where the
# docs promise nothing (max_age at three of them, acr_values at two), the toy does not do it.
KEYCLOAK = Profile(
    assurance_claim="acr", acr_alone_reauthenticates=False, auth_time_when_max_age_zero=True,
    honours_prompt_login=True, honours_max_age=True, assurance_unasked=True, amr_names=None,
)
WSO2 = Profile(
    assurance_claim="acr", acr_alone_reauthenticates=False, auth_time_when_max_age_zero=False,
    honours_prompt_login=True, honours_max_age=False, assurance_unasked=True,
    amr_names=(("pwd", "BasicAuthenticator"), ("otp", "totp")), auth_time_unasked=False,
)
B2C = Profile(
    assurance_claim="tfp", acr_alone_reauthenticates=False, auth_time_when_max_age_zero=True,
    honours_prompt_login=True, honours_max_age=False, assurance_unasked=True,
    fixed_assurance=B2C_FLOW, amr_names=None, honours_acr_values=False,
)
ENTRA = Profile(
    assurance_claim="amr", acr_alone_reauthenticates=False, auth_time_when_max_age_zero=False,
    honours_prompt_login=True, honours_max_age=False,
    amr_names=(("pwd", "pwd"), ("otp", "totp"), ("mfa", "mfa")), honours_acr_values=False,
    auth_time_unasked=False,
)
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
    iss = claims.get("iss")
    rule = rules.get(iss, {}).get(level) if isinstance(iss, str) else None
    if rule is None:
        return False
    claim, accepted = rule
    if claim == "amr":
        amr = claims.get("amr")
        return (isinstance(amr, list) and all(isinstance(m, str) for m in amr)
                and any(method in amr for method in accepted))
    value = claims.get(claim)
    return isinstance(value, str) and value in accepted


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
    """alice signs in with her password and a one-time password, and app asks for MFA with acr_values. Each provider here is played as its docs describe it, as of November 2026. What does each put in acr, amr or tfp? At which can app see, in a standard claim, that a second factor was used?"""
    asked = {"acr_values": ACR_MFA}
    reported = {
        name: _reported(_sign_in_for(_world(profile), asked), ("acr", "amr", "tfp"))
        for name, profile in PROFILES.items()
    }
    assert reported == {
        "Keycloak": {"acr": ACR_MFA},
        "WSO2 Identity Server": {"acr": ACR_MFA, "amr": ["BasicAuthenticator", "totp"]},
        "Azure AD B2C": {"tfp": "B2C_1_signin"},
        "Microsoft Entra ID": {"amr": ["pwd", "totp", "mfa"]},
    }
    standard = sorted(
        name for name, claims in reported.items()
        if claims.get("acr") == ACR_MFA or "mfa" in claims.get("amr", [])
    )
    assert standard == ["Keycloak", "Microsoft Entra ID", "WSO2 Identity Server"]


def test_a_flow_name_is_not_a_level():
    """B2C's tfp is "The name of the policy that was used to acquire the ID token", and "The value of acr is only provided for backward-compatibility". Whether that policy asked for a second factor is set in the policy, not in the token. alice signs in once with her password alone and once with both factors; app sends acr_values for MFA each time, which B2C does not document. Can app tell the two apart from tfp?"""
    world = _world(B2C)
    weak = _sign_in_for(world, {"acr_values": ACR_MFA}, ("pwd",))
    strong = _sign_in_for(world, {"acr_values": ACR_MFA}, ("pwd", "otp"))
    assert (weak["tfp"], strong["tfp"]) == (B2C_FLOW, B2C_FLOW)
    assert (weak["tfp"] == strong["tfp"]) is True
    assert ("acr" in weak, "amr" in weak) == (False, False)


def test_amr_names_outside_rfc_8176():
    """RFC_8176 holds the method names RFC 8176 §2 registers. WSO2 reports its authenticators' own names unless an admin maps them; Entra documents ENTRA_AMR, among others. Which names are not registered? Entra's wiaormfa is its own value, not RFC 8176's mfa: does a check for "mfa" in the list count it, and one for "mfa" in the joined text?"""
    wso2 = _sign_in_for(_world(WSO2))["amr"]
    assert sorted(set(wso2) - RFC_8176) == ["BasicAuthenticator", "totp"]
    assert sorted(set(ENTRA_AMR) - RFC_8176) == ["fed", "ngcmfa", "none", "rsa", "wiaormfa"]
    assert ("mfa" in ["pwd", "wiaormfa"]) is False
    assert ("mfa" in " ".join(["pwd", "wiaormfa"])) is True


def test_what_forces_a_fresh_sign_in():
    """alice signed in with her password an hour ago. app sends one of three requests: prompt=login, max_age=0, or acr_values for MFA. Each provider is played as documented: where its docs promise nothing, it does nothing. Which requests get a sign-in page at each? Which one works at all four?"""
    requests = {"prompt=login": {"prompt": "login"}, "max_age=0": {"max_age": 0},
                "acr_values": {"acr_values": ACR_MFA}}
    asked = {
        name: tuple(_asks_to_sign_in(profile, extra) for extra in requests.values())
        for name, profile in PROFILES.items()
    }
    assert asked == {
        "Keycloak": (True, True, True),
        "WSO2 Identity Server": (True, False, True),
        "Azure AD B2C": (True, False, False),
        "Microsoft Entra ID": (True, False, False),
    }
    everywhere = [request for i, request in enumerate(requests)
                  if all(row[i] for row in asked.values())]
    assert everywhere == ["prompt=login"]


def test_what_goes_missing():
    """A plain login: alice signs in with both factors and app asks for nothing more. Which of acr, amr, tfp and auth_time does each send? Entra is played sending amr unasked, one reading of pages that disagree. Its auth_time is an optional claim; asking for it as an essential claim stands in here for configuring it. Does a token without acr mean no second factor was used?"""
    plain = {name: sorted(_reported(_sign_in_for(_world(profile))))
             for name, profile in PROFILES.items()}
    assert plain == {
        "Keycloak": ["acr", "auth_time"],
        "WSO2 Identity Server": ["acr", "amr"],
        "Azure AD B2C": ["auth_time", "tfp"],
        "Microsoft Entra ID": ["amr"],
    }
    essential = {"claims": {"id_token": {"auth_time": {"essential": True}}}}
    entra = _sign_in_for(_world(ENTRA), essential)
    assert "auth_time" in entra
    assert ("acr" in entra, "mfa" in entra["amr"]) == (False, True)


def test_accepts_mfa_however_each_issuer_reports_it():
    """Implement meets above: True when claims show level by the rule app keeps for claims["iss"]. rules[iss][level] is (claim, accepted). For "amr", the claim must be a list of strings holding one of accepted; for any other claim, a string that is one of accepted. An issuer or level the rules do not list shows nothing. id.example is played as Keycloak, other-id.example as Entra. alice signs in at each with both factors, then with her password alone."""
    world = _world(KEYCLOAK, ENTRA)
    keycloak = _sign_in_for(world, {"acr_values": ACR_MFA})
    entra = _sign_in_for(world, issuer=OTHER_ISSUER)
    assert (keycloak["iss"], keycloak["acr"]) == (ISSUER, ACR_MFA)
    assert meets(keycloak, RULES, "mfa") is True
    assert meets(entra, RULES, "mfa") is True
    weak_keycloak = _sign_in_for(world, {"acr_values": ACR_PASSWORD}, ("pwd",))
    weak_entra = _sign_in_for(world, factors=("pwd",), issuer=OTHER_ISSUER)
    assert meets(weak_keycloak, RULES, "mfa") is False
    assert meets(weak_entra, RULES, "mfa") is False


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
    assert [meets(claims, RULES, "mfa") for claims in rows] == [False] * 16
    numbered = {ISSUER: {"gold": ("acr", frozenset({"2"}))}}
    assert meets({"iss": ISSUER, "acr": 2}, numbered, "gold") is False
    assert meets({"iss": ISSUER, "acr": "2"}, numbered, "gold") is True
    assert meets({"iss": ISSUER, "acr": ACR_MFA}, RULES, "hwk") is False
    assert meets({"iss": ISSUER, "acr": ACR_MFA}, RULES, "mfa") is True
    assert meets({"iss": OTHER_ISSUER, "amr": ["wiaormfa", "mfa"]}, RULES, "mfa") is True


def test_a_step_up_challenge_that_is_not_rfc_9470():
    """Entra's step-up is a claims challenge: a 401 whose error "Must be "insufficient_claims" when a claims challenge should be generated", with a base64 claims request, sent only to clients that declare the "cp1" capability. This one is shaped like Entra's documented example. Would a client that waits for RFC 9470's error step up? What does it ask for? And an acrs value in a token: "If no Conditional Access policy is assigned to an ACRS value the claim might still be issued". Is acrs "c1" proof of a fresh second factor?"""
    request = {"access_token": {"acrs": {"essential": True, "value": "c1"}}}
    encoded = base64.b64encode(json.dumps(request, separators=(",", ":")).encode()).decode()
    challenge = parse_challenge(f'Bearer error="insufficient_claims", claims="{encoded}"')
    assert challenge["error"] == "insufficient_claims"
    rfc_9470 = challenge["error"] == "insufficient_user_authentication" or "acr_values" in challenge
    assert rfc_9470 is False
    asked = json.loads(base64.b64decode(challenge["claims"]))
    assert asked == {"access_token": {"acrs": {"essential": True, "value": "c1"}}}
    proves_fresh_mfa = False
    assert proves_fresh_mfa is False
