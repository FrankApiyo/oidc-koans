"""Claims and scopes; the claims parameter and essential claims.

Scope values ask for sets of claims (Core §5.4): email asks for email and
email_verified, profile for name and its kin. They "are treated by
Authorization Servers as Voluntary Claims". In the code flow, where an
access token is issued, they come "from the UserInfo Endpoint"; only when
none is (response_type=id_token) are they "returned in the ID Token".
Scope values "not understood by an implementation SHOULD be ignored"
(§3.1.2.1).

The claims parameter (Core §5.5) asks for single claims, in its id_token
member, its userinfo member, or both. Each claim asks with null, the
default manner, or an object with essential, value or values. Support "is
OPTIONAL": look for claims_parameter_supported in Discovery first.

Essential does not oblige the provider: "the Authorization Server MUST NOT
generate an error when Claims are not returned, whether they are Essential
or Voluntary, unless otherwise specified in the description of the
specific claim". sub with a value is one exception: "a mismatch MUST cause
the authentication to fail"; an essential acr with values is another. A
claim not returned "SHOULD be omitted", not sent as null or "" (§5.3.2).

A common mistake: counting on a requested claim, essential or not. Look
for it, and decide what to do without it.

Read more:
  https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
  https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
  https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
"""

from dataclasses import dataclass

from conftest import __
from toy.client import Transaction, exchange_code, fetch_userinfo, start_login, validate_id_token
from toy.clock import Clock
from toy.http import Browser, FakeNetwork, Request, Response
from toy.provider import Provider

ISSUER = "https://id.example"
APP = "https://app.example"
REDIRECT_URI = f"{APP}/callback"
CLIENT_ID = "app"


@dataclass(frozen=True)
class World:
    clock: Clock
    network: FakeNetwork
    provider: Provider
    config: dict
    jwks: dict


def _world() -> World:
    """id.example with one client, app; alice and bob have accounts there."""
    clock, network = Clock(), FakeNetwork()
    provider = Provider(ISSUER, clock=clock, network=network)
    provider.register_client(CLIENT_ID, [REDIRECT_URI])
    provider.add_user("alice", "alice@example.com", True, "alice-password")
    provider.add_user("bob", "bob@example.com", False, "bob-password")
    config = network.send(Request("GET", f"{ISSUER}/.well-known/openid-configuration")).body
    jwks = network.send(Request("GET", config["jwks_uri"])).body
    network.mount(APP, lambda request: Response(200, {}, "callback reached"))
    return World(clock, network, provider, config, jwks)


def _signed_in(world: World, sub: str) -> Browser:
    browser = Browser(world.network)
    world.provider.sign_in(browser, sub, ("pwd",))
    return browser


def _authorize(world: World, browser: Browser, scope: str, **extra) -> tuple[dict, Transaction]:
    """What app's callback receives for this request, and app's transaction."""
    url, transaction = start_login(
        issuer_config=world.config, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI,
        now=world.clock.now(), scope=scope, extra=extra or None,
    )
    answer = world.network.send(Request("GET", url, cookies=browser.cookies(ISSUER)))
    returned = Request("GET", answer.location).query if answer.location else answer.body
    return returned, transaction


def _login(world: World, sub: str, scope: str = "openid email", **extra) -> tuple[dict, dict]:
    """sub signs in to app: the validated ID token claims, and what UserInfo returns."""
    returned, transaction = _authorize(world, _signed_in(world, sub), scope, **extra)
    tokens = exchange_code(
        issuer_config=world.config, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI,
        code=returned["code"], code_verifier=transaction.code_verifier, network=world.network,
    )
    id_claims = validate_id_token(
        tokens["id_token"], issuer=ISSUER, client_id=CLIENT_ID, jwks=world.jwks,
        now=world.clock.now(), nonce=transaction.nonce,
    )
    userinfo = fetch_userinfo(
        issuer_config=world.config, access_token=tokens["access_token"], network=world.network
    )
    return id_claims, userinfo


def test_the_email_scope_asks_for_two_claims():
    """Core §5.4: the email scope value "requests access to the email and email_verified Claims". UserInfo always adds sub. Which claims come back with each scope?"""
    world = _world()
    _, with_email = _login(world, "alice", scope="openid email")
    _, without = _login(world, "alice", scope="openid")
    assert set(with_email) == _a({"sub", "email", "email_verified"})
    assert set(without) == _a({"sub"})


def test_scope_claims_come_from_userinfo_in_the_code_flow():
    """The code flow issues an access token, so the claims that scope=openid email asks for come from UserInfo. This provider's ID token puts in its ID token only the claims an ID token needs, its own choice. Where is email?"""
    world = _world()
    id_claims, userinfo = _login(world, "alice", scope="openid email")
    assert ("email" in id_claims) is _a(False)
    assert userinfo["email"] == _a("alice@example.com")


def test_the_claims_parameter_can_ask_for_email_in_the_id_token():
    """Core §5.5: the claims parameter is a JSON object whose id_token member lists claims wanted in the ID token. Request email there in the default manner, with null. First check that this provider supports the parameter: which Discovery member says so?"""
    world = _world()
    assert world.config[_a("claims_parameter_supported")] is True
    claims = _a({"id_token": {"email": None}})
    id_claims, _ = _login(world, "alice", scope="openid", claims=claims)
    assert id_claims["email"] == "alice@example.com"
    assert "email_verified" not in id_claims


def test_the_userinfo_member_adds_to_the_scope():
    """The userinfo member's claims "are being requested to be added to any Claims that are being requested using scope values" (Core §5.5). With scope=openid, what does UserInfo return when the userinfo member asks for email alone?"""
    world = _world()
    _, userinfo = _login(world, "alice", scope="openid", claims={"userinfo": {"email": None}})
    assert set(userinfo) == _a({"sub", "email"})


def test_an_unmet_essential_claim_is_not_an_error():
    """app asks for phone_number as essential. alice has no phone number at this provider. Core §5.5.1: the provider "MUST NOT generate an error when Claims are not returned". What reaches app's callback, and what is in the ID token?"""
    world = _world()
    claims = {"id_token": {"phone_number": {"essential": True}}}
    returned, _ = _authorize(world, _signed_in(world, "alice"), "openid", claims=claims)
    assert ("code" in returned, "error" in returned) == _a((True, False))
    id_claims, _ = _login(world, "alice", scope="openid", claims=claims)
    assert ("phone_number" in id_claims) is _a(False)


def missing_essential_claims(claims: dict, requested: dict) -> tuple[str, ...]:
    # >>> answer
    return tuple(sorted(
        name for name, request in requested.items()
        if isinstance(request, dict) and request.get("essential") is True
        and claims.get(name) is None
    ))
    # <<<


def test_names_the_essential_claims_that_did_not_arrive():
    """Implement missing_essential_claims above. requested is one member of a claims parameter, such as its id_token member. Return, sorted in a tuple, each claim requested as an object with "essential": true that claims lacks. A claim present with a null value is missing too; false and "" are values."""
    world = _world()
    requested = {
        "email": {"essential": True}, "phone_number": {"essential": True},
        "auth_time": {"essential": True}, "address": None,
    }
    id_claims, _ = _login(world, "alice", scope="openid", claims={"id_token": requested})
    assert missing_essential_claims(id_claims, requested) == _a(("phone_number",))
    both = {"phone_number": {"essential": True}, "address": {"essential": True}}
    assert missing_essential_claims({}, both) == _a(("address", "phone_number"))
    assert missing_essential_claims({"phone_number": None}, both) == ("address", "phone_number")
    falsy = {"email_verified": False, "email": ""}
    essential = {"email_verified": {"essential": True}, "email": {"essential": True}}
    assert missing_essential_claims(falsy, essential) == ()


def test_counts_only_claims_marked_essential_true():
    """Core §5.5.1: essential is a JSON boolean, and "The default is false". A null request, an empty object, false, or the string "true" all ask for a voluntary claim. Which of these does missing_essential_claims name?"""
    requested = {
        "email": None, "name": {}, "nickname": {"essential": False},
        "locale": {"essential": "true"}, "picture": {"essential": 1},
        "phone_number": {"essential": True},
    }
    assert missing_essential_claims({}, requested) == _a(("phone_number",))


def test_a_sub_value_lets_only_that_user_in():
    """Core §3.1.2.2: with sub requested at a value, the provider "MUST NOT reply with an ID Token or Access Token for a different user, even if they have an active session". Here bob is signed in and app asks for alice, without a login page (prompt=none). What comes back? Then alice tries it."""
    world = _world()
    claims = {"id_token": {"sub": {"value": "alice"}}}
    bob = _signed_in(world, "bob")
    returned, _ = _authorize(world, bob, "openid", claims=claims, prompt="none")
    assert "code" not in returned
    assert returned["error"] == _a("login_required")
    id_claims, _ = _login(world, "alice", scope="openid", claims=claims)
    assert id_claims["sub"] == _a("alice")


def test_a_claim_not_returned_is_left_out():
    """Core §5.3.2: a claim not returned "SHOULD be omitted from the JSON object", and "SHOULD NOT be present with a null or empty string value". bob has no phone number and did not verify his email. What does UserInfo say?"""
    world = _world()
    claims = {"userinfo": {"phone_number": None}}
    _, userinfo = _login(world, "bob", scope="openid email", claims=claims)
    assert userinfo.get("phone_number", "left out") == _a("left out")
    assert userinfo["email_verified"] is _a(False)


def test_an_unknown_scope_is_ignored():
    """Core §3.1.2.1: scope values "not understood by an implementation SHOULD be ignored". app asks for a scope this provider has never heard of. Does the login go through, and what does UserInfo return?"""
    world = _world()
    returned, _ = _authorize(world, _signed_in(world, "alice"), "openid email shoe_size")
    assert ("code" in returned) is _a(True)
    _, userinfo = _login(world, "alice", scope="openid email shoe_size")
    assert set(userinfo) == _a({"sub", "email", "email_verified"})
