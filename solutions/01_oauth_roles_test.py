"""OAuth 2.0 roles, and why OpenID Connect sits on top.

OAuth 2.0 (RFC 6749) is about delegation. Its four roles, in this course:
the resource owner (alice), the client (https://app.example), the
authorization server (https://id.example) and the resource server (an API).

The client sends alice's browser to the authorization server. She signs in
there, never at the client, and the browser returns with a one-time code.
The client swaps the code for tokens by calling the server directly. The
access token is "a string representing an authorization issued to the
client", and "usually opaque to the client" (RFC 6749 §1.4). It is for an
API to accept. It is not a statement to the client about who signed in.

OpenID Connect is "a simple identity layer on top of the OAuth 2.0
protocol". Add openid to the scope and the token response also carries an
ID Token, a signed JWT in which the server tells this client who signed in.
OIDC calls the client a Relying Party (RP) and the authorization server an
OpenID Provider (OP). Its UserInfo endpoint is a protected resource like any
API, and it answers to an access token.

A common mistake: treating a working access token as a login. Any client
holding a token for alice can call the API with it. Only an ID token whose
audience is you, once validated, tells you that alice signed in to you.

Read more:
  https://www.rfc-editor.org/rfc/rfc6749.html#section-1.1
  https://openid.net/specs/openid-connect-core-1_0.html#Overview
  https://openid.net/specs/openid-connect-core-1_0.html#IDToken
"""

from dataclasses import dataclass

from conftest import __
from toy.client import exchange_code, fetch_userinfo, start_login
from toy.clock import Clock
from toy.http import Browser, FakeNetwork, Request, Response
from toy.jose import jws_split
from toy.provider import Provider

ISSUER = "https://id.example"
APP = "https://app.example"
REDIRECT_URI = f"{APP}/callback"
QUIZ = "https://quiz.example"
QUIZ_REDIRECT_URI = f"{QUIZ}/callback"
OIDC_CORE_TERMS = {
    "End-User": "Human participant.",
    "OpenID Provider": (
        "OAuth 2.0 Authorization Server that is capable of Authenticating the End-User"
        " and providing Claims to a Relying Party about the Authentication event and the"
        " End-User."
    ),
    "Relying Party": (
        "OAuth 2.0 Client application requiring End-User Authentication and Claims"
        " from an OpenID Provider."
    ),
}


@dataclass(frozen=True)
class World:
    clock: Clock
    network: FakeNetwork
    browser: Browser
    config: dict


def _world() -> World:
    """alice is signed in at the provider; app and quiz are two registered clients."""
    clock, network = Clock(), FakeNetwork()
    provider = Provider(ISSUER, clock=clock, network=network)
    provider.register_client("app", [REDIRECT_URI])
    provider.register_client("quiz", [QUIZ_REDIRECT_URI])
    provider.add_user("alice", "alice@example.com", True, "alice-password")
    for origin in (APP, QUIZ):
        network.mount(origin, lambda request: Response(200, body="callback reached"))
    browser = Browser(network)
    provider.sign_in(browser, "alice", ("pwd",))
    config = network.send(Request("GET", f"{ISSUER}/.well-known/openid-configuration")).body
    return World(clock, network, browser, config)


def _start(world, client_id="app", redirect_uri=REDIRECT_URI, scope="openid email"):
    return start_login(
        issuer_config=world.config, client_id=client_id, redirect_uri=redirect_uri,
        now=world.clock.now(), scope=scope,
    )


def _authorize(world, client_id="app", redirect_uri=REDIRECT_URI, scope="openid email"):
    """The request the browser lands on at the client, and the client's transaction."""
    url, transaction = _start(world, client_id, redirect_uri, scope)
    world.browser.get(url)
    return world.browser.history[-1], transaction


def _tokens(world, client_id="app", redirect_uri=REDIRECT_URI) -> dict:
    callback, transaction = _authorize(world, client_id, redirect_uri)
    return exchange_code(
        issuer_config=world.config, client_id=client_id, code=callback.query["code"],
        redirect_uri=redirect_uri, code_verifier=transaction.code_verifier,
        network=world.network,
    )


def _accepts_access_token(world, actor: str, access_token: str) -> bool:
    if not actor.startswith("https://"):
        return False
    request = Request("GET", actor, headers={"Authorization": f"Bearer {access_token}"})
    return world.network.send(request).status == 200


def test_name_the_four_roles():
    """RFC 6749 §1.1 names four roles: resource owner, resource server, client and authorization server. Give each actor here its role."""
    world = _world()
    tokens = _tokens(world)
    claims = jws_split(tokens["id_token"])[1]
    roles = {
        "alice": "resource owner",
        "app": "client",
        ISSUER: "authorization server",
        world.config["userinfo_endpoint"]: "resource server",
    }
    plays = {
        "resource owner": lambda actor: actor == claims["sub"],
        "client": lambda actor: actor == claims["aud"],
        "authorization server": lambda actor: actor == claims["iss"],
        "resource server": lambda actor: _accepts_access_token(
            world, actor, tokens["access_token"]
        ),
    }
    assert all(plays.get(role, lambda actor: False)(actor) for actor, role in roles.items())


def test_oidc_renames_two_roles():
    """OIDC Core §1.2 defines its own terms. Read the definitions in OIDC_CORE_TERMS and name the OIDC term for an OAuth client, and for an authorization server."""
    client, authorization_server = "Relying Party", "OpenID Provider"
    assert OIDC_CORE_TERMS.get(client, "").startswith("OAuth 2.0 Client")
    assert OIDC_CORE_TERMS.get(authorization_server, "").startswith("OAuth 2.0 Authorization Server")


def test_the_browser_brings_a_code_back_to_the_client():
    """After alice signs in, the server redirects her browser to the client's redirect_uri with the code and the state the client sent. This provider also adds its own issuer (RFC 9207)."""
    callback, _ = _authorize(_world())
    assert callback.origin == "https://app.example"
    assert sorted(callback.query) == ["code", "iss", "state"]


def test_the_client_redeems_the_code_without_the_browser():
    """The browser carries the code (the front channel). The client calls /token itself (the back channel). List what the browser visited."""
    world = _world()
    before = len(world.browser.history)
    tokens = _tokens(world)
    visited = [(request.origin, request.path) for request in world.browser.history[before:]]
    assert visited == [("https://id.example", "/authorize"), ("https://app.example", "/callback")]
    assert "access_token" in tokens


def test_the_grant_type_names_the_grant():
    """RFC 6749 §4.1.3: the client redeems an authorization code by posting grant_type with the grant's name, snake_case."""
    world = _world()
    callback, transaction = _authorize(world)
    form = {
        "grant_type": "authorization_code",
        "code": callback.query["code"],
        "redirect_uri": REDIRECT_URI,
        "code_verifier": transaction.code_verifier,
        "client_id": "app",
    }
    response = world.network.send(Request("POST", world.config["token_endpoint"], form=form))
    assert response.status == 200


def test_an_access_token_is_not_for_the_client_to_read():
    """RFC 6749 §1.4: an access token is "usually opaque to the client". This toy's are random strings; a provider may issue JWT access tokens (RFC 9068), still meant for the API. The ID token is a JWT for the client. Count the dots."""
    tokens = _tokens(_world())
    assert tokens["access_token"].count(".") == 0
    assert tokens["id_token"].count(".") == 2


def test_the_id_token_is_a_statement_to_the_client():
    """The ID token says who issued it (iss), whom it is about (sub) and whom it is for (aud). Here we only read it; chapter 03 shows why reading is not trusting."""
    claims = jws_split(_tokens(_world())["id_token"])[1]
    assert claims["iss"] == "https://id.example"
    assert claims["sub"] == "alice"
    assert claims["aud"] == "app"


def test_userinfo_is_a_protected_resource():
    """UserInfo is an API like any other. Without an access token it answers 401 Unauthorized; with one, it says whom the token is about."""
    world = _world()
    tokens = _tokens(world)
    refused = world.network.send(Request("GET", world.config["userinfo_endpoint"]))
    userinfo = fetch_userinfo(
        issuer_config=world.config, access_token=tokens["access_token"], network=world.network
    )
    assert refused.status == 401
    assert userinfo["sub"] == "alice"


def test_without_openid_it_is_not_openid_connect():
    """OIDC Core §3.1.2.2: with no openid scope a request "is not an OpenID Connect request". This toy provider speaks only OIDC, so it redirects back with an error."""
    callback, _ = _authorize(_world(), scope="email")
    assert "code" not in callback.query
    assert callback.query["error"] == "invalid_scope"


def test_userinfo_does_not_say_which_client_a_token_was_issued_to():
    """Delegation is not authentication. UserInfo answers just the same for a token issued to quiz, so a client calling it cannot tell. The ID token's aud says which client a login was for."""
    world = _world()
    quiz = _tokens(world, client_id="quiz", redirect_uri=QUIZ_REDIRECT_URI)
    userinfo = fetch_userinfo(
        issuer_config=world.config, access_token=quiz["access_token"], network=world.network
    )
    assert userinfo["sub"] == "alice"
    assert jws_split(quiz["id_token"])[1]["aud"] == "quiz"
