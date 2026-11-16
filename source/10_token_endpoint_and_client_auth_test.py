"""The token endpoint and client authentication.

The client redeems its single-use code with a POST to the token endpoint,
and a confidential client proves who it is there. A public client (RFC
6749 §2.1) cannot keep a secret, so it sends only its client_id, and PKCE
plus the code's binding to that client_id protect the exchange.

client_secret_basic is the default when no method is registered (OIDC
Core §9). RFC 6749 §2.3.1 form-urlencodes the client_id and the secret,
each on its own, before they are joined with ":" and base64-encoded into
an HTTP Basic header; client_secret_post sends both in the form. "The
client MUST NOT use more than one authentication method in each request".

private_key_jwt sends a JWT signed with the client's own key: iss and sub
are the client_id, jti is single-use, exp is near. RFC 9700 §2.5: "It is
RECOMMENDED to use asymmetric cryptography for client authentication".
Core §9 still says "The Audience SHOULD be the URL of the Authorization
Server's Token Endpoint". RFC 10070 (November 2026) replaces that: aud
"MUST use the issuer identifier [RFC8414] of the authorization server as
its sole value", and the server "MUST reject any JWT that does not
contain its issuer identifier as its sole audience value".

A common mistake: base64(f"{client_id}:{secret}"). The first ":" ends the
client_id (RFC 7617 §2), and a "%" or "+" in either part is form-decoded.

Read more:
  https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3.1
  https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
  https://www.rfc-editor.org/rfc/rfc10070.html#section-4
  https://www.rfc-editor.org/rfc/rfc9700.html#section-2.5
"""

import base64
from dataclasses import dataclass
from urllib.parse import quote_plus

from conftest import __
from toy.client import Transaction, start_login
from toy.clock import Clock
from toy.http import Browser, FakeNetwork, Request, Response
from toy.jose import jws_encode, jws_verify, jwks_of, public_jwk
from toy.keys import RSA_2
from toy.provider import Provider

ISSUER = "https://id.example"
TOKEN_ENDPOINT = f"{ISSUER}/token"
OTHER_ISSUER = "https://other-id.example"
APP = "https://app.example"
REDIRECT_URI = f"{APP}/callback"
CLIENT_ID = "app"
CLIENT_SECRET = b"app-secret-of-at-least-32-octets"
URL_CLIENT_ID = "https://app.example/client"
URL_CLIENT_SECRET = b"p:ss%2B w+rd"
JWT_CLIENT_ID = "app-jwt"
JWT_CLIENT_KEYS = jwks_of(public_jwk(RSA_2, "c1"))
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
RFC_CLIENT_ID, RFC_SECRET = "s6BhdRkqt3", b"7Fjfp0ZBr1KtDRbnfVdmIw"
RFC_HEADER = "Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3"


@dataclass(frozen=True)
class World:
    clock: Clock
    network: FakeNetwork
    provider: Provider
    config: dict
    alice: Browser


def _world() -> World:
    """id.example and its clients. app and the URL-named client have secrets, app-jwt has a
    key pair, and mobile and quiz are public. alice is signed in at the provider."""
    clock, network = Clock(), FakeNetwork()
    provider = Provider(ISSUER, clock=clock, network=network)
    provider.register_client(CLIENT_ID, [REDIRECT_URI], secret=CLIENT_SECRET)
    provider.register_client(URL_CLIENT_ID, [REDIRECT_URI], secret=URL_CLIENT_SECRET)
    provider.register_client(JWT_CLIENT_ID, [REDIRECT_URI], jwks=JWT_CLIENT_KEYS)
    provider.register_client("mobile", [REDIRECT_URI])
    provider.register_client("quiz", [REDIRECT_URI])
    provider.add_user("alice", "alice@example.com", True, "alice-password")
    network.mount(APP, lambda request: Response(200, {}, "callback reached"))
    config = network.send(Request("GET", f"{ISSUER}/.well-known/openid-configuration")).body
    alice = Browser(network)
    provider.sign_in(alice, "alice", ("pwd",))
    return World(clock, network, provider, config, alice)


def _code(world: World, client_id: str = CLIENT_ID) -> tuple[str, Transaction]:
    """A code issued to client_id for alice, and the login's transaction."""
    url, transaction = start_login(
        issuer_config=world.config, client_id=client_id, redirect_uri=REDIRECT_URI,
        now=world.clock.now(),
    )
    answer = world.network.send(Request("GET", url, cookies=world.alice.cookies(ISSUER)))
    return Request("GET", answer.location).query["code"], transaction


def _redeem(world: World, code: str, transaction: Transaction, headers=None, **form) -> Response:
    """The token endpoint's answer to a code redemption with these headers and form fields."""
    base = {
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI,
        "code_verifier": transaction.code_verifier,
    }
    request = Request("POST", TOKEN_ENDPOINT, form={**base, **form}, headers=headers or {})
    return world.network.send(request)


def _signed(claims: dict, typ: str | None = "client-authentication+jwt") -> str:
    """claims signed with app-jwt's private key, typed as RFC 10070 suggests unless typ is None."""
    header = {"alg": "RS256", "kid": "c1", **({"typ": typ} if typ else {})}
    return jws_encode(header, claims, RSA_2)


def _assertion(world: World, jti: str, **changes) -> str:
    """An honest client assertion from app-jwt, with changes."""
    claims = {
        "iss": JWT_CLIENT_ID, "sub": JWT_CLIENT_ID, "aud": ISSUER, "jti": jti,
        "exp": world.clock.now() + 60, **changes,
    }
    return _signed(claims)


def _redeem_as_jwt_client(world: World, assertion: str) -> Response:
    code, transaction = _code(world, JWT_CLIENT_ID)
    return _redeem(
        world, code, transaction, client_assertion_type=ASSERTION_TYPE, client_assertion=assertion
    )


def _userinfo(world: World, access_token: str) -> Response:
    headers = {"Authorization": f"Bearer {access_token}"}
    return world.network.send(Request("GET", world.config["userinfo_endpoint"], headers=headers))


def test_a_confidential_client_must_authenticate():
    """app was given a secret, so it is a confidential client. Redeeming its code with only its client_id, as a public client would, fails: which status and error does the token endpoint answer?"""
    world = _world()
    code, transaction = _code(world)
    answer = _redeem(world, code, transaction, client_id=CLIENT_ID)
    assert answer.status == _a(401)
    assert answer.body["error"] == _a("invalid_client")


def basic_authorization(client_id: str, secret: bytes) -> str:
    # >>> answer
    pair = f"{quote_plus(client_id)}:{quote_plus(secret)}"
    return "Basic " + base64.b64encode(pair.encode("ascii")).decode("ascii")
    # <<<


def test_basic_authorization_matches_rfc_6749():
    """Implement basic_authorization above. Form-urlencode the client_id and the secret each (urllib.parse.quote_plus takes str or bytes), join them with ":", base64-encode that ASCII text and put "Basic " in front. RFC 6749 §2.3.1's example comes first."""
    assert basic_authorization(RFC_CLIENT_ID, RFC_SECRET) == RFC_HEADER
    world = _world()
    code, transaction = _code(world)
    headers = {"Authorization": basic_authorization(CLIENT_ID, CLIENT_SECRET)}
    assert _redeem(world, code, transaction, headers).status == _a(200)


def test_form_encodes_each_part_before_base64():
    """This client's id is a URL, and its secret holds ":", "%", "+" and a space. What does the provider read from your header once it is base64-decoded? And what does a header built without the encoding get?"""
    world = _world()
    header = basic_authorization(URL_CLIENT_ID, URL_CLIENT_SECRET)
    decoded = base64.b64decode(header.removeprefix("Basic ")).decode("ascii")
    assert decoded == _a("https%3A%2F%2Fapp.example%2Fclient:p%3Ass%252B+w%2Brd")
    code, transaction = _code(world, URL_CLIENT_ID)
    assert _redeem(world, code, transaction, {"Authorization": header}).status == 200
    raw = URL_CLIENT_ID.encode("ascii") + b":" + URL_CLIENT_SECRET
    naive = "Basic " + base64.b64encode(raw).decode("ascii")
    code, transaction = _code(world, URL_CLIENT_ID)
    answer = _redeem(world, code, transaction, {"Authorization": naive})
    assert answer.body["error"] == _a("invalid_client")


def test_refuses_two_authentication_methods_at_once():
    """RFC 6749 §2.3: "The client MUST NOT use more than one authentication method in each request." client_secret_post puts client_id and client_secret in the form. It works alone; beside a Basic header, which error does the provider answer?"""
    world = _world()
    post = {"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET.decode("ascii")}
    code, transaction = _code(world)
    assert _redeem(world, code, transaction, **post).status == _a(200)
    basic = {"Authorization": basic_authorization(CLIENT_ID, CLIENT_SECRET)}
    code, transaction = _code(world)
    assert _redeem(world, code, transaction, basic, **post).body["error"] == _a("invalid_request")


def test_refuses_a_code_redeemed_twice():
    """RFC 6749 §4.1.2: if a code "is used more than once, the authorization server MUST deny the request and SHOULD revoke (when possible) all tokens previously issued based on that authorization code". Which error answers the second redemption, and what happens to the first access token?"""
    world = _world()
    basic = {"Authorization": basic_authorization(CLIENT_ID, CLIENT_SECRET)}
    code, transaction = _code(world)
    first = _redeem(world, code, transaction, basic)
    access_token = first.body["access_token"]
    assert _userinfo(world, access_token).status == 200
    assert _redeem(world, code, transaction, basic).body["error"] == _a("invalid_grant")
    assert _userinfo(world, access_token).status == _a(401)
    assert world.provider.introspect(access_token)["active"] is _a(False)


def test_refuses_a_code_redeemed_by_another_client():
    """mobile and quiz are public clients: a client_id is all they send. quiz has stolen a code issued to mobile and mobile's code_verifier too. What stops it? mobile's own redemption is the honest twin."""
    world = _world()
    code, transaction = _code(world, "mobile")
    stolen = _redeem(world, code, transaction, client_id="quiz")
    assert stolen.body["error"] == _a("invalid_grant")
    code, transaction = _code(world, "mobile")
    assert _redeem(world, code, transaction, client_id="mobile").status == _a(200)


def test_accepts_a_private_key_jwt_for_the_issuer():
    """app-jwt registered a public key, not a secret. Fill in its client assertion: who issued it, who it is about, and its aud under RFC 10070; then the client_assertion_type of RFC 7523 §2.2. RFC 10070 says these JWTs "SHOULD be explicitly typed", but rejecting an untyped one is "NOT RECOMMENDED": does this provider take one?"""
    world = _world()
    claims = {
        "iss": _a(JWT_CLIENT_ID), "sub": _a(JWT_CLIENT_ID), "aud": _a(ISSUER), "jti": "a-1",
        "exp": world.clock.now() + 60,
    }
    assertion_type = _a("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
    code, transaction = _code(world, JWT_CLIENT_ID)
    form = {"client_assertion_type": assertion_type, "client_assertion": _signed(claims)}
    assert _redeem(world, code, transaction, **form).status == 200
    untyped = _signed({**claims, "jti": "a-2"}, typ=None)
    assert (_redeem_as_jwt_client(world, untyped).status == 200) is _a(True)


def audience_is_issuer(aud, issuer: str) -> bool:
    # >>> answer
    return aud == issuer or aud == [issuer]
    # <<<


def test_accepts_the_issuer_alone_as_audience():
    """Implement audience_is_issuer above, the provider's RFC 10070 check of a client assertion's aud. aud may be one string or an array of strings (RFC 7519 §4.1.3). Return True only when the issuer identifier is its one and only value, compared character for character."""
    assert audience_is_issuer(ISSUER, ISSUER) is True
    assert audience_is_issuer([ISSUER], ISSUER) is True
    assert audience_is_issuer(TOKEN_ENDPOINT, ISSUER) is _a(False)


def test_refuses_an_assertion_meant_for_another_audience():
    """Audience injection: an assertion whose aud names an endpoint, or more than one server, can be replayed somewhere it was not meant for. Every aud below fails your check. The provider refuses the token endpoint one too, though its signature is good."""
    others = [
        TOKEN_ENDPOINT, [TOKEN_ENDPOINT], [ISSUER, TOKEN_ENDPOINT], [ISSUER, OTHER_ISSUER],
        OTHER_ISSUER, f"{ISSUER}/", "https://ID.example", "https://id.example.evil.example",
        "https://id.exampl", "", None, [], [[ISSUER]],
    ]
    assert [aud for aud in others if audience_is_issuer(aud, ISSUER)] == _a([])
    world = _world()
    assertion = _assertion(world, "a-1", aud=TOKEN_ENDPOINT)
    assert jws_verify(assertion, JWT_CLIENT_KEYS, frozenset({"RS256"}))["sub"] == JWT_CLIENT_ID
    answer = _redeem_as_jwt_client(world, assertion)
    assert (answer.status, answer.body["error"]) == _a((401, "invalid_client"))


def test_refuses_a_replayed_client_assertion():
    """Core §9: jti "can be used to prevent reuse of the token", and these tokens "MUST only be used once" unless the parties agreed otherwise. Someone who copies app-jwt's assertion off the wire tries it again. An assertion at its exp is refused too."""
    world = _world()
    once = _assertion(world, "a-1")
    assert _redeem_as_jwt_client(world, once).status == 200
    assert _redeem_as_jwt_client(world, once).body["error"] == _a("invalid_client")
    expired = _assertion(world, "a-2", exp=world.clock.now())
    assert _redeem_as_jwt_client(world, expired).body["error"] == _a("invalid_client")
