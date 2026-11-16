"""Access tokens, ID tokens, UserInfo, and matching sub.

The two tokens have different readers. The ID token is the provider's
statement to the client about one sign-in, and its aud is the client. The
access token is for an API, sent as "Authorization: Bearer <token>" (RFC
6750 §2.1). The client never reads it: RFC 9068 §6 says "The client MUST
NOT inspect the content of the access token", even when it is a JWT.

UserInfo (Core §5.3) is one such API. It answers with claims about whoever
the access token belongs to, and "The sub (subject) Claim MUST always be
returned". It cannot know which sign-in the client has in mind. So Core
§5.3.2: the UserInfo sub "MUST be verified to exactly match the sub Claim
in the ID Token; if they do not match, the UserInfo Response values MUST
NOT be used." That stops token substitution (Core §16.11): another user's
access token sent along with your ID token.

An API refuses with a WWW-Authenticate challenge (RFC 6750 §3.1):
invalid_token, with 401, for a token "expired, revoked, malformed, or
invalid for other reasons"; insufficient_scope, with 403, for a token
without the scope needed. For a request with no token at all, "the
resource server SHOULD NOT include an error code".

A common mistake: merging UserInfo into the signed-in user without
comparing sub, or comparing it loosely.

Read more:
  https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
  https://openid.net/specs/openid-connect-core-1_0.html#TokenSubstitution
  https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1
  https://www.rfc-editor.org/rfc/rfc9068.html#section-6
"""

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

import pytest

from conftest import __
from toy.client import (
    account_key,
    exchange_code,
    fetch_userinfo,
    parse_challenge,
    start_login,
    validate_id_token,
)
from toy.clock import Clock
from toy.errors import InvalidToken, OAuthError
from toy.http import Browser, FakeNetwork, Request, Response, with_query
from toy.jose import jws_split
from toy.provider import Provider
from toy.resource import ResourceServer

ISSUER = "https://id.example"
APP = "https://app.example"
REDIRECT_URI = f"{APP}/callback"
CLIENT_ID = "app"
QUIZ = "https://quiz.example"
QUIZ_REDIRECT_URI = f"{QUIZ}/callback"
API = "https://api.example"


class App:
    """The backend of app's mobile build, at https://app.example.

    The mobile build signs its user in at id.example with no nonce and posts both
    tokens to /profile-sync. The backend validates the ID token, fetches UserInfo
    with the access token, checks the two with check_userinfo_subject, and stores
    the merged profile under (iss, sub).
    """

    def __init__(self, clock: Clock, network: FakeNetwork, config: dict, jwks: dict):
        self._clock, self._network, self._config, self._jwks = clock, network, config, jwks
        self.profiles: dict[tuple[str, str], dict] = {}

    def __call__(self, request: Request) -> Response:
        if request.path != "/profile-sync":
            return Response(404, {}, {"error": "not_found"})
        try:
            claims = validate_id_token(
                request.form.get("id_token"), issuer=self._config["issuer"],
                client_id=CLIENT_ID, jwks=self._jwks, now=self._clock.now(), nonce=None,
            )
            userinfo = fetch_userinfo(
                issuer_config=self._config, access_token=request.form.get("access_token", ""),
                network=self._network,
            )
            check_userinfo_subject(claims, userinfo)
        except InvalidToken as refused:
            return Response(401, {}, {"error": refused.reason})
        except OAuthError as refused:
            return Response(401, {}, {"error": refused.error})
        user = account_key(claims)
        profile = {**userinfo, **claims}
        self.profiles = {**self.profiles, user: profile}
        return Response(200, {}, {"user": list(user), "email": profile.get("email")})


@dataclass(frozen=True)
class World:
    clock: Clock
    network: FakeNetwork
    provider: Provider
    config: dict
    app: App


def _world() -> World:
    """id.example with app and quiz, mallory's app; alice and mallory have accounts."""
    clock, network = Clock(), FakeNetwork()
    provider = Provider(ISSUER, clock=clock, network=network)
    provider.register_client(CLIENT_ID, [REDIRECT_URI])
    provider.register_client("quiz", [QUIZ_REDIRECT_URI])
    provider.add_user("alice", "alice@example.com", True, "alice-password")
    provider.add_user("mallory", "mallory@example.com", True, "mallory-password")
    config = network.send(Request("GET", f"{ISSUER}/.well-known/openid-configuration")).body
    jwks = network.send(Request("GET", config["jwks_uri"])).body
    app = App(clock, network, config, jwks)
    network.mount(APP, app)
    network.mount(QUIZ, lambda request: Response(200, {}, "callback reached"))
    return World(clock, network, provider, config, app)


def _tokens(world: World, sub: str, client_id: str = CLIENT_ID, scope="openid email") -> dict:
    """The token response id.example sends client_id after sub signs in to it with no nonce."""
    redirect_uri = REDIRECT_URI if client_id == CLIENT_ID else QUIZ_REDIRECT_URI
    browser = Browser(world.network)
    world.provider.sign_in(browser, sub, ("pwd",))
    url, transaction = start_login(
        issuer_config=world.config, client_id=client_id, redirect_uri=redirect_uri,
        now=world.clock.now(), scope=scope,
    )
    params = {k: v for k, v in parse_qsl(urlsplit(url).query) if k != "nonce"}
    authorize = with_query(world.config["authorization_endpoint"], params)
    answer = world.network.send(Request("GET", authorize, cookies=browser.cookies(ISSUER)))
    return exchange_code(
        issuer_config=world.config, client_id=client_id, redirect_uri=redirect_uri,
        code=Request("GET", answer.location).query["code"],
        code_verifier=transaction.code_verifier, network=world.network,
    )


def _userinfo(world: World, headers: dict) -> Response:
    return world.network.send(Request("GET", world.config["userinfo_endpoint"], headers=headers))


def _sync(world: World, id_token: str, access_token: str) -> Response:
    form = {"id_token": id_token, "access_token": access_token}
    return world.network.send(Request("POST", f"{APP}/profile-sync", form=form))


def test_userinfo_takes_the_access_token_as_a_bearer():
    """RFC 6750 §2.1: the client sends the access token in the Authorization header, after the scheme name. Core §5.3.1 calls UserInfo this way. With scope "openid email", what does this provider answer?"""
    world = _world()
    tokens = _tokens(world, "alice")
    answer = _userinfo(world, {"Authorization": "Bearer" + " " + tokens["access_token"]})
    assert answer.status == 200
    claims = {"sub": "alice", "email": "alice@example.com", "email_verified": True}
    assert answer.body == claims


def test_an_expired_access_token_gets_invalid_token():
    """This provider's access tokens live 300 seconds. After that, UserInfo answers as RFC 6750 §3.1 describes, with a challenge in WWW-Authenticate (Core §5.3.3)."""
    world = _world()
    tokens = _tokens(world, "alice")
    world.clock.advance(300)
    answer = _userinfo(world, {"Authorization": f"Bearer {tokens['access_token']}"})
    challenge = parse_challenge(answer.headers["WWW-Authenticate"])
    assert answer.status == 401
    assert challenge["scheme"] == "Bearer"
    assert challenge["error"] == "invalid_token"


def test_an_api_reads_access_tokens_not_id_tokens():
    """api.example asks id.example about each bearer token it receives (RFC 7662 introspection). The ID token is a statement to app, not a key to the API. A request with no token gets a bare challenge: RFC 6750 §3.1 says it SHOULD NOT carry an error code."""
    world = _world()
    ResourceServer(API, network=world.network, clock=world.clock,
                   introspect=world.provider.introspect)
    tokens = _tokens(world, "alice")

    def call(token=None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return world.network.send(Request("GET", f"{API}/orders", headers=headers))

    assert call().headers["WWW-Authenticate"] == "Bearer"
    with_id_token = parse_challenge(call(tokens["id_token"]).headers["WWW-Authenticate"])
    assert with_id_token["error"] == "invalid_token"
    assert call(tokens["access_token"]).body["sub"] == "alice"


def test_the_client_treats_the_access_token_as_opaque():
    """This provider's access tokens are random strings, its own choice; RFC 9068 lets others issue JWT access tokens. Either way the client must not read one (RFC 9068 §6). The API learns what it means by asking the provider. What does each party see?"""
    world = _world()
    access_token = _tokens(world, "alice")["access_token"]
    refused = None
    try:
        jws_split(access_token)
    except InvalidToken as error:
        refused = error.reason
    assert access_token.count(".") == 0
    assert refused == "malformed"
    report = world.provider.introspect(access_token)
    assert (report["active"], report["sub"], report["client_id"]) == (True, "alice", "app")


def test_userinfo_answers_for_whoever_holds_the_token():
    """alice once signed in to quiz, mallory's app, so mallory holds alice's access token from quiz. UserInfo does not ask who is calling or which sign-in they mean. Whose claims come back?"""
    world = _world()
    from_quiz = _tokens(world, "alice", client_id="quiz")["access_token"]
    assert world.provider.introspect(from_quiz)["client_id"] == "quiz"
    answer = _userinfo(world, {"Authorization": f"Bearer {from_quiz}"})
    assert answer.body["sub"] == "alice"
    assert answer.body["email"] == "alice@example.com"


def check_userinfo_subject(id_claims: dict, userinfo: dict) -> None:
    sub = userinfo.get("sub")
    if not isinstance(sub, str) or sub != id_claims["sub"]:
        raise InvalidToken("sub_mismatch")


def test_accepts_userinfo_about_the_signed_in_user():
    """Implement check_userinfo_subject above; /profile-sync calls it before it uses any UserInfo claim. Core §5.3.2: the UserInfo sub "MUST be verified to exactly match" the ID token's sub. If it is not a string equal to id_claims["sub"], raise InvalidToken("sub_mismatch"). id_claims has passed validate_id_token, so its sub is a non-empty string."""
    assert check_userinfo_subject({"sub": "alice"}, {"sub": "alice", "email": "a"}) is None
    world = _world()
    for sub in ("alice", "mallory"):
        tokens = _tokens(world, sub)
        answer = _sync(world, tokens["id_token"], tokens["access_token"])
        assert answer.status == 200
    assert world.app.profiles[(ISSUER, "alice")]["email"] == "alice@example.com"
    assert world.app.profiles[(ISSUER, "mallory")]["email"] == "mallory@example.com"


def test_refuses_userinfo_about_another_user():
    """Token substitution: mallory posts her own ID token for app, which is genuine, with alice's access token from quiz. Without the sub check app would store alice's verified email on mallory's account, and an app that links accounts by email would hand her alice's. Which reason does app give, and what does it store?"""
    world = _world()
    from_quiz = _tokens(world, "alice", client_id="quiz")["access_token"]
    mallorys = _tokens(world, "mallory")
    assert jws_split(mallorys["id_token"])[1]["sub"] == "mallory"
    assert _userinfo(world, {"Authorization": f"Bearer {from_quiz}"}).body["sub"] == "alice"
    answer = _sync(world, mallorys["id_token"], from_quiz)
    assert (answer.status, answer.body["error"]) == (401, "sub_mismatch")
    assert world.app.profiles == {}
    honest = _sync(world, mallorys["id_token"], mallorys["access_token"])
    assert honest.body["email"] == "mallory@example.com"


def test_refuses_a_sub_that_only_looks_the_same():
    """"Exactly match" means the same JSON string: no case folding, no trimming, no number that prints the same, and no missing sub. Each of these UserInfo answers must raise InvalidToken("sub_mismatch")."""
    lookalikes = [
        ("alice", {"sub": "Alice"}),
        ("alice", {"sub": "alice "}),
        ("alice", {"sub": ["alice"]}),
        ("alice", {"sub": None}),
        ("alice", {"email": "alice@example.com"}),
        ("123", {"sub": 123}),
        ("alice", {"sub": ""}),
    ]
    for id_sub, userinfo in lookalikes:
        with pytest.raises(InvalidToken) as refused:
            check_userinfo_subject({"sub": id_sub}, userinfo)
        assert refused.value.reason == "sub_mismatch"
    assert check_userinfo_subject({"sub": "123"}, {"sub": "123"}) is None
