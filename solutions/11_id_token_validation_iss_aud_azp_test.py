"""ID token validation, part 1: what kind, who signed, from whom, for whom.

OIDC Core §3.1.3.7 lists what a client checks before it believes an ID
token. This chapter takes the checks of who made it and who it is for;
chapter 12 takes time, nonce, acr and auth_time. This course runs them in
one order, so a token with two defects always gets the same reason: typ,
then alg, key and signature, then sub, iss, aud and azp. Item 6 lets TLS
stand in for the signature in the code flow (a MAY); this course verifies.

The issuer "MUST exactly match the value of the iss (issuer) Claim": no
trailing-slash fixes, no prefixes. aud, one string or an array of strings,
must contain the client's "client_id value", and the token "MUST be
rejected" if it "contains additional audiences not trusted by the Client".

azp follows errata set 2. Core §2 says it "only occurs when extensions
beyond the scope of this specification are used", and implementations
without them "are encouraged to not use azp and to ignore it when it does
occur". Under such an extension, validate azp as the extension says. This
course's toy extension wants azp equal to the client_id, and present when
aud has several values. azp never stands in for the aud check.

A common mistake: client_id in aud. When aud is the string "webapp", in
finds "app" inside it.

Read more:
  https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
  https://openid.net/specs/openid-connect-core-1_0.html#IDToken
  https://www.rfc-editor.org/rfc/rfc8725.html#section-3.9
  https://www.rfc-editor.org/rfc/rfc8725.html#section-3.11
"""

from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

import pytest

from conftest import __
from toy.client import exchange_code, start_login, validate_id_token
from toy.clock import Clock
from toy.errors import InvalidToken
from toy.http import Browser, FakeNetwork, Request, Response, with_query
from toy.id_token import numeric_date
from toy.jose import jws_encode, jws_split, jws_verify, jwks_of
from toy.keys import ATTACKER_RSA, EC_1, RSA_1
from toy.provider import Provider

ISSUER = "https://id.example"
OTHER_ISSUER = "https://other-id.example"
APP = "https://app.example"
REDIRECT_URI = f"{APP}/callback"
CLIENT_ID = "app"
API = "https://api.example"
MALLORY = "https://mallory.example"
MALLORY_CALLBACK = f"{MALLORY}/callback"
ALGS = frozenset({"RS256", "ES256"})
LOGOUT_EVENT = {"http://schemas.openid.net/event/backchannel-logout": {}}
DROP = object()


class App:
    """The backend of app's mobile build, at https://app.example.

    The mobile app signs its user in at id.example with no nonce and posts the
    ID token to /token-login. The backend checks it with check_posted_token,
    using check_aud as its audience check (check_audience unless told
    otherwise), and answers with the user it signed in.
    """

    def __init__(self, clock: Clock, jwks: dict, check_aud: Callable | None):
        self._clock, self._jwks, self._check_aud = clock, jwks, check_aud

    def __call__(self, request: Request) -> Response:
        if request.path != "/token-login":
            return Response(404, {}, {"error": "not_found"})
        try:
            claims = check_posted_token(
                request.form.get("id_token"), jwks=self._jwks, now=self._clock.now(),
                check_aud=self._check_aud or check_audience,
            )
        except InvalidToken as refused:
            return Response(401, {}, {"error": refused.reason})
        return Response(200, {}, {"user": [claims["iss"], claims["sub"]]})


def check_posted_token(token: str, *, jwks: dict, now: int, check_aud: Callable) -> dict:
    """app's check of an ID token its mobile build posts. That build sends no nonce."""
    header, payload, _, _ = jws_split(token)
    typ = header.get("typ", "JWT")
    if not isinstance(typ, str) or typ.lower() not in ("jwt", "application/jwt"):
        raise InvalidToken("wrong_typ")
    if "events" in payload:
        raise InvalidToken("wrong_typ")
    claims = jws_verify(token, jwks, frozenset({"RS256"}))
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise InvalidToken("malformed")
    if claims.get("iss") != ISSUER:
        raise InvalidToken("wrong_issuer")
    check_aud(claims, CLIENT_ID, frozenset())
    if "exp" not in claims or "iat" not in claims:
        raise InvalidToken("malformed")
    if not now < numeric_date(claims, "exp"):
        raise InvalidToken("expired")
    if not numeric_date(claims, "iat") <= now:
        raise InvalidToken("issued_in_future")
    if "nonce" in claims:
        raise InvalidToken("nonce_mismatch")
    return claims


def audience_matches(claims: dict, client_id: str, trusted: frozenset[str]) -> None:
    """app's first audience check: its own client_id, and no audience it does not trust."""
    aud = claims.get("aud", "")
    if client_id not in aud:
        raise InvalidToken("wrong_audience")
    if isinstance(aud, list) and set(aud) - {client_id} - trusted:
        raise InvalidToken("wrong_audience")


def validate_signed_part(
    token: str,
    *,
    issuer: str,
    client_id: str,
    jwks: dict,
    allowed_algs: frozenset[str] = ALGS,
    trusted_audiences: frozenset[str] = frozenset(),
    azp_extension: bool = False,
) -> dict:
    """OIDC Core §3.1.3.7 items 2 to 8, in this course's order, with your checks."""
    header, payload, _, _ = jws_split(token)
    check_type(header, payload)
    claims = jws_verify(token, jwks, allowed_algs)
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise InvalidToken("malformed")
    check_issuer(claims, issuer)
    check_audience(claims, client_id, trusted_audiences)
    check_authorized_party(claims, client_id, azp_extension)
    return claims


@dataclass(frozen=True)
class World:
    clock: Clock
    network: FakeNetwork
    provider: Provider
    other: Provider
    config: dict
    jwks: dict


def _world(check_aud: Callable | None = None) -> World:
    """id.example and other-id.example; app's backend; mallory's site; alice has an account."""
    clock, network = Clock(), FakeNetwork()
    provider = Provider(ISSUER, clock=clock, network=network)
    other = Provider(OTHER_ISSUER, clock=clock, network=network, signing_key=EC_1, kid="o1")
    provider.register_client(CLIENT_ID, [REDIRECT_URI])
    provider.add_user("alice", "alice@example.com", True, "alice-password")
    config = network.send(Request("GET", f"{ISSUER}/.well-known/openid-configuration")).body
    jwks = network.send(Request("GET", config["jwks_uri"])).body
    network.mount(APP, App(clock, jwks, check_aud))
    network.mount(MALLORY, lambda request: Response(200, {}, "callback reached"))
    return World(clock, network, provider, other, config, jwks)


def _id_token_for(world: World, client_id: str, extra_audiences: tuple[str, ...] = ()) -> str:
    """The ID token id.example issues to client_id when alice signs in to it with no nonce.

    A client other than app is mallory's: it is registered first, with her callback.
    """
    redirect_uri = REDIRECT_URI if client_id == CLIENT_ID else MALLORY_CALLBACK
    if client_id != CLIENT_ID:
        world.provider.register_client(client_id, [redirect_uri], extra_audiences=extra_audiences)
    alice = Browser(world.network)
    world.provider.sign_in(alice, "alice", ("pwd",))
    url, transaction = start_login(
        issuer_config=world.config, client_id=client_id, redirect_uri=redirect_uri,
        now=world.clock.now(),
    )
    params = {k: v for k, v in parse_qsl(urlsplit(url).query) if k != "nonce"}
    authorize = with_query(world.config["authorization_endpoint"], params)
    answer = world.network.send(Request("GET", authorize, cookies=alice.cookies(ISSUER)))
    tokens = exchange_code(
        issuer_config=world.config, client_id=client_id, redirect_uri=redirect_uri,
        code=Request("GET", answer.location).query["code"],
        code_verifier=transaction.code_verifier, network=world.network,
    )
    return tokens["id_token"]


def _mint(world: World, key=RSA_1, kid: str = "k1", header: dict | None = None, **changes) -> str:
    """A token signed with key: an honest ID token for app from id.example, with changes."""
    now = world.clock.now()
    claims = {"iss": ISSUER, "sub": "alice", "aud": CLIENT_ID, "exp": now + 300, "iat": now}
    claims = {k: v for k, v in {**claims, **changes}.items() if v is not DROP}
    alg = "ES256" if key is EC_1 else "RS256"
    return jws_encode({"alg": alg, "kid": kid, **(header or {})}, claims, key)


def _post(world: World, token: str) -> Response:
    return world.network.send(Request("POST", f"{APP}/token-login", form={"id_token": token}))


def _reason(check: Callable) -> str | None:
    try:
        check()
    except InvalidToken as refused:
        return refused.reason
    return None


def test_checks_the_signature_and_alg_before_any_claim():
    """Toy validate_id_token checks the token's kind, then its alg, key and signature, before it reads one claim. A forged token gets one reason, however many claims are wrong. Which reason does each token get?"""
    world = _world()
    now = world.clock.now()
    forged = _mint(world, key=ATTACKER_RSA, iss=MALLORY, aud="quiz", exp=now - 1)
    from_other = _mint(world, key=EC_1, kid="o1", iss=OTHER_ISSUER)
    assert world.other.verify_own(from_other)["iss"] == OTHER_ISSUER
    both_keys = jwks_of(*world.jwks["keys"], *world.other.jwks["keys"])

    def reason(token, jwks=world.jwks, algs=ALGS):
        return _reason(lambda: validate_id_token(
            token, issuer=ISSUER, client_id=CLIENT_ID, jwks=jwks, now=now, nonce=None,
            allowed_algs=algs,
        ))

    assert reason(forged) == "bad_signature"
    assert reason(from_other) == "unknown_kid"
    assert reason(from_other, both_keys, frozenset({"RS256"})) == "alg_not_allowed"
    assert reason(from_other, both_keys) == "wrong_issuer"


def check_type(header: dict, payload: dict) -> None:
    typ = header.get("typ")
    id_token_typ = isinstance(typ, str) and typ.lower() in ("jwt", "application/jwt")
    if typ is not None and not id_token_typ:
        raise InvalidToken("wrong_typ")
    if "events" in payload:
        raise InvalidToken("wrong_typ")


def test_accepts_an_id_token_typed_jwt_or_untyped():
    """Implement check_type above (RFC 8725 §3.11). OIDC does not require typ, so an ID token may have none, or "JWT" or "application/jwt" in any case. This verifier also treats a null typ as none. Any other typ, including another value that is not a string, raises InvalidToken("wrong_typ"), and so does a payload with an events claim, a logout token's mark."""
    world = _world()
    for typ in (None, "JWT", "jwt", "application/jwt", "Application/JWT"):
        header = {"alg": "RS256", **({"typ": typ} if typ else {})}
        assert check_type(header, {"sub": "alice"}) is None
    assert check_type({"alg": "RS256", "typ": None}, {"sub": "alice"}) is None
    header, payload, _, _ = jws_split(_id_token_for(world, CLIENT_ID))
    assert header["typ"] == "JWT"
    assert check_type(header, payload) is None


def test_refuses_another_kind_of_jwt():
    """Cross-JWT confusion: suppose id.example also issued RFC 9068 JWT access tokens (typ at+jwt) with its ID token key, as it already does its logout tokens. Each of these passes the signature check, so check_type has to stop it."""
    world = _world()
    others = [
        _mint(world, header={"typ": "at+jwt"}),
        _mint(world, header={"typ": "application/at+jwt"}),
        _mint(world, header={"typ": "logout+jwt"}, events=LOGOUT_EVENT),
        _mint(world, events=LOGOUT_EVENT),
        _mint(world, header={"typ": "JWT"}, events=LOGOUT_EVENT),
        _mint(world, header={"typ": 7}),
    ]
    for token in others:
        assert jws_verify(token, world.jwks, ALGS)["iss"] == ISSUER
        header, payload, _, _ = jws_split(token)
        with pytest.raises(InvalidToken) as refused:
            check_type(header, payload)
        assert refused.value.reason == "wrong_typ"


def check_issuer(claims: dict, issuer: str) -> None:
    if claims.get("iss") != issuer:
        raise InvalidToken("wrong_issuer")


def test_refuses_an_issuer_that_only_looks_right():
    """Implement check_issuer above. Core §3.1.3.7 item 2: the issuer "MUST exactly match" the iss claim. Raise InvalidToken("wrong_issuer") for anything else, a missing iss included. The exact issuer passes; every lookalike fails."""
    assert check_issuer({"iss": ISSUER}, ISSUER) is None
    lookalikes = [
        f"{ISSUER}/", "https://ID.example", "http://id.example", "https://id.example:443",
        f"{ISSUER}.evil.example", f"{ISSUER}/tenant", "https://id.exampl", OTHER_ISSUER,
        [ISSUER], "", None, DROP,
    ]
    for iss in lookalikes:
        claims = {"sub": "alice"} if iss is DROP else {"sub": "alice", "iss": iss}
        with pytest.raises(InvalidToken) as refused:
            check_issuer(claims, ISSUER)
        assert refused.value.reason == "wrong_issuer"


def mallorys_client_id() -> str:
    return "webapp"


def test_spot_the_bug_in_check_posted_token():
    """Spot the bug: app's backend signs in whoever posts an ID token that check_posted_token accepts, using audience_matches. Read both. mallory registers a client of her own at id.example, which lets developers pick their client ids, and alice signs in to it. Make mallorys_client_id return an id that lets that client's ID tokens sign mallory in to app as alice."""
    world = _world(check_aud=audience_matches)
    client_id = mallorys_client_id()
    token = _id_token_for(world, client_id)
    assert client_id != CLIENT_ID
    assert jws_split(token)[1]["aud"] == client_id
    assert _post(world, token).body["user"] == [ISSUER, "alice"]


def check_audience(claims: dict, client_id: str, trusted: frozenset[str]) -> None:
    aud = claims.get("aud", [])
    audiences = [aud] if isinstance(aud, str) else aud
    if not isinstance(audiences, list) or not all(isinstance(a, str) for a in audiences):
        raise InvalidToken("malformed")
    if client_id not in audiences:
        raise InvalidToken("wrong_audience")
    if set(audiences) - {client_id} - trusted:
        raise InvalidToken("wrong_audience")


def test_accepts_this_client_alone_or_with_trusted_audiences():
    """Implement check_audience above, the fix. A missing aud lists nobody: InvalidToken("wrong_audience"). An aud that is neither a string nor an array of strings is "malformed". Otherwise compare whole values, never substrings: client_id must be one of them, and every other value must be in trusted, or "wrong_audience"."""
    world = _world()
    nobody = frozenset()
    assert check_audience({"aud": CLIENT_ID}, CLIENT_ID, nobody) is None
    assert check_audience({"aud": [CLIENT_ID]}, CLIENT_ID, nobody) is None
    assert check_audience({"aud": [API, CLIENT_ID]}, CLIENT_ID, frozenset({API})) is None
    honest = _id_token_for(world, CLIENT_ID)
    assert _post(world, honest).body["user"] == ["https://id.example", "alice"]


def test_refuses_a_token_issued_to_another_client():
    """Token substitution: a token alice got for some other client is posted to app. app's backend, now on check_audience, refuses your exploit and the hidden ones, and a client that asked id.example to add app to its aud. Then the reasons, case by case."""
    world = _world()
    hidden = [mallorys_client_id(), "webapp", "apple", "happ", "quiz"]
    tokens = [_id_token_for(world, client_id) for client_id in hidden]
    assert audience_matches(jws_split(tokens[1])[1], CLIENT_ID, frozenset()) is None
    tokens = [*tokens, _id_token_for(world, "quiz-api", extra_audiences=(CLIENT_ID,))]
    assert jws_split(tokens[-1])[1]["aud"] == ["quiz-api", CLIENT_ID]
    for token in tokens:
        assert _post(world, token).body["error"] == "wrong_audience"
    assert _post(world, _id_token_for(world, CLIENT_ID)).body["user"] == [ISSUER, "alice"]
    cases = [
        ({"aud": "APP"}, "wrong_audience"),
        ({"aud": "app "}, "wrong_audience"),
        ({"aud": ["webapp"]}, "wrong_audience"),
        ({"aud": [CLIENT_ID, "unknown-api"]}, "wrong_audience"),
        ({}, "wrong_audience"),
        ({"aud": []}, "wrong_audience"),
        ({"aud": None}, "malformed"),
        ({"aud": 7}, "malformed"),
        ({"aud": [CLIENT_ID, 7]}, "malformed"),
        ({"aud": ["quiz", 7]}, "malformed"),
        ({"aud": {CLIENT_ID: True}}, "malformed"),
    ]
    for claims, reason in cases:
        assert _reason(lambda: check_audience(claims, CLIENT_ID, frozenset({API}))) == reason


def check_authorized_party(claims: dict, client_id: str, azp_extension: bool) -> None:
    if not azp_extension:
        return
    azp = claims.get("azp")
    several = isinstance(claims.get("aud"), list) and len(claims["aud"]) > 1
    if azp is None and several:
        raise InvalidToken("azp_mismatch")
    if azp is not None and azp != client_id:
        raise InvalidToken("azp_mismatch")


def test_ignores_azp_without_an_extension():
    """Implement check_authorized_party above; aud has already passed check_audience. With azp_extension False, ignore azp, as Core §2 encourages. Under the toy extension, aud with several values needs an azp, and an azp must equal client_id, or InvalidToken("azp_mismatch")."""
    for claims in ({"aud": CLIENT_ID, "azp": "quiz"}, {"aud": [CLIENT_ID, API]}):
        assert check_authorized_party(claims, CLIENT_ID, False) is None
    for claims in ({"aud": [CLIENT_ID, API], "azp": CLIENT_ID}, {"aud": CLIENT_ID}):
        assert check_authorized_party(claims, CLIENT_ID, True) is None
    assert check_authorized_party({"aud": [CLIENT_ID], "azp": CLIENT_ID}, CLIENT_ID, True) is None


def test_refuses_an_azp_for_another_client_under_the_extension():
    """quiz asks id.example to put app in its tokens' aud too, so they carry aud ["quiz", "app"] and azp quiz. If app trusts quiz as an audience, aud alone lets quiz sign people in to app; the extension's azp check stops it. azp never replaces aud. Which reason does each get?"""
    world = _world()
    token = _id_token_for(world, "quiz", extra_audiences=(CLIENT_ID,))
    assert jws_split(token)[1]["azp"] == "quiz"

    def reason(token, trusted=frozenset(), azp_extension=False):
        return _reason(lambda: validate_signed_part(
            token, issuer=ISSUER, client_id=CLIENT_ID, jwks=world.jwks,
            trusted_audiences=trusted, azp_extension=azp_extension,
        ))

    assert reason(token) == "wrong_audience"
    assert reason(token, frozenset({"quiz"})) == None
    assert reason(token, frozenset({"quiz"}), azp_extension=True) == "azp_mismatch"
    for changes in ({"aud": [CLIENT_ID, API]}, {"aud": CLIENT_ID, "azp": "quiz"}):
        assert reason(_mint(world, **changes), frozenset({API}), True) == "azp_mismatch"
    azp_for_app = _mint(world, aud=["quiz"], azp=CLIENT_ID)
    assert reason(azp_for_app, azp_extension=True) == "wrong_audience"
    world.provider.register_client(CLIENT_ID, [REDIRECT_URI], extra_audiences=(API,))
    honest = _id_token_for(world, CLIENT_ID)
    assert reason(honest, frozenset({API}), azp_extension=True) is None


def test_reports_the_first_check_that_fails():
    """validate_signed_part above runs your checks in this course's order, the order of toy validate_id_token. A token with several defects gets the reason of the first check it fails. Which one is it each time?"""
    world = _world()
    now = world.clock.now()

    def reason(token, **options):
        return _reason(lambda: validate_signed_part(
            token, issuer=ISSUER, client_id=CLIENT_ID, jwks=world.jwks, **options
        ))

    logout_forged = _mint(world, key=ATTACKER_RSA, header={"typ": "logout+jwt"}, iss=MALLORY)
    assert reason(logout_forged) == "wrong_typ"
    assert reason(_mint(world, key=ATTACKER_RSA, iss=MALLORY, aud="quiz")) == "bad_signature"
    assert reason(_mint(world, sub=DROP, iss=MALLORY)) == "malformed"
    assert reason(_mint(world, iss=MALLORY, aud="quiz")) == "wrong_issuer"
    wrong_aud_and_azp = _mint(world, aud=["quiz", API], azp="quiz")
    assert reason(wrong_aud_and_azp, azp_extension=True) == "wrong_audience"
    odd_aud_and_azp = _mint(world, aud=[CLIENT_ID, 7], azp="quiz")
    assert reason(odd_aud_and_azp, azp_extension=True) == "malformed"
    expired = _mint(world, exp=now - 600, iat=now - 900)
    assert reason(expired) is None
