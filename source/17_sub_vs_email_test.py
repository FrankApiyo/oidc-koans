"""sub vs email: choosing an account key.

An ID token's sub is "A locally unique and never reassigned identifier
within the Issuer for the End-User" (Core §2): a case-sensitive string of
at most 255 ASCII characters. Locally unique means unique at that issuer
only, and another provider may give the same sub to someone else. So Core
§5.7: iss and sub together "are the only Claims that an RP can rely upon as
a stable identifier", and email, phone_number, preferred_username and name
"MUST NOT be used as unique identifiers". An issuer "MAY re-use an email
Claim Value across different End-Users at different points in time".

email_verified true (Core §5.1) "means that the OP took affirmative steps
to ensure that this e-mail address was controlled by the End-User at the
time the verification was performed". It is a JSON boolean, so the string
"true" is not true. It says nothing about today, and each provider
verifies by its own rules, which are not yours.

So key accounts by (iss, sub). An email may suggest that a new sign-in
belongs to an account you already have, but linking the two takes proof:
the person signs in to that account the way they already do.

A provider may also give each client its own sub for the same person
(pairwise identifiers, Core §8), so that clients cannot correlate users.

A common mistake: finding the account by email, or by sub alone.

Read more:
  https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability
  https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
  https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes
"""

import hashlib
import secrets
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

import pytest

from conftest import __
from toy.client import (
    check_userinfo_subject,
    exchange_code,
    fetch_userinfo,
    start_login,
    validate_id_token,
)
from toy.client import account_key as toy_account_key
from toy.clock import Clock
from toy.errors import InvalidToken, OAuthError
from toy.http import Browser, FakeNetwork, Request, Response, with_query
from toy.jose import jws_split
from toy.keys import EC_1
from toy.provider import Provider

ISSUER = "https://id.example"
OTHER_ISSUER = "https://other-id.example"
APP = "https://app.example"
REDIRECT_URI = f"{APP}/callback"
QUIZ_REDIRECT_URI = "https://quiz.example/callback"
CLIENT_ID = "app"
LINK_COOKIE = "link"
PROVE = "sign in to the account that has this email"


def account_key(claims: dict) -> tuple[str, str]:
    # >>> answer
    key = (claims.get("iss"), claims.get("sub"))
    if not all(isinstance(part, str) and part for part in key):
        raise InvalidToken("malformed")
    return key
    # <<<


class App:
    """app at https://app.example, with sign-in at id.example and other-id.example.

    A browser posts to /signin the issuer its login went to (provider), and the
    ID token and access token it got there. app validates the ID token, checks
    UserInfo's sub against it, and finds the account:
    1. An identity app knows, by account_key, signs in to its account. If this
       browser is proving a link to that account, the pending identity joins it.
    2. An unknown identity whose verified_email an account already has links
       nothing: app keeps it pending in this browser and answers 202, asking
       the person to sign in to that account.
    3. Any other identity gets a new account.
    identities maps each (iss, sub) to its account, and emails each account to
    the verified email it was created with, or None.
    """

    def __init__(self, clock: Clock, network: FakeNetwork):
        self._clock, self._network = clock, network
        self._providers = {
            issuer: _discovered(network, issuer) for issuer in (ISSUER, OTHER_ISSUER)
        }
        self.identities: dict[tuple[str, str], str] = {}
        self.emails: dict[str, str | None] = {}
        self._pending: dict[str, tuple[tuple[str, str], str]] = {}

    def __call__(self, request: Request) -> Response:
        if request.path != "/signin" or request.form.get("provider") not in self._providers:
            return Response(404, {}, {"error": "not_found"})
        try:
            claims = self._claims(request.form)
            identity = account_key(claims)
        except InvalidToken as refused:
            return Response(401, {}, {"error": refused.reason})
        except OAuthError as refused:
            return Response(401, {}, {"error": refused.error})
        account = self.identities.get(identity)
        if account is not None:
            return self._signed_in(account, request.cookies.get(LINK_COOKIE))
        email = verified_email(claims)
        candidate = next((a for a, known in self.emails.items() if email and known == email), None)
        if candidate is not None:
            link = secrets.token_urlsafe(16)
            self._pending = {**self._pending, link: (identity, candidate)}
            return Response(202, {}, {"prove": PROVE}, {LINK_COOKIE: link})
        account = f"account-{len(self.emails) + 1}"
        self.emails = {**self.emails, account: email}
        self.identities = {**self.identities, identity: account}
        return Response(200, {}, {"account": account})

    def _claims(self, form: dict) -> dict:
        config, jwks = self._providers[form["provider"]]
        claims = validate_id_token(
            form.get("id_token"), issuer=config["issuer"], client_id=CLIENT_ID, jwks=jwks,
            now=self._clock.now(), nonce=None,
        )
        userinfo = fetch_userinfo(
            issuer_config=config, access_token=form.get("access_token", ""), network=self._network,
        )
        check_userinfo_subject(claims, userinfo)
        return {**userinfo, **claims}

    def _signed_in(self, account: str, link: str | None) -> Response:
        pending, for_account = self._pending.get(link or "", (None, None))
        if for_account != account:
            return Response(200, {}, {"account": account})
        self._pending = {k: v for k, v in self._pending.items() if k != link}
        self.identities = {**self.identities, pending: account}
        return Response(200, {}, {"account": account, "linked": list(pending)}, {LINK_COOKIE: None})


def _discovered(network: FakeNetwork, issuer: str) -> tuple[dict, dict]:
    config = network.send(Request("GET", f"{issuer}/.well-known/openid-configuration")).body
    return config, network.send(Request("GET", config["jwks_uri"])).body


@dataclass(frozen=True)
class World:
    clock: Clock
    network: FakeNetwork
    provider: Provider
    other: Provider
    app: App


def _world() -> World:
    """id.example, where alice, Alice and mallory have accounts, and other-id.example, where alice is someone else."""
    clock, network = Clock(), FakeNetwork()
    provider = Provider(ISSUER, clock=clock, network=network)
    other = Provider(OTHER_ISSUER, clock=clock, network=network, signing_key=EC_1, kid="o1")
    for op in (provider, other):
        op.register_client(CLIENT_ID, [REDIRECT_URI])
    provider.add_user("alice", "alice@example.com", True, "alice-password")
    provider.add_user("Alice", "big-alice@example.com", True, "big-alice-password")
    provider.add_user("mallory", "mallory@example.com", True, "mallory-password")
    other.add_user("alice", "another-alice@example.com", True, "other-alice-password")
    app = App(clock, network)
    network.mount(APP, app)
    return World(clock, network, provider, other, app)


def _tokens(world: World, browser: Browser, provider: Provider, sub: str) -> dict:
    """The tokens provider sends app, with no nonce, after sub signs in there in browser."""
    provider.sign_in(browser, sub, ("pwd",))
    config, _ = _discovered(world.network, provider.issuer)
    url, transaction = start_login(
        issuer_config=config, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI,
        now=world.clock.now(),
    )
    params = {k: v for k, v in parse_qsl(urlsplit(url).query) if k != "nonce"}
    authorize = with_query(config["authorization_endpoint"], params)
    answer = world.network.send(Request("GET", authorize, cookies=browser.cookies(provider.issuer)))
    return exchange_code(
        issuer_config=config, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI,
        code=Request("GET", answer.location).query["code"],
        code_verifier=transaction.code_verifier, network=world.network,
    )


def _sign_in(world: World, browser: Browser, provider: Provider, sub: str) -> Response:
    """sub signs in at provider in browser, and the browser posts the tokens to app."""
    tokens = _tokens(world, browser, provider, sub)
    form = {"provider": provider.issuer, **{k: tokens[k] for k in ("id_token", "access_token")}}
    return browser.post(f"{APP}/signin", form)


def _claims(world: World, provider: Provider, sub: str) -> dict:
    """What app learns about sub from provider: UserInfo, overlaid with the ID token."""
    tokens = _tokens(world, Browser(world.network), provider, sub)
    config, _ = _discovered(world.network, provider.issuer)
    userinfo = fetch_userinfo(
        issuer_config=config, access_token=tokens["access_token"], network=world.network
    )
    return {**userinfo, **jws_split(tokens["id_token"])[1]}


def _account(response: Response) -> str | None:
    return response.body.get("account") if response.status == 200 else None


def test_only_iss_and_sub_stay_put():
    """alice changes her email at id.example between two sign-ins, a minute apart. Core §5.7: "the claimed email address for a given End-User MAY change over time". Which of these claims are the same both times, and which account key do they give?"""
    world = _world()
    before = _claims(world, world.provider, "alice")
    world.clock.advance(60)
    world.provider.add_user("alice", "alice@new.example", True, "alice-password")
    after = _claims(world, world.provider, "alice")
    same = [name for name in ("iss", "sub", "email", "iat") if before[name] == after[name]]
    assert same == _a(["iss", "sub"])
    assert toy_account_key(after) == _a(("https://id.example", "alice"))


def test_accepts_the_same_person_after_an_email_change():
    """Implement account_key above: return (iss, sub). If either is missing, empty or not a string, raise InvalidToken("malformed"). alice signs in to id.example, changes her email there, and signs in again. Both sign-ins give one key."""
    world = _world()
    before = _claims(world, world.provider, "alice")
    world.provider.add_user("alice", "alice@new.example", True, "alice-password")
    after = _claims(world, world.provider, "alice")
    assert account_key(before) == _a(("https://id.example", "alice"))
    assert account_key(after) == account_key(before)


def test_refuses_a_second_issuer_with_the_same_sub():
    """Core §8: a sub is unique "within the Issuer". other-id.example's alice is not id.example's alice, and Core §2 makes sub case-sensitive, so id.example's Alice is a third person. How many accounts do their keys make? A claim set without a usable iss or sub has no key at all."""
    world = _world()
    people = [
        _claims(world, world.provider, "alice"),
        _claims(world, world.other, "alice"),
        _claims(world, world.provider, "Alice"),
    ]
    assert [person["sub"] for person in people] == ["alice", "alice", "Alice"]
    assert len({account_key(person) for person in people}) == _a(3)
    for claims in [
        {"sub": "alice"}, {"iss": ISSUER}, {"iss": ISSUER, "sub": ""}, {"iss": "", "sub": "alice"},
        {"iss": ISSUER, "sub": 123}, {"iss": ISSUER, "sub": ["alice"]}, {"iss": None, "sub": "a"},
    ]:
        with pytest.raises(InvalidToken) as refused:
            account_key(claims)
        assert refused.value.reason == _a("malformed")


def verified_email(claims: dict) -> str | None:
    # >>> answer
    email = claims.get("email")
    if claims.get("email_verified") is not True or not isinstance(email, str) or not email:
        return None
    return email
    # <<<


def test_accepts_an_email_verified_as_json_true():
    """Implement verified_email above: return claims["email"] when email_verified is JSON true (Python True, nothing else) and email is a non-empty string; otherwise None. app records the verified email of each new account."""
    world = _world()
    assert verified_email({"email": "a@example.com", "email_verified": True}) == _a("a@example.com")
    assert _account(_sign_in(world, Browser(world.network), world.provider, "alice")) == "account-1"
    assert world.app.emails == _a({"account-1": "alice@example.com"})


def test_refuses_an_email_not_verified_as_json_true():
    """mallory signs up at other-id.example with alice@example.com and never verifies it; other-id then sends email_verified in shapes Core §5.1 does not allow. None of them is JSON true, so app offers no link and records no email. What does each give?"""
    for shape in [False, None, "true", "false", 1, 1.0, [True], {}]:
        assert verified_email({"email": "alice@example.com", "email_verified": shape}) is _a(None)
    for email in [None, "", ["alice@example.com"]]:
        assert verified_email({"email": email, "email_verified": True}) is None
    assert verified_email({"email": "alice@example.com"}) is None
    world = _world()
    assert _account(_sign_in(world, Browser(world.network), world.provider, "alice")) == "account-1"
    world.other.add_user("mallory", "alice@example.com", "true", "mallory-password")
    mallory = _sign_in(world, Browser(world.network), world.other, "mallory")
    assert (mallory.status, _account(mallory)) == _a((200, "account-2"))
    assert world.app.emails["account-2"] is None


def test_refuses_to_key_by_a_reassigned_email():
    """alice moves to a new address, and id.example gives alice@example.com to carol, a new user. Her ID token comes with that email and email_verified true, which is honest: it is hers now. Core §5.1: verified means controlled "at the time the verification was performed". carol must not land in alice's account; app asks her to prove she owns it, which she cannot. What does app answer, and where does alice land?"""
    world = _world()
    alice = Browser(world.network)
    assert _account(_sign_in(world, alice, world.provider, "alice")) == "account-1"
    world.provider.add_user("alice", "alice@new.example", True, "alice-password")
    world.provider.add_user("carol", "alice@example.com", True, "carol-password")
    carol = _sign_in(world, Browser(world.network), world.provider, "carol")
    assert carol.status == _a(202)
    assert carol.body == {"prove": PROVE}
    assert (ISSUER, "carol") not in world.app.identities
    assert _account(_sign_in(world, alice, world.provider, "alice")) == _a("account-1")


def test_refuses_to_link_without_proof():
    """mallory gets other-id.example to vouch for alice@example.com: email_verified true, by other-id's rules, not app's. A client that linked by that email would hand her alice's account. app only asks for proof, and the proof mallory can give is a sign-in to her own id.example account, which is not alice's. Where does she end up, and does alice's account gain an identity?"""
    world = _world()
    assert _account(_sign_in(world, Browser(world.network), world.provider, "alice")) == "account-1"
    own = _sign_in(world, Browser(world.network), world.provider, "mallory")
    assert _account(own) == "account-2"
    world.other.add_user("mallory", "alice@example.com", True, "mallory-password")
    mallory = Browser(world.network)
    assert _sign_in(world, mallory, world.other, "mallory").status == _a(202)
    assert _account(_sign_in(world, mallory, world.provider, "mallory")) == _a("account-2")
    alices = sorted(i for i, a in world.app.identities.items() if a == "account-1")
    assert alices == _a([("https://id.example", "alice")])


def test_accepts_a_link_proven_by_the_existing_login():
    """alice signs up at other-id.example too, with her verified alice@example.com. app answers 202. In the same browser she signs in to id.example, as she always has, and app links the two. From then on either provider brings her to the same account."""
    world = _world()
    alice = Browser(world.network)
    assert _account(_sign_in(world, alice, world.provider, "alice")) == "account-1"
    world.other.add_user("alice-o", "alice@example.com", True, "alice-password")
    assert _sign_in(world, alice, world.other, "alice-o").status == _a(202)
    proof = _sign_in(world, alice, world.provider, "alice")
    assert proof.body == _a({
        "account": "account-1", "linked": ["https://other-id.example", "alice-o"],
    })
    assert _account(_sign_in(world, Browser(world.network), world.other, "alice-o")) == "account-1"


def pairwise_sub(sector: str, local_id: str, salt: bytes) -> str:
    """Core §8.1's first example method: sub = SHA-256(sector_identifier || local_account_id || salt)."""
    return hashlib.sha256(sector.encode("ascii") + local_id.encode("utf-8") + salt).hexdigest()


def test_a_pairwise_sub_differs_per_client():
    """Core §8: a pairwise sub is "a different sub value to each Client, so as not to enable Clients to correlate the End-User's activities without permission". With no sector_identifier_uri, §8.1 takes "the host component of the registered redirect_uri" as the Sector Identifier. A provider using pairwise_sub computes alice's sub for app and for quiz. Do the two match? Does app get the same one next time? Which subject types does id.example support?"""
    salt = b"known-only-to-the-provider"
    sector = urlsplit(REDIRECT_URI).hostname
    assert sector == _a("app.example")
    at_app = pairwise_sub(sector, "alice", salt)
    at_quiz = pairwise_sub(urlsplit(QUIZ_REDIRECT_URI).hostname, "alice", salt)
    assert (at_app == at_quiz) is _a(False)
    assert (pairwise_sub("app.example", "alice", salt) == at_app) is _a(True)
    config, _ = _discovered(_world().network, ISSUER)
    assert config["subject_types_supported"] == _a(["public"])
