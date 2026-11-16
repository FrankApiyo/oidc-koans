"""Refresh tokens and rotation.

A refresh token gets a new access token without the user: the client
posts grant_type=refresh_token (RFC 6749 §6), and its scope "MUST NOT
include any scope not originally granted by the resource owner". The toy
grants a refresh token with every code, so offline_access is left out.
Core §11: "The use of Refresh Tokens is not exclusive to the
offline_access use case. The Authorization Server MAY grant Refresh Tokens
in other contexts that are beyond the scope of this specification."

A refresh is not a sign-in. An ID token in the response is about the
original one (Core §12.2): its iss, sub and aud "MUST be the same as in
the ID Token issued when the original authentication occurred", its
auth_time "MUST represent the time of the original authentication", and it
"SHOULD NOT have a nonce Claim". So refreshing never satisfies max_age.

A refresh token holds the whole grant, so it is worth stealing. RFC 9700
§2.2.2: refresh tokens for public clients "MUST be sender-constrained or
use refresh token rotation". With rotation each refresh returns a new
refresh token and spends the old one, which the client "MUST discard" (RFC
6749 §6). If a spent token comes back, the server "cannot determine which
party submitted the invalid refresh token, but it will revoke the active
refresh token" (RFC 9700 §4.14.2).

A common mistake: treating a refreshed ID token as a fresh sign-in.

Read more:
  https://www.rfc-editor.org/rfc/rfc6749.html#section-6
  https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
  https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2
"""

from collections.abc import Callable
from dataclasses import dataclass, replace

import pytest

from conftest import __
from toy.client import exchange_code, refresh, start_login, validate_id_token
from toy.clock import Clock
from toy.errors import InvalidToken, OAuthError
from toy.http import Browser, FakeNetwork, Request, Response
from toy.jose import jws_split
from toy.provider import Provider
from toy.token_endpoint import ACCESS_LIFETIME, RefreshLedger

ISSUER = "https://id.example"
OTHER_ISSUER = "https://other-id.example"
APP = "https://app.example"
REDIRECT_URI = f"{APP}/callback"
CLIENT_ID = "app"
BILLING_SECRET = b"billing-secret-koans-only"
DROP = object()


@dataclass(frozen=True)
class World:
    clock: Clock
    network: FakeNetwork
    provider: Provider
    config: dict
    jwks: dict


def _world() -> World:
    """id.example with alice and mallory, the public clients app and quiz, and the confidential billing."""
    clock, network = Clock(), FakeNetwork()
    provider = Provider(ISSUER, clock=clock, network=network)
    provider.register_client(CLIENT_ID, [REDIRECT_URI])
    provider.register_client("quiz", [REDIRECT_URI])
    provider.register_client("billing", [REDIRECT_URI], secret=BILLING_SECRET)
    provider.add_user("alice", "alice@example.com", True, "alice-password")
    provider.add_user("mallory", "mallory@example.com", True, "mallory-password")
    network.mount(APP, lambda request: Response(200, {}, "callback reached"))
    config = network.send(Request("GET", f"{ISSUER}/.well-known/openid-configuration")).body
    jwks = network.send(Request("GET", config["jwks_uri"])).body
    return World(clock, network, provider, config, jwks)


def _login(
    world: World, sub: str = "alice", scope: str = "openid email", client_id: str = CLIENT_ID,
    client_secret: bytes | None = None,
) -> tuple[dict, dict]:
    """sub signs in to client_id at id.example: the token response, and its ID token's claims."""
    browser = Browser(world.network)
    world.provider.sign_in(browser, sub, ("pwd",))
    url, transaction = start_login(
        issuer_config=world.config, client_id=client_id, redirect_uri=REDIRECT_URI,
        now=world.clock.now(), scope=scope,
    )
    answer = world.network.send(Request("GET", url, cookies=browser.cookies(ISSUER)))
    tokens = exchange_code(
        issuer_config=world.config, client_id=client_id, redirect_uri=REDIRECT_URI,
        code=Request("GET", answer.location).query["code"],
        code_verifier=transaction.code_verifier, network=world.network,
        client_secret=client_secret,
    )
    claims = validate_id_token(
        tokens["id_token"], issuer=ISSUER, client_id=client_id, jwks=world.jwks,
        now=world.clock.now(), nonce=transaction.nonce,
    )
    return tokens, claims


def _refresh(world: World, refresh_token: str, client_id: str = CLIENT_ID, **form) -> Response:
    """A refresh request from a public client: no secret, just its client_id."""
    body = {"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": client_id}
    request = Request("POST", world.config["token_endpoint"], form={**body, **form})
    return world.network.send(request)


def _userinfo(world: World, access_token: str) -> Response:
    headers = {"Authorization": f"Bearer {access_token}"}
    return world.network.send(Request("GET", world.config["userinfo_endpoint"], headers=headers))


def _refusal(check: Callable) -> str | None:
    try:
        check()
    except InvalidToken as refused:
        return refused.reason
    except OAuthError as refused:
        return refused.error
    return None


def test_a_refresh_names_its_grant_type():
    """alice's access token has expired, and UserInfo turns it away. app posts its refresh token to the token endpoint instead of sending alice to sign in again. RFC 6749 §6: grant_type is "REQUIRED. Value MUST be set to" what? What does UserInfo say to the new access token?"""
    world = _world()
    tokens, _ = _login(world)
    world.clock.advance(ACCESS_LIFETIME)
    assert _userinfo(world, tokens["access_token"]).status == 401
    form = {
        "grant_type": __, "refresh_token": tokens["refresh_token"],
        "client_id": CLIENT_ID,
    }
    answer = world.network.send(Request("POST", world.config["token_endpoint"], form=form))
    assert answer.status == 200
    assert _userinfo(world, answer.body["access_token"]).status == __
    assert answer.body["refresh_token"] != tokens["refresh_token"]


def test_a_refresh_asks_for_the_grant_or_less():
    """RFC 6749 §6: the scope "MUST NOT include any scope not originally granted by the resource owner". alice granted app openid and email. A refresh may ask for less, and its access token gets less. The new refresh token still holds the whole grant: §6 says its scope "MUST be identical to that of the refresh token included by the client in the request". A scope id.example does not know was never granted either, so it gets the same answer."""
    world = _world()
    tokens, _ = _login(world, scope="openid")
    wider = _refresh(world, tokens["refresh_token"], scope="openid email")
    assert (wider.status, wider.body["error"]) == (400, __)
    unknown = _refresh(world, tokens["refresh_token"], scope="openid shoe_size")
    assert unknown.body["error"] == __
    tokens, _ = _login(world, scope="openid email")
    narrow = _refresh(world, tokens["refresh_token"], scope="openid").body
    assert narrow["scope"] == __
    assert ("email" in _userinfo(world, narrow["access_token"]).body) is __
    again = _refresh(world, narrow["refresh_token"]).body
    assert again["scope"] == __


def test_a_refreshed_id_token_keeps_the_original_sign_in():
    """alice signed in 1000 seconds ago, and app refreshes. Core §12.2: the new ID token's iat is "the time that the new ID Token is issued", but auth_time is "the time of the original authentication", and it "SHOULD NOT have a nonce Claim". So a client that needs a sign-in within the last 600 seconds (max_age, chapter 20) cannot get one by refreshing."""
    world = _world()
    tokens, original = _login(world)
    world.clock.advance(1000)
    token = _refresh(world, tokens["refresh_token"]).body["id_token"]
    refreshed = jws_split(token)[1]
    assert refreshed["iat"] - original["iat"] == __
    assert refreshed["auth_time"] - original["auth_time"] == __
    assert ("nonce" in refreshed) is __
    with pytest.raises(InvalidToken) as refused:
        validate_id_token(
            token, issuer=ISSUER, client_id=CLIENT_ID, jwks=world.jwks, now=world.clock.now(),
            nonce=None, max_age=600,
        )
    assert refused.value.reason == __


def check_refreshed_id_token(original: dict, refreshed: dict) -> None:
    __()


def _refreshed_claims(world: World, original: dict, response: dict) -> dict:
    """The claims of a refresh response's ID token, checked as app checks them.

    validate_id_token comes first. It expects the original nonce if the new token
    carries one, and no nonce otherwise. Then your check_refreshed_id_token.
    """
    token = response["id_token"]
    carries_nonce = "nonce" in jws_split(token)[1]
    claims = validate_id_token(
        token, issuer=ISSUER, client_id=CLIENT_ID, jwks=world.jwks, now=world.clock.now(),
        nonce=original.get("nonce") if carries_nonce else None,
    )
    check_refreshed_id_token(original, claims)
    return claims


def test_accepts_a_refreshed_id_token_about_the_same_sign_in():
    """Implement check_refreshed_id_token above; original holds the claims of the ID token from alice's sign-in. In this order, raise InvalidToken with "wrong_issuer", "sub_mismatch" or "wrong_audience" when refreshed's iss, sub or aud is not equal to the original's, compared as whole values: that is this course's reading of "the same". Then, if refreshed has a nonce at all, it must equal the original's, or "nonce_mismatch". Last, Core §12.2: "if the ID Token contains an auth_time Claim, its value MUST represent the time of the original authentication - not the time that the new ID token is issued". So if refreshed has an auth_time at all, it must equal the original's, or "auth_time_changed"."""
    world = _world()
    tokens, original = _login(world)
    world.clock.advance(120)
    claims = _refreshed_claims(world, original, _refresh(world, tokens["refresh_token"]).body)
    assert claims["sub"] == __
    assert check_refreshed_id_token(original, {**claims, "nonce": original["nonce"]}) is None
    assert check_refreshed_id_token(original, {**original, "iat": original["iat"] + 60}) is None


def test_refuses_a_refreshed_id_token_about_someone_else():
    """A refresh response hands app mallory's own genuine ID token, as a provider with a bug in its grant book-keeping might. It is signed by id.example and made out to app, so validate_id_token passes it. Your check does not. Then, a reason for each of these changes to alice's original claims, among them the auth_time of a provider that stamps each refresh as a new sign-in. validate_id_token with max_age would take that one as fresh."""
    world = _world()
    tokens, original = _login(world)
    mallorys, _ = _login(world, "mallory")
    her_token = _refresh(world, mallorys["refresh_token"]).body["id_token"]
    response = {**_refresh(world, tokens["refresh_token"]).body, "id_token": her_token}
    assert jws_split(her_token)[1]["aud"] == CLIENT_ID
    assert _refusal(lambda: _refreshed_claims(world, original, response)) == __
    cases = [
        ({"iss": OTHER_ISSUER}, __),
        ({"iss": OTHER_ISSUER, "sub": "mallory"}, __),
        ({"sub": "Alice"}, __),
        ({"sub": ""}, "sub_mismatch"),
        ({"sub": DROP}, "sub_mismatch"),
        ({"aud": [CLIENT_ID, "quiz"]}, __),
        ({"aud": [CLIENT_ID]}, "wrong_audience"),
        ({"nonce": "another"}, __),
        ({"nonce": ""}, "nonce_mismatch"),
        ({"auth_time": original["auth_time"] + 120}, __),
        ({"auth_time": None}, "auth_time_changed"),
        ({"auth_time": DROP}, __),
        ({"iat": original["iat"] + 120}, None),
    ]
    for changes, reason in cases:
        refreshed = {k: v for k, v in {**original, **changes}.items() if v is not DROP}
        assert _refusal(lambda: check_refreshed_id_token(original, refreshed)) == reason


def spend_refresh_token(ledger: RefreshLedger, token: str) -> tuple[str | None, RefreshLedger]:
    __()


class RefreshDesk:
    """A token endpoint's refresh-token book-keeping, built on your spend_refresh_token.

    grant(grant_id) starts a grant and returns its first refresh token, and
    refresh(token) returns the next one or raises OAuthError("invalid_grant").
    Tokens are named rt-1, rt-2 and so on, in the order they are issued.
    """

    def __init__(self):
        self.ledger = RefreshLedger()
        self._issued = 0

    def grant(self, grant_id: str) -> str:
        return self._issue(grant_id)

    def refresh(self, token: str) -> str:
        grant_id, self.ledger = spend_refresh_token(self.ledger, token)
        if grant_id is None:
            raise OAuthError("invalid_grant")
        return self._issue(grant_id)

    def _issue(self, grant_id: str) -> str:
        self._issued += 1
        token = f"rt-{self._issued}"
        self.ledger = replace(self.ledger, active={**self.ledger.active, token: grant_id})
        return token


def test_accepts_each_rotated_refresh_token_once():
    """Implement spend_refresh_token above; it returns the grant a token is good for, or None, with the ledger after this use. ledger.active maps each usable token to its grant, ledger.spent each used one, and ledger.revoked holds grants whose tokens no longer work. 1. An active token of a grant not revoked: return its grant, and a new RefreshLedger with the token moved from active to spent. 2. A spent token: return None, and the ledger with its grant added to revoked. 3. Anything else: None and the ledger as it was. Never change ledger itself."""
    desk = RefreshDesk()
    first = desk.grant("alice-at-app")
    second = desk.refresh(first)
    third = desk.refresh(second)
    assert (first, second, third) == __
    bobs = desk.grant("bob-at-app")
    assert desk.refresh(bobs) == __
    assert desk.ledger.active == __
    assert desk.ledger.revoked == frozenset()


def test_refuses_a_refresh_token_used_twice():
    """A thief copies alice's rt-1. Whoever sends it second, the client or the thief, gets invalid_grant, and so does every token of alice's grant from then on, since the server cannot tell them apart. bob's grant is untouched. Try both orders, and a token nobody issued."""
    desk = RefreshDesk()
    stolen, bobs = desk.grant("alice-at-app"), desk.grant("bob-at-app")
    clients = desk.refresh(stolen)
    assert _refusal(lambda: desk.refresh(stolen)) == __
    assert _refusal(lambda: desk.refresh(clients)) == __
    assert desk.ledger.revoked == __
    assert desk.refresh(bobs) == "rt-4"

    desk = RefreshDesk()
    stolen = desk.grant("alice-at-app")
    thiefs = desk.refresh(stolen)
    assert _refusal(lambda: desk.refresh(stolen)) == "invalid_grant"
    assert _refusal(lambda: desk.refresh(thiefs)) == __
    for unknown in ("", "rt-9", "RT-2"):
        before = desk.ledger
        assert _refusal(lambda: desk.refresh(unknown)) == "invalid_grant"
        assert desk.ledger == before


def test_the_provider_revokes_the_whole_grant_on_reuse():
    """id.example rotates refresh tokens and spots reuse the same way. app refreshes; then a thief replays the refresh token app has just spent. What do the thief, app's current refresh token and app's current access token get? alice's next sign-in starts a new grant, which works."""
    world = _world()
    tokens, _ = _login(world)
    stolen = tokens["refresh_token"]
    current = _refresh(world, stolen).body
    assert _refresh(world, stolen).body["error"] == __
    assert _refresh(world, current["refresh_token"]).body["error"] == __
    assert world.provider.introspect(current["access_token"])["active"] is __
    fresh, _ = _login(world)
    assert _refresh(world, fresh["refresh_token"]).status == 200


def test_a_refresh_token_is_bound_to_its_client():
    """RFC 6749 §10.4: "The authorization server MUST maintain the binding between a refresh token and the client to whom it was issued." billing is a confidential client, so a thief holding its refresh token also needs its secret. RFC 9700 §2.2.2 asks rotation or sender-constraining of public clients only, because "[RFC6749] already mandates" this binding for confidential ones. What does each attempt get?"""
    world = _world()
    tokens, _ = _login(world, client_id="billing", client_secret=BILLING_SECRET)
    as_quiz = _refresh(world, tokens["refresh_token"], client_id="quiz")
    assert as_quiz.body["error"] == __
    as_billing = _refresh(world, tokens["refresh_token"], client_id="billing")
    assert (as_billing.status, as_billing.body["error"]) == __
    renewed = refresh(
        issuer_config=world.config, client_id="billing", refresh_token=tokens["refresh_token"],
        network=world.network, client_secret=BILLING_SECRET,
    )
    assert renewed["token_type"] == __
