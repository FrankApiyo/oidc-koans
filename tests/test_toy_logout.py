from urllib.parse import parse_qsl, urlsplit

import pytest

from toy.client import exchange_code, start_login
from toy.errors import InvalidToken
from toy.http import Request, Response
from toy.jose import jws_encode, jws_split
from toy.keys import ATTACKER_RSA, RSA_1
from toy.logout import (
    LOGOUT_EVENT,
    check_logout_claims,
    logout_url,
    post_logout_target,
    sessions_to_end,
    validate_logout_token,
)

ISSUER = "https://id.example"
APP = "https://app.example"
QUIZ = "https://quiz.example"
AFTER = f"{APP}/signed-out"
EVENTS = {LOGOUT_EVENT: {}}


def _reason(check):
    try:
        check()
    except InvalidToken as refused:
        return refused.reason
    return None


class Inbox:
    def __init__(self):
        self.posts = ()

    def __call__(self, request):
        if request.method == "POST":
            self.posts = (*self.posts, request)
        return Response(200, {}, "ok")


def _register(world, client_id, origin, inbox=None):
    world.provider.register_client(
        client_id, [f"{origin}/callback"], post_logout_redirect_uris=[f"{origin}/signed-out"],
        backchannel_logout_uri=f"{origin}/backchannel" if inbox else None,
    )
    world.network.mount(origin, inbox or Inbox())


def _id_token(world, browser, client_id="app", origin=APP):
    url, transaction = start_login(
        issuer_config=world.config, client_id=client_id, redirect_uri=f"{origin}/callback",
        now=world.clock.now(),
    )
    landed = browser.get(url)
    assert landed.status == 200, landed.body
    code = browser.history[-1].query["code"]
    return exchange_code(
        issuer_config=world.config, client_id=client_id, code=code,
        redirect_uri=f"{origin}/callback", code_verifier=transaction.code_verifier,
        network=world.network,
    )["id_token"]


def _signed_in(world, sub="alice"):
    browser = world.browser()
    world.provider.sign_in(browser, sub, ("pwd",))
    return browser


# --- the logout request -------------------------------------------------------


def test_logout_url_carries_the_hint_and_only_the_parameters_given():
    config = {"end_session_endpoint": f"{ISSUER}/logout"}
    url = logout_url(issuer_config=config, id_token="t", client_id="app")
    assert dict(parse_qsl(urlsplit(url).query)) == {"id_token_hint": "t", "client_id": "app"}
    full = logout_url(
        issuer_config=config, id_token="t", client_id="app", post_logout_redirect_uri=AFTER,
        state="s",
    )
    assert url.startswith(f"{ISSUER}/logout?")
    assert dict(parse_qsl(urlsplit(full).query)) == {
        "id_token_hint": "t", "client_id": "app", "post_logout_redirect_uri": AFTER, "state": "s",
    }


REGISTERED = {"app": (AFTER,), "quiz": (f"{QUIZ}/signed-out",)}
HINTS = {
    "app": {"aud": "app"},
    "quiz": {"aud": "quiz"},
    "app-in-a-list": {"aud": ["app"]},
    "both": {"aud": ["quiz", "app"], "azp": "app"},
}


def _verify(token):
    return HINTS.get(token)


@pytest.mark.parametrize("params, expected", [
    ({"id_token_hint": "app", "post_logout_redirect_uri": AFTER}, AFTER),
    ({"id_token_hint": "app", "client_id": "app", "post_logout_redirect_uri": AFTER}, AFTER),
    ({"id_token_hint": "app-in-a-list", "post_logout_redirect_uri": AFTER}, AFTER),
    ({"id_token_hint": "both", "client_id": "app", "post_logout_redirect_uri": AFTER}, AFTER),
    ({"id_token_hint": "both", "post_logout_redirect_uri": AFTER}, None),
    ({"id_token_hint": "app"}, None),
    ({"id_token_hint": "app", "post_logout_redirect_uri": f"{AFTER}/"}, None),
    ({"id_token_hint": "app", "post_logout_redirect_uri": f"{AFTER}?next=x"}, None),
    ({"id_token_hint": "app", "post_logout_redirect_uri": APP}, None),
    ({"id_token_hint": "app", "post_logout_redirect_uri": f"{QUIZ}/signed-out"}, None),
    ({"id_token_hint": "quiz", "client_id": "app", "post_logout_redirect_uri": AFTER}, None),
    ({"id_token_hint": "app", "client_id": "", "post_logout_redirect_uri": AFTER}, None),
    ({"client_id": "app", "post_logout_redirect_uri": AFTER}, None),
    ({"id_token_hint": "", "client_id": "app", "post_logout_redirect_uri": AFTER}, None),
    ({"id_token_hint": "forged", "client_id": "app", "post_logout_redirect_uri": AFTER}, None),
])
def test_post_logout_target_needs_a_valid_hint_and_an_exact_registered_uri(params, expected):
    assert post_logout_target(params, REGISTERED, _verify) == expected


# --- Logout Tokens -------------------------------------------------------------


def test_check_logout_claims_accepts_sub_sid_or_both():
    for named in ({"sub": "alice"}, {"sid": "s1"}, {"sub": "alice", "sid": "s1"}):
        assert check_logout_claims({**named, "events": EVENTS}) is None
    extra = {"sid": "s1", "events": {LOGOUT_EVENT: {"x": 1}, "other": 1}}
    assert check_logout_claims(extra) is None


@pytest.mark.parametrize("claims, reason", [
    ({"events": EVENTS}, "malformed"),
    ({"sub": "", "events": EVENTS}, "malformed"),
    ({"sid": "", "events": EVENTS}, "malformed"),
    ({"sub": "alice", "sid": "", "events": EVENTS}, "malformed"),
    ({"sub": None, "events": EVENTS}, "malformed"),
    ({"sid": 7, "events": EVENTS}, "malformed"),
    ({"sub": "alice"}, "wrong_typ"),
    ({"sub": "alice", "events": LOGOUT_EVENT}, "wrong_typ"),
    ({"sub": "alice", "events": [LOGOUT_EVENT]}, "wrong_typ"),
    ({"sub": "alice", "events": {}}, "wrong_typ"),
    ({"sub": "alice", "events": {LOGOUT_EVENT: True}}, "wrong_typ"),
    ({"sub": "alice", "events": {LOGOUT_EVENT: None}}, "wrong_typ"),
    ({"sub": "alice", "events": EVENTS, "nonce": "n"}, "wrong_typ"),
    ({"sub": "alice", "events": EVENTS, "nonce": ""}, "wrong_typ"),
    ({"sub": "alice", "events": EVENTS, "nonce": None}, "wrong_typ"),
])
def test_check_logout_claims_refuses_what_is_not_a_logout_token(claims, reason):
    assert _reason(lambda: check_logout_claims(claims)) == reason


def test_validate_logout_token_checks_the_shared_claims_first(world):
    _register(world, "app", APP)
    token = world.provider.logout_token("app", sub="alice", sid="s1")
    assert jws_split(token)[0]["typ"] == "logout+jwt"
    options = {"issuer": ISSUER, "jwks": world.jwks, "now": world.clock.now()}
    claims = validate_logout_token(token, client_id="app", **options)
    assert (claims["sub"], claims["sid"], claims["events"]) == ("alice", "s1", EVENTS)
    assert _reason(lambda: validate_logout_token(token, client_id="quiz", **options)) == (
        "wrong_audience"
    )
    late = {**options, "now": world.clock.now() + 120}
    assert _reason(lambda: validate_logout_token(token, client_id="app", **late)) == "expired"
    forged = jws_encode(
        {"alg": "RS256", "kid": "k1"}, jws_split(token)[1], ATTACKER_RSA,
    )
    assert _reason(lambda: validate_logout_token(forged, client_id="app", **options)) == (
        "bad_signature"
    )
    id_token = _id_token(world, _signed_in(world))
    assert _reason(lambda: validate_logout_token(id_token, client_id="app", **options)) == (
        "wrong_typ"
    )
    claims_with_nonce = {**jws_split(token)[1], "nonce": "n"}
    with_nonce = jws_encode({"alg": "RS256", "kid": "k1"}, claims_with_nonce, RSA_1)
    assert _reason(lambda: validate_logout_token(with_nonce, client_id="app", **options)) == (
        "wrong_typ"
    )


SESSIONS = {
    "laptop": (ISSUER, "alice", "s1"),
    "phone": (ISSUER, "alice", "s2"),
    "bob": (ISSUER, "bob", "s3"),
    "no-sid": (ISSUER, "alice", None),
    "other-alice": ("https://other-id.example", "alice", "s1"),
}


@pytest.mark.parametrize("claims, ended", [
    ({"iss": ISSUER, "sid": "s1"}, {"laptop"}),
    ({"iss": ISSUER, "sub": "alice", "sid": "s1"}, {"laptop"}),
    ({"iss": ISSUER, "sub": "bob", "sid": "s1"}, set()),
    ({"iss": ISSUER, "sub": "alice"}, {"laptop", "phone", "no-sid"}),
    ({"iss": ISSUER, "sub": "bob"}, {"bob"}),
    ({"iss": ISSUER, "sub": "carol"}, set()),
    ({"iss": ISSUER, "sid": "s9"}, set()),
    ({"iss": "https://other-id.example", "sid": "s1"}, {"other-alice"}),
    ({"iss": "https://mallory.example", "sub": "alice"}, set()),
])
def test_sessions_to_end_follows_sid_when_given_and_iss_always(claims, ended):
    assert sessions_to_end(SESSIONS, claims) == frozenset(ended)


# --- the provider ----------------------------------------------------------------


def test_discovery_advertises_back_channel_logout_with_sid(world):
    assert world.config["backchannel_logout_supported"] is True
    assert world.config["backchannel_logout_session_supported"] is True


def test_only_a_back_channel_client_gets_sid_in_its_id_tokens(world):
    inbox = Inbox()
    _register(world, "app", APP, inbox)
    _register(world, "quiz", QUIZ)
    browser = _signed_in(world)
    app_claims = jws_split(_id_token(world, browser))[1]
    quiz_claims = jws_split(_id_token(world, browser, "quiz", QUIZ))[1]
    assert isinstance(app_claims["sid"], str) and app_claims["sid"]
    assert "sid" not in quiz_claims


def test_logout_posts_a_logout_token_to_each_client_of_the_session(world):
    app_inbox, quiz_inbox, unused_inbox = Inbox(), Inbox(), Inbox()
    _register(world, "app", APP, app_inbox)
    _register(world, "quiz", QUIZ, quiz_inbox)
    _register(world, "unused", "https://unused.example", unused_inbox)
    browser = _signed_in(world)
    hint = _id_token(world, browser)
    sid = jws_split(hint)[1]["sid"]
    _id_token(world, browser, "quiz", QUIZ)
    bob = _signed_in(world, "mallory")
    _id_token(world, bob)
    landed = browser.get(logout_url(
        issuer_config=world.config, id_token=hint, client_id="app", post_logout_redirect_uri=AFTER,
    ))
    assert landed.body == "ok"
    assert unused_inbox.posts == ()
    for inbox, client_id in ((app_inbox, "app"), (quiz_inbox, "quiz")):
        (post,) = inbox.posts
        claims = validate_logout_token(
            post.form["logout_token"], issuer=ISSUER, client_id=client_id, jwks=world.jwks,
            now=world.clock.now(),
        )
        assert (claims["sub"], claims["sid"]) == ("alice", sid)
    again = browser.get(logout_url(issuer_config=world.config, id_token=hint, client_id="app"))
    assert again.body == {"signed_out": True}
    assert len(app_inbox.posts) == 1


def test_signing_in_again_as_the_same_user_keeps_the_sid(world):
    inbox = Inbox()
    _register(world, "app", APP, inbox)
    browser = _signed_in(world)
    first = jws_split(_id_token(world, browser))[1]["sid"]
    world.provider.sign_in(browser, "alice", ("pwd",))
    assert jws_split(_id_token(world, browser))[1]["sid"] == first
    world.provider.sign_in(browser, "mallory", ("pwd",))
    assert jws_split(_id_token(world, browser))[1]["sid"] != first


def test_logout_without_a_session_tells_no_client(world):
    inbox = Inbox()
    _register(world, "app", APP, inbox)
    assert world.browser().get(f"{ISSUER}/logout").status == 200
    assert world.network.send(Request("GET", f"{ISSUER}/logout")).status == 200
    assert inbox.posts == ()
