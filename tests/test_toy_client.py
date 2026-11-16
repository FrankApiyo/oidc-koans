import base64
import hashlib
from dataclasses import replace
from urllib.parse import parse_qsl, urlencode, urlsplit

import pytest

from toy.client import (
    STATE_COOKIE,
    Transaction,
    account_key,
    basic_authorization,
    check_acr,
    discover,
    exchange_code,
    finish_login,
    refresh,
    start_login,
    validate_id_token,
)
from toy.errors import FlowError, InvalidToken, OAuthError
from toy.http import Request, Response
from toy.jose import jws_encode, jwks_of, public_jwk
from toy.keys import ATTACKER_RSA, EC_1, RSA_1

ISSUER = "https://id.example"
APP = "https://app.example"
REDIRECT_URI = f"{APP}/callback"
NOW = 1_800_000_000
EXP = NOW + 300
JWKS = jwks_of(public_jwk(RSA_1, "k1"), public_jwk(EC_1, "e1"))
DROP = object()


def claims(**changes):
    base = {
        "iss": ISSUER, "sub": "alice", "aud": "app", "exp": EXP, "iat": NOW,
        "nonce": "n-1", "auth_time": NOW - 10,
    }
    return {name: value for name, value in {**base, **changes}.items() if value is not DROP}


def mint(header=None, key=RSA_1, **changes):
    return jws_encode({"alg": "RS256", "kid": "k1", **(header or {})}, claims(**changes), key)


def validate(token, **options):
    settings = {"issuer": ISSUER, "client_id": "app", "jwks": JWKS, "now": NOW, "nonce": "n-1"}
    return validate_id_token(token, **{**settings, **options})


def reason_of(call):
    with pytest.raises(InvalidToken) as caught:
        call()
    return caught.value.reason


def flow_reason_of(call):
    with pytest.raises(FlowError) as caught:
        call()
    return caught.value.reason


class FixedRng:
    def __init__(self):
        self._count = 0

    def token_urlsafe(self, nbytes):
        self._count += 1
        return f"{'v' * 40}{self._count:03d}"


# --- start_login -----------------------------------------------------------


def test_start_login_builds_a_code_flow_request_with_pkce(world):
    url, transaction = start_login(
        issuer_config=world.config, client_id="app", redirect_uri=REDIRECT_URI, now=NOW,
        rng=FixedRng(),
    )
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query))
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == f"{ISSUER}/authorize"
    assert query == {
        "response_type": "code", "client_id": "app", "redirect_uri": REDIRECT_URI,
        "scope": "openid email", "state": transaction.state, "nonce": transaction.nonce,
        "code_challenge": query["code_challenge"], "code_challenge_method": "S256",
    }
    digest = hashlib.sha256(transaction.code_verifier.encode("ascii")).digest()
    assert query["code_challenge"] == base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert transaction == Transaction(
        state=transaction.state, nonce=transaction.nonce,
        code_verifier=transaction.code_verifier, redirect_uri=REDIRECT_URI, started_at=NOW,
    )
    assert len({transaction.state, transaction.nonce, transaction.code_verifier}) == 3
    assert 43 <= len(transaction.code_verifier) <= 128


def test_start_login_adds_extra_parameters_but_never_replaces_its_own(world):
    url, _ = start_login(
        issuer_config=world.config, client_id="app", redirect_uri=REDIRECT_URI, now=NOW,
        extra={"max_age": 0, "prompt": "login", "claims": {"id_token": {"acr": None}}},
    )
    query = dict(parse_qsl(urlsplit(url).query))
    assert (query["max_age"], query["prompt"]) == ("0", "login")
    assert query["claims"] == '{"id_token":{"acr":null}}'
    with pytest.raises(ValueError, match="state"):
        start_login(
            issuer_config=world.config, client_id="app", redirect_uri=REDIRECT_URI, now=NOW,
            extra={"state": "chosen-by-caller"},
        )


def test_start_login_marks_the_purpose(world):
    _, transaction = start_login(
        issuer_config=world.config, client_id="app", redirect_uri=REDIRECT_URI, now=NOW,
        purpose="step_up",
    )
    assert transaction.purpose == "step_up"


# --- finish_login through the browser -------------------------------------


def login(world, app, browser, query=""):
    """Run the browser to the client callback; return (transaction, callback request)."""
    landed = browser.get(f"{APP}/login{query}")
    assert landed.body == "callback reached", landed.body
    callback = browser.history[-1]
    return app.transactions[callback.cookies[STATE_COOKIE]], callback


def finish(world, transaction, callback, **options):
    return finish_login(
        transaction=transaction, callback=callback, issuer_config=world.config,
        client_id="app", jwks=world.jwks, network=world.network, now=world.clock.now(),
        **options,
    )


def test_happy_path_returns_claims_with_sub_email_and_auth_time(world, app):
    browser = world.browser()
    world.provider.sign_in(browser, "alice", ("pwd",))
    signed_in_at = world.clock.now()
    world.clock.advance(30)
    transaction, callback = login(world, app, browser)
    assert callback.url.startswith(f"{REDIRECT_URI}?code=")
    result = finish(world, transaction, callback)
    assert result["sub"] == "alice"
    assert result["email"] == "alice@example.com"
    assert result["auth_time"] == signed_in_at
    assert result["iss"] == ISSUER
    assert result["nonce"] == transaction.nonce


def test_refuses_a_callback_with_another_browsers_state(world, app):
    alice, mallory = world.browser(), world.browser()
    world.provider.sign_in(mallory, "mallory", ("pwd",))
    world.provider.sign_in(alice, "alice", ("pwd",))
    mallorys_transaction, mallorys_callback = login(world, app, mallory)
    alices_transaction, _ = login(world, app, alice)
    planted = Request("GET", mallorys_callback.url, cookies=alice.cookies(APP))
    assert planted.query["state"] == mallorys_transaction.state
    reason = flow_reason_of(lambda: finish(world, alices_transaction, planted))
    assert reason == "state_mismatch"
    assert reason == flow_reason_of(lambda: finish(world, mallorys_transaction, planted))
    assert finish(world, mallorys_transaction, mallorys_callback)["sub"] == "mallory"


def test_refuses_a_callback_without_state_even_when_no_cookie_was_set(world, app):
    browser = world.browser()
    world.provider.sign_in(browser, "alice", ("pwd",))
    transaction, callback = login(world, app, browser)
    query = {name: value for name, value in callback.query.items() if name != "state"}
    stripped = Request("GET", f"{REDIRECT_URI}?code={query['code']}&iss={query['iss']}")
    no_state = replace(transaction, state=None)
    assert flow_reason_of(lambda: finish(world, no_state, stripped)) == "missing_state"
    assert flow_reason_of(lambda: finish(world, transaction, stripped)) == "missing_state"
    assert finish(world, transaction, callback)["sub"] == "alice"


def test_refuses_a_callback_whose_cookie_is_missing(world, app):
    browser = world.browser()
    world.provider.sign_in(browser, "alice", ("pwd",))
    transaction, callback = login(world, app, browser)
    cookieless = Request("GET", callback.url)
    assert flow_reason_of(lambda: finish(world, transaction, cookieless)) == "state_mismatch"
    assert finish(world, transaction, callback)["sub"] == "alice"


def test_refuses_a_callback_from_another_issuer(world, app):
    browser = world.browser()
    world.provider.sign_in(browser, "alice", ("pwd",))
    transaction, callback = login(world, app, browser)
    evil_url = callback.url.replace("iss=https%3A%2F%2Fid.", "iss=https%3A%2F%2Fevil.")
    swapped = Request("GET", evil_url, cookies=callback.cookies)
    assert swapped.query["iss"] == "https://evil.example"
    assert flow_reason_of(lambda: finish(world, transaction, swapped)) == "issuer_mismatch"
    assert finish(world, transaction, callback)["sub"] == "alice"


def test_an_error_callback_raises_the_providers_error(world, app):
    browser = world.browser()
    landed = browser.get(f"{APP}/login?prompt=none")
    assert landed.body == "callback reached"
    callback = browser.history[-1]
    transaction = app.transactions[callback.cookies[STATE_COOKIE]]
    with pytest.raises(OAuthError) as caught:
        finish(world, transaction, callback)
    assert caught.value.error == "login_required"


def test_refuses_an_id_token_for_another_nonce(world, app):
    browser = world.browser()
    world.provider.sign_in(browser, "alice", ("pwd",))
    transaction, callback = login(world, app, browser)
    other = replace(transaction, nonce="a-nonce-from-another-login")
    assert reason_of(lambda: finish(world, other, callback)) == "nonce_mismatch"


def test_accepts_the_matching_nonce(world, app):
    browser = world.browser()
    world.provider.sign_in(browser, "alice", ("pwd",))
    transaction, callback = login(world, app, browser)
    assert finish(world, transaction, callback)["nonce"] == transaction.nonce


def test_refuses_userinfo_for_another_subject(world, app):
    browser = world.browser()
    world.provider.sign_in(browser, "alice", ("pwd",))
    transaction, callback = login(world, app, browser)

    def substituting(request):
        response = world.provider(request)
        if request.path == "/userinfo":
            return replace(response, body={**response.body, "sub": "mallory"})
        return response

    world.network.mount(ISSUER, substituting)
    assert reason_of(lambda: finish(world, transaction, callback)) == "sub_mismatch"


def test_accepts_userinfo_for_the_same_subject(world, app):
    browser = world.browser()
    world.provider.sign_in(browser, "alice", ("pwd",))
    transaction, callback = login(world, app, browser)
    world.network.mount(ISSUER, lambda request: world.provider(request))
    assert finish(world, transaction, callback)["email"] == "alice@example.com"


def test_max_age_zero_login_returns_a_fresh_auth_time(world, app):
    browser = world.browser()
    world.provider.sign_in(browser, "alice", ("pwd",))
    world.clock.advance(600)
    started = browser.get(f"{APP}/login?max_age=0")
    assert (started.status, started.body["error"]) == (401, "login_required")
    authorize_url = browser.history[-1].url
    world.provider.sign_in(browser, "alice", ("pwd",))
    transaction = app.transactions[browser.cookies(APP)[STATE_COOKIE]]
    assert browser.get(authorize_url).body == "callback reached"
    result = finish(world, transaction, browser.history[-1], max_age=0)
    assert result["auth_time"] == world.clock.now()


def without(callback, name):
    query = {key: value for key, value in callback.query.items() if key != name}
    return Request("GET", f"{REDIRECT_URI}?{urlencode(query)}", cookies=callback.cookies)


def test_refuses_a_response_without_iss_when_the_provider_sends_it(world, app):
    browser = world.browser()
    world.provider.sign_in(browser, "alice", ("pwd",))
    transaction, callback = login(world, app, browser)
    assert world.config["authorization_response_iss_parameter_supported"] is True
    stripped = without(callback, "iss")
    assert set(stripped.query) == {"code", "state"}
    assert flow_reason_of(lambda: finish(world, transaction, stripped)) == "issuer_mismatch"


def test_accepts_a_response_with_the_right_iss(world, app):
    browser = world.browser()
    world.provider.sign_in(browser, "alice", ("pwd",))
    transaction, callback = login(world, app, browser)
    assert callback.query["iss"] == ISSUER
    assert finish(world, transaction, callback)["sub"] == "alice"


def test_refuses_a_callback_without_a_code(world, app):
    browser = world.browser()
    world.provider.sign_in(browser, "alice", ("pwd",))
    transaction, callback = login(world, app, browser)
    codeless = without(callback, "code")
    assert set(codeless.query) == {"state", "iss"}
    assert flow_reason_of(lambda: finish(world, transaction, codeless)) == "missing_code"
    assert finish(world, transaction, callback)["sub"] == "alice"


def serving_configuration(world, origin, issuer):
    config = {**world.config, "issuer": issuer}
    world.network.mount(origin, lambda request: Response(200, {}, config))


@pytest.mark.parametrize("named", ["https://op.example/", "https://evil.example"])
def test_discover_refuses_a_document_for_another_issuer(world, named):
    serving_configuration(world, "https://op.example", named)
    with pytest.raises(FlowError) as caught:
        discover(issuer="https://op.example", network=world.network)
    assert caught.value.reason == "issuer_mismatch"


def test_discover_accepts_an_exact_issuer(world):
    assert discover(issuer=ISSUER, network=world.network)["issuer"] == ISSUER
    serving_configuration(world, "https://op.example", "https://op.example")
    found = discover(issuer="https://op.example", network=world.network)
    assert found["issuer"] == "https://op.example"


def with_token_type(world, token_type):
    def rewriting(request):
        response = world.provider(request)
        if request.path == "/token" and response.status == 200:
            return replace(response, body={**response.body, "token_type": token_type})
        return response

    world.network.mount(ISSUER, rewriting)


def test_refuses_a_token_type_it_does_not_understand(world, app):
    browser = world.browser()
    world.provider.sign_in(browser, "alice", ("pwd",))
    transaction, callback = login(world, app, browser)
    with_token_type(world, "DPoP")
    with pytest.raises(OAuthError) as caught:
        finish(world, transaction, callback)
    assert caught.value.error == "unsupported_token_type"


def test_accepts_bearer_in_any_case(world, app):
    browser = world.browser()
    world.provider.sign_in(browser, "alice", ("pwd",))
    transaction, callback = login(world, app, browser)
    with_token_type(world, "bearer")
    assert finish(world, transaction, callback)["sub"] == "alice"


def test_basic_authorization_matches_rfc6749_section_2_3_1():
    header = basic_authorization("s6BhdRkqt3", b"7Fjfp0ZBr1KtDRbnfVdmIw")
    assert header == "Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3"


def test_basic_authorization_form_encodes_each_part_first():
    encoded = basic_authorization("a b", b"s3cr:t%+x").removeprefix("Basic ")
    assert base64.b64decode(encoded) == b"a+b:s3cr%3At%25%2Bx"


SECRET = b"s3cr:t%+x"


def confidential_login(world, make_app):
    world.provider.register_client("conf", [REDIRECT_URI], secret=SECRET)
    conf_app = make_app("conf")
    browser = world.browser()
    world.provider.sign_in(browser, "alice", ("pwd",))
    return login(world, conf_app, browser)


def finish_confidential(world, transaction, callback, secret):
    return finish_login(
        transaction=transaction, callback=callback, issuer_config=world.config,
        client_id="conf", jwks=world.jwks, network=world.network, now=world.clock.now(),
        client_secret=secret,
    )


def test_refuses_a_confidential_client_with_the_wrong_secret(world, make_app):
    transaction, callback = confidential_login(world, make_app)
    with pytest.raises(OAuthError) as caught:
        finish_confidential(world, transaction, callback, b"s3cr:t%+y")
    assert caught.value.error == "invalid_client"


def test_accepts_a_confidential_client_with_its_secret(world, make_app):
    transaction, callback = confidential_login(world, make_app)
    result = finish_confidential(world, transaction, callback, SECRET)
    assert (result["sub"], result["aud"]) == ("alice", "conf")


def first_tokens(world, app):
    browser = world.browser()
    world.provider.sign_in(browser, "alice", ("pwd",))
    transaction, callback = login(world, app, browser)
    return exchange_code(
        issuer_config=world.config, client_id="app", code=callback.query["code"],
        redirect_uri=transaction.redirect_uri, code_verifier=transaction.code_verifier,
        network=world.network,
    )


def refreshed(world, refresh_token, **options):
    return refresh(
        issuer_config=world.config, client_id="app", refresh_token=refresh_token,
        network=world.network, **options,
    )


def test_refresh_rotates_the_refresh_token(world, app):
    first = first_tokens(world, app)
    second = refreshed(world, first["refresh_token"], scope="openid")
    assert second["refresh_token"] != first["refresh_token"]
    assert second["scope"] == "openid"
    third = refreshed(world, second["refresh_token"])
    assert third["token_type"] == "Bearer"


def test_refuses_a_reused_refresh_token(world, app):
    first = first_tokens(world, app)
    assert refreshed(world, first["refresh_token"])["token_type"] == "Bearer"
    with pytest.raises(OAuthError) as caught:
        refreshed(world, first["refresh_token"])
    assert caught.value.error == "invalid_grant"


def test_fresh_login_then_reload_same_authorize_url(world, app):
    browser = world.browser()
    world.provider.sign_in(browser, "alice", ("pwd",))
    world.clock.advance(600)
    started = browser.get(f"{APP}/login?prompt=login")
    assert (started.status, started.body["error"]) == (401, "login_required")
    authorize_url = browser.history[-1].url
    assert authorize_url.startswith(f"{ISSUER}/authorize?")
    world.provider.sign_in(browser, "alice", ("pwd",))
    assert browser.get(authorize_url).body == "callback reached"
    callback = browser.history[-1]
    transaction = app.transactions[callback.cookies[STATE_COOKIE]]
    result = finish(world, transaction, callback, not_before=transaction.started_at)
    assert result["auth_time"] == world.clock.now()


# --- validate_id_token: the fixed order ---------------------------------


def test_accepts_an_honest_id_token():
    assert validate(mint()) == claims()
    assert validate(jws_encode({"alg": "ES256", "kid": "e1"}, claims(), EC_1)) == claims()


def test_refuses_a_token_that_is_not_a_jws():
    assert reason_of(lambda: validate("not.a-token")) == "malformed"
    assert reason_of(lambda: validate(mint() + ".extra")) == "malformed"


@pytest.mark.parametrize("typ", ["at+jwt", "application/at+jwt", "logout+jwt", 7])
def test_refuses_other_kinds_of_jwt(typ):
    assert reason_of(lambda: validate(mint({"typ": typ}))) == "wrong_typ"


def test_refuses_a_logout_token_without_typ():
    events = {"http://schemas.openid.net/event/backchannel-logout": {}}
    assert reason_of(lambda: validate(mint(events=events))) == "wrong_typ"


@pytest.mark.parametrize("typ", ["JWT", "jwt", "application/jwt"])
def test_accepts_an_id_token_typed_jwt_or_untyped(typ):
    assert validate(mint({"typ": typ}))["sub"] == "alice"
    assert validate(mint())["sub"] == "alice"


def test_refuses_alg_none_and_algs_outside_the_allowed_set():
    unsigned = jws_encode({"alg": "none", "kid": "k1"}, claims(), None)
    assert reason_of(lambda: validate(unsigned)) == "alg_not_allowed"
    only_es = frozenset({"ES256"})
    assert reason_of(lambda: validate(mint(), allowed_algs=only_es)) == "alg_not_allowed"
    assert validate(mint(), allowed_algs=frozenset({"RS256"}))["sub"] == "alice"


def test_refuses_an_unknown_kid_and_a_forged_signature():
    assert reason_of(lambda: validate(mint({"kid": "k9"}))) == "unknown_kid"
    assert reason_of(lambda: validate(mint(key=ATTACKER_RSA))) == "bad_signature"


def test_checks_the_signature_before_any_claim():
    forged = mint(key=ATTACKER_RSA, iss="https://evil.example", exp=NOW - 1, nonce="x")
    assert reason_of(lambda: validate(forged)) == "bad_signature"


@pytest.mark.parametrize("sub", [DROP, "", 42, None])
def test_refuses_a_token_without_a_string_sub(sub):
    assert reason_of(lambda: validate(mint(sub=sub))) == "malformed"


@pytest.mark.parametrize("iss", ["https://id.example/", "https://ID.example", DROP, None])
def test_refuses_any_issuer_but_the_exact_one(iss):
    assert reason_of(lambda: validate(mint(iss=iss))) == "wrong_issuer"
    assert validate(mint(iss=ISSUER))["iss"] == ISSUER


@pytest.mark.parametrize("aud", ["webapp", "ap", ["quiz"], [], DROP, ["app", "unknown-api"]])
def test_refuses_an_audience_without_this_client_or_with_untrusted_extras(aud):
    assert reason_of(lambda: validate(mint(aud=aud))) == "wrong_audience"


@pytest.mark.parametrize("aud", [7, ["app", 7], {"app": True}])
def test_refuses_an_audience_of_the_wrong_type(aud):
    assert reason_of(lambda: validate(mint(aud=aud))) == "malformed"


def test_accepts_this_client_alone_or_with_trusted_extras():
    assert validate(mint(aud="app"))["aud"] == "app"
    assert validate(mint(aud=["app"]))["aud"] == ["app"]
    trusted = frozenset({"api.trusted"})
    token = mint(aud=["app", "api.trusted"])
    assert validate(token, trusted_audiences=trusted)["aud"] == ["app", "api.trusted"]


def test_ignores_azp_without_the_extension():
    trusted = frozenset({"api.trusted"})
    assert validate(mint(azp="quiz"))["azp"] == "quiz"
    assert validate(mint(aud=["app", "api.trusted"]), trusted_audiences=trusted)["sub"] == "alice"


def test_refuses_a_wrong_or_missing_azp_with_the_extension():
    trusted = frozenset({"api.trusted"})
    several = {"aud": ["app", "api.trusted"]}
    options = {"trusted_audiences": trusted, "azp_extension": True}
    assert reason_of(lambda: validate(mint(azp="quiz"), **options)) == "azp_mismatch"
    assert reason_of(lambda: validate(mint(**several), **options)) == "azp_mismatch"
    assert reason_of(lambda: validate(mint(**several, azp="quiz"), **options)) == "azp_mismatch"
    assert validate(mint(**several, azp="app"), **options)["azp"] == "app"
    assert validate(mint(), **options)["sub"] == "alice"


# --- time: Review Focus 2 ------------------------------------------------


def test_exp_boundary_without_leeway():
    token = mint()
    assert validate(token, now=EXP - 1)["exp"] == EXP
    assert reason_of(lambda: validate(token, now=EXP)) == "expired"


def test_exp_boundary_with_leeway():
    token = mint()
    assert validate(token, now=EXP + 4, leeway=5)["exp"] == EXP
    assert reason_of(lambda: validate(token, now=EXP + 5, leeway=5)) == "expired"


def test_iat_boundary_without_leeway():
    assert validate(mint(iat=NOW))["iat"] == NOW
    assert reason_of(lambda: validate(mint(iat=NOW + 1))) == "issued_in_future"


def test_iat_boundary_with_leeway():
    assert validate(mint(iat=NOW + 5), leeway=5)["iat"] == NOW + 5
    assert reason_of(lambda: validate(mint(iat=NOW + 6), leeway=5)) == "issued_in_future"


def test_nbf_is_checked_when_present():
    assert validate(mint(nbf=NOW))["nbf"] == NOW
    assert validate(mint(nbf=NOW + 5), leeway=5)["nbf"] == NOW + 5
    assert reason_of(lambda: validate(mint(nbf=NOW + 1))) == "not_yet_valid"


@pytest.mark.parametrize("value", [True, "1800000300", float("nan"), float("inf"), None, [EXP]])
@pytest.mark.parametrize("name", ["exp", "iat", "nbf", "auth_time"])
def test_refuses_a_time_claim_that_is_not_a_number(name, value):
    assert reason_of(lambda: validate(mint(**{name: value}))) == "malformed"


@pytest.mark.parametrize("name", ["exp", "iat"])
def test_refuses_a_token_without_exp_or_iat(name):
    assert reason_of(lambda: validate(mint(**{name: DROP}))) == "malformed"


def test_accepts_a_non_integer_numeric_date():
    assert validate(mint(exp=NOW + 0.5))["exp"] == NOW + 0.5
    assert reason_of(lambda: validate(mint(exp=NOW - 0.5))) == "expired"


@pytest.mark.parametrize("leeway", [-1, 301, 300_000, True, 1.5])
def test_refuses_a_leeway_outside_a_few_minutes(leeway):
    with pytest.raises((ValueError, TypeError)):
        validate(mint(), leeway=leeway)
    assert validate(mint(), leeway=300)["sub"] == "alice"


def test_refuses_a_non_integer_now():
    with pytest.raises(TypeError):
        validate(mint(), now=True)


# --- nonce ----------------------------------------------------------------


@pytest.mark.parametrize("nonce", [DROP, "n-2", None, 1])
def test_refuses_a_missing_or_different_nonce(nonce):
    assert reason_of(lambda: validate(mint(nonce=nonce))) == "nonce_mismatch"


def test_refuses_a_nonce_that_was_never_sent():
    assert reason_of(lambda: validate(mint(), nonce=None)) == "nonce_mismatch"
    assert validate(mint(nonce=DROP), nonce=None)["sub"] == "alice"


# --- auth_time, max_age and not_before ----------------------------------


def test_refuses_max_age_without_auth_time():
    token = mint(auth_time=DROP)
    assert reason_of(lambda: validate(token, max_age=300)) == "auth_time_missing"
    assert reason_of(lambda: validate(token, not_before=NOW)) == "auth_time_missing"
    assert validate(token)["sub"] == "alice"


def test_max_age_boundary():
    token = mint(auth_time=NOW - 300)
    assert validate(token, max_age=300)["auth_time"] == NOW - 300
    assert reason_of(lambda: validate(token, max_age=299)) == "stale_auth_time"
    assert validate(token, max_age=295, leeway=5)["auth_time"] == NOW - 300
    assert reason_of(lambda: validate(token, max_age=294, leeway=5)) == "stale_auth_time"


def test_max_age_zero_accepts_only_this_second():
    assert validate(mint(auth_time=NOW), max_age=0)["auth_time"] == NOW
    assert reason_of(lambda: validate(mint(auth_time=NOW - 1), max_age=0)) == "stale_auth_time"


def test_not_before_refuses_an_authentication_before_the_step_up():
    started = NOW - 20
    assert validate(mint(auth_time=started), not_before=started)["auth_time"] == started
    stale = mint(auth_time=started - 1)
    assert reason_of(lambda: validate(stale, not_before=started)) == "stale_auth_time"


def test_refuses_an_auth_time_in_the_future():
    assert reason_of(lambda: validate(mint(auth_time=NOW + 1), max_age=300)) == "issued_in_future"
    assert validate(mint(auth_time=NOW + 5), max_age=300, leeway=5)["sub"] == "alice"


# --- acr: Review Focus 5 -------------------------------------------------


@pytest.mark.parametrize("acr", [2, True, None, ["2"], "02", " 2", DROP])
def test_check_acr_refuses_anything_but_a_listed_string(acr):
    required = frozenset({"2"})
    assert reason_of(lambda: check_acr(claims(acr=acr), required)) == "acr_not_met"
    assert check_acr(claims(acr="2"), required) is None


def test_check_acr_refuses_true_against_a_level_one():
    assert reason_of(lambda: check_acr(claims(acr=True), frozenset({"1"}))) == "acr_not_met"
    assert check_acr(claims(acr="1"), frozenset({"1"})) is None


def test_check_acr_does_not_order_levels():
    required = frozenset({"urn:toy:acr:mfa"})
    for acr in ("urn:toy:acr:pwd", "urn:toy:acr:zzz", "URN:TOY:ACR:MFA", "0"):
        assert reason_of(lambda: check_acr(claims(acr=acr), required)) == "acr_not_met"
    assert check_acr(claims(acr="urn:toy:acr:mfa"), required) is None


def test_check_acr_refuses_a_requirement_that_is_not_a_set_of_strings():
    with pytest.raises(TypeError):
        check_acr(claims(acr="2"), frozenset({2}))
    with pytest.raises(TypeError):
        check_acr(claims(acr="2"), {"2"})


def test_validate_checks_acr_last():
    required = frozenset({"urn:toy:acr:mfa"})
    weak = mint(acr="urn:toy:acr:pwd")
    assert reason_of(lambda: validate(weak, required_acr=required)) == "acr_not_met"
    assert reason_of(lambda: validate(weak, required_acr=required, nonce="n-2")) == "nonce_mismatch"
    assert validate(mint(acr="urn:toy:acr:mfa"), required_acr=required)["sub"] == "alice"


# --- account_key ----------------------------------------------------------


def test_account_key_is_issuer_and_subject():
    assert account_key(claims()) == (ISSUER, "alice")
    with pytest.raises(InvalidToken):
        account_key(claims(sub=DROP))
