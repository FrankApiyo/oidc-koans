import base64
import hashlib
import json
from urllib.parse import quote_plus, urlencode

import pytest

from toy.http import Request, Response
from toy.jose import b64url_encode, jws_encode, jws_split, jws_verify, jwks_of, public_jwk
from toy.keys import EC_1, RSA_1, RSA_2, RSA_3
from toy.provider import ACR_MFA, ACR_PASSWORD, SPEC, Profile

ISSUER = "https://id.example"
APP = "https://app.example"
REDIRECT_URI = f"{APP}/callback"
NOW = 1_800_000_000
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


@pytest.fixture
def callback_site(world):
    world.network.mount(APP, lambda request: Response(200, {}, "callback reached"))


def authorize_url(**params):
    query = {
        "response_type": "code", "client_id": "app", "redirect_uri": REDIRECT_URI,
        "scope": "openid email", "state": "s-1", "nonce": "n-1",
        "code_challenge": CHALLENGE, "code_challenge_method": "S256", **params,
    }
    return f"{ISSUER}/authorize?{urlencode({k: v for k, v in query.items() if v is not None})}"


def callback_query(browser, **params):
    landed = browser.get(authorize_url(**params))
    assert landed.body == "callback reached", landed.body
    return browser.history[-1].query


def code_for(world, browser, **params):
    return callback_query(browser, **params)["code"]


def token_request(world, form, headers=None):
    request = Request("POST", f"{ISSUER}/token", form=form, headers=headers or {})
    return world.network.send(request)


def redeem(world, code, **changes):
    form = {
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI,
        "code_verifier": VERIFIER, "client_id": "app", **changes,
    }
    return token_request(world, {k: v for k, v in form.items() if v is not None})


def id_claims(response):
    assert response.status == 200, response.body
    return jws_split(response.body["id_token"])[1]


def userinfo(world, access_token):
    headers = {"Authorization": f"Bearer {access_token}"}
    return world.network.send(Request("GET", f"{ISSUER}/userinfo", headers=headers))


def signed_in(world, sub="alice", factors=("pwd",)):
    browser = world.browser()
    world.provider.sign_in(browser, sub, factors)
    return browser


# --- discovery and keys ---------------------------------------------------


def test_discovery_names_the_issuer_and_its_endpoints(world):
    config = world.config
    assert config["issuer"] == ISSUER
    for name, path in (
        ("authorization_endpoint", "/authorize"), ("token_endpoint", "/token"),
        ("userinfo_endpoint", "/userinfo"), ("jwks_uri", "/jwks"),
        ("end_session_endpoint", "/logout"),
    ):
        assert config[name] == f"{ISSUER}{path}"
    assert config["code_challenge_methods_supported"] == ["S256"]
    assert config["response_types_supported"] == ["code"]
    assert config["authorization_response_iss_parameter_supported"] is True
    assert config["id_token_signing_alg_values_supported"] == ["RS256"]


def test_jwks_publishes_the_signing_key(world):
    assert world.jwks == jwks_of(public_jwk(RSA_1, "k1"))
    assert "d" not in world.jwks["keys"][0]


def test_the_default_profile_is_the_spec():
    assert SPEC == Profile(
        assurance_claim="acr", acr_alone_reauthenticates=False,
        auth_time_when_max_age_zero=True, honours_prompt_login=True, honours_max_age=True,
    )


# --- /authorize -----------------------------------------------------------


def test_authorize_without_a_session_is_a_login_required_page(world, callback_site):
    page = world.browser().get(authorize_url())
    assert (page.status, page.body["error"]) == (401, "login_required")
    assert page.location is None


def test_authorize_redirects_with_code_state_and_iss(world, callback_site):
    browser = signed_in(world)
    first = browser.get(authorize_url())
    assert first.body == "callback reached"
    redirect = browser.history[-1]
    assert set(redirect.query) == {"code", "state", "iss"}
    assert (redirect.query["state"], redirect.query["iss"]) == ("s-1", ISSUER)
    assert redirect.url.startswith(f"{REDIRECT_URI}?")


def test_authorize_answers_the_callback_with_a_303(world):
    browser = signed_in(world)
    request = Request("GET", authorize_url(), cookies=browser.cookies(ISSUER))
    response = world.provider(request)
    assert response.status == 303
    assert response.location.startswith(f"{REDIRECT_URI}?code=")


@pytest.mark.parametrize(
    "redirect_uri",
    [
        f"{REDIRECT_URI}/",
        "https://APP.example/callback",
        f"{REDIRECT_URI}?next=x",
        "https://app.example/callback.evil.example",
        "https://app.example/callback/../evil",
        "https://app.example/CALLBACK",
        None,
    ],
)
def test_refuses_a_redirect_uri_that_is_not_exactly_registered(world, callback_site, redirect_uri):
    browser = signed_in(world)
    page = browser.get(authorize_url(redirect_uri=redirect_uri))
    assert (page.status, page.body["error"]) == (400, "invalid_request")
    assert page.location is None
    assert [request.origin for request in browser.history[-1:]] == [ISSUER]


def test_accepts_the_exactly_registered_redirect_uri(world, callback_site):
    assert "code" in callback_query(signed_in(world), redirect_uri=REDIRECT_URI)


def test_refuses_an_unknown_client_with_an_error_page(world, callback_site):
    page = signed_in(world).get(authorize_url(client_id="quiz"))
    assert (page.status, page.body["error"]) == (400, "invalid_request")
    assert page.location is None


@pytest.mark.parametrize(
    "params, error",
    [
        ({"code_challenge": None, "code_challenge_method": None}, "invalid_request"),
        ({"code_challenge_method": "plain"}, "invalid_request"),
        ({"code_challenge_method": None}, "invalid_request"),
        ({"code_challenge": "too-short"}, "invalid_request"),
        ({"response_type": "token"}, "unsupported_response_type"),
        ({"scope": "email"}, "invalid_scope"),
        ({"prompt": "none login"}, "invalid_request"),
        ({"max_age": "-1"}, "invalid_request"),
        ({"max_age": "soon"}, "invalid_request"),
        ({"claims": "not json"}, "invalid_request"),
    ],
)
def test_refuses_a_bad_request_with_an_error_redirect(world, callback_site, params, error):
    query = callback_query(signed_in(world), **params)
    assert query["error"] == error
    assert (query["state"], query["iss"]) == ("s-1", ISSUER)
    assert "code" not in query


def test_prompt_none_without_a_session_redirects_with_login_required(world, callback_site):
    query = callback_query(world.browser(), prompt="none")
    assert (query["error"], query["state"]) == ("login_required", "s-1")


def test_prompt_none_with_a_session_returns_a_code(world, callback_site):
    assert "code" in callback_query(signed_in(world), prompt="none")


# --- re-authentication ------------------------------------------------------


@pytest.mark.parametrize("params", [{"max_age": "0"}, {"prompt": "login"}])
def test_needs_a_sign_in_after_the_request(world, callback_site, params):
    browser = signed_in(world)
    for _ in range(2):
        page = browser.get(authorize_url(**params))
        assert (page.status, page.body["error"]) == (401, "login_required")
    world.clock.advance(5)
    world.provider.sign_in(browser, "alice", ("pwd",))
    code = code_for(world, browser, **params)
    assert id_claims(redeem(world, code))["auth_time"] == NOW + 5


@pytest.mark.parametrize("params", [{"max_age": "0"}, {"prompt": "login"}])
def test_a_sign_in_before_the_request_does_not_count(world, callback_site, params):
    browser = world.browser()
    first = browser.get(authorize_url(**params))
    assert first.status == 401
    world.provider.sign_in(browser, "alice", ("pwd",))
    assert "code" in callback_query(browser, **params)
    world.provider.sign_in(browser, "alice", ("pwd",))
    page = browser.get(authorize_url(**params, state="s-2"))
    assert (page.status, page.body["error"]) == (401, "login_required")


def test_prompt_none_never_shows_the_login_page(world, callback_site):
    query = callback_query(signed_in(world), prompt="none", max_age="0")
    assert query["error"] == "login_required"


def test_max_age_reauthenticates_only_when_exceeded(world, callback_site):
    browser = signed_in(world)
    world.clock.advance(300)
    assert "code" in callback_query(browser, max_age="300")
    world.clock.advance(1)
    page = browser.get(authorize_url(max_age="300"))
    assert (page.status, page.body["error"]) == (401, "login_required")
    world.provider.sign_in(browser, "alice", ("pwd",))
    code = code_for(world, browser, max_age="300")
    assert id_claims(redeem(world, code))["auth_time"] == NOW + 301


def test_a_profile_that_ignores_prompt_and_max_age_replays_the_session(make_world):
    lax = Profile(
        assurance_claim="acr", acr_alone_reauthenticates=False,
        auth_time_when_max_age_zero=False, honours_prompt_login=False, honours_max_age=False,
    )
    world = make_world(profile=lax)
    world.network.mount(APP, lambda request: Response(200, {}, "callback reached"))
    browser = signed_in(world)
    world.clock.advance(600)
    assert "code" in callback_query(browser, prompt="login")
    claims = id_claims(redeem(world, code_for(world, browser, max_age="0")))
    assert "auth_time" not in claims
    essential = json.dumps({"id_token": {"auth_time": {"essential": True}}})
    claims = id_claims(redeem(world, code_for(world, browser, max_age="0", claims=essential)))
    assert claims["auth_time"] == NOW


# --- the ID token -----------------------------------------------------------


def test_id_token_carries_the_listed_claims(world, callback_site):
    browser = signed_in(world)
    world.clock.advance(10)
    response = redeem(world, code_for(world, browser))
    header = jws_split(response.body["id_token"])[0]
    assert header == {"alg": "RS256", "kid": "k1", "typ": "JWT"}
    assert id_claims(response) == {
        "iss": ISSUER, "sub": "alice", "aud": "app", "exp": NOW + 10 + 300,
        "iat": NOW + 10, "nonce": "n-1", "auth_time": NOW, "amr": ["pwd"],
    }
    jwks = world.jwks
    assert jws_verify(response.body["id_token"], jwks, frozenset({"RS256"}))["sub"] == "alice"


def test_id_token_reports_mfa_and_acr_when_asked(world, callback_site):
    browser = signed_in(world, factors=("pwd", "otp"))
    claims = id_claims(redeem(world, code_for(world, browser, acr_values=ACR_MFA)))
    assert (claims["acr"], claims["amr"]) == (ACR_MFA, ["pwd", "otp", "mfa"])
    asked = json.dumps({"id_token": {"acr": None}})
    assert id_claims(redeem(world, code_for(world, browser, claims=asked)))["acr"] == ACR_MFA


def test_id_token_omits_nonce_when_none_was_sent(world, callback_site):
    claims = id_claims(redeem(world, code_for(world, signed_in(world), nonce=None)))
    assert "nonce" not in claims


def test_azp_appears_only_with_several_audiences(make_world):
    world = make_world()
    world.provider.register_client("multi", [REDIRECT_URI], extra_audiences=("api.example",))
    world.network.mount(APP, lambda request: Response(200, {}, "callback reached"))
    browser = signed_in(world)
    code = code_for(world, browser, client_id="multi")
    claims = id_claims(redeem(world, code, client_id="multi"))
    assert (claims["aud"], claims["azp"]) == (["multi", "api.example"], "multi")
    assert "azp" not in id_claims(redeem(world, code_for(world, browser)))


def test_an_ec_provider_signs_es256(make_world):
    world = make_world(signing_key=EC_1, kid="e1")
    world.network.mount(APP, lambda request: Response(200, {}, "callback reached"))
    token = redeem(world, code_for(world, signed_in(world))).body["id_token"]
    assert jws_split(token)[0]["alg"] == "ES256"
    assert jws_verify(token, world.jwks, frozenset({"ES256"}))["sub"] == "alice"


def test_an_ec_provider_also_signs_rs256_as_discovery_requires(make_world):
    world = make_world(signing_key=EC_1, kid="e1")
    world.network.mount(APP, lambda request: Response(200, {}, "callback reached"))
    assert world.config["id_token_signing_alg_values_supported"] == ["ES256", "RS256"]
    assert world.jwks == jwks_of(public_jwk(EC_1, "e1"), public_jwk(RSA_3, "e1-rs256"))
    world.provider.register_client("app", [REDIRECT_URI], id_token_signed_response_alg="RS256")
    token = redeem(world, code_for(world, signed_in(world))).body["id_token"]
    assert jws_split(token)[0] == {"alg": "RS256", "kid": "e1-rs256", "typ": "JWT"}
    assert jws_verify(token, world.jwks, frozenset({"RS256"}))["sub"] == "alice"
    assert world.provider.verify_own(token)["sub"] == "alice"


def test_an_ec_provider_takes_its_own_rs256_key(make_world):
    world = make_world(signing_key=EC_1, kid="e1", rs256_key=RSA_2)
    assert world.jwks == jwks_of(public_jwk(EC_1, "e1"), public_jwk(RSA_2, "e1-rs256"))


def test_an_rsa_provider_publishes_one_key_and_signs_only_rs256(make_world, world):
    assert world.config["id_token_signing_alg_values_supported"] == ["RS256"]
    assert world.jwks == jwks_of(public_jwk(RSA_1, "k1"))
    with pytest.raises(ValueError, match="ES256"):
        world.provider.register_client("app", [REDIRECT_URI], id_token_signed_response_alg="ES256")
    with pytest.raises(ValueError, match="signing_key"):
        make_world(rs256_key=RSA_2)


def test_rotation_publishes_then_signs_then_retires(world, callback_site):
    world.provider.publish_key(RSA_2, "k2")
    assert world.jwks == jwks_of(public_jwk(RSA_1, "k1"), public_jwk(RSA_2, "k2"))
    old = redeem(world, code_for(world, signed_in(world))).body["id_token"]
    assert jws_split(old)[0]["kid"] == "k1"
    world.provider.sign_with("k2")
    new = redeem(world, code_for(world, signed_in(world))).body["id_token"]
    assert jws_split(new)[0]["kid"] == "k2"
    assert world.jwks == jwks_of(public_jwk(RSA_2, "k2"), public_jwk(RSA_1, "k1"))
    assert world.provider.verify_own(old)["sub"] == "alice"
    world.provider.retire_key("k1")
    assert world.jwks == jwks_of(public_jwk(RSA_2, "k2"))
    assert world.provider.verify_own(old) is None
    assert world.provider.verify_own(new)["sub"] == "alice"


def test_rotation_refuses_steps_out_of_order(world):
    with pytest.raises(ValueError, match="publish"):
        world.provider.sign_with("k2")
    with pytest.raises(ValueError, match="in use"):
        world.provider.retire_key("k1")
    with pytest.raises(ValueError, match="no key"):
        world.provider.retire_key("k2")
    world.provider.publish_key(RSA_2, "k2")
    with pytest.raises(ValueError, match="already"):
        world.provider.publish_key(RSA_3, "k2")
    with pytest.raises(ValueError, match="already"):
        world.provider.publish_key(RSA_3, "k1")
    world.provider.publish_key(EC_1, "e1")
    with pytest.raises(ValueError, match="ES256"):
        world.provider.sign_with("e1")
    assert [jwk["kid"] for jwk in world.jwks["keys"]] == ["k1", "k2", "e1"]


def test_email_goes_into_the_id_token_only_when_claimed(world, callback_site):
    browser = signed_in(world)
    assert "email" not in id_claims(redeem(world, code_for(world, browser)))
    asked = json.dumps({"id_token": {"email": None}})
    assert id_claims(redeem(world, code_for(world, browser, claims=asked)))["email"] == (
        "alice@example.com"
    )


# --- acr_values and essential acr ----------------------------------------


def test_acr_values_above_the_session_asks_for_a_stronger_sign_in(world, callback_site):
    browser = signed_in(world)
    page = browser.get(authorize_url(acr_values=ACR_MFA))
    assert (page.status, page.body["error"]) == (401, "login_required")
    world.provider.sign_in(browser, "alice", ("pwd", "otp"))
    claims = id_claims(redeem(world, code_for(world, browser, acr_values=ACR_MFA)))
    assert claims["acr"] == ACR_MFA


def test_voluntary_acr_that_cannot_be_met_returns_the_session_level(world, callback_site):
    browser = signed_in(world, sub="mallory")
    claims = id_claims(redeem(world, code_for(world, browser, acr_values=ACR_MFA)))
    assert claims["acr"] == ACR_PASSWORD


def test_essential_acr_that_cannot_be_met_fails(world, callback_site):
    essential = json.dumps({"id_token": {"acr": {"essential": True, "values": [ACR_MFA]}}})
    query = callback_query(signed_in(world, sub="mallory"), claims=essential)
    assert query["error"] == "unmet_authentication_requirements"
    alice = signed_in(world, factors=("pwd", "otp"))
    assert id_claims(redeem(world, code_for(world, alice, claims=essential)))["acr"] == ACR_MFA


def test_sign_in_refuses_a_factor_the_user_lacks(world):
    with pytest.raises(ValueError):
        world.provider.sign_in(world.browser(), "mallory", ("pwd", "otp"))
    with pytest.raises(ValueError):
        world.provider.sign_in(world.browser(), "nobody", ("pwd",))


def test_id_token_hint_for_another_user_needs_that_user(world, callback_site):
    alice = signed_in(world)
    hint = redeem(world, code_for(world, alice)).body["id_token"]
    mallory = signed_in(world, sub="mallory")
    page = mallory.get(authorize_url(id_token_hint=hint))
    assert (page.status, page.body["error"]) == (401, "login_required")
    assert callback_query(mallory, id_token_hint=hint, prompt="none")["error"] == "login_required"
    assert "code" in callback_query(alice, id_token_hint=hint)


# --- /token -----------------------------------------------------------------


def test_token_response_is_bearer_and_not_cached(world, callback_site):
    response = redeem(world, code_for(world, signed_in(world)))
    assert response.status == 200
    assert response.headers == {"Cache-Control": "no-store", "Pragma": "no-cache"}
    assert response.body["token_type"] == "Bearer"
    assert response.body["expires_in"] == 300
    assert response.body["scope"] == "openid email"
    assert {"access_token", "id_token", "refresh_token"} <= set(response.body)


def test_refuses_a_reused_code_and_revokes_its_tokens(world, callback_site):
    code = code_for(world, signed_in(world))
    first = redeem(world, code)
    assert userinfo(world, first.body["access_token"]).status == 200
    second = redeem(world, code)
    assert (second.status, second.body["error"]) == (400, "invalid_grant")
    assert userinfo(world, first.body["access_token"]).status == 401


def test_refuses_a_wrong_verifier(world, callback_site):
    code = code_for(world, signed_in(world))
    wrong = redeem(world, code, code_verifier="x" * 43)
    assert (wrong.status, wrong.body["error"]) == (400, "invalid_grant")
    assert redeem(world, code_for(world, signed_in(world))).status == 200


@pytest.mark.parametrize("verifier", [None, "x" * 42, "x" * 129, VERIFIER + "!"])
def test_refuses_a_missing_or_malformed_verifier(world, callback_site, verifier):
    response = redeem(world, code_for(world, signed_in(world)), code_verifier=verifier)
    assert (response.status, response.body["error"]) == (400, "invalid_grant")


def test_a_code_lives_for_sixty_seconds(world, callback_site):
    browser = signed_in(world)
    code = code_for(world, browser)
    world.clock.advance(59)
    assert redeem(world, code).status == 200
    late = code_for(world, browser)
    world.clock.advance(60)
    assert redeem(world, late).body["error"] == "invalid_grant"


def test_refuses_a_different_redirect_uri_at_the_token_endpoint(world, callback_site):
    response = redeem(world, code_for(world, signed_in(world)), redirect_uri=f"{REDIRECT_URI}/")
    assert response.body["error"] == "invalid_grant"
    missing = redeem(world, code_for(world, signed_in(world)), redirect_uri=None)
    assert missing.body["error"] == "invalid_request"


def test_refuses_a_code_issued_to_another_client(world, callback_site):
    world.provider.register_client("quiz", [REDIRECT_URI])
    response = redeem(world, code_for(world, signed_in(world)), client_id="quiz")
    assert response.body["error"] == "invalid_grant"


def test_refuses_an_unknown_grant_type(world):
    response = token_request(world, {"grant_type": "password", "client_id": "app"})
    assert response.body["error"] == "unsupported_grant_type"


# --- client authentication --------------------------------------------------

SECRET = b"s3cr:t%+x"


def confidential(world):
    world.provider.register_client("conf", [REDIRECT_URI], secret=SECRET)
    return code_for(
        world, signed_in(world), client_id="conf", code_challenge=None, code_challenge_method=None
    )


def basic(client_id, secret):
    pair = f"{client_id}:{secret}".encode()
    return {"Authorization": "Basic " + base64.b64encode(pair).decode()}


def confidential_form(code, **changes):
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI}
    return {k: v for k, v in {**form, **changes}.items() if v is not None}


def test_client_secret_basic_form_encodes_before_base64(world, callback_site):
    headers = basic(quote_plus("conf"), quote_plus(SECRET))
    response = token_request(world, confidential_form(confidential(world)), headers)
    assert response.status == 200
    naive = token_request(world, confidential_form(confidential(world)), basic("conf", "s3cr:t%+x"))
    assert (naive.status, naive.body["error"]) == (401, "invalid_client")


def test_client_secret_post(world, callback_site):
    form = confidential_form(confidential(world), client_id="conf", client_secret=SECRET.decode())
    assert token_request(world, form).status == 200
    wrong = confidential_form(confidential(world), client_id="conf", client_secret="guess")
    assert token_request(world, wrong).body["error"] == "invalid_client"


def test_refuses_two_client_authentication_methods_at_once(world, callback_site):
    headers = basic(quote_plus("conf"), quote_plus(SECRET))
    form = confidential_form(confidential(world), client_id="conf", client_secret=SECRET.decode())
    response = token_request(world, form, headers)
    assert (response.status, response.body["error"]) == (400, "invalid_request")


def test_refuses_a_confidential_client_without_credentials(world, callback_site):
    form = confidential_form(confidential(world), client_id="conf")
    response = token_request(world, form)
    assert (response.status, response.body["error"]) == (401, "invalid_client")


def test_refuses_a_verifier_for_a_code_issued_without_a_challenge(world, callback_site):
    headers = basic(quote_plus("conf"), quote_plus(SECRET))
    form = confidential_form(confidential(world), code_verifier=VERIFIER)
    assert token_request(world, form, headers).body["error"] == "invalid_grant"
    assert token_request(world, confidential_form(confidential(world)), headers).status == 200


ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def assertion(world, jti, **changes):
    claims = {
        "iss": "signed", "sub": "signed", "aud": ISSUER, "jti": jti,
        "exp": world.clock.now() + 60, **changes,
    }
    header = {"alg": "ES256", "kid": "c1", "typ": "client-authentication+jwt"}
    return jws_encode(header, claims, EC_1)


def private_key_jwt(world, client_assertion):
    world.provider.register_client("signed", [REDIRECT_URI], jwks=jwks_of(public_jwk(EC_1, "c1")))
    code = code_for(world, signed_in(world), client_id="signed")
    form = {
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI,
        "code_verifier": VERIFIER, "client_assertion_type": ASSERTION_TYPE,
        "client_assertion": client_assertion,
    }
    return token_request(world, form)


def test_private_key_jwt_with_the_issuer_as_audience(world, callback_site):
    assert private_key_jwt(world, assertion(world, "j-1")).status == 200
    assert private_key_jwt(world, assertion(world, "j-2", aud=[ISSUER])).status == 200


@pytest.mark.parametrize(
    "aud", [f"{ISSUER}/token", [ISSUER, "https://other.example"], [f"{ISSUER}/token"], "x"]
)
def test_refuses_private_key_jwt_with_any_other_audience(world, callback_site, aud):
    response = private_key_jwt(world, assertion(world, "j-1", aud=aud))
    assert (response.status, response.body["error"]) == (401, "invalid_client")


def test_refuses_private_key_jwt_without_an_audience(world, callback_site):
    claims = jws_split(assertion(world, "j-1"))[1]
    without_aud = {name: value for name, value in claims.items() if name != "aud"}
    response = private_key_jwt(world, jws_encode({"alg": "ES256", "kid": "c1"}, without_aud, EC_1))
    assert (response.status, response.body["error"]) == (401, "invalid_client")
    assert private_key_jwt(world, assertion(world, "j-2")).status == 200


@pytest.mark.parametrize("sub", ["app", None])
def test_refuses_private_key_jwt_unless_sub_is_the_client(world, callback_site, sub):
    response = private_key_jwt(world, assertion(world, "j-1", sub=sub))
    assert (response.status, response.body["error"]) == (401, "invalid_client")
    assert private_key_jwt(world, assertion(world, "j-2")).status == 200


def test_refuses_a_code_redeemed_with_another_clients_assertion(world, callback_site):
    """keyed authenticates with its own key, but the code was issued to signed."""
    world.provider.register_client("keyed", [REDIRECT_URI], jwks=jwks_of(public_jwk(RSA_1, "k")))
    claims = {
        "iss": "keyed", "sub": "keyed", "aud": ISSUER, "jti": "j-1",
        "exp": world.clock.now() + 60,
    }
    keyed = jws_encode({"alg": "RS256", "kid": "k"}, claims, RSA_1)
    assert jws_verify(keyed, jwks_of(public_jwk(RSA_1, "k")), frozenset({"RS256"}))["sub"] == "keyed"
    response = private_key_jwt(world, keyed)
    assert (response.status, response.body["error"]) == (400, "invalid_grant")
    assert private_key_jwt(world, assertion(world, "j-2")).status == 200


def test_refuses_a_replayed_client_assertion(world, callback_site):
    once = assertion(world, "j-1")
    assert private_key_jwt(world, once).status == 200
    assert private_key_jwt(world, once).body["error"] == "invalid_client"


def test_refuses_an_expired_or_foreign_client_assertion(world, callback_site):
    expired = assertion(world, "j-1", exp=world.clock.now())
    assert private_key_jwt(world, expired).body["error"] == "invalid_client"
    other = assertion(world, "j-2", iss="app", sub="app")
    assert private_key_jwt(world, other).body["error"] == "invalid_client"


# --- refresh tokens ---------------------------------------------------------


def refresh(world, refresh_token, **changes):
    form = {"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": "app"}
    return token_request(world, {k: v for k, v in {**form, **changes}.items() if v is not None})


def test_refuses_a_refresh_token_used_twice_and_revokes_the_grant(world, callback_site):
    first = redeem(world, code_for(world, signed_in(world))).body
    rotated = refresh(world, first["refresh_token"])
    assert rotated.status == 200
    assert rotated.body["refresh_token"] != first["refresh_token"]
    again = refresh(world, first["refresh_token"])
    assert (again.status, again.body["error"]) == (400, "invalid_grant")
    assert refresh(world, rotated.body["refresh_token"]).body["error"] == "invalid_grant"
    assert userinfo(world, rotated.body["access_token"]).status == 401


def test_a_refreshed_id_token_keeps_auth_time_and_drops_nonce(world, callback_site):
    first = redeem(world, code_for(world, signed_in(world)))
    world.clock.advance(100)
    claims = id_claims(refresh(world, first.body["refresh_token"]))
    assert (claims["sub"], claims["aud"], claims["auth_time"]) == ("alice", "app", NOW)
    assert claims["iat"] == NOW + 100
    assert "nonce" not in claims


def test_refresh_refuses_a_broader_scope(world, callback_site):
    first = redeem(world, code_for(world, signed_in(world), scope="openid")).body
    broader = refresh(world, first["refresh_token"], scope="openid email")
    assert broader.body["error"] == "invalid_scope"
    assert refresh(world, first["refresh_token"], scope="openid").status == 200


def test_an_unknown_scope_is_ignored_not_granted(world, callback_site):
    # Authorization requests only: RFC 6749 §3.3 lets a provider ignore scope it does not know.
    # A refresh may not name anything outside the grant (§6), unknown scope included.
    tokens = redeem(world, code_for(world, signed_in(world), scope="openid shoe_size email"))
    assert tokens.body["scope"] == "openid email"
    assert world.provider.introspect(tokens.body["access_token"])["scope"] == "openid email"


@pytest.mark.parametrize(
    "scope", ["openid shoe_size", "shoe_size", "openid email", "OPENID", "", " "]
)
def test_refresh_refuses_a_scope_outside_the_grant(world, callback_site, scope):
    first = redeem(world, code_for(world, signed_in(world), scope="openid")).body
    refused = refresh(world, first["refresh_token"], scope=scope)
    assert (refused.status, refused.body["error"]) == (400, "invalid_scope")
    assert refresh(world, first["refresh_token"]).body["scope"] == "openid"


@pytest.mark.parametrize("scope", ["openid\temail", "openid\nemail", "openid\u00a0email"])
def test_refresh_splits_scope_on_spaces_only(world, callback_site, scope):
    # RFC 6749 §3.3: scope tokens are delimited by space (%x20), so a tab is part of a token.
    first = redeem(world, code_for(world, signed_in(world))).body
    refused = refresh(world, first["refresh_token"], scope=scope)
    assert (refused.status, refused.body["error"]) == (400, "invalid_scope")
    assert refresh(world, first["refresh_token"], scope=" openid  email ").body["scope"] == (
        "openid email"
    )


def test_refresh_keeps_the_grant_unless_a_subset_narrows_it(world, callback_site):
    first = redeem(world, code_for(world, signed_in(world))).body
    narrowed = refresh(world, first["refresh_token"], scope="email openid openid").body
    assert narrowed["scope"] == "openid email"
    narrowed = refresh(world, narrowed["refresh_token"], scope="openid").body
    assert narrowed["scope"] == "openid"
    assert "email" not in userinfo(world, narrowed["access_token"]).body
    assert refresh(world, narrowed["refresh_token"]).body["scope"] == "openid email"


def test_refresh_refuses_another_client(world, callback_site):
    world.provider.register_client("quiz", [REDIRECT_URI])
    first = redeem(world, code_for(world, signed_in(world))).body
    assert refresh(world, first["refresh_token"], client_id="quiz").body["error"] == (
        "invalid_grant"
    )
    assert refresh(world, first["refresh_token"]).status == 200


# --- /userinfo --------------------------------------------------------------


def test_userinfo_returns_the_scoped_claims(world, callback_site):
    token = redeem(world, code_for(world, signed_in(world))).body["access_token"]
    response = userinfo(world, token)
    assert response.body == {"sub": "alice", "email": "alice@example.com", "email_verified": True}
    narrow = redeem(world, code_for(world, signed_in(world), scope="openid")).body
    assert userinfo(world, narrow["access_token"]).body == {"sub": "alice"}


def test_userinfo_refuses_an_unknown_or_expired_token(world, callback_site):
    response = userinfo(world, "made-up")
    assert response.status == 401
    assert response.headers["WWW-Authenticate"].startswith('Bearer error="invalid_token"')
    token = redeem(world, code_for(world, signed_in(world))).body["access_token"]
    world.clock.advance(299)
    assert userinfo(world, token).status == 200
    world.clock.advance(1)
    assert userinfo(world, token).status == 401


@pytest.mark.parametrize("authorization", [None, "", "Bearer", "Bearer ", "Basic YTpi", "x"])
def test_userinfo_without_a_bearer_token_names_no_error(world, authorization):
    headers = {} if authorization is None else {"Authorization": authorization}
    response = world.network.send(Request("GET", f"{ISSUER}/userinfo", headers=headers))
    assert (response.status, response.headers, response.body) == (
        401, {"WWW-Authenticate": "Bearer"}, {},
    )


# --- /logout ----------------------------------------------------------------

AFTER_LOGOUT = f"{APP}/signed-out"


def logout_url(**params):
    return f"{ISSUER}/logout?{urlencode(params)}"


def logged_in_with_hint(world):
    world.provider.register_client("app", [REDIRECT_URI], post_logout_redirect_uris=[AFTER_LOGOUT])
    browser = signed_in(world)
    return browser, redeem(world, code_for(world, browser)).body["id_token"]


def test_logout_ends_the_session_and_redirects_back(world, callback_site):
    browser, hint = logged_in_with_hint(world)
    landed = browser.get(
        logout_url(id_token_hint=hint, post_logout_redirect_uri=AFTER_LOGOUT, state="bye")
    )
    assert landed.body == "callback reached"
    assert browser.history[-1].url == f"{AFTER_LOGOUT}?state=bye"
    assert browser.get(authorize_url()).status == 401


def test_logout_refuses_to_redirect_to_an_unregistered_uri(world, callback_site):
    browser, hint = logged_in_with_hint(world)
    page = browser.get(logout_url(id_token_hint=hint, post_logout_redirect_uri=f"{AFTER_LOGOUT}/"))
    assert (page.status, page.location) == (400, None)
    no_hint = browser.get(logout_url(post_logout_redirect_uri=AFTER_LOGOUT))
    assert (no_hint.status, no_hint.location) == (400, None)


def test_logout_is_idempotent(world, callback_site):
    browser = signed_in(world)
    assert browser.get(logout_url()).status == 200
    assert browser.get(logout_url()).status == 200
    assert browser.cookies(ISSUER) == {}


def test_introspection_reports_acr_and_auth_time(world, callback_site):
    token = redeem(world, code_for(world, signed_in(world))).body["access_token"]
    report = world.provider.introspect(token)
    assert report["active"] is True
    assert (report["sub"], report["acr"], report["auth_time"]) == ("alice", ACR_PASSWORD, NOW)
    assert world.provider.introspect("made-up") == {"active": False}


def test_b64url_helper_matches_challenge():
    digest = hashlib.sha256(VERIFIER.encode("ascii")).digest()
    assert b64url_encode(digest) == CHALLENGE
