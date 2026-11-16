from urllib.parse import urlencode

import pytest

from toy.client import parse_challenge
from toy.http import Request, Response
from toy.provider import ACR_MFA, ACR_PASSWORD
from toy.resource import ResourceServer

ISSUER = "https://id.example"
API = "https://api.example"
APP = "https://app.example"
REDIRECT_URI = f"{APP}/callback"
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def access_token(world, factors=("pwd",)):
    world.network.mount(APP, lambda request: Response(200, {}, "callback reached"))
    browser = world.browser()
    world.provider.sign_in(browser, "alice", factors)
    query = {
        "response_type": "code", "client_id": "app", "redirect_uri": REDIRECT_URI,
        "scope": "openid", "state": "s-1", "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
    }
    browser.get(f"{ISSUER}/authorize?{urlencode(query)}")
    form = {
        "grant_type": "authorization_code", "code": browser.history[-1].query["code"],
        "redirect_uri": REDIRECT_URI, "code_verifier": VERIFIER, "client_id": "app",
    }
    return world.network.send(Request("POST", f"{ISSUER}/token", form=form)).body["access_token"]


def api(world, **requirements):
    ResourceServer(
        API, network=world.network, clock=world.clock,
        introspect=world.provider.introspect, **requirements,
    )


def call(world, token=None, scheme="Bearer"):
    headers = {"Authorization": f"{scheme} {token}"} if token else {}
    return world.network.send(Request("GET", f"{API}/statement", headers=headers))


def test_a_request_without_a_token_gets_a_bare_bearer_challenge(world):
    api(world, acr_values=(ACR_MFA,))
    response = call(world)
    assert (response.status, response.headers["WWW-Authenticate"]) == (401, "Bearer")


def test_an_unknown_token_gets_invalid_token(world):
    api(world, acr_values=(ACR_MFA,))
    response = call(world, "made-up")
    assert response.status == 401
    assert response.headers["WWW-Authenticate"] == (
        'Bearer error="invalid_token", error_description="The access token is not active"'
    )


def test_refuses_a_low_acr_with_the_rfc9470_challenge(world):
    api(world, acr_values=(ACR_MFA,))
    response = call(world, access_token(world))
    assert response.status == 401
    assert response.headers["WWW-Authenticate"] == (
        'Bearer error="insufficient_user_authentication", '
        'error_description="A different authentication level is required", '
        f'acr_values="{ACR_MFA}"'
    )


def test_accepts_a_token_from_a_multi_factor_sign_in(world):
    api(world, acr_values=(ACR_MFA,))
    response = call(world, access_token(world, factors=("pwd", "otp")))
    assert (response.status, response.body["sub"]) == (200, "alice")


def test_refuses_an_old_authentication_with_max_age(world):
    api(world, max_age=60)
    token = access_token(world)
    world.clock.advance(60)
    assert call(world, token).status == 200
    world.clock.advance(1)
    stale = call(world, token)
    assert stale.status == 401
    assert stale.headers["WWW-Authenticate"] == (
        'Bearer error="insufficient_user_authentication", '
        'error_description="More recent authentication is required", '
        'max_age="60"'
    )
    assert call(world, access_token(world)).status == 200


def test_a_challenge_carries_every_requirement(world):
    api(world, acr_values=(ACR_MFA, "urn:example:loa:3"), max_age=60)
    header = call(world, access_token(world)).headers["WWW-Authenticate"]
    assert parse_challenge(header) == {
        "scheme": "Bearer", "error": "insufficient_user_authentication",
        "error_description": "A different authentication level is required",
        "acr_values": f"{ACR_MFA} urn:example:loa:3", "max_age": 60,
    }


@pytest.mark.parametrize("max_age", ['"5"', "5"])
def test_parse_challenge_reads_max_age_quoted_or_not(max_age):
    header = f'Bearer error="insufficient_user_authentication", max_age={max_age}'
    assert parse_challenge(header)["max_age"] == 5


@pytest.mark.parametrize("max_age", ['"-1"', "five", '"1.5"', '""'])
def test_parse_challenge_refuses_a_max_age_that_is_not_a_non_negative_integer(max_age):
    with pytest.raises(ValueError):
        parse_challenge(f'Bearer error="insufficient_user_authentication", max_age={max_age}')
    assert parse_challenge('Bearer max_age="0"')["max_age"] == 0


def test_resource_server_reads_the_scheme_case_insensitively(world):
    api(world, acr_values=(ACR_PASSWORD,))
    token = access_token(world)
    assert call(world, token, scheme="bearer").status == 200
    assert call(world, token, scheme="Basic").status == 401
