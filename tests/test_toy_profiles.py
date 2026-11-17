"""Profile fields for how a provider reports assurance and what it does with a request."""

import json
from dataclasses import replace

from tests.test_toy_provider import (
    APP, NOW, authorize_url, callback_query, code_for, id_claims, redeem, signed_in,
)
from toy.http import Response
from toy.provider import ACR_MFA, SPEC


def _site(world):
    world.network.mount(APP, lambda request: Response(200, {}, "callback reached"))
    return world


def _claims(world, browser, **params):
    return id_claims(redeem(world, code_for(world, browser, **params)))


def test_spec_keeps_its_behaviour_under_the_new_fields():
    assert (SPEC.assurance_unasked, SPEC.fixed_assurance, SPEC.amr_names) == (False, None, ())
    assert (SPEC.honours_acr_values, SPEC.auth_time_unasked) == (True, True)


def test_assurance_unasked_sends_the_claim_without_a_request(make_world):
    world = _site(make_world(profile=replace(SPEC, assurance_unasked=True)))
    claims = _claims(world, signed_in(world, factors=("pwd", "otp")))
    assert claims["acr"] == ACR_MFA


def test_fixed_assurance_names_the_same_value_for_every_sign_in(make_world):
    profile = replace(SPEC, assurance_claim="tfp", assurance_unasked=True,
                      fixed_assurance="flow-1")
    world = _site(make_world(profile=profile))
    weak = _claims(world, signed_in(world))
    strong = _claims(world, signed_in(world, factors=("pwd", "otp")))
    assert weak["tfp"] == strong["tfp"] == "flow-1"
    assert "acr" not in weak


def test_amr_names_rename_or_drop_methods(make_world):
    renamed = replace(SPEC, amr_names=(("pwd", "password"), ("otp", "code")))
    world = _site(make_world(profile=renamed))
    assert _claims(world, signed_in(world, factors=("pwd", "otp")))["amr"] == ["password", "code"]
    world = _site(make_world(profile=replace(SPEC, amr_names=None)))
    assert "amr" not in _claims(world, signed_in(world, factors=("pwd", "otp")))


def test_a_provider_that_ignores_acr_values_answers_from_the_session(make_world):
    world = _site(make_world(profile=replace(SPEC, honours_acr_values=False)))
    browser = signed_in(world)
    assert "code" in callback_query(browser, acr_values=ACR_MFA)
    essential = json.dumps({"id_token": {"acr": {"essential": True, "values": [ACR_MFA]}}})
    assert browser.get(authorize_url(claims=essential)).status == 401


def test_auth_time_only_when_asked_for(make_world):
    world = _site(make_world(profile=replace(SPEC, auth_time_unasked=False)))
    browser = signed_in(world)
    assert "auth_time" not in _claims(world, browser)
    essential = json.dumps({"id_token": {"auth_time": {"essential": True}}})
    assert _claims(world, browser, claims=essential)["auth_time"] == NOW
    world.clock.advance(60)
    assert _claims(world, browser, max_age="3600")["auth_time"] == NOW
