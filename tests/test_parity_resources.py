"""Parity for chapters 13 to 15: each solved function agrees with its toy/ counterpart."""

import pytest

from tests.parity_support import ID, OTHER, _outcome, _solved
from toy import client
from toy.errors import FlowError
from toy.http import FakeNetwork


CHAPTER_13 = "13_access_tokens_and_userinfo_test.py"
USERINFO_CASES = [
    ("alice", {"sub": "alice"}),
    ("alice", {"sub": "alice", "email": "alice@example.com"}),
    ("123", {"sub": "123"}),
    ("alice", {"sub": "Alice"}),
    ("alice", {"sub": "alice "}),
    ("alice", {"sub": " alice"}),
    ("alice", {"sub": "mallory"}),
    ("alice", {"sub": ["alice"]}),
    ("alice", {"sub": None}),
    ("alice", {"sub": ""}),
    ("alice", {}),
    ("123", {"sub": 123}),
    ("1", {"sub": True}),
    ("ä", {"sub": "ä"}),
]


def test_userinfo_cases_hold_both_outcomes():
    outcomes = {
        _outcome(client.check_userinfo_subject, {"sub": id_sub}, userinfo)
        for id_sub, userinfo in USERINFO_CASES
    }
    assert outcomes == {("value", None), ("refused", "sub_mismatch")}


@pytest.mark.parametrize(("id_sub", "userinfo"), USERINFO_CASES, ids=repr)
def test_chapter_13_check_userinfo_subject_matches_toy(id_sub, userinfo):
    solved = _solved(CHAPTER_13).check_userinfo_subject
    id_claims = {"sub": id_sub}
    expected = _outcome(client.check_userinfo_subject, id_claims, userinfo)
    assert _outcome(solved, id_claims, userinfo) == expected


CHAPTER_14 = "14_claims_and_scopes_test.py"
ESSENTIAL_REQUESTS = [
    {"email": {"essential": True}},
    {"email": {"essential": True}, "phone_number": {"essential": True}},
    {"email": None, "name": {}, "nickname": {"essential": False}},
    {"locale": {"essential": "true"}, "picture": {"essential": 1}, "zoneinfo": {"essential": 0}},
    {"sub": {"value": "alice", "essential": True}, "acr": {"essential": True, "values": ["1"]}},
    {"email_verified": {"essential": True}, "address": {"essential": True}},
    {},
]
RETURNED_CLAIMS = [
    {}, {"sub": "alice", "email": "alice@example.com"}, {"email": None},
    {"email_verified": False, "email": ""}, {"acr": "1", "phone_number": "+1"},
]


@pytest.mark.parametrize("requested", ESSENTIAL_REQUESTS, ids=repr)
@pytest.mark.parametrize("claims", RETURNED_CLAIMS, ids=repr)
def test_chapter_14_missing_essential_claims_matches_toy(claims, requested):
    solved = _solved(CHAPTER_14).missing_essential_claims
    assert solved(claims, requested) == client.missing_essential_claims(claims, requested)


CHAPTER_15 = "15_discovery_and_mix_up_test.py"
ACME = f"{ID}/acme"


def _flow_outcome(function, *args, **kwargs):
    try:
        return ("value", function(*args, **kwargs))
    except FlowError as refused:
        return ("refused", refused.reason)


def _discovery_document(issuer: str | None) -> dict:
    document = _solved(CHAPTER_15)._metadata(issuer or ID)
    return document if issuer else {k: v for k, v in document.items() if k != "issuer"}


DISCOVERY_HOSTS = {
    "honest": {"": ID, "/acme": ACME, "/zeta": f"{ID}/zeta/"},
    "slashes-differ": {"": f"{ID}/", "/acme": f"{ACME}/", "/zeta": f"{ID}/zeta"},
    "names-another": {"": ACME, "/acme": OTHER, "/zeta": ID},
    "no-issuer": {"": None, "/acme": None},
    "empty": {},
}
DISCOVERY_ISSUERS = [ID, f"{ID}/", f"{ID}//", ACME, f"{ACME}/", f"{ID}/zeta/", f"{ID}/zeta"]


def _discovery_host(named: dict):
    host = _solved(CHAPTER_15).TenantHost(
        {tenant: _discovery_document(issuer) for tenant, issuer in named.items()}
    )
    network = FakeNetwork()
    network.mount(ID, host)
    return network, host


def test_discovery_cases_hold_both_outcomes():
    outcomes = set()
    for named in DISCOVERY_HOSTS.values():
        for issuer in DISCOVERY_ISSUERS:
            network, _ = _discovery_host(named)
            outcomes.add(_flow_outcome(client.discover, issuer=issuer, network=network)[0])
    assert outcomes == {"value", "refused"}


@pytest.mark.parametrize("issuer", DISCOVERY_ISSUERS)
@pytest.mark.parametrize("host_name", DISCOVERY_HOSTS)
def test_chapter_15_discover_matches_toy(host_name, issuer):
    solved = _solved(CHAPTER_15).discover
    network, host = _discovery_host(DISCOVERY_HOSTS[host_name])
    toy_network, toy_host = _discovery_host(DISCOVERY_HOSTS[host_name])
    expected = _flow_outcome(client.discover, issuer=issuer, network=toy_network)
    assert _flow_outcome(solved, issuer=issuer, network=network) == expected
    assert host.asked == toy_host.asked


RESPONSE_PARAMS = [
    {"code": "c", "state": "s", "iss": ID},
    {"code": "c", "state": "s"},
    {"error": "access_denied", "state": "s"},
    {"error": "access_denied", "state": "s", "iss": OTHER},
    {"error": "access_denied", "state": "s", "iss": ID},
    {"code": "c", "state": "s", "iss": f"{ID}/"},
    {"code": "c", "state": "s", "iss": "https://ID.example"},
    {"code": "c", "state": "s", "iss": f"{ID}.evil.example"},
    {"code": "c", "state": "s", "iss": ACME},
    {"code": "c", "state": "s", "iss": "https%3A%2F%2Fid.example"},
    {"code": "c", "state": "s", "iss": ""},
]
ISS_CONFIGS = {
    "advertised": {"issuer": ID, "authorization_response_iss_parameter_supported": True},
    "not-advertised": {"issuer": ID, "authorization_response_iss_parameter_supported": False},
    "silent": {"issuer": ID},
}


@pytest.mark.parametrize("config_name", ISS_CONFIGS)
@pytest.mark.parametrize("params", RESPONSE_PARAMS, ids=repr)
def test_chapter_15_check_response_issuer_matches_toy(params, config_name):
    solved = _solved(CHAPTER_15).check_response_issuer
    config = ISS_CONFIGS[config_name]
    expected = _flow_outcome(client._check_response_issuer, params, config)
    assert _flow_outcome(solved, params, config) == expected


def test_response_issuer_cases_hold_both_outcomes():
    outcomes = {
        _flow_outcome(client._check_response_issuer, params, config)
        for params in RESPONSE_PARAMS for config in ISS_CONFIGS.values()
    }
    assert outcomes == {("value", None), ("refused", "issuer_mismatch")}
