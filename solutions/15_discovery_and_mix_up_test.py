"""Discovery, issuer matching and mix-up defence.

A client learns a provider's endpoints and keys from a JSON document at
the issuer plus /.well-known/openid-configuration (Discovery §4). If the
issuer has a path, "any terminating / MUST be removed before appending".
RFC 8414, for OAuth metadata, inserts /.well-known/ between host and path.

"The issuer value returned MUST be identical to the Issuer URL that was
used as the prefix", and to iss in ID tokens (§4.3); otherwise it "MUST
NOT be used". A document naming another issuer, with its own keys, is an
impersonation (§7.2). The path belongs to the issuer: sub 1234 at
https://id.example is not sub 1234 at https://id.example/sales.

A client with several providers and one callback can be mixed up: a login
sent to one provider comes back with a code from another, and the client
hands that code and its PKCE verifier to the wrong token endpoint. RFC
9207 adds iss to authorization responses, errors included. The client
decodes it and compares it, by "simple string comparison", with the
issuer it sent the request to. On a mismatch, clients "MUST reject the
authorization response and MUST NOT proceed". They "MUST reject
authorization responses without the iss parameter" from a provider that
supports it: authorization_response_iss_parameter_supported says so.

A common mistake: comparing issuers by prefix, or after trimming a slash.

Read more:
  https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
  https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation
  https://www.rfc-editor.org/rfc/rfc8414.html#section-5
  https://www.rfc-editor.org/rfc/rfc9207.html#section-2.4
"""

from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from conftest import __
from toy.client import (
    STATE_COOKIE,
    Transaction,
    account_key,
    exchange_code,
    start_login,
    validate_id_token,
)
from toy.client import discover as toy_discover
from toy.clock import Clock
from toy.errors import FlowError, InvalidToken, OAuthError
from toy.http import Browser, FakeNetwork, Request, Response, with_query
from toy.jose import jwks_of, public_jwk
from toy.keys import ATTACKER_RSA, EC_1
from toy.provider import Provider

ISSUER = "https://id.example"
OTHER_ISSUER = "https://other-id.example"
ACME = f"{ISSUER}/acme"
APP = "https://app.example"
REDIRECT_URI = f"{APP}/callback"
CLIENT_ID = "app"
MALLORY = "https://mallory.example"
WELL_KNOWN = "/.well-known/openid-configuration"


def _metadata(issuer: str, **changes) -> dict:
    """A Discovery document for issuer, with its endpoints under it; changes override."""
    endpoints = issuer.rstrip("/")
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{endpoints}/authorize",
        "token_endpoint": f"{endpoints}/token",
        "jwks_uri": f"{endpoints}/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "authorization_response_iss_parameter_supported": True,
        **changes,
    }


class TenantHost:
    """https://id.example as a host of several issuers, one per tenant path.

    documents maps a tenant's path ("" for the host's own issuer) to the document
    it serves at that path plus /.well-known/openid-configuration. asked records
    each URL requested, in order.
    """

    def __init__(self, documents: dict[str, dict]):
        self._documents = dict(documents)
        self.asked: tuple[str, ...] = ()

    def __call__(self, request: Request) -> Response:
        self.asked = (*self.asked, request.url)
        tenant, found, rest = request.path.rpartition(WELL_KNOWN)
        document = self._documents.get(tenant) if found and not rest else None
        if document is None:
            return Response(404, {}, {"error": "not_found"})
        return Response(200, {}, document)


def _host(documents: dict[str, dict]) -> tuple[FakeNetwork, TenantHost]:
    network, host = FakeNetwork(), TenantHost(documents)
    network.mount(ISSUER, host)
    return network, host


def _flow_reason(check: Callable) -> str | None:
    try:
        check()
    except FlowError as refused:
        return refused.reason
    return None


class MixUp:
    """mallory's provider at https://other-id.example, run for a mix-up attack.

    Its Discovery document is in order. Its /authorize sends the browser on to
    id.example's authorization endpoint with the very same request, and its
    /token keeps every form posted to it.
    """

    def __init__(self):
        self.stolen: tuple[dict, ...] = ()

    def __call__(self, request: Request) -> Response:
        if request.path == WELL_KNOWN:
            return Response(200, {}, _metadata(OTHER_ISSUER))
        if request.path == "/jwks":
            return Response(200, {}, jwks_of(public_jwk(ATTACKER_RSA, "m1")))
        if request.path == "/authorize":
            onward = with_query(f"{ISSUER}/authorize", request.query)
            return Response(303, {"Location": onward}, "")
        if request.path == "/token":
            self.stolen = (*self.stolen, dict(request.form))
            return Response(400, {}, {"error": "invalid_grant"})
        return Response(404, {}, {"error": "not_found"})


class App:
    """app at https://app.example: sign-in with id.example or other-id.example, one callback.

    /login?provider=<issuer> starts a login there and binds its state to the
    browser, one login at a time. /callback finds the login by its state and
    checks the response with check_iss (check_response_issuer unless told
    otherwise) before anything else. Only then does it look for an error,
    redeem the code at that login's provider and validate the ID token.
    """

    def __init__(self, clock: Clock, network: FakeNetwork, check_iss: Callable | None):
        self._clock, self._network, self._check_iss = clock, network, check_iss
        self._providers = {
            issuer: _discovered(network, issuer) for issuer in (ISSUER, OTHER_ISSUER)
        }
        self.pending: dict[str, tuple[Transaction, str]] = {}

    def __call__(self, request: Request) -> Response:
        routes = {"/login": self._login, "/callback": self._callback}
        route = routes.get(request.path)
        return route(request) if route else Response(404, {}, {"error": "not_found"})

    def _login(self, request: Request) -> Response:
        issuer = request.query.get("provider", "")
        config, _ = self._providers[issuer]
        url, transaction = start_login(
            issuer_config=config, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI,
            now=self._clock.now(),
        )
        self.pending = {**self.pending, transaction.state: (transaction, issuer)}
        return Response(303, {"Location": url}, "", {STATE_COOKIE: transaction.state})

    def _callback(self, request: Request) -> Response:
        state = request.query.get("state", "")
        if state not in self.pending or request.cookies.get(STATE_COOKIE) != state:
            return Response(400, {}, {"error": "no login is pending"})
        transaction, issuer = self.pending[state]
        self.pending = {k: v for k, v in self.pending.items() if k != state}
        config, jwks = self._providers[issuer]
        try:
            (self._check_iss or check_response_issuer)(request.query, config)
            if "error" in request.query:
                raise OAuthError(request.query["error"])
            tokens = exchange_code(
                issuer_config=config, client_id=CLIENT_ID, code=request.query.get("code", ""),
                redirect_uri=REDIRECT_URI, code_verifier=transaction.code_verifier,
                network=self._network,
            )
            claims = validate_id_token(
                tokens["id_token"], issuer=issuer, client_id=CLIENT_ID, jwks=jwks,
                now=self._clock.now(), nonce=transaction.nonce,
            )
        except (FlowError, InvalidToken, OAuthError) as refused:
            return Response(401, {}, {"error": getattr(refused, "reason", None) or refused.error})
        return Response(200, {}, {"user": [claims["iss"], claims["sub"]]}, {STATE_COOKIE: None})


def _discovered(network: FakeNetwork, issuer: str) -> tuple[dict, dict]:
    config = toy_discover(issuer=issuer, network=network)
    return config, network.send(Request("GET", config["jwks_uri"])).body


@dataclass(frozen=True)
class World:
    clock: Clock
    network: FakeNetwork
    provider: Provider
    other: Provider | MixUp
    app: App


def _world(mix_up: bool = False, check_iss: Callable | None = None) -> World:
    """id.example, where alice has an account, and other-id.example, where bob has one.

    app is registered at both with one callback. With mix_up, other-id.example is
    mallory's MixUp instead.
    """
    clock, network = Clock(), FakeNetwork()
    provider = Provider(ISSUER, clock=clock, network=network)
    provider.register_client(CLIENT_ID, [REDIRECT_URI])
    provider.add_user("alice", "alice@example.com", True, "alice-password")
    if mix_up:
        other = MixUp()
        network.mount(OTHER_ISSUER, other)
    else:
        other = Provider(OTHER_ISSUER, clock=clock, network=network, signing_key=EC_1, kid="o1")
        other.register_client(CLIENT_ID, [REDIRECT_URI])
        other.add_user("bob", "bob@example.com", True, "bob-password")
    app = App(clock, network, check_iss)
    network.mount(APP, app)
    return World(clock, network, provider, other, app)


def _signed_in(world: World, provider: Provider, sub: str) -> Browser:
    browser = Browser(world.network)
    provider.sign_in(browser, sub, ("pwd",))
    return browser


def _log_in(browser: Browser, issuer: str) -> Response:
    """The browser asks app to sign it in with issuer and follows every redirect."""
    return browser.get(with_query(f"{APP}/login", {"provider": issuer}))


def test_discovery_appends_to_the_issuer():
    """Discovery §4.1: for an issuer with a path, "any terminating / MUST be removed before appending" the well-known part. The toy client's discover then wants the issuer the document names to be the one it was asked for, character for character. Which URLs does it fetch, and which issuer does it refuse?"""
    network, host = _host({"": _metadata(ISSUER), "/acme": _metadata(ACME)})
    assert toy_discover(issuer=ISSUER, network=network)["issuer"] == ISSUER
    assert toy_discover(issuer=ACME, network=network)["issuer"] == ACME
    with_slash = _flow_reason(lambda: toy_discover(issuer=f"{ACME}/", network=network))
    assert host.asked == (
        "https://id.example/.well-known/openid-configuration",
        "https://id.example/acme/.well-known/openid-configuration",
        "https://id.example/acme/.well-known/openid-configuration",
    )
    assert with_slash == "issuer_mismatch"


def test_rfc_8414_inserts_between_host_and_path():
    """RFC 8414 §3.1, for OAuth metadata: "any terminating "/" MUST be removed before inserting "/.well-known/" and the well-known URI suffix between the host component and the path component". Its suffix is oauth-authorization-server. Where is ACME's OAuth metadata? RFC 8414 §5 notes the OpenID form appends instead."""
    oauth = "https://id.example/.well-known/oauth-authorization-server/acme"
    parts = urlsplit(oauth)
    assert f"{parts.scheme}://{parts.netloc}" == ISSUER
    assert parts.path == "/.well-known/oauth-authorization-server" + urlsplit(ACME).path
    assert not oauth.startswith(ACME)


def discover(*, issuer: str, network: FakeNetwork) -> dict:
    url = f"{issuer.rstrip('/')}{WELL_KNOWN}"
    config = network.send(Request("GET", url)).body
    if config.get("issuer") != issuer:
        raise FlowError("issuer_mismatch")
    return config


def test_accepts_a_document_naming_exactly_this_issuer():
    """Implement discover above. 1. GET the issuer, less any trailing /, plus WELL_KNOWN, with network.send(Request(...)). 2. Unless the body's issuer is identical to the issuer you were given, raise FlowError("issuer_mismatch"). 3. Return the body. An issuer may end in /: the zeta tenant's does."""
    zeta = f"{ISSUER}/zeta/"
    documents = {"": _metadata(ISSUER), "/acme": _metadata(ACME), "/zeta": _metadata(zeta)}
    issuers = [ISSUER, ACME, zeta]
    network, host = _host(documents)
    for issuer in issuers:
        assert discover(issuer=issuer, network=network) == _metadata(issuer)
    reference_network, reference = _host(documents)
    for issuer in issuers:
        toy_discover(issuer=issuer, network=reference_network)
    assert host.asked == reference.asked
    assert host.asked[-1] == "https://id.example/zeta/.well-known/openid-configuration"


def test_refuses_a_document_naming_another_issuer():
    """Discovery §7.2: an attacker "may also attempt to impersonate an OpenID Provider by publishing a Discovery document that contains an issuer Claim using the Issuer URL of the OP being impersonated, but with its own endpoints and signing keys". mallory runs the beta tenant, and its document names ACME. Your discover refuses it, and every document below, though each is served."""
    impersonation = _metadata(ACME, jwks_uri=f"{MALLORY}/jwks")
    cases = [
        (f"{ISSUER}/beta", "/beta", impersonation),
        (ISSUER, "", _metadata(f"{ISSUER}/")),
        (ISSUER, "", _metadata(ACME)),
        (f"{ACME}/", "/acme", _metadata(ACME)),
        (ACME, "/acme", _metadata(f"{ACME}/")),
        (ACME, "/acme", _metadata("https://ID.example/acme")),
        (ACME, "/acme", _metadata(OTHER_ISSUER)),
        (ACME, "/acme", {k: v for k, v in _metadata(ACME).items() if k != "issuer"}),
    ]
    for asked, tenant, document in cases:
        network, host = _host({tenant: document})
        assert network.send(Request("GET", f"{ISSUER}{tenant}{WELL_KNOWN}")).status == 200
        reason = _flow_reason(lambda: discover(issuer=asked, network=network))
        assert reason == "issuer_mismatch"


def test_metadata_names_the_endpoints_keys_and_algorithms():
    """Discovery §3 names the metadata. app reads its endpoints and key set from it, and what the provider supports: id.example signs with RSA, other-id.example with EC, and Discovery says RS256 "MUST be included" among the ID token algorithms. RFC 8414 §2: if code_challenge_methods_supported is "omitted, the authorization server does not support PKCE"."""
    world = _world()
    config = toy_discover(issuer=ISSUER, network=world.network)
    other = toy_discover(issuer=OTHER_ISSUER, network=world.network)
    assert config["token_endpoint"] == f"{ISSUER}/token"
    assert config["jwks_uri"] == f"{ISSUER}/jwks"
    assert config["id_token_signing_alg_values_supported"] == ["RS256"]
    assert other["id_token_signing_alg_values_supported"] == ["ES256", "RS256"]
    assert ("S256" in config["code_challenge_methods_supported"]) is True


def test_iss_arrives_form_encoded():
    """RFC 9207 §2.4: clients decode iss "from its "application/x-www-form-urlencoded" form" before they compare it. What does the callback URL hold, and what is it once decoded?"""
    world = _world()
    alice = _signed_in(world, world.provider, "alice")
    config = toy_discover(issuer=ISSUER, network=world.network)
    url, _ = start_login(
        issuer_config=config, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI,
        now=world.clock.now(),
    )
    location = world.network.send(Request("GET", url, cookies=alice.cookies(ISSUER))).location
    raw = dict(pair.split("=", 1) for pair in urlsplit(location).query.split("&"))
    assert raw["iss"] == "https%3A%2F%2Fid.example"
    assert Request("GET", location).query["iss"] == "https://id.example"


def check_response_issuer(params: dict, issuer_config: dict) -> None:
    returned = params.get("iss")
    if returned is None and issuer_config.get("authorization_response_iss_parameter_supported"):
        raise FlowError("issuer_mismatch")
    if returned is not None and returned != issuer_config["issuer"]:
        raise FlowError("issuer_mismatch")


def test_accepts_the_iss_of_the_provider_the_login_went_to():
    """Implement check_response_issuer above; params is the decoded callback query and issuer_config the Discovery document of the provider this login went to. Raise FlowError("issuer_mismatch") if iss is missing and that provider advertises authorization_response_iss_parameter_supported, or if iss is present and not identical to its issuer. A provider that does not advertise it may send no iss. If it sends one anyway, RFC 9207 says clients SHOULD discard the response and leaves the rest to local policy; this course, like the toy client, compares it."""
    world = _world()
    alice = _signed_in(world, world.provider, "alice")
    bob = _signed_in(world, world.other, "bob")
    assert _log_in(alice, ISSUER).body["user"] == ["https://id.example", "alice"]
    assert _log_in(bob, OTHER_ISSUER).body["user"] == ["https://other-id.example", "bob"]
    quiet = _metadata(ISSUER, authorization_response_iss_parameter_supported=False)
    assert check_response_issuer({"code": "c", "state": "s"}, quiet) is None


def test_refuses_a_code_from_another_provider():
    """Mix-up: alice has a session at id.example and picks "sign in with other-id" at app. mallory's other-id sends her browser on to id.example with app's request, and id.example answers app's callback with a code. An app that skips the iss check sends that code and its PKCE verifier to mallory, who redeems them at id.example. Your app refuses the response before it redeems anything."""
    careless = _world(mix_up=True, check_iss=lambda params, config: None)
    alice = _signed_in(careless, careless.provider, "alice")
    assert _log_in(alice, OTHER_ISSUER).body["error"] == "invalid_grant"
    assert alice.history[-1].query["iss"] == ISSUER
    [stolen] = careless.other.stolen
    redeemed = careless.network.send(Request("POST", f"{ISSUER}/token", form=stolen))
    assert careless.provider.verify_own(redeemed.body["id_token"])["sub"] == "alice"

    world = _world(mix_up=True)
    alice = _signed_in(world, world.provider, "alice")
    assert _log_in(alice, OTHER_ISSUER).body["error"] == "issuer_mismatch"
    assert world.other.stolen == ()
    assert _log_in(alice, ISSUER).body["user"] == [ISSUER, "alice"]


def test_refuses_a_missing_or_lookalike_iss():
    """RFC 9207 §2.4: compare by "simple string comparison", and "Clients MUST reject authorization responses without the iss parameter" from a provider that supports it. An error response is checked too: clients "MUST NOT assume that the error originates from the intended authorization server"."""
    config = _metadata(ISSUER)
    responses = [
        {"code": "c", "state": "s"},
        {"error": "access_denied", "state": "s"},
        {"error": "access_denied", "state": "s", "iss": OTHER_ISSUER},
        {"code": "c", "state": "s", "iss": f"{ISSUER}/"},
        {"code": "c", "state": "s", "iss": "https://ID.example"},
        {"code": "c", "state": "s", "iss": f"{ISSUER}.evil.example"},
        {"code": "c", "state": "s", "iss": ACME},
        {"code": "c", "state": "s", "iss": "https%3A%2F%2Fid.example"},
        {"code": "c", "state": "s", "iss": ""},
    ]
    for params in responses:
        assert _flow_reason(lambda: check_response_issuer(params, config)) == "issuer_mismatch"
    assert check_response_issuer({"code": "c", "state": "s", "iss": ISSUER}, config) is None


def test_the_issuer_path_is_part_of_the_user():
    """Core §16.15: "the subject "1234" with an Issuer Identifier of "https://example.com" is not equivalent to the subject "1234" with an Issuer Identifier of "https://example.com/sales"". Are these two the same account at app?"""
    at_host = account_key({"iss": ISSUER, "sub": "1234"})
    at_sales = account_key({"iss": f"{ISSUER}/sales", "sub": "1234"})
    assert (at_host == at_sales) is False
    assert at_sales == ("https://id.example/sales", "1234")
