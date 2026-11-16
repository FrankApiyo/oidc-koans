"""A toy world for the provider and client tests: one provider, one client app, two users."""

from dataclasses import dataclass

import pytest

from toy.client import STATE_COOKIE, start_login
from toy.clock import Clock
from toy.http import Browser, FakeNetwork, Request, Response
from toy.provider import Provider

APP = "https://app.example"
REDIRECT_URI = f"{APP}/callback"
ISSUER = "https://id.example"


class StopAtCallback:
    """A client app that starts logins and stops at its callback.

    /login runs start_login, keeps the transaction and binds its state to the
    browser with a cookie. /callback only answers 200, so a test can hand the
    request the browser sent to finish_login itself.
    """

    def __init__(self, world, client_id="app"):
        self._world = world
        self._client_id = client_id
        self.transactions = {}

    def __call__(self, request):
        if request.path != "/login":
            return Response(200, {}, "callback reached")
        url, transaction = start_login(
            issuer_config=self._world.config,
            client_id=self._client_id,
            redirect_uri=REDIRECT_URI,
            now=self._world.clock.now(),
            extra=dict(request.query) or None,
        )
        self.transactions = {**self.transactions, transaction.state: transaction}
        return Response(303, {"Location": url}, "", {STATE_COOKIE: transaction.state})


@dataclass(frozen=True)
class World:
    clock: Clock
    network: FakeNetwork
    provider: Provider

    @property
    def config(self) -> dict:
        return self.network.send(_get(f"{ISSUER}/.well-known/openid-configuration")).body

    @property
    def jwks(self) -> dict:
        return self.network.send(_get(f"{ISSUER}/jwks")).body

    def browser(self) -> Browser:
        return Browser(self.network)


def _get(url):
    return Request("GET", url)


def build_world(**provider_options) -> World:
    clock = Clock()
    network = FakeNetwork()
    provider = Provider(clock=clock, network=network, **provider_options)
    provider.register_client("app", [REDIRECT_URI])
    provider.add_user("alice", "alice@example.com", True, "alice-password", factors=("otp",))
    provider.add_user("mallory", "mallory@example.com", True, "mallory-password")
    return World(clock, network, provider)


@pytest.fixture
def world():
    return build_world()


@pytest.fixture
def app(world):
    client_app = StopAtCallback(world)
    world.network.mount(APP, client_app)
    return client_app


@pytest.fixture
def make_world():
    return build_world


@pytest.fixture
def make_app(world):
    def mount(client_id):
        client_app = StopAtCallback(world, client_id=client_id)
        world.network.mount(APP, client_app)
        return client_app

    return mount
