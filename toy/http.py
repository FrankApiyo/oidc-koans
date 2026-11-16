"""An in-memory network: apps mounted at origins, and a browser that keeps cookies per origin."""

from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit

MAX_REDIRECTS = 10
_REDIRECTS = frozenset({301, 302, 303, 307, 308})
_REDIRECTS_KEEPING_METHOD = frozenset({307, 308})


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        raise ValueError(f"not an absolute URL: {url!r}")
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}"


@dataclass(frozen=True)
class Request:
    method: str
    url: str
    form: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)

    @property
    def origin(self) -> str:
        return origin_of(self.url)

    @property
    def path(self) -> str:
        return urlsplit(self.url).path or "/"

    @property
    def query(self) -> dict[str, str]:
        return dict(parse_qsl(urlsplit(self.url).query, keep_blank_values=True))


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict = field(default_factory=dict)
    body: dict | str = ""
    set_cookies: dict = field(default_factory=dict)

    @property
    def location(self) -> str | None:
        return next((v for k, v in self.headers.items() if k.lower() == "location"), None)


App = Callable[[Request], Response]


def with_query(url: str, params: dict) -> str:
    """url with params appended to any query it already has."""
    separator = "&" if urlsplit(url).query else "?"
    return f"{url}{separator}{urlencode(params)}"


class FakeNetwork:
    def __init__(self):
        self._apps: dict[str, App] = {}

    def mount(self, origin: str, app: App) -> None:
        if urlsplit(origin).path not in ("", "/"):
            raise ValueError(f"mount at an origin, not a path: {origin!r}")
        self._apps = {**self._apps, origin_of(origin): app}

    def send(self, request: Request) -> Response:
        app = self._apps.get(request.origin)
        if app is None:
            raise LookupError(f"nothing is mounted at {request.origin}")
        return app(request)


class Browser:
    """Follows redirects and keeps a cookie jar per origin.

    A set_cookies value of None deletes that cookie. Cookies have no path,
    expiry or flags here: an origin's whole jar goes with each request to it.
    """

    def __init__(self, network: FakeNetwork):
        self._network = network
        self._jars: dict[str, dict] = {}
        self._history: tuple[Request, ...] = ()

    @property
    def history(self) -> tuple[Request, ...]:
        return self._history

    def cookies(self, origin: str) -> dict:
        return dict(self._jars.get(origin_of(origin), {}))

    def set_cookie(self, origin: str, name: str, value: str) -> None:
        """A cookie written into this jar from elsewhere, such as a sibling subdomain's page."""
        self._store_cookies(origin_of(origin), {name: value})

    def get(self, url: str) -> Response:
        return self._navigate("GET", url, {})

    def post(self, url: str, form: dict) -> Response:
        return self._navigate("POST", url, form)

    def _navigate(self, method: str, url: str, form: dict) -> Response:
        response = self._send(method, url, form)
        for _ in range(MAX_REDIRECTS):
            if response.status not in _REDIRECTS or response.location is None:
                return response
            if response.status not in _REDIRECTS_KEEPING_METHOD:
                method, form = "GET", {}
            url = urljoin(url, response.location)
            response = self._send(method, url, form)
        if response.status in _REDIRECTS and response.location is not None:
            raise RuntimeError(f"more than {MAX_REDIRECTS} redirects")
        return response

    def _send(self, method: str, url: str, form: dict) -> Response:
        request = Request(method, url, form=dict(form), cookies=self.cookies(url))
        self._history = (*self._history, request)
        response = self._network.send(request)
        self._store_cookies(request.origin, response.set_cookies)
        return response

    def _store_cookies(self, origin: str, set_cookies: dict) -> None:
        merged = {**self._jars.get(origin, {}), **set_cookies}
        kept = {name: value for name, value in merged.items() if value is not None}
        self._jars = {**self._jars, origin: kept}
