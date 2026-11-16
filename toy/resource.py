"""A toy API that demands an authentication level and recency, per RFC 9470.

It validates the token first, through introspection, and only then states its
requirements, so a caller without a working token learns nothing about them.
"""

from collections.abc import Callable

from toy.client_auth import header
from toy.clock import Clock
from toy.http import FakeNetwork, Request, Response

API = "https://api.example"
INSUFFICIENT = "insufficient_user_authentication"


class ResourceServer:
    def __init__(
        self,
        origin: str = API,
        *,
        network: FakeNetwork,
        clock: Clock,
        introspect: Callable[[str], dict],
        acr_values: tuple[str, ...] = (),
        max_age: int | None = None,
    ):
        """acr_values lists the accepted levels in order of preference; max_age is in seconds."""
        if max_age is not None and (isinstance(max_age, bool) or not isinstance(max_age, int)
                                    or max_age < 0):
            raise ValueError(f"max_age is a non-negative integer, not {max_age!r}")
        self._clock = clock
        self._introspect = introspect
        self._acr_values = tuple(acr_values)
        self._max_age = max_age
        network.mount(origin, self)

    def __call__(self, request: Request) -> Response:
        scheme, _, token = (header(request.headers, "Authorization") or "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            return _challenge("Bearer")
        report = self._introspect(token)
        if report.get("active") is not True:
            return _challenge(_bearer(error="invalid_token",
                                      error_description="The access token is not active"))
        shortfall = self._shortfall(report)
        if shortfall is not None:
            return _challenge(self._step_up_challenge(shortfall))
        return Response(200, {}, {"sub": report["sub"], "path": request.path})

    def _shortfall(self, report: dict) -> str | None:
        acr = report.get("acr")
        if self._acr_values and (not isinstance(acr, str) or acr not in self._acr_values):
            return "A different authentication level is required"
        auth_time = report.get("auth_time")
        if self._max_age is not None and (
            isinstance(auth_time, bool)
            or not isinstance(auth_time, int)
            or self._clock.now() - auth_time > self._max_age
        ):
            return "More recent authentication is required"
        return None

    def _step_up_challenge(self, description: str) -> str:
        requirements = {
            **({"acr_values": " ".join(self._acr_values)} if self._acr_values else {}),
            **({"max_age": str(self._max_age)} if self._max_age is not None else {}),
        }
        return _bearer(error=INSUFFICIENT, error_description=description, **requirements)


def _bearer(**params: str) -> str:
    """A Bearer challenge with quoted-string auth-params, as in RFC 9470 Figures 2 and 3."""
    return "Bearer " + ", ".join(f'{name}="{value}"' for name, value in params.items())


def _challenge(value: str) -> Response:
    return Response(401, {"WWW-Authenticate": value}, {"error": "unauthorized"})
