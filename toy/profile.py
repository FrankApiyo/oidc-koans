"""How a provider reports and enforces authentication assurance."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    """A provider's behaviour where OIDC Core leaves room, or where real providers differ.

    assurance_claim: the ID token claim that carries the authentication level when it is
        requested: "acr", a custom claim name, or "amr" to report it through amr alone.
    acr_alone_reauthenticates: a request with acr_values forces a fresh sign-in even when
        the session already meets the level.
    auth_time_when_max_age_zero: the ID token keeps auth_time under max_age=0 without an
        essential auth_time request.
    honours_prompt_login / honours_max_age: the provider re-authenticates when asked.
    """

    assurance_claim: str
    acr_alone_reauthenticates: bool
    auth_time_when_max_age_zero: bool
    honours_prompt_login: bool
    honours_max_age: bool


SPEC = Profile(
    assurance_claim="acr",
    acr_alone_reauthenticates=False,
    auth_time_when_max_age_zero=True,
    honours_prompt_login=True,
    honours_max_age=True,
)
