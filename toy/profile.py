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
    assurance_unasked: the assurance claim is sent even when nobody asked for acr.
    fixed_assurance: the assurance claim always holds this value, whatever the sign-in,
        such as the name of the flow that ran.
    amr_names: the name the provider reports for each toy method in amr; a method left
        out is not reported. Empty keeps the toy's names; None sends no amr at all.
    honours_acr_values: acr_values can make the provider ask for a stronger sign-in.
    auth_time_unasked: auth_time is sent with no max_age and no essential request for it.
    """

    assurance_claim: str
    acr_alone_reauthenticates: bool
    auth_time_when_max_age_zero: bool
    honours_prompt_login: bool
    honours_max_age: bool
    assurance_unasked: bool = False
    fixed_assurance: str | None = None
    amr_names: tuple[tuple[str, str], ...] | None = ()
    honours_acr_values: bool = True
    auth_time_unasked: bool = True


SPEC = Profile(
    assurance_claim="acr",
    acr_alone_reauthenticates=False,
    auth_time_when_max_age_zero=True,
    honours_prompt_login=True,
    honours_max_age=True,
)
