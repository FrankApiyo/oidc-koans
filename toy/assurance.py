"""What a client concludes from amr and acr once an ID token is valid (OIDC Core §2)."""

from collections.abc import Mapping

from toy.errors import InvalidToken


def amr_includes(claims: dict, method: str) -> bool:
    """amr is a JSON array of case-sensitive strings, in no particular order, that lists method."""
    amr = claims.get("amr")
    return isinstance(amr, list) and all(isinstance(m, str) for m in amr) and method in amr


def check_level(
    claims: dict, policy: Mapping[str, Mapping[str, frozenset[str]]], level: str
) -> None:
    """acr must be one of the values the client agreed with this issuer to count as level.

    policy maps each issuer to the client's levels, and each level to the exact acr
    strings that meet it. An issuer or level the policy does not list meets nothing.
    """
    iss, acr = claims.get("iss"), claims.get("acr")
    levels = policy.get(iss, {}) if isinstance(iss, str) else {}
    if not isinstance(acr, str) or acr not in levels.get(level, frozenset()):
        raise InvalidToken("acr_not_met", f"acr {acr!r} from {iss!r} is not {level!r}")
