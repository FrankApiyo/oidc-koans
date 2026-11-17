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


def meets(claims: dict, rules: Mapping[str, Mapping[str, tuple[str, frozenset[str]]]],
          level: str) -> bool:
    """Whether a valid ID token shows level, read the way the client agreed with its issuer.

    rules maps each issuer to the client's levels, and each level to the claim that
    issuer reports it in and the values that count. amr must be a list of strings that
    holds one of them; any other claim must be one of them. An issuer or level the rules
    do not list shows nothing.
    """
    iss = claims.get("iss")
    rule = rules.get(iss, {}).get(level) if isinstance(iss, str) else None
    if rule is None:
        return False
    claim, accepted = rule
    if claim == "amr":
        return any(amr_includes(claims, method) for method in accepted)
    value = claims.get(claim)
    return isinstance(value, str) and value in accepted
