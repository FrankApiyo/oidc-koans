"""Step-up at a client: a fresh sign-in by the same user, and grants spent once.

RFC 9470 defines how a resource asks for a stronger or more recent sign-in. Tying
the answer to the user who asked is the client's job: OIDC Core §5.7 makes iss and
sub, together, the only stable identifier for a user.
"""

import hmac
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from toy.client import Transaction
from toy.errors import InvalidToken
from toy.id_token import numeric_date


@dataclass(frozen=True)
class PendingStepUp:
    """A step-up a client started: its own login transaction, for one user, one session
    and one action with its parameters. It lapses at expires_at."""

    transaction: Transaction
    user_key: tuple[str, str]
    session_id: str
    action: str
    params: Mapping
    required_acr: frozenset[str]
    expires_at: int


@dataclass(frozen=True)
class StepUpGrant:
    """What a completed step-up allows: one action, with these parameters, for one user
    in one session, until expires_at."""

    user_key: tuple[str, str]
    session_id: str
    action: str
    params: Mapping
    acr: str
    expires_at: int


def check_same_user(claims: dict, user_key: tuple[str, str]) -> None:
    """The step-up's ID token names the signed-in user: the same iss and the same sub."""
    iss, sub = user_key
    if claims.get("iss") != iss:
        raise InvalidToken("wrong_issuer", f"iss {claims.get('iss')!r} is not the session's")
    if claims.get("sub") != sub:
        raise InvalidToken("sub_mismatch", f"sub {claims.get('sub')!r} is not the session's")


def check_step_up(claims: dict, pending: PendingStepUp, now: int, leeway: int = 0) -> None:
    """A valid ID token answers this step-up: the same user, with this step-up's own nonce,
    signed in after the step-up started, at one of the levels it requires, read from the
    token."""
    check_same_user(claims, pending.user_key)
    nonce = claims.get("nonce")
    if not isinstance(nonce, str) or not hmac.compare_digest(
        nonce.encode(), pending.transaction.nonce.encode()
    ):
        raise InvalidToken("nonce_mismatch", "the ID token answers another login")
    if "auth_time" not in claims:
        raise InvalidToken("auth_time_missing")
    auth_time = numeric_date(claims, "auth_time")
    if auth_time > now + leeway:
        raise InvalidToken("issued_in_future", f"auth_time {auth_time} at {now}")
    if auth_time < pending.transaction.started_at - leeway:
        raise InvalidToken("stale_auth_time", f"auth_time {auth_time} is before the step-up")
    acr = claims.get("acr")
    if not isinstance(acr, str) or acr not in pending.required_acr:
        raise InvalidToken("acr_not_met", f"acr {acr!r}")


def grant_refusal(
    grant: StepUpGrant, *, user_key: tuple, session_id: str, action: str, params, now: int
) -> str | None:
    """Why this grant cannot be spent on this request, or None when it can."""
    same_session = isinstance(session_id, str) and hmac.compare_digest(
        grant.session_id.encode(), session_id.encode()
    )
    if grant.user_key != user_key or not same_session:
        return "user"
    if grant.action != action or grant.params != params:
        return "action"
    if not now < grant.expires_at:
        return "expired"
    return None


def take_grant(
    grants: Mapping[str, StepUpGrant], grant_id: str,
    refusal: Callable[[StepUpGrant], str | None],
) -> tuple[StepUpGrant | None, str | None, dict]:
    """Check and remove a grant in one step: (grant, None, the grants without it).

    A grant that is not there gives (None, "grant", grants). One the request may not
    spend gives (None, refusal's reason, grants) and stays, so a wrong request cannot
    use up someone else's grant.
    """
    grant = grants.get(grant_id)
    if grant is None:
        return None, "grant", dict(grants)
    reason = refusal(grant)
    if reason is not None:
        return None, reason, dict(grants)
    return grant, None, {key: value for key, value in grants.items() if key != grant_id}
