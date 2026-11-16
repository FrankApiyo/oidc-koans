"""Logout: RP-Initiated Logout 1.0 requests and Back-Channel Logout 1.0 Logout Tokens."""

from collections.abc import Callable, Mapping

from toy.errors import InvalidToken
from toy.http import with_query
from toy.id_token import DEFAULT_ALGS, _check_audience, _check_dates, _check_issuer
from toy.jose import jws_verify

LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


def logout_url(
    *,
    issuer_config: dict,
    id_token: str,
    client_id: str,
    post_logout_redirect_uri: str | None = None,
    state: str | None = None,
) -> str:
    """The RP-Initiated Logout request: id_token_hint, client_id and the optional rest."""
    optional = {"post_logout_redirect_uri": post_logout_redirect_uri, "state": state}
    params = {
        "id_token_hint": id_token,
        "client_id": client_id,
        **{name: value for name, value in optional.items() if value is not None},
    }
    return with_query(issuer_config["end_session_endpoint"], params)


def post_logout_target(
    params: Mapping[str, str],
    registered: Mapping[str, tuple[str, ...]],
    verify_own: Callable[[str], dict | None],
) -> str | None:
    """The post_logout_redirect_uri to redirect to, or None when there must be no redirect.

    The id_token_hint must be a token this provider signed. It was issued to its only
    audience or, with several, to its azp, which must be one of them. A client_id, when
    sent, must be that client. The target must exactly match one of that client's
    registered post_logout_redirect_uris. Without a hint this provider never redirects:
    it has no other means of confirming the target.
    """
    target = params.get("post_logout_redirect_uri")
    claims = verify_own(params.get("id_token_hint", ""))
    if target is None or claims is None:
        return None
    aud = claims.get("aud")
    audiences = [aud] if isinstance(aud, str) else aud if isinstance(aud, list) else []
    issued_to = audiences[0] if len(audiences) == 1 else claims.get("azp")
    if not isinstance(issued_to, str) or issued_to not in audiences:
        return None
    client_id = params.get("client_id", issued_to)
    if client_id != issued_to or target not in registered.get(client_id, ()):
        return None
    return target


def check_logout_claims(claims: dict) -> None:
    """Back-Channel Logout §2.6, after the checks a Logout Token shares with an ID token.

    sub, sid or both, each a non-empty string, else "malformed". An events object whose
    LOGOUT_EVENT member is an object, and no nonce, else "wrong_typ": not a Logout Token.
    """
    named = [claims[name] for name in ("sub", "sid") if name in claims]
    if not named or not all(isinstance(value, str) and value for value in named):
        raise InvalidToken("malformed", "a Logout Token names sub, sid or both")
    events = claims.get("events")
    if not isinstance(events, dict) or not isinstance(events.get(LOGOUT_EVENT), dict):
        raise InvalidToken("wrong_typ", "a Logout Token carries the back-channel logout event")
    if "nonce" in claims:
        raise InvalidToken("wrong_typ", "a Logout Token must not contain a nonce")


def validate_logout_token(
    token: str,
    *,
    issuer: str,
    client_id: str,
    jwks: dict,
    now: int,
    allowed_algs: frozenset[str] = DEFAULT_ALGS,
) -> dict:
    """The claims of a valid Logout Token, or InvalidToken (Back-Channel Logout §2.6)."""
    claims = jws_verify(token, jwks, allowed_algs)
    _check_issuer(claims, issuer)
    _check_audience(claims, client_id, frozenset())
    _check_dates(claims, now, 0)
    check_logout_claims(claims)
    return claims


def sessions_to_end(
    sessions: Mapping[str, tuple[str, str, str | None]], claims: dict
) -> frozenset[str]:
    """The ids of the RP sessions, each (iss, sub, sid), that valid Logout Token claims name.

    With a sid: that issuer's sessions with that sid, and that sub when one is given.
    Without: every session of the user that iss and sub name (Back-Channel Logout §2.4).
    """
    iss, sub = claims.get("iss"), claims.get("sub")

    def named(session: tuple[str, str, str | None]) -> bool:
        session_iss, session_sub, session_sid = session
        if session_iss != iss:
            return False
        if "sid" in claims:
            return session_sid == claims["sid"] and (sub is None or session_sub == sub)
        return session_sub == sub

    return frozenset(key for key, session in sessions.items() if named(session))
