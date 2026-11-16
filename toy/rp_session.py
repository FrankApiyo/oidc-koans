"""A client's own sessions, kept on its server and named by a cookie."""

from collections.abc import Mapping


def sign_in_session(
    sessions: Mapping[str, tuple], cookie: str | None, record: tuple, new_id: str
) -> tuple[str, dict]:
    """The session id to set, and the sessions after a sign-in, which is a privilege change.

    The signed-in record goes under new_id, a fresh id, and the session the browser
    brought, if any, is gone: an id known before the sign-in names nothing after it.
    """
    kept = {key: value for key, value in sessions.items() if key != cookie}
    return new_id, {**kept, new_id: record}
