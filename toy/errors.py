REASONS = frozenset(
    {
        "malformed",
        "alg_not_allowed",
        "bad_signature",
        "unknown_kid",
        "wrong_issuer",
        "wrong_audience",
        "azp_mismatch",
        "expired",
        "not_yet_valid",
        "issued_in_future",
        "nonce_mismatch",
        "auth_time_missing",
        "stale_auth_time",
        "acr_not_met",
        "sub_mismatch",
        "wrong_typ",
        "auth_time_changed",
    }
)


class InvalidToken(Exception):
    """A token was refused. `reason` is one of REASONS."""

    def __init__(self, reason: str, detail: str = ""):
        if reason not in REASONS:
            raise ValueError(f"unknown InvalidToken reason: {reason!r}")
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


class OAuthError(Exception):
    """An error response from an OAuth or OIDC endpoint, such as invalid_grant."""

    def __init__(self, error: str, description: str = ""):
        super().__init__(f"{error}: {description}" if description else error)
        self.error = error
        self.description = description


FLOW_REASONS = frozenset({"missing_state", "state_mismatch", "issuer_mismatch", "missing_code"})


class FlowError(Exception):
    """A client refused a callback or a discovery document. `reason` is one of FLOW_REASONS."""

    def __init__(self, reason: str, detail: str = ""):
        if reason not in FLOW_REASONS:
            raise ValueError(f"unknown FlowError reason: {reason!r}")
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


FORBIDDEN_REASONS = frozenset({"grant", "user", "action", "expired", "csrf"})


class Forbidden(Exception):
    """A client refused to act on a request. `reason` is one of FORBIDDEN_REASONS."""

    def __init__(self, reason: str, detail: str = ""):
        if reason not in FORBIDDEN_REASONS:
            raise ValueError(f"unknown Forbidden reason: {reason!r}")
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail
