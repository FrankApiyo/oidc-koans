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
