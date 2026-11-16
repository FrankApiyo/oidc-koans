"""The reference relying party.

The client binds each login to the browser that started it: the app that calls
start_login sets the STATE_COOKIE cookie to bind_state(cookie, state), and
finish_login refuses a callback unless its state equals the transaction's and
that cookie binds it. A browser may have several logins pending at once.
"""

import base64
import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from urllib.parse import quote_plus

from toy.errors import FlowError, InvalidToken, OAuthError
from toy.http import FakeNetwork, Request, with_query
from toy.id_token import check_acr, validate_id_token
from toy.jose import b64url_encode, constant_time_equal

__all__ = [
    "STATE_COOKIE", "Transaction", "account_key", "basic_authorization", "bind_state",
    "check_acr", "check_refreshed_id_token", "check_userinfo_subject", "discover",
    "exchange_code", "fetch_userinfo", "finish_login", "missing_essential_claims",
    "parse_challenge", "refresh", "release_state", "s256", "start_login", "validate_id_token",
    "verified_email",
]

STATE_COOKIE = "oidc_state"
STATE_SEPARATOR = "."
_REQUEST_PARAMS = frozenset({
    "response_type", "client_id", "redirect_uri", "scope", "state", "nonce",
    "code_challenge", "code_challenge_method",
})
_AUTH_PARAM = re.compile(r'\s*([A-Za-z0-9_.-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,"]+))\s*(?:,|$)')


@dataclass(frozen=True)
class Transaction:
    state: str
    nonce: str
    code_verifier: str
    redirect_uri: str
    started_at: int
    purpose: str = "login"


def start_login(
    *,
    issuer_config: dict,
    client_id: str,
    redirect_uri: str,
    now: int,
    scope: str = "openid email",
    extra: dict | None = None,
    purpose: str = "login",
    rng=secrets,
) -> tuple[str, Transaction]:
    """The authorization request URL, and the transaction to keep for this browser."""
    extra = dict(extra or {})
    clash = _REQUEST_PARAMS & extra.keys()
    if clash:
        raise ValueError(f"extra cannot set {sorted(clash)}")
    transaction = Transaction(
        state=rng.token_urlsafe(32),
        nonce=rng.token_urlsafe(32),
        code_verifier=rng.token_urlsafe(32),
        redirect_uri=redirect_uri,
        started_at=now,
        purpose=purpose,
    )
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": transaction.state,
        "nonce": transaction.nonce,
        "code_challenge": s256(transaction.code_verifier),
        "code_challenge_method": "S256",
        **{name: _param_text(value) for name, value in extra.items()},
    }
    return with_query(issuer_config["authorization_endpoint"], params), transaction


def finish_login(
    *,
    transaction: Transaction,
    callback: Request,
    issuer_config: dict,
    client_id: str,
    jwks: dict,
    network: FakeNetwork,
    now: int,
    client_secret: bytes | None = None,
    leeway: int = 0,
    max_age: int | None = None,
    required_acr: frozenset[str] | None = None,
    not_before: int | None = None,
    trusted_audiences: frozenset[str] = frozenset(),
) -> dict:
    """Check the callback, redeem the code, validate the ID token and match UserInfo.

    callback is the request the browser sent to the redirect URI, cookies included.
    Returns the UserInfo claims overlaid with the ID token claims.
    """
    params = callback.query
    _check_state(transaction, callback)
    _check_response_issuer(params, issuer_config)
    if "error" in params:
        raise OAuthError(params["error"], params.get("error_description", ""))
    if not params.get("code"):
        raise FlowError("missing_code")
    tokens = exchange_code(
        issuer_config=issuer_config, client_id=client_id, code=params["code"],
        redirect_uri=transaction.redirect_uri, code_verifier=transaction.code_verifier,
        network=network, client_secret=client_secret,
    )
    claims = validate_id_token(
        tokens["id_token"], issuer=issuer_config["issuer"], client_id=client_id, jwks=jwks,
        now=now, nonce=transaction.nonce, leeway=leeway, max_age=max_age,
        required_acr=required_acr, not_before=not_before, trusted_audiences=trusted_audiences,
    )
    userinfo = fetch_userinfo(
        issuer_config=issuer_config, access_token=tokens["access_token"], network=network
    )
    check_userinfo_subject(claims, userinfo)
    return {**userinfo, **claims}


def exchange_code(
    *,
    issuer_config: dict,
    client_id: str,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    network: FakeNetwork,
    client_secret: bytes | None = None,
) -> dict:
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    return _token_request(issuer_config, form, client_id, client_secret, network)


def refresh(
    *,
    issuer_config: dict,
    client_id: str,
    refresh_token: str,
    network: FakeNetwork,
    client_secret: bytes | None = None,
    scope: str | None = None,
) -> dict:
    form = {"grant_type": "refresh_token", "refresh_token": refresh_token}
    if scope is not None:
        form = {**form, "scope": scope}
    return _token_request(issuer_config, form, client_id, client_secret, network)


def fetch_userinfo(*, issuer_config: dict, access_token: str, network: FakeNetwork) -> dict:
    headers = {"Authorization": f"Bearer {access_token}"}
    response = network.send(Request("GET", issuer_config["userinfo_endpoint"], headers=headers))
    if response.status != 200:
        raise OAuthError("invalid_token", f"UserInfo answered {response.status}")
    return response.body


def check_userinfo_subject(id_claims: dict, userinfo: dict) -> None:
    """OIDC Core 5.3.2: UserInfo sub must exactly match the ID token's, or it is not used."""
    if not isinstance(userinfo.get("sub"), str) or userinfo["sub"] != id_claims["sub"]:
        raise InvalidToken("sub_mismatch", f"UserInfo sub {userinfo.get('sub')!r}")


def check_refreshed_id_token(original: dict, refreshed: dict) -> None:
    """OIDC Core 12.2: an ID token from a refresh is about the original sign-in.

    iss, sub and aud must equal the original's, compared as whole values. It
    SHOULD NOT carry a nonce; one that it carries must equal the original's. An
    auth_time it carries is the original sign-in's, so it must equal the original's.
    """
    same_as_original = (("iss", "wrong_issuer"), ("sub", "sub_mismatch"), ("aud", "wrong_audience"))
    for name, reason in same_as_original:
        if refreshed.get(name) != original.get(name):
            raise InvalidToken(reason, f"{name} {refreshed.get(name)!r} after a refresh")
    if "nonce" in refreshed and refreshed["nonce"] != original.get("nonce"):
        raise InvalidToken("nonce_mismatch", "a refreshed ID token's nonce must be the original's")
    if "auth_time" in refreshed and refreshed["auth_time"] != original.get("auth_time"):
        raise InvalidToken("auth_time_changed", "a refresh is not a new sign-in")


def missing_essential_claims(claims: dict, requested: dict) -> tuple[str, ...]:
    """The claims a claims request member marked essential that claims lacks, sorted.

    OIDC Core 5.5.1: the provider does not fail for them, so the client looks. A claim
    present with a null value is missing too.
    """
    return tuple(sorted(
        name for name, request in requested.items()
        if isinstance(request, dict) and request.get("essential") is True
        and claims.get(name) is None
    ))


def discover(*, issuer: str, network: FakeNetwork) -> dict:
    """Fetch the provider's configuration; its issuer must be exactly the one asked for."""
    url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    config = network.send(Request("GET", url)).body
    if config.get("issuer") != issuer:
        raise FlowError("issuer_mismatch", f"discovery names {config.get('issuer')!r}")
    return config


def account_key(claims: dict) -> tuple[str, str]:
    """The only stable account identifier OIDC Core 5.7 guarantees: (iss, sub)."""
    key = (claims.get("iss"), claims.get("sub"))
    if not all(isinstance(part, str) and part for part in key):
        raise InvalidToken("malformed", "iss and sub must be non-empty strings")
    return key


def verified_email(claims: dict) -> str | None:
    """The email the provider vouches for, or None.

    OIDC Core 5.1: email_verified is a boolean, so only JSON true counts, never
    "true" or 1. It says the address was the user's when it was verified, not
    that it still is, and it never makes the email an account key.
    """
    email = claims.get("email")
    if claims.get("email_verified") is not True or not isinstance(email, str) or not email:
        return None
    return email


def basic_authorization(client_id: str, secret: bytes) -> str:
    """client_secret_basic: each part is form-urlencoded before the Basic encoding."""
    pair = f"{quote_plus(client_id)}:{quote_plus(secret)}".encode("ascii")
    return "Basic " + base64.b64encode(pair).decode("ascii")


def parse_challenge(header: str) -> dict:
    """A WWW-Authenticate challenge as {"scheme": ..., param: value}; max_age as an int."""
    scheme, _, rest = header.strip().partition(" ")
    rest = rest.strip()
    params = {"scheme": scheme}
    position = 0
    while position < len(rest):
        match = _AUTH_PARAM.match(rest, position)
        if match is None:
            raise ValueError(f"not an auth-param list: {rest[position:]!r}")
        name, quoted, token = match.groups()
        value = re.sub(r"\\(.)", r"\1", quoted) if quoted is not None else token
        params = {**params, name: value}
        position = match.end()
    if "max_age" in params:
        params = {**params, "max_age": _non_negative_int(params["max_age"])}
    return params


def bind_state(cookie: str | None, state: str) -> str:
    """The STATE_COOKIE value once another login, with this state, starts in the browser."""
    if not state or STATE_SEPARATOR in state:
        raise ValueError(f"a state cannot be empty or hold {STATE_SEPARATOR!r}")
    return STATE_SEPARATOR.join((*_bound_states(cookie), state))


def release_state(cookie: str | None, state: str) -> str | None:
    """The STATE_COOKIE value once this login is over; None deletes the cookie."""
    kept = tuple(bound for bound in _bound_states(cookie) if bound != state)
    return STATE_SEPARATOR.join(kept) if kept else None


def s256(verifier: str) -> str:
    """The PKCE S256 code challenge: BASE64URL(SHA256(ASCII(verifier)))."""
    return b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())


def _check_state(transaction: Transaction, callback: Request) -> None:
    returned = callback.query.get("state")
    if not returned:
        raise FlowError("missing_state")
    bound = callback.cookies.get(STATE_COOKIE)
    expected = transaction.state
    if not all(isinstance(value, str) for value in (bound, expected)):
        raise FlowError("state_mismatch", "no state is bound to this browser")
    bound_here = any(_same(state, expected) for state in _bound_states(bound))
    if not (_same(returned, expected) and bound_here):
        raise FlowError("state_mismatch")


def _bound_states(cookie: str | None) -> tuple[str, ...]:
    return tuple(state for state in (cookie or "").split(STATE_SEPARATOR) if state)


def _check_response_issuer(params: dict, issuer_config: dict) -> None:
    """RFC 9207: the iss response parameter, required when the provider advertises it."""
    returned = params.get("iss")
    if returned is None and issuer_config.get("authorization_response_iss_parameter_supported"):
        raise FlowError("issuer_mismatch", "the response has no iss")
    if returned is not None and returned != issuer_config["issuer"]:
        raise FlowError("issuer_mismatch", f"iss {returned!r}")


def _token_request(issuer_config, form, client_id, client_secret, network) -> dict:
    if client_secret is None:
        form, headers = {**form, "client_id": client_id}, {}
    else:
        headers = {"Authorization": basic_authorization(client_id, client_secret)}
    response = network.send(
        Request("POST", issuer_config["token_endpoint"], form=form, headers=headers)
    )
    body = response.body if isinstance(response.body, dict) else {}
    if response.status != 200:
        raise OAuthError(body.get("error", "server_error"), body.get("error_description", ""))
    if str(body.get("token_type", "")).lower() != "bearer":
        raise OAuthError("unsupported_token_type", f"token_type {body.get('token_type')!r}")
    return body


def _same(a: str, b: str) -> bool:
    return constant_time_equal(a.encode("utf-8"), b.encode("utf-8"))


def _param_text(value) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def _non_negative_int(text: str) -> int:
    if not re.fullmatch(r"[0-9]+", text):
        raise ValueError(f"max_age must be a non-negative integer, not {text!r}")
    return int(text)
