"""Pictures of flows: the code flow with state, nonce and PKCE, and step-up (RFC 9470)."""

from diagrams import (
    BLUE,
    FILL_BLUE,
    FILL_GREEN,
    FILL_ORANGE,
    FILL_RED,
    GREEN,
    INK,
    MUTED,
    ORANGE,
    PURPLE,
    RED,
    Svg,
)

STATE = ("state", BLUE)
NONCE = ("nonce", PURPLE)
VERIFIER = ("code_verifier", ORANGE)
CHALLENGE = ("code_challenge", ORANGE)
CODE = ("code", GREEN)


def _plain(text):
    return (text, INK)


def code_flow():
    browser, app, op = 110, 400, 690
    s = Svg(
        800,
        720,
        "The authorization code flow, showing where state, nonce, the PKCE verifier and challenge "
        "travel",
    )
    s.lifeline(browser, 30, 660, "alice's browser", "user agent")
    s.lifeline(app, 30, 660, "https://app.example", "client, client_id=app")
    s.lifeline(op, 30, 660, "https://id.example", "OpenID Provider")
    s.message(browser, app, 104, (_plain("GET /login"),))
    s.note(
        220,
        116,
        360,
        (
            (_plain("app makes a pending login and keeps it:"),),
            (STATE, _plain(", "), NONCE, _plain(", "), VERIFIER),
            (CHALLENGE, _plain(" = BASE64URL(SHA256(code_verifier))")),
        ),
    )
    s.message(app, browser, 196, (_plain("303  Set-Cookie: oidc_state="), STATE))
    s.spans(
        (browser + op) / 2,
        222,
        (_plain("GET /authorize?response_type=code&scope=openid"),),
        size=11,
        mono=True,
    )
    s.spans(
        (browser + op) / 2,
        236,
        (_plain("&client_id=app&redirect_uri=https://app.example/callback"),),
        size=11,
        mono=True,
    )
    s.message(
        browser,
        op,
        258,
        (
            _plain("&"),
            STATE,
            _plain("&"),
            NONCE,
            _plain("&"),
            CHALLENGE,
            _plain("&code_challenge_method=S256"),
        ),
    )
    s.note(
        440,
        272,
        350,
        (
            (_plain("alice signs in; the code remembers"),),
            (NONCE, _plain(", "), CHALLENGE, _plain(", client_id, redirect_uri")),
        ),
    )
    s.message(
        op, browser, 340, (_plain("303 to redirect_uri?"), CODE, _plain("&"), STATE, _plain("&iss"))
    )
    s.spans(
        (browser + app) / 2,
        366,
        (_plain("GET /callback?"), CODE, _plain("&"), STATE, _plain("&iss")),
        size=11,
        mono=True,
    )
    s.message(browser, app, 386, (_plain("Cookie: oidc_state="), STATE))
    s.note(
        220,
        398,
        360,
        (
            (_plain("the returned "), STATE, _plain(" is a pending login's,")),
            (_plain("bound to this browser by its cookie;"),),
            (_plain("iss is https://id.example"),),
        ),
    )
    s.spans((app + op) / 2, 462, (_plain("POST /token"),), size=11, mono=True)
    s.message(app, op, 482, (CODE, _plain(" redirect_uri "), VERIFIER))
    s.text((app + op) / 2, 498, "back channel: no browser", size=10, fill=MUTED)
    s.note(
        440,
        508,
        350,
        (
            (_plain("code unused, for app, unexpired,"),),
            (_plain("same redirect_uri, then"),),
            (_plain("S256("), VERIFIER, _plain(") == "), CHALLENGE),
        ),
    )
    s.spans((app + op) / 2, 582, (_plain("200  Cache-Control: no-store"),), size=11, mono=True)
    s.message(op, app, 602, (_plain("id_token{"), NONCE, _plain("} access_token")))
    s.note(
        220,
        614,
        360,
        (
            (_plain("validate the ID token; its "), NONCE),
            (_plain("must equal the pending login's "), NONCE),
        ),
    )
    s.spans(
        400,
        688,
        (
            STATE,
            _plain(" ties the callback to this browser.   "),
            NONCE,
            _plain(" ties the ID token to this login."),
        ),
        size=12,
    )
    s.spans(
        400,
        708,
        (
            ("PKCE", ORANGE),
            _plain(": only the client that holds "),
            VERIFIER,
            _plain(" can redeem the code."),
        ),
        size=12,
    )
    return s


def step_up():
    s = Svg(
        800,
        420,
        "Step-up: max_age=0 forces a fresh sign-in, whose auth_time must follow the step-up "
        "request, by the same iss and sub",
    )
    s.text(
        20,
        26,
        "Step-up: a fresh sign-in, by the same user, for one action",
        size=15,
        anchor="start",
        weight="bold",
    )
    s.rect(40, 104, 340, 32, fill=FILL_RED, stroke=RED, width=1)
    s.rect(380, 104, 290, 32, fill=FILL_GREEN, stroke=GREEN, width=1)
    s.line(40, 120, 770, 120, stroke=INK)
    s.text(772, 140, "time", size=11, anchor="end", fill=MUTED)
    events = (
        (90, "alice signs in", "pwd, an hour earlier", INK),
        (380, "step-up starts", "started_at", BLUE),
        (500, "she signs in again", "pwd + otp, 20 s later", GREEN),
        (640, "app checks", "the ID token", INK),
    )
    for x, first, second, color in events:
        s.circle(x, 120, 5, fill=color, stroke=color)
        s.text(x, 70, first, size=12, fill=color, weight="bold")
        s.text(x, 88, second, size=11, fill=MUTED, mono=second == "started_at")
    s.text(210, 156, "auth_time earlier: stale_auth_time", size=11, fill=RED)
    s.text(525, 156, "started_at - L <= auth_time <= now + L", size=11, mono=True, fill=GREEN)
    s.note(
        20,
        180,
        370,
        (
            (_plain("app sends a login of its own:"),),
            (_plain("GET https://id.example/authorize?"),),
            (_plain("  acr_values=urn:toy:acr:mfa"),),
            (_plain("  "), ("max_age=0", RED), _plain("  (= prompt=login)")),
            (_plain("  id_token_hint=<alice's ID token>"),),
            (_plain("  new "), STATE, _plain(", "), NONCE, _plain(", "), CHALLENGE),
        ),
        fill=FILL_BLUE,
    )
    s.note(
        410,
        180,
        370,
        (
            (_plain("app checks the step-up's ID token:"),),
            (
                _plain("1 "),
                ("iss", BLUE),
                _plain(" and "),
                ("sub", BLUE),
                _plain(" = the session's user"),
            ),
            (("  (https://id.example, alice), no other", MUTED),),
            (_plain("2 "), NONCE, _plain(" = this step-up's own")),
            (_plain("3 "), ("auth_time", GREEN), _plain(" in the green window")),
            (_plain("4 acr in {urn:toy:acr:mfa}, from the token"),),
        ),
        fill=FILL_GREEN,
    )
    s.text(
        20,
        314,
        'max_age=0 makes id.example sign alice in again: Core says it "is equivalent to '
        'prompt=login".',
        size=12,
        anchor="start",
    )
    s.text(
        20,
        334,
        "auth_time is compared with started_at, not with now: with max_age=0, now - auth_time <= "
        "max_age",
        size=12,
        anchor="start",
    )
    s.text(20, 350, "fails as soon as the clock moves past the leeway.", size=12, anchor="start")
    s.text(
        20,
        374,
        "The same user means the same iss and sub together (Core §5.7). That check is the app's; "
        "RFC 9470",
        size=12,
        anchor="start",
    )
    s.text(
        20,
        390,
        "does not make it. Passing all four buys a grant for one action, one user, one session, "
        "spent once.",
        size=12,
        anchor="start",
    )
    s.text(
        20,
        410,
        "Refused: an answer from the old session, another tab's login, or alice at "
        "https://other-id.example.",
        size=11,
        anchor="start",
        fill=RED,
    )
    return s


def step_up_challenge():
    app, api, op = 120, 420, 690
    s = Svg(
        800,
        600,
        "An API answers 401 with an RFC 9470 WWW-Authenticate challenge, and the client asks for "
        "that sign-in",
    )
    s.lifeline(app, 30, 530, "https://app.example", "client")
    s.lifeline(api, 30, 530, "https://api.example", "resource server")
    s.lifeline(op, 30, 530, "https://id.example", "OpenID Provider")
    s.spans((app + api) / 2, 104, (_plain("GET /statement"),), size=11, mono=True)
    s.message(app, api, 124, (_plain("Authorization: Bearer <access token>"),))
    s.note(
        290,
        136,
        490,
        (
            (_plain("checks the token first (introspection): active?"),),
            (_plain("then acr in {urn:toy:acr:mfa}? signed in within 60 s?"),),
            (("alice's token: acr urn:toy:acr:pwd, from 120 s ago", MUTED),),
        ),
    )
    s.message(api, app, 218, (("401 Unauthorized", RED),), stroke=RED)
    s.note(
        20,
        230,
        760,
        (
            (
                _plain("WWW-Authenticate: Bearer error="),
                ('"insufficient_user_authentication"', RED),
                _plain(","),
            ),
            (_plain('  error_description="A different authentication level is required",'),),
            (
                _plain("  acr_values="),
                ('"urn:toy:acr:mfa"', BLUE),
                _plain(", max_age="),
                ('"60"', BLUE),
            ),
        ),
        size=12,
        fill=FILL_ORANGE,
    )
    s.text(
        24,
        302,
        "one header line, folded here as RFC 9470 folds its examples",
        size=10,
        anchor="start",
        fill=MUTED,
    )
    s.note(
        20,
        314,
        380,
        (
            (_plain("parse_challenge reads acr_values"),),
            (_plain("and max_age, a non-negative int"),),
        ),
    )
    s.message(app, op, 392, (_plain("/authorize?…&acr_values=urn:toy:acr:mfa&max_age=60"),))
    s.text(
        (app + op) / 2,
        408,
        "through alice's browser, with a new state, nonce and code_challenge",
        size=10,
        fill=MUTED,
    )
    s.message(op, app, 446, (_plain("tokens: acr urn:toy:acr:mfa, a fresh auth_time"),))
    s.message(app, api, 486, (_plain("GET /statement  Bearer <new token>"),))
    s.message(api, app, 516, (("200 OK", GREEN),), stroke=GREEN)
    s.text(
        20,
        560,
        'A token that is not active gets only error="invalid_token", with no acr_values or '
        'max_age:',
        size=12,
        anchor="start",
    )
    s.text(
        20,
        578,
        'a challenge sent before checking the token "will leak the required properties" (RFC 9470 '
        '§9).',
        size=12,
        anchor="start",
    )
    return s
