"""Pictures of the parties and the tokens: roles, JWS anatomy, the ID token checks, key rotation."""

import base64
import json

from diagrams import (
    BLUE,
    FILL_BLUE,
    FILL_GREEN,
    FILL_GREY,
    FILL_ORANGE,
    FILL_PURPLE,
    FILL_RED,
    FILL_YELLOW,
    GREEN,
    INK,
    MUTED,
    ORANGE,
    PURPLE,
    RED,
    Svg,
)


def roles():
    s = Svg(
        780,
        360,
        "The four OAuth roles, and the two tokens: the ID token for the client, the access token "
        "for an API",
    )
    s.box(
        20, 140, 170, 64, "alice", fill=FILL_BLUE, stroke=BLUE, sub="resource owner, in her browser"
    )
    s.box(
        290,
        30,
        210,
        64,
        "https://id.example",
        fill=FILL_GREEN,
        stroke=GREEN,
        sub="authorization server = OpenID Provider",
    )
    s.box(
        290,
        250,
        210,
        64,
        "https://app.example",
        fill=FILL_ORANGE,
        stroke=ORANGE,
        sub="client = Relying Party",
    )
    s.box(590, 250, 170, 64, "an API", fill=FILL_GREY, sub="resource server; UserInfo is one")
    s.line(150, 138, 286, 72, stroke=BLUE)
    s.text(200, 84, "1  she signs in at id.example", size=12, anchor="end", fill=BLUE)
    s.text(200, 100, "never at the client", size=11, anchor="end", fill=MUTED)
    s.line(150, 206, 286, 274, stroke=BLUE)
    s.text(228, 268, "2  back with a one-time code", size=12, anchor="end", fill=BLUE)
    s.line(395, 248, 395, 98, stroke=ORANGE)
    s.text(405, 160, "3  code in, tokens out", size=12, anchor="start", fill=ORANGE)
    s.text(405, 176, "client to server, no browser", size=11, anchor="start", fill=MUTED)
    s.line(502, 282, 586, 282, stroke=GREEN)
    s.text(545, 274, "4  Bearer", size=11, fill=GREEN)
    s.text(545, 302, "access token", size=10, fill=MUTED)
    s.text(525, 46, "OIDC = OAuth 2.0 + scope=openid", size=12, anchor="start", weight="bold")
    s.text(525, 70, "ID token: a signed JWT to the client", size=12, anchor="start")
    s.text(525, 86, "about who signed in. aud = the client.", size=12, anchor="start")
    s.text(525, 112, "Access token: for an API to accept.", size=12, anchor="start")
    s.text(525, 128, "Opaque to the client; not a login.", size=12, anchor="start")
    s.text(
        390,
        345,
        "Blue goes through the browser (front channel). Orange and green go from the client "
        "straight to a server.",
        size=11,
        fill=MUTED,
    )
    return s


def _b64url_json(value: dict) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


JWS_HEADER = {"alg": "RS256", "kid": "k1", "typ": "JWT"}
JWS_PAYLOAD = {
    "iss": "https://id.example",
    "sub": "alice",
    "aud": "app",
    "exp": 1700000600,
    "iat": 1700000000,
    "nonce": "n-0S6",
}


def _json_lines(value: dict) -> tuple[str, ...]:
    members = [f"  {json.dumps(k)}: {json.dumps(v)}" for k, v in value.items()]
    return ("{", *(f"{m}," for m in members[:-1]), members[-1], "}")


def jws_anatomy():
    s = Svg(
        780,
        350,
        "A JWS in compact form: header, payload and signature, each base64url, joined by dots",
    )
    columns = (
        (20, 230, _b64url_json(JWS_HEADER), BLUE, FILL_BLUE, "1  JOSE header"),
        (275, 290, _b64url_json(JWS_PAYLOAD), GREEN, FILL_GREEN, "2  payload: the claims"),
        (590, 170, "3sP1ZQ0yP7Uu", ORANGE, FILL_ORANGE, "3  signature"),
    )
    for x, w, encoded, color, fill, title in columns:
        s.rect(x, 30, w, 34, fill=fill, stroke=color)
        s.text(x + w / 2, 52, f"{encoded[:16]}…", size=12, mono=True, fill=color)
        s.line(x + w / 2, 66, x + w / 2, 96, stroke=MUTED)
        s.text(x + w / 2 + 6, 86, "base64url-decode", size=10, anchor="start", fill=MUTED)
        s.text(x + 4, 116, title, size=12, anchor="start", weight="bold", fill=color)
    s.text(262, 54, ".", size=22, weight="bold")
    s.text(578, 54, ".", size=22, weight="bold")
    s.rect(20, 124, 230, 112, fill=FILL_BLUE, stroke=BLUE)
    for row, text in enumerate(_json_lines(JWS_HEADER)):
        s.text(30, 144 + 17 * row, text, size=12, anchor="start", mono=True)
    s.rect(275, 124, 290, 140, fill=FILL_GREEN, stroke=GREEN)
    for row, text in enumerate(_json_lines(JWS_PAYLOAD)):
        s.text(285, 142 + 15 * row, text, size=11, anchor="start", mono=True)
    s.rect(590, 124, 170, 112, fill=FILL_ORANGE, stroke=ORANGE)
    for row, text in enumerate(
        ("raw bytes:", "RS256, 2048-bit", "  key: 256 bytes", "ES256: 64 bytes,", "  R then S")
    ):
        s.text(600, 144 + 19 * row, text, size=12, anchor="start", mono=row > 0)
    s.spans(
        390,
        292,
        (
            ("signing input = ", INK),
            ("BASE64URL(header)", BLUE),
            (" '.' ", INK),
            ("BASE64URL(payload)", GREEN),
            ("   the text as sent", MUTED),
        ),
        size=12,
        mono=True,
    )
    s.text(
        390, 316, "Signed, not encrypted: anyone can decode it. Decoding is not verifying.", size=12
    )
    s.text(
        390,
        336,
        "To verify, use only algs you chose, and a key you already trust, found by kid.",
        size=12,
        fill=MUTED,
    )
    return s


CHECKLIST = (
    ("three base64url segments of JSON", "malformed", 11),
    ("typ absent, JWT or application/jwt; no events claim", "wrong_typ", 11),
    ("alg is one you allow (RS256, ES256 here)", "alg_not_allowed", 11),
    ("kid names a key in the issuer's JWKS, of the alg's kty", "unknown_kid, alg_not_allowed", 11),
    ("the signature verifies with that key", "bad_signature", 11),
    ("sub is a non-empty string", "malformed", 11),
    ("iss equals the issuer, exactly", "wrong_issuer", 11),
    ("aud lists client_id; any other audience is trusted", "wrong_audience", 11),
    ("azp equals client_id (only under the azp extension)", "azp_mismatch", 11),
    (
        "exp, iat: iat - L <= now < exp + L; nbf - L <= now",
        "expired, issued_in_future, not_yet_valid",
        12,
    ),
    ("nonce equals the one sent, or neither has one", "nonce_mismatch", 12),
    (
        "auth_time: required by max_age; age <= max_age + L",
        "auth_time_missing, stale_auth_time",
        12,
    ),
    ("acr is in the set you accept, when you ask", "acr_not_met", 12),
)


def id_token_checklist():
    top = 66
    row_h = 30
    s = Svg(
        780,
        top + row_h * len(CHECKLIST) + 74,
        "The ID token checks in the order toy/client.py runs them, each with the reason it raises",
    )
    s.text(
        20, 26, "validate_id_token, in this course's order", size=15, anchor="start", weight="bold"
    )
    s.text(20, 46, "check", size=11, anchor="start", fill=MUTED)
    s.text(470, 46, "InvalidToken reason", size=11, anchor="start", fill=MUTED)
    for row, (check, reason, chapter) in enumerate(CHECKLIST):
        y = top + row_h * row
        color, fill = (BLUE, FILL_BLUE) if chapter == 11 else (PURPLE, FILL_PURPLE)
        s.rect(20, y, 440, row_h - 6, fill=fill, stroke=color, width=1)
        s.text(
            34,
            y + 17,
            f"{row + 1:>2}",
            size=12,
            anchor="middle",
            mono=True,
            fill=color,
            weight="bold",
        )
        s.text(52, y + 17, check, size=12, anchor="start")
        s.text(470, y + 17, reason, size=11, anchor="start", mono=True, fill=RED)
    s.spans(
        470,
        26,
        (("chapter 11", BLUE), ("   ", INK), ("chapter 12", PURPLE)),
        size=12,
        anchor="start",
        weight="bold",
    )
    bottom = top + row_h * len(CHECKLIST)
    s.text(
        20,
        bottom + 18,
        "L is the leeway, 0 unless stated. The first failing check names the reason,",
        size=12,
        anchor="start",
        fill=MUTED,
    )
    s.text(
        20,
        bottom + 36,
        "so a token with two defects always gets the same one. Checks 1, 3, 4 and 5 are",
        size=12,
        anchor="start",
        fill=MUTED,
    )
    s.text(
        20,
        bottom + 54,
        "jws_split and jws_verify; sub comes before iss.",
        size=12,
        anchor="start",
        fill=MUTED,
    )
    return s


PHASES = (
    ("before", ("k1",), "k1", "one key"),
    ("publish k2", ("k1", "k2"), "k1", "wait one cache lifetime"),
    ("switch", ("k1", "k2"), "k2", "k1 tokens still verify"),
    ("retire k1", ("k2",), "k2", "once k1 tokens expire"),
)


def _key_chip(s, x, y, kid, signing):
    color, fill = (GREEN, FILL_GREEN) if kid == "k2" else (BLUE, FILL_BLUE)
    s.rect(x, y, 44, 26, fill=fill, stroke=color, width=2.5 if signing else 1)
    s.text(
        x + 22, y + 18, kid, size=12, mono=True, fill=color, weight="bold" if signing else "normal"
    )


def key_rotation():
    s = Svg(
        780,
        420,
        "A provider rotates its signing key, and a client's cached copy of the key set follows",
    )
    s.text(20, 26, "id.example's jwks_uri, over time", size=14, anchor="start", weight="bold")
    for column, (title, published, signer, sub) in enumerate(PHASES):
        x = 20 + column * 190
        s.rect(x, 40, 170, 120, fill="none", stroke=MUTED, width=1)
        s.text(x + 85, 60, title, size=13, weight="bold")
        s.text(x + 10, 86, "keys", size=11, anchor="start", fill=MUTED)
        for slot, kid in enumerate(published):
            _key_chip(s, x + 50 + slot * 54, 70, kid, kid == signer)
        s.text(x + 10, 124, "signs with", size=11, anchor="start", fill=MUTED)
        _key_chip(s, x + 80, 108, signer, True)
        s.text(x + 85, 152, sub, size=11, fill=MUTED)
        if column < len(PHASES) - 1:
            s.line(x + 172, 100, x + 188, 100, stroke=INK)
    s.text(
        20,
        196,
        "app's copy of that set: one entry per issuer",
        size=14,
        anchor="start",
        weight="bold",
    )
    steps = (
        ("no copy, or one", "an hour old or more", "fetch jwks_uri", FILL_YELLOW, ORANGE),
        ("kid is in the copy", "(or names nothing)", "use the copy", FILL_GREEN, GREEN),
        ("unknown kid, last fetch", "60 s ago or more", "fetch once more", FILL_YELLOW, ORANGE),
        ("unknown kid, sooner", "than that", "unknown_kid", FILL_RED, RED),
    )
    for column, (first, second, outcome, fill, color) in enumerate(steps):
        x = 20 + column * 190
        s.rect(x, 210, 170, 50, fill="none", stroke=INK, width=1)
        s.text(x + 85, 230, first, size=12)
        s.text(x + 85, 248, second, size=12)
        s.line(x + 85, 262, x + 85, 282, stroke=MUTED)
        s.rect(x + 20, 284, 130, 30, fill=fill, stroke=color)
        s.text(
            x + 85, 304, outcome, size=12, mono=outcome == "unknown_kid", fill=color, weight="bold"
        )
    s.text(
        20,
        346,
        "Asked in this order. A fetched set replaces the copy, never merges with it, so a dropped "
        "key",
        size=12,
        anchor="start",
    )
    s.text(
        20,
        364,
        "stops working. The cooldown keeps made-up kids from making app flood id.example with "
        "fetches.",
        size=12,
        anchor="start",
    )
    s.text(
        20,
        392,
        "Keys come only from the issuer's jwks_uri, never from a jku, x5u or jwk in the token's "
        "header.",
        size=12,
        anchor="start",
        fill=RED,
    )
    s.text(
        20,
        410,
        "An hour and a minute are this course's numbers; the specs set neither.",
        size=11,
        anchor="start",
        fill=MUTED,
    )
    return s
