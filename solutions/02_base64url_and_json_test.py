"""Bytes, base64url and JSON.

Signatures and hashes work on bytes, never on text. Text becomes bytes
through an encoding, and JOSE encodes its JSON as UTF-8. "Zoë" is three
characters but four bytes.

A token travels in URLs and headers, so its bytes are written in base64url
(RFC 4648 §5), which is base64 with - and _ in place of + and /. RFC 7515 §2 also
drops the padding. Its Base64url Encoding has "all trailing '=' characters
omitted", and comes "without the inclusion of any line breaks, whitespace,
or other additional characters". A decoder puts the padding back, decodes,
and refuses anything else.

JSON (RFC 8259) has many spellings of one object. An object is "an
unordered collection" of members, and whitespace between tokens is
insignificant. Two equal dicts can serialize to different bytes, so a
signature covers the exact bytes that were sent, never an object you parsed
and wrote out again. Forms (RFC 6749 Appendix B) are a third encoding, where
a space becomes + and a + becomes %2B.

A common mistake: decoding with base64.urlsafe_b64decode alone. It refuses
unpadded text unless its length happens to be a multiple of 4, and once you
pad that text it also accepts + and /, spaces, and junk after the padding.

Read more:
  https://www.rfc-editor.org/rfc/rfc4648.html#section-5
  https://www.rfc-editor.org/rfc/rfc7515.html#section-2
  https://www.rfc-editor.org/rfc/rfc7515.html#appendix-C
  https://www.rfc-editor.org/rfc/rfc8259.html
"""

import base64
import json
import re
from urllib.parse import quote, urlencode

import pytest

from conftest import __
from toy.errors import InvalidToken
from toy.jose import b64url_encode, json_segment

BASE64URL_ALPHABET = re.compile(r"[A-Za-z0-9_-]*")


def test_text_is_not_bytes():
    """JOSE encodes text as UTF-8 before it does anything else. The ë takes two bytes."""
    name = "Zoë"
    assert len(name) == 3
    assert name.encode("utf-8") == b"Zo\xc3\xab"


def test_base64url_swaps_two_characters():
    """RFC 4648 §5: base64url writes - where base64 writes +, and _ where it writes /."""
    data = b"\xfb\xff"
    assert base64.b64encode(data) == b"+/8="
    assert b64url_encode(data) == "-_8"


def test_jose_drops_the_padding():
    """RFC 7515 §2 omits the trailing '=' characters. One byte becomes two characters, not four."""
    assert base64.b64encode(b"a") == b"YQ=="
    assert b64url_encode(b"a") == "YQ"


def test_thirty_two_bytes_make_forty_three_characters():
    """Every 3 bytes become 4 characters, and nothing pads the last group. You will meet this length again in PKCE."""
    assert len(b64url_encode(bytes(32))) == 43


def b64url_decode(text: str) -> bytes:
    if not isinstance(text, str) or not BASE64URL_ALPHABET.fullmatch(text) or len(text) % 4 == 1:
        raise InvalidToken("malformed", "not unpadded base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def test_accepts_unpadded_base64url():
    """Implement b64url_decode above. 1. Raise InvalidToken("malformed") if text is not a str, does not fullmatch BASE64URL_ALPHABET, or has len(text) % 4 == 1. 2. Add "=" * (-len(text) % 4) to the end. 3. Return base64.urlsafe_b64decode of the padded text."""
    samples = [bytes(range(length)) for length in range(6)] + [b"\xfb\xff"]
    assert [b64url_decode(b64url_encode(data)) for data in samples] == samples


def test_refuses_padding_whitespace_and_the_standard_alphabet():
    """Python's own decoder is lax once padding is added: it takes + and /, spaces and trailing junk. Yours refuses each of these, and says why."""
    assert base64.urlsafe_b64decode("+/8=") == b"\xfb\xff"
    assert base64.urlsafe_b64decode("Y Q==") == b"a"
    assert base64.urlsafe_b64decode("-_8=junk") == b"\xfb\xff"
    for text in ["YQ==", "+/8", "Y Q", "YQ\n", " YQ", "-_8=junk", "Y"]:
        with pytest.raises(InvalidToken) as refused:
            b64url_decode(text)
        assert refused.value.reason == "malformed"


def test_a_non_ascii_claim_round_trips_as_utf8():
    """json_segment writes compact UTF-8 JSON in base64url. Decode a segment with yours: the ë comes back as its two UTF-8 bytes."""
    segment = json_segment({"name": "Zoë"})
    raw = b64url_decode(segment)
    assert raw == b'{"name":"Zo\xc3\xab"}'
    assert json.loads(raw.decode("utf-8")) == {"name": "Zoë"}


def test_equal_objects_can_have_different_bytes():
    """RFC 8259: an object is "an unordered collection", and whitespace between tokens is insignificant. Equal dicts, different text."""
    spaced = json.dumps({"iss": "joe", "exp": 1})
    compact = json.dumps({"exp": 1, "iss": "joe"}, separators=(",", ":"))
    assert json.loads(spaced) == json.loads(compact)
    assert spaced == '{"iss": "joe", "exp": 1}'
    assert compact == '{"exp":1,"iss":"joe"}'


def test_json_dumps_escapes_non_ascii_by_default():
    """json.dumps writes ë as a \\u escape unless you pass ensure_ascii=False. One object, two spellings again."""
    assert json.dumps({"name": "Zoë"}) == '{"name": "Zo\\u00eb"}'
    assert json.dumps({"name": "Zoë"}, ensure_ascii=False) == '{"name": "Zoë"}'


def test_a_form_is_a_third_encoding():
    """RFC 6749 Appendix B: token requests are form-urlencoded, where a space is + and a + is %2B. In a URL path, quote writes a space as %20."""
    assert urlencode({"q": "a b+c"}) == "q=a+b%2Bc"
    assert quote("a b+c") == "a%20b%2Bc"
