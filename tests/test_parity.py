"""Each chapter's solved function agrees with its toy/ counterpart, attack inputs included.

The solved functions are loaded from solutions/ by path, since chapter files
are not a package. Run from the repo root with: pytest tests/test_parity.py
"""

import importlib.util
from functools import cache
from pathlib import Path

import pytest

from toy import jose
from toy.errors import InvalidToken

ROOT = Path(__file__).resolve().parent.parent


@cache
def _solved(filename: str):
    path = ROOT / "solutions" / filename
    spec = importlib.util.spec_from_file_location(f"solved_{path.stem}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _outcome(function, *args):
    try:
        return ("value", function(*args))
    except InvalidToken as refused:
        return ("refused", refused.reason)


B64URL_TEXTS = [
    "", "YQ", "YR", "YWI", "YWJj", "-_8", "AAECAwQ",
    "YQ==", "YQ=", "+/8", "+/8=", "-_8=junk", "Y", "YWJjZ",
    "Y Q", " YQ", "YQ ", "YQ\n", "YQ\r\n", "YQ\t", "Zm9v.", "ë", None, b"YQ",
]


def test_b64url_texts_hold_both_honest_and_malformed_inputs():
    outcomes = {_outcome(jose.b64url_decode, text)[0] for text in B64URL_TEXTS}
    assert outcomes == {"value", "refused"}


@pytest.mark.parametrize("text", B64URL_TEXTS)
def test_chapter_02_b64url_decode_matches_toy(text):
    solved = _solved("02_base64url_and_json_test.py").b64url_decode
    assert _outcome(solved, text) == _outcome(jose.b64url_decode, text)
