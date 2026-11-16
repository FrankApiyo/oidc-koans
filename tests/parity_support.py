"""Shared parity helpers. Chapter files are not a package, so solutions load by path."""

import importlib.util
from functools import cache
from pathlib import Path

from toy.errors import InvalidToken

ROOT = Path(__file__).resolve().parent.parent
ID, OTHER = "https://id.example", "https://other-id.example"


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
