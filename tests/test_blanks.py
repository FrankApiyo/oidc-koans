"""Proves every blank fails as a blank, not only the first in its koan.

Each answer in source/ is blanked alone, with every other answer solved, and
the chapter is run. A value blank must fail the koan it sits in; no other
koan runs that line, so only that koan is run. A value blank in a helper
must fail the first koan that names the helper. A code block must fail the
koan whose meditation says "Implement <its function>". For both, every
earlier koan must still pass, so no koan needs a later one's answer.

Run from the repo root with: pytest tests/test_blanks.py
"""

import ast
import os
import re
import shutil
import subprocess
import sys
import tokenize
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import generate  # noqa: E402


@dataclass(frozen=True)
class Variant:
    chapter: str
    blank: str
    text: str
    must_fail: str | None
    must_pass: tuple[str, ...]


def _koans(tree: ast.Module) -> list[ast.FunctionDef]:
    return [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
    ]


def _enclosing_koan(tree: ast.Module, line: int) -> str | None:
    return next(
        (koan.name for koan in _koans(tree) if koan.lineno <= line <= koan.end_lineno), None
    )


def _innermost_function(tree: ast.Module, line: int) -> str | None:
    spans = [
        (node.end_lineno - node.lineno, node.name)
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.lineno <= line <= node.end_lineno
    ]
    return min(spans)[1] if spans else None


def _first_koan_naming(tree: ast.Module, function: str | None) -> int | None:
    return next(
        (
            n
            for n, koan in enumerate(_koans(tree))
            if any(isinstance(node, ast.Name) and node.id == function for node in ast.walk(koan))
        ),
        None,
    )


def _implementing_koan(tree: ast.Module, function: str | None) -> int | None:
    return next(
        (
            n
            for n, koan in enumerate(_koans(tree))
            if re.search(rf"\bImplement {function}\b", ast.get_docstring(koan) or "")
        ),
        None,
    )


def _variant(chapter: str, blank: str, text: str, koan: int | None) -> Variant:
    koans = [node.name for node in _koans(ast.parse(text))]
    if koan is None:
        return Variant(chapter, blank, text, None, ())
    return Variant(chapter, blank, text, koans[koan], tuple(koans[:koan]))


def _value_variants(chapter: str, text: str) -> list[Variant]:
    chunks = generate._split_answers(generate._render_blocks(text, blank=False))
    variants = []
    for index, (literal, answer) in enumerate(chunks):
        if not answer:
            continue
        line = "".join(lit + ans for lit, ans in chunks[:index]).count("\n")
        line += literal.count("\n") + 1
        blanked = "".join(
            lit + ("__" if i == index else ans) for i, (lit, ans) in enumerate(chunks)
        )
        tree = ast.parse(blanked)
        koan = _enclosing_koan(tree, line)
        if koan is None:
            helper = _innermost_function(tree, line)
            variants.append(
                _variant(chapter, f"value at line {line}", blanked, _first_koan_naming(tree, helper))
            )
        else:
            variants.append(Variant(chapter, f"value at line {line}", blanked, koan, ()))
    return variants


def _block_variants(chapter: str, text: str) -> list[Variant]:
    lines = text.splitlines(keepends=True)
    variants = []
    for start, opening in enumerate(lines):
        if opening.strip() != generate.BLOCK_OPEN:
            continue
        end = next(i for i in range(start, len(lines)) if lines[i].strip() == generate.BLOCK_CLOSE)
        indent = opening[: len(opening) - len(opening.lstrip())]
        blanked = generate.render(
            "".join(lines[:start] + [f"{indent}__()\n"] + lines[end + 1 :]), blank=False
        )
        tree = ast.parse(blanked)
        line = blanked.splitlines().index(f"{indent}__()") + 1
        function = _innermost_function(tree, line)
        variants.append(
            _variant(chapter, f"block in {function}", blanked, _implementing_koan(tree, function))
        )
    return variants


def _variants() -> list[Variant]:
    return [
        variant
        for path in sorted((ROOT / "source").glob("*_test.py"))
        for text in [path.read_text()]
        for variant in _block_variants(path.name, text) + _value_variants(path.name, text)
    ]


def _run(variants: list[Variant], directory: Path) -> dict[tuple[str, str], str]:
    """Run each variant's named koans in one pytest process; return {(module, koan): outcome}."""
    shutil.copy(ROOT / "conftest.py", directory / "conftest.py")
    (directory / "pytest.ini").write_text("[pytest]\n")
    node_ids = []
    for number, variant in enumerate(variants):
        module = f"v{number:04d}_test"
        (directory / f"{module}.py").write_text(variant.text)
        koans = (*variant.must_pass, variant.must_fail) if variant.must_fail else ()
        node_ids += [f"{module}.py::{koan}" for koan in koans]
    report = directory / "report.xml"
    finished = subprocess.run(
        [
            sys.executable, "-m", "pytest", *node_ids,
            "--import-mode=importlib", "-p", "no:cacheprovider", "-q", "--tb=no",
            f"--junitxml={report}",
        ],
        cwd=directory,
        env={**os.environ, "PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1",
             "PYTHONHASHSEED": "0"},
        capture_output=True,
        check=False,
        text=True,
    )
    assert report.exists(), finished.stdout[-2000:] + finished.stderr[-2000:]
    return {
        (case.get("classname").split(".")[-1], case.get("name")): next(
            (child.tag for child in case if child.tag != "system-out"), "passed"
        )
        for case in ET.parse(report).getroot().iter("testcase")
    }


@pytest.fixture(scope="module")
def variants() -> list[Variant]:
    return _variants()


def _names_called_blank(path: Path) -> int:
    with path.open("rb") as source:
        return sum(token.string == "__" for token in tokenize.tokenize(source.readline))


def test_there_is_one_variant_per_blank_in_koans(variants):
    in_koans = sum(
        _names_called_blank(path) - _names_called_blank(ROOT / "solutions" / path.name)
        for path in (ROOT / "koans").glob("*_test.py")
    )
    assert len(variants) == in_koans > 500


def test_every_blank_belongs_to_a_koan(variants):
    orphans = [f"{v.chapter}: {v.blank}" for v in variants if v.must_fail is None]
    assert orphans == []


def test_every_blank_fails_its_koan_alone(variants, tmp_path):
    outcomes = _run(variants, tmp_path)
    wrong = [
        f"{variant.chapter}: {variant.blank}: {koan} {outcome}"
        for number, variant in enumerate(variants)
        for koan, expected in [
            *((k, "passed") for k in variant.must_pass),
            (variant.must_fail, "failure"),
        ]
        for outcome in [outcomes.get((f"v{number:04d}_test", koan), "not run")]
        if outcome != expected
    ]
    assert wrong == []
