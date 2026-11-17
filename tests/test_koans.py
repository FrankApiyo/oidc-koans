"""Proves the koans are honest: every unsolved koan fails, every solution passes,
the two directories mirror each other, and both match source/.

Run from the repo root with: pytest tests/
"""

import ast
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import diagrams  # noqa: E402
import generate  # noqa: E402
import lessons  # noqa: E402


def run_suite(directory: str, tmp_path: Path) -> dict[tuple[str, str], str]:
    """Run pytest on a directory in a subprocess and return {(file, koan): outcome}."""
    report = tmp_path / f"{directory}.xml"
    subprocess.run(
        [
            sys.executable, "-m", "pytest", directory,
            "--maxfail=0", "--tb=no", "-q", "-p", "no:cacheprovider",
            f"--junitxml={report}",
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    outcomes = {}
    for case in ET.parse(report).getroot().iter("testcase"):
        key = (case.get("classname").split(".")[-1], case.get("name"))
        outcomes[key] = next((child.tag for child in case), "passed")
    return outcomes


@pytest.fixture(scope="session")
def koan_outcomes(tmp_path_factory):
    return run_suite("koans", tmp_path_factory.mktemp("koans"))


@pytest.fixture(scope="session")
def solution_outcomes(tmp_path_factory):
    return run_suite("solutions", tmp_path_factory.mktemp("solutions"))


def test_there_are_koans(koan_outcomes):
    assert len(koan_outcomes) > 180


def test_every_solution_passes(solution_outcomes):
    not_passing = {k: v for k, v in solution_outcomes.items() if v != "passed"}
    assert not_passing == {}


def test_every_unsolved_koan_fails_rather_than_errors_or_passes(koan_outcomes):
    wrong = {k: v for k, v in koan_outcomes.items() if v != "failure"}
    assert wrong == {}


def test_koans_and_solutions_mirror_each_other(koan_outcomes, solution_outcomes):
    assert set(koan_outcomes) == set(solution_outcomes)


def test_generated_files_match_source():
    stale = [
        path.relative_to(ROOT)
        for path, content in generate.generate(ROOT).items()
        if not path.exists() or path.read_text() != content
    ]
    assert stale == [], "run: python tools/generate.py"


def test_no_koan_compares_a_blank_with_not_equal():
    offenders = [
        f"{path.name}:{number}"
        for path in (ROOT / "source").glob("*_test.py")
        for number, line in enumerate(path.read_text().splitlines(), 1)
        if "_a(" in line and (" != " in line or " is not " in line)
    ]
    assert offenders == []


def test_every_block_is_closed():
    for path in (ROOT / "source").glob("*_test.py"):
        generate.render(path.read_text(), blank=True)


def test_every_file_with_a_block_has_an_implement_meditation():
    for path in (ROOT / "source").glob("*_test.py"):
        text = path.read_text()
        if generate.BLOCK_OPEN in text:
            assert "Implement " in text, path.name


def test_every_koan_has_a_meditation():
    missing = [
        f"{path.name}:{number}"
        for path in (ROOT / "source").glob("*_test.py")
        for number, (line, following) in enumerate(
            zip(path.read_text().splitlines(), path.read_text().splitlines()[1:]), 1
        )
        if line.startswith("def test_") and not following.strip().startswith('"""')
    ]
    assert missing == []


COURSE_CODE_DIRS = ("source", "toy", "tools")
REAL_CLOCK_CALLS = ("time.time(", "datetime.now(", "datetime.utcnow(", "time.monotonic(")
NETWORK_IMPORT = re.compile(r"^\s*(import|from)\s+(socket|requests|http\.client|urllib\.request)\b")
URL = re.compile(r"https?://[^\s)>\]\"'`,;]+")


def _course_files():
    return [
        path
        for name in COURSE_CODE_DIRS
        for path in sorted((ROOT / name).rglob("*.py"))
    ]


def _source_modules():
    return {
        path: ast.parse(path.read_text())
        for path in sorted((ROOT / "source").glob("*_test.py"))
    }


def test_no_course_file_reads_the_real_clock():
    offenders = [
        f"{path.relative_to(ROOT)}:{number}"
        for path in _course_files()
        for number, line in enumerate(path.read_text().splitlines(), 1)
        if any(call in line for call in REAL_CLOCK_CALLS)
    ]
    assert offenders == []


def test_no_course_file_imports_the_network():
    offenders = [
        f"{path.relative_to(ROOT)}:{number}"
        for path in _course_files()
        for number, line in enumerate(path.read_text().splitlines(), 1)
        if NETWORK_IMPORT.match(line)
    ]
    assert offenders == []


def test_read_more_links_are_verified():
    verified = set((ROOT / "tools" / "links.txt").read_text().split())
    unverified = [
        f"{path.name}: {url}"
        for path, module in _source_modules().items()
        for url in URL.findall((ast.get_docstring(module) or "").partition("Read more:")[2])
        if url.rstrip(".") not in verified
    ]
    assert unverified == []


def _read_more_count(lesson: str) -> int:
    _, marker, links = lesson.partition("Read more:")
    return len(URL.findall(links)) if marker else 0


def test_read_more_lists_two_to_four_links():
    wrong = {
        path.name: count
        for path, module in _source_modules().items()
        for lesson in [ast.get_docstring(module) or ""]
        for count in [_read_more_count(lesson)]
        if not 2 <= count <= 4
        and not (path.name.startswith("00_") and "Read more:" not in lesson)
    }
    assert wrong == {}


def test_lessons_are_short():
    too_long = [
        path.name
        for path, module in _source_modules().items()
        if len((ast.get_docstring(module) or "").splitlines()) > 30
    ]
    assert too_long == []


def test_security_koans_assert_both_halves():
    unpaired = [
        f"{path.name}: {node.name}"
        for path, module in _source_modules().items()
        for node in module.body
        if isinstance(node, ast.FunctionDef)
        and node.name.startswith("test_refuses_")
        and not any(
            other.name.startswith("test_accepts_")
            for other in module.body
            if isinstance(other, ast.FunctionDef)
        )
    ]
    assert unpaired == []


LESSONS = ROOT / "lessons"
REMOTE_REFERENCE = re.compile(r'(?:src|href)="([^"]*//[^"]*)"')
EXTERNAL_LOAD = re.compile(r"<script|<link|@import|url\((?!#)")


def test_lessons_page_is_current():
    page = (LESSONS / "index.html").read_text()
    assert page == lessons.build(ROOT), "run: python tools/lessons.py"


def test_lessons_pictures_are_current():
    stale = [
        name
        for name, text in diagrams.render().items()
        if not (LESSONS / "svg" / name).exists() or (LESSONS / "svg" / name).read_text() != text
    ]
    assert stale == [], "run: python tools/diagrams.py"


def test_every_svg_is_used():
    page = (LESSONS / "index.html").read_text()
    shown = set(re.findall(r'<img src="svg/([^"]+)"', page))
    on_disk = {path.name for path in (LESSONS / "svg").glob("*.svg")}
    assert (sorted(on_disk - shown), sorted(shown - on_disk)) == ([], [])


def test_lessons_page_works_offline():
    page = (LESSONS / "index.html").read_text()
    verified = set((ROOT / "tools" / "links.txt").read_text().split())
    remote = [
        ref
        for ref in REMOTE_REFERENCE.findall(page)
        if not (f'<a href="{ref}">' in page and ref in verified)
    ]
    assert remote == []
    assert EXTERNAL_LOAD.findall(page) == []


def test_lessons_svgs_work_offline():
    paths = sorted((LESSONS / "svg").glob("*.svg"))
    assert "url(#arrow-" in paths[0].read_text()
    loads = {
        path.name: found
        for path in paths
        for text in [path.read_text()]
        for found in [REMOTE_REFERENCE.findall(text) + EXTERNAL_LOAD.findall(text)]
        if found
    }
    assert loads == {}
