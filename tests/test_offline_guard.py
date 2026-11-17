"""Proves the socket guard in conftest.py keeps koans offline on every platform.

The probes run in a child pytest with a copy of conftest.py. A plugin loaded
before any fixture swaps in socket._fallback_socketpair, which is what
socket.socketpair is on Windows, so the guard is checked against it too.
"""

import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

WINDOWS_SOCKETPAIR = """\
import socket

calls = []


def windows_socketpair(*args, **kwargs):
    calls.append(args)
    return socket._fallback_socketpair(*args, **kwargs)


socket.socketpair = windows_socketpair
"""

PROBES = """\
import asyncio
import socket
import sys

import pytest

UNROUTABLE = ("192.0.2.1", 80)


def test_runs_an_event_loop():
    async def answer():
        return 42

    assert asyncio.run(answer()) == 42


def test_makes_a_socketpair():
    first, second = socket.socketpair()
    with first, second:
        first.sendall(b"ping")
        assert second.recv(4) == b"ping"
    simulated = sys.modules.get("windows_socketpair")
    assert simulated is None or simulated.calls


def test_refuses_an_outbound_connect():
    with socket.socket() as sock:
        sock.settimeout(0.5)
        with pytest.raises(RuntimeError, match="koans are offline"):
            sock.connect(UNROUTABLE)


def test_refuses_create_connection():
    with pytest.raises(RuntimeError, match="koans are offline"):
        socket.create_connection(UNROUTABLE, timeout=0.5)


def test_refuses_a_loopback_connect_outside_a_socketpair():
    with socket.socket() as listener, socket.socket() as sock:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        sock.settimeout(0.5)
        with pytest.raises(RuntimeError, match="koans are offline"):
            sock.connect(listener.getsockname())
"""


def _outcomes(directory: Path, *plugin: str) -> dict[str, str]:
    shutil.copy(ROOT / "conftest.py", directory / "conftest.py")
    (directory / "pytest.ini").write_text("[pytest]\n")
    (directory / "windows_socketpair.py").write_text(WINDOWS_SOCKETPAIR)
    (directory / "probe_test.py").write_text(PROBES)
    report = directory / "report.xml"
    subprocess.run(
        [
            sys.executable, "-m", "pytest", "probe_test.py", *plugin,
            "-p", "no:cacheprovider", "-q", "--tb=short", f"--junitxml={report}",
        ],
        cwd=directory,
        env={**os.environ, "PYTHONPATH": os.pathsep.join((str(directory), str(ROOT))),
             "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        check=False,
    )
    return {
        case.get("name"): next(
            (child.tag for child in case if child.tag not in ("system-out", "system-err")),
            "passed",
        )
        for case in ET.parse(report).getroot().iter("testcase")
    }


EVERY_PROBE = {
    "test_runs_an_event_loop": "passed",
    "test_makes_a_socketpair": "passed",
    "test_refuses_an_outbound_connect": "passed",
    "test_refuses_create_connection": "passed",
    "test_refuses_a_loopback_connect_outside_a_socketpair": "passed",
}


def test_the_guard_holds_with_this_platforms_socketpair(tmp_path):
    assert _outcomes(tmp_path) == EVERY_PROBE


def test_the_guard_holds_with_the_windows_socketpair(tmp_path):
    assert _outcomes(tmp_path, "-p", "windows_socketpair") == EVERY_PROBE
