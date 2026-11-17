"""How a koan works.

Every file in koans/ is a list of tiny tests. Each has a blank, written __.
Replace the blank with whatever makes the assertion true, save, run again.
The runner stops at the first failure and prints the file and line to look
at, plus the koan's docstring, which we call the meditation.

There are two kinds of blank. A plain __ stands for a value: a number, a
string, a list. A __() on a line of its own stands for code you write. It
sits where a function body should be, and the meditation tells you what the
function must do, step by step. Until you replace it, calling that function
raises NotImplementedError and the footer points straight at it.

Each file starts with a lesson like this one. Read it once before the koans.
Between the lesson, the earlier chapters, and each meditation, you have
everything a koan needs.

This course is offline. Nothing here opens a socket or reads the real clock:
the provider lives in the toy/ package, and time is a clock you can advance.
Read toy/ whenever you like, but the koans never ask you to edit it.

The lessons page, lessons/index.html, gathers every chapter's lesson in one
place, with pictures where a picture helps. It opens in any browser, offline.
"""

from conftest import __


def test_a_koan_has_a_blank():
    """Replace __ with whatever makes the assertion true, save, run again."""
    assert 1 + 1 == _a(2)


def test_the_footer_tells_you_where_to_look():
    """The runner stops at the first failure and prints the file and line. Go there."""
    assert "koan".upper() == _a("KOAN")


def test_a_blank_equals_nothing():
    """An unfilled blank is never equal to anything, not even to another blank."""
    assert (__ == __) is _a(False)


def bearer_header(token):
    # >>> answer
    return f"Bearer {token}"
    # <<<


def test_a_called_blank_is_code_you_write():
    """Implement bearer_header above. 1. Replace the whole __() line with a return of the string "Bearer " followed by token."""
    assert bearer_header("abc123") == "Bearer abc123"


def test_you_can_always_start_over():
    """git checkout -- koans/ restores every blank. Repetition is the point."""
    assert len("__") == _a(2)
