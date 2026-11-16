import pytest

from toy.clock import Clock


def test_clock_fixture_is_a_fresh_toy_clock(clock):
    assert type(clock) is Clock
    assert clock.now() == 1_800_000_000


def test_clock_moves_only_when_advanced():
    clock = Clock(now=100)
    assert clock.now() == 100
    clock.advance(60)
    assert clock.now() == 160


@pytest.mark.parametrize("seconds", [1.5, "60", True])
def test_clock_counts_whole_seconds(seconds):
    clock = Clock()
    clock.advance(1)
    assert clock.now() == 1_800_000_001
    with pytest.raises(TypeError):
        clock.advance(seconds)
