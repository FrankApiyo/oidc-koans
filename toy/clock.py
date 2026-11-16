class Clock:
    """Integer seconds since the epoch. Nothing moves unless a koan advances it."""

    def __init__(self, now: int = 1_800_000_000):
        self._now = _whole_seconds(now)

    def now(self) -> int:
        return self._now

    def advance(self, seconds: int) -> None:
        self._now += _whole_seconds(seconds)


def _whole_seconds(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"the clock counts whole seconds, not {value!r}")
    return value
