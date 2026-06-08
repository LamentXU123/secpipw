from __future__ import annotations

import subprocess
import sys
from typing import TYPE_CHECKING, Iterable, TextIO

if TYPE_CHECKING:
    from secpipw.severity import Severity


class _FrozenRecord:
    __slots__ = ()
    _field_names: tuple[str, ...] = ()

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(f"{type(self).__name__} is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f"{type(self).__name__} is immutable")

    def __repr__(self) -> str:
        values = ", ".join(
            f"{name}={getattr(self, name)!r}" for name in self._field_names
        )
        return f"{type(self).__name__}({values})"

    def __eq__(self, other: object) -> bool:
        if type(self) is not type(other):
            return False
        return all(
            getattr(self, name) == getattr(other, name) for name in self._field_names
        )

    def __hash__(self) -> int:
        return hash(tuple(getattr(self, name) for name in self._field_names))


class OutputEvent(_FrozenRecord):
    __slots__ = ("severity", "stream", "text")
    _field_names = __slots__

    def __init__(self, severity: Severity, stream: str, text: str) -> None:
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "stream", stream)
        object.__setattr__(self, "text", text)

    severity: "Severity"
    stream: str
    text: str


class BridgeResult(_FrozenRecord):
    __slots__ = ("returncode", "events")
    _field_names = __slots__

    def __init__(self, returncode: int, events: tuple[OutputEvent, ...]) -> None:
        object.__setattr__(self, "returncode", returncode)
        object.__setattr__(self, "events", events)

    returncode: int
    events: tuple[OutputEvent, ...]


def run_pip(argv: list[str] | None = None) -> int:
    result = subprocess.run(build_pip_command(argv), check=False)
    return result.returncode


def build_pip_command(argv: list[str] | None = None) -> list[str]:
    return [sys.executable, "-m", "pip", *(argv or [])]


def collect_pip_output(argv: list[str] | None = None) -> BridgeResult:
    command = build_pip_command(argv)
    completed = subprocess.run(command, capture_output=True, text=True, check=False)

    events = []
    events.extend(_events_from_text("stdout", completed.stdout))
    events.extend(_events_from_text("stderr", completed.stderr))
    return BridgeResult(returncode=completed.returncode, events=tuple(events))


def replay_events(
    events: Iterable[OutputEvent],
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> None:
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr

    for event in events:
        target = stdout if event.stream == "stdout" else stderr
        target.write(event.text)


def _events_from_text(stream: str, text: str) -> list[OutputEvent]:
    from secpipw.severity import Severity

    if not text:
        return []
    return [
        OutputEvent(severity=Severity.INFO, stream=stream, text=line)
        for line in text.splitlines(keepends=True)
    ]
