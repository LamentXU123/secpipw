from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable, TextIO

from secpipw.severity import Severity


@dataclass(frozen=True)
class OutputEvent:
    severity: Severity
    stream: str
    text: str


@dataclass(frozen=True)
class BridgeResult:
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
    if not text:
        return []
    return [
        OutputEvent(severity=Severity.INFO, stream=stream, text=line)
        for line in text.splitlines(keepends=True)
    ]
