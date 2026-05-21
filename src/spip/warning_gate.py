from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Callable, Iterable, Protocol, TextIO

from spip.severity import Severity
from spip.terminal import colorize


class WarningLike(Protocol):
    severity: Severity
    message: str


@dataclass(frozen=True)
class GateDecision:
    allow_install: bool
    exit_code: int


def enforce_warning_policy(
    warnings: Iterable[WarningLike],
    *,
    ignore_warning: bool,
    stdin: TextIO | None = None,
    stderr: TextIO | None = None,
    is_tty: Callable[[], bool] | None = None,
) -> GateDecision:
    warning_list = list(warnings)
    stdin = sys.stdin if stdin is None else stdin
    stderr = sys.stderr if stderr is None else stderr
    is_tty = _default_is_tty if is_tty is None else is_tty

    if not warning_list:
        return GateDecision(allow_install=True, exit_code=0)

    if ignore_warning:
        return GateDecision(allow_install=True, exit_code=0)

    if any(warning.severity >= Severity.HIGH for warning in warning_list):
        stderr.write(
            colorize(
                "installation paused: high severity warning detected.\n",
                Severity.HIGH,
            )
        )
        stderr.write(
            colorize(
                "rerun with --ignore-warning to continue anyway.\n",
                Severity.HIGH,
            )
        )
        return GateDecision(allow_install=False, exit_code=2)

    if any(warning.severity == Severity.MEDIUM for warning in warning_list):
        if not is_tty():
            stderr.write(
                colorize(
                    "installation paused: medium severity warning requires confirmation.\n",
                    Severity.MEDIUM,
                )
            )
            stderr.write(
                colorize(
                    "run interactively and answer y/n, or rerun with --ignore-warning.\n",
                    Severity.MEDIUM,
                )
            )
            return GateDecision(allow_install=False, exit_code=2)

        stderr.write(
            colorize(
                "medium severity warning detected. continue install? enter y/n [y/N]: ",
                Severity.MEDIUM,
            )
        )
        stderr.flush()
        answer = stdin.readline().strip().lower()
        if answer not in {"y", "yes"}:
            stderr.write(colorize("installation cancelled.\n", Severity.MEDIUM))
            return GateDecision(allow_install=False, exit_code=1)

    return GateDecision(allow_install=True, exit_code=0)


def _default_is_tty() -> bool:
    return sys.stdin.isatty()
