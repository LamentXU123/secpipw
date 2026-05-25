from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Callable, Iterable, Protocol, TextIO

from secured_pip.severity import Severity
from secured_pip.terminal import colorize


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
    sensitivity: Severity = Severity.LOW,
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

    block_at = _block_threshold(sensitivity)
    prompt_at = _prompt_threshold(sensitivity)
    blocking_severities = [
        warning.severity for warning in warning_list if warning.severity >= block_at
    ]
    if blocking_severities:
        severity = max(blocking_severities)
        stderr.write(
            colorize(
                f"installation paused: {severity.label} severity warning detected.\n",
                severity,
            )
        )
        stderr.write(
            colorize(
                "rerun with --ignore-warning to continue anyway.\n",
                severity,
            )
        )
        return GateDecision(allow_install=False, exit_code=2)

    if prompt_at is not None:
        prompt_severities = [
            warning.severity
            for warning in warning_list
            if prompt_at <= warning.severity < block_at
        ]
    else:
        prompt_severities = []
    if prompt_severities:
        severity = max(prompt_severities)
        if not is_tty():
            stderr.write(
                colorize(
                    f"installation paused: {severity.label} severity warning requires confirmation.\n",
                    severity,
                )
            )
            stderr.write(
                colorize(
                    "run interactively and answer y/n, or rerun with --ignore-warning "
                    "to ignore this warning.\n",
                    severity,
                )
            )
            return GateDecision(allow_install=False, exit_code=2)

        stderr.write(
            colorize(
                f"{severity.label} severity warning detected. continue install? enter y/n [y/N] "
                "(rerun with --ignore-warning to ignore this warning): ",
                severity,
            )
        )
        stderr.flush()
        answer = stdin.readline().strip().lower()
        if answer not in {"y", "yes"}:
            stderr.write(colorize("installation cancelled.\n", severity))
            return GateDecision(allow_install=False, exit_code=1)

    return GateDecision(allow_install=True, exit_code=0)


def _default_is_tty() -> bool:
    return sys.stdin.isatty()


def _block_threshold(sensitivity: Severity) -> Severity:
    if sensitivity >= Severity.HIGH:
        return Severity.LOW
    if sensitivity >= Severity.MEDIUM:
        return Severity.MEDIUM
    return Severity.HIGH


def _prompt_threshold(sensitivity: Severity) -> Severity | None:
    if sensitivity >= Severity.HIGH:
        return None
    if sensitivity >= Severity.MEDIUM:
        return Severity.LOW
    return Severity.MEDIUM
