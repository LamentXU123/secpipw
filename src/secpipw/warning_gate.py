from __future__ import annotations

import sys
from typing import Callable, Iterable, Protocol, TextIO

from secpipw.severity import Severity


class WarningLike(Protocol):
    severity: Severity
    message: str


class GateDecision:
    __slots__ = ("allow_install", "exit_code")

    def __init__(self, allow_install: bool, exit_code: int) -> None:
        object.__setattr__(self, "allow_install", allow_install)
        object.__setattr__(self, "exit_code", exit_code)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("GateDecision is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("GateDecision is immutable")

    def __repr__(self) -> str:
        return (
            "GateDecision("
            f"allow_install={self.allow_install!r}, exit_code={self.exit_code!r})"
        )

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, GateDecision)
            and self.allow_install == other.allow_install
            and self.exit_code == other.exit_code
        )

    def __hash__(self) -> int:
        return hash((self.allow_install, self.exit_code))

    allow_install: bool
    exit_code: int


def enforce_warning_policy(
    warnings: Iterable[WarningLike],
    *,
    ignore_warning: bool,
    ignore_severity: Severity | None = None,
    sensitivity: Severity = Severity.LOW,
    stdin: TextIO | None = None,
    stderr: TextIO | None = None,
    is_tty: Callable[[], bool] | None = None,
) -> GateDecision:
    warning_list = filter_ignored_warnings(warnings, ignore_severity)
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
            _colorize(
                f"installation paused: {severity.label} severity warning detected.\n",
                severity,
            )
        )
        stderr.write(
            _colorize(
                "rerun with --spip-ignore-warning to continue anyway.\n",
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
                _colorize(
                    f"installation paused: {severity.label} severity warning requires confirmation.\n",
                    severity,
                )
            )
            stderr.write(
                _colorize(
                    "run interactively and answer y/n, or rerun with --spip-ignore-warning "
                    "to ignore this warning.\n",
                    severity,
                )
            )
            return GateDecision(allow_install=False, exit_code=2)

        stderr.write(
            _colorize(
                f"{severity.label} severity warning detected. continue install? enter y/n [y/N] "
                "(rerun with --spip-ignore-warning to ignore this warning): ",
                severity,
            )
        )
        stderr.flush()
        answer = stdin.readline().strip().lower()
        if answer not in {"y", "yes"}:
            stderr.write(_colorize("installation cancelled.\n", severity))
            return GateDecision(allow_install=False, exit_code=1)

    return GateDecision(allow_install=True, exit_code=0)


def filter_ignored_warnings(
    warnings: Iterable[WarningLike],
    ignore_severity: Severity | None,
) -> list[WarningLike]:
    if ignore_severity is None:
        return list(warnings)
    return [warning for warning in warnings if warning.severity > ignore_severity]


def severity_is_ignored(
    ignore_severity: Severity | None,
    severity: Severity,
) -> bool:
    return ignore_severity is not None and severity <= ignore_severity


def _default_is_tty() -> bool:
    return sys.stdin.isatty()


def _colorize(text: str, severity: Severity) -> str:
    from secpipw.terminal import colorize

    return colorize(text, severity)


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
