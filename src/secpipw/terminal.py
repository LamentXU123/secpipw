from __future__ import annotations

from secpipw.severity import Severity

ANSI_RESET = "\033[0m"
ANSI_COLORS = {
    Severity.INFO: "36",
    Severity.LOW: "33",
    Severity.MEDIUM: "1;93",
    Severity.HIGH: "1;91",
}


def colorize(text: str, severity: Severity) -> str:
    code = ANSI_COLORS[severity]
    return f"\033[{code}m{text}{ANSI_RESET}"
