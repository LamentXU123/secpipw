from __future__ import annotations

from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name.lower()


def parse_severity(value: str) -> Severity:
    normalized = value.strip().lower()
    mapping = {
        "info": Severity.INFO,
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
    }
    try:
        return mapping[normalized]
    except KeyError as exc:
        raise ValueError(f"unknown severity: {value}") from exc
