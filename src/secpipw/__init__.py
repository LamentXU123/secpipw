__all__ = ["__version__", "Severity", "parse_severity"]

__version__ = "8.0"


def __getattr__(name: str):
    if name in {"Severity", "parse_severity"}:
        from secpipw.severity import Severity, parse_severity

        globals()["Severity"] = Severity
        globals()["parse_severity"] = parse_severity
        return globals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
