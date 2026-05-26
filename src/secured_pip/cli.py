from __future__ import annotations

import sys

from secured_pip.cache_refresh import refresh_all_caches
from secured_pip import __version__
from secured_pip.severity import Severity, parse_severity
from secured_pip.install_checks import run_install_checks
from secured_pip.pip_bridge import run_pip
from secured_pip.pip_guard import run_guarded_pip_install
from secured_pip.pth_monitor import (
    PthMonitor,
    gate_suspicious_pth_alerts,
    handle_suspicious_pth_alerts,
    inspect_install_artifacts,
)
from secured_pip.pypi_api import OfficialPyPIClient


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["refresh-cache"]:
        return _refresh_caches()
    if args[:1] == ["install"]:
        try:
            pip_args, ignore_warning, debug, spip_status, sensitivity = (
                _split_wrapper_args(args[1:])
            )
        except ValueError as exc:
            sys.stderr.write(f"ERROR: {exc}\n")
            return 2
        if spip_status:
            sys.stderr.write(f"spip {__version__} guard enabled.\n")
        return _install_with_guard(
            pip_args,
            ignore_warning=ignore_warning,
            debug=debug,
            sensitivity=sensitivity,
        )
    return run_pip(args)


def _split_wrapper_args(
    args: list[str],
) -> tuple[list[str], bool, bool, bool, Severity]:
    pip_args: list[str] = []
    ignore_warning = False
    debug = False
    spip_status = False
    sensitivity = Severity.LOW

    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--ignore-warning":
            ignore_warning = True
            i += 1
            continue
        if arg == "--debug":
            debug = True
            i += 1
            continue
        if arg == "--spip-status":
            spip_status = True
            i += 1
            continue
        if arg == "--sensitivity":
            if i + 1 >= len(args):
                raise ValueError("--sensitivity requires low, medium, or high")
            sensitivity = _parse_sensitivity(args[i + 1])
            i += 2
            continue
        if arg.startswith("--sensitivity="):
            sensitivity = _parse_sensitivity(arg.split("=", 1)[1])
            i += 1
            continue
        pip_args.append(arg)
        i += 1

    return pip_args, ignore_warning, debug, spip_status, sensitivity


def _parse_sensitivity(value: str) -> Severity:
    try:
        sensitivity = parse_severity(value)
    except ValueError as exc:
        raise ValueError("--sensitivity must be low, medium, or high") from exc
    if sensitivity not in {Severity.LOW, Severity.MEDIUM, Severity.HIGH}:
        raise ValueError("--sensitivity must be low, medium, or high")
    return sensitivity


def _create_pth_monitor(pip_args: list[str], *, debug: bool) -> PthMonitor | None:
    try:
        return PthMonitor.from_install_args(pip_args)
    except Exception as exc:
        if debug:
            sys.stderr.write(f"[INFO] pth-monitor unavailable: {exc}\n")
        return None


def _refresh_caches() -> int:
    client = OfficialPyPIClient()
    try:
        results = refresh_all_caches(client)
    except Exception as exc:
        sys.stderr.write(f"failed to refresh caches: {exc}\n")
        return 1
    for result in results:
        sys.stdout.write(
            f"refreshed {result.description} with {result.count} entries at {result.location}\n"
        )
    return 0


def _install_with_guard(
    pip_args: list[str],
    *,
    ignore_warning: bool,
    debug: bool,
    sensitivity: Severity,
) -> int:
    monitor = _create_pth_monitor(pip_args, debug=debug)
    if monitor is None:
        sys.stderr.write(
            "ERROR: spip could not initialize .pth monitoring for this install path.\n"
        )
        sys.stderr.write(
            "Refusing to continue because post-install .pth protection would be disabled.\n"
        )
        return 2

    def plan_hook(plan):
        return run_install_checks(
            plan,
            pip_args,
            ignore_warning=ignore_warning,
            sensitivity=sensitivity,
            debug=debug,
        )

    def artifact_hook(requirements):
        return gate_suspicious_pth_alerts(
            inspect_install_artifacts(requirements),
            ignore_warning=ignore_warning,
            sensitivity=sensitivity,
        )

    try:
        rc = run_guarded_pip_install(pip_args, plan_hook, artifact_hook)
    except Exception as exc:
        sys.stderr.write(f"ERROR: spip failed to run guarded pip install: {exc}\n")
        return 1
    if rc != 0:
        return rc
    decision = handle_suspicious_pth_alerts(
        monitor.inspect(),
        ignore_warning=ignore_warning,
    )
    return decision.exit_code
