from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from secpipw import __version__

if TYPE_CHECKING:
    from secpipw.severity import Severity

DEDICATED_TOOL_ENTRYPOINTS = {
    "pipx": "spipx",
    "poetry": "spoetry",
    "uv": "suv",
}
PIPX_FAST_PASSTHROUGH_COMMANDS = {
    "completions",
    "ensurepath",
    "environment",
    "help",
    "interpreter",
    "list",
    "runpip",
    "uninstall",
    "uninstall-all",
    "version",
}
PIPX_FAST_VALUE_OPTIONS = {"--default-python"}
POETRY_FAST_PASSTHROUGH_COMMANDS = {
    "about",
    "build",
    "cache",
    "check",
    "config",
    "env",
    "help",
    "init",
    "install",
    "lock",
    "new",
    "publish",
    "remove",
    "run",
    "search",
    "show",
    "update",
    "version",
}
POETRY_FAST_VALUE_OPTIONS = {"--directory", "-C", "--project", "-P"}
UV_FAST_TOP_LEVEL_COMMANDS = {
    "cache",
    "help",
    "python",
    "self",
    "venv",
    "version",
}
UV_FAST_NESTED_COMMANDS = {
    ("pip", "check"),
    ("pip", "freeze"),
    ("pip", "list"),
    ("pip", "show"),
    ("pip", "tree"),
}
UV_FAST_VALUE_OPTIONS = {
    "--allow-insecure-host",
    "--cache-dir",
    "--color",
    "--config-file",
    "--directory",
    "--project",
}


def run_pip(*args, **kwargs):
    from secpipw.pip_bridge import run_pip as impl

    return impl(*args, **kwargs)


def run_tool(*args, **kwargs):
    from secpipw.tool_bridge import run_tool as impl

    return impl(*args, **kwargs)


def preflight_pip_args_for_tool(*args, **kwargs):
    from secpipw.tool_bridge import preflight_pip_args_for_tool as impl

    return impl(*args, **kwargs)


def tool_command_requires_preflight(*args, **kwargs):
    from secpipw.tool_bridge import tool_command_requires_preflight as impl

    return impl(*args, **kwargs)


def resolve_install_plan(*args, **kwargs):
    from secpipw.install_plan import resolve_install_plan as impl

    return impl(*args, **kwargs)


def inspect_install_plan_artifacts(*args, **kwargs):
    from secpipw.tool_bridge import inspect_install_plan_artifacts as impl

    return impl(*args, **kwargs)


def refresh_all_caches(*args, **kwargs):
    from secpipw.cache_refresh import refresh_all_caches as impl

    return impl(*args, **kwargs)


def OfficialPyPIClient(*args, **kwargs):
    from secpipw.pypi_api import OfficialPyPIClient as client_class

    return client_class(*args, **kwargs)


def _allow_install_decision():
    from secpipw.warning_gate import GateDecision

    return GateDecision(allow_install=True, exit_code=0)


def run_install_checks(*args, **kwargs):
    from secpipw.install_checks import run_install_checks as impl

    return impl(*args, **kwargs)


def run_guarded_pip_install(*args, **kwargs):
    from secpipw.pip_guard import run_guarded_pip_install as impl

    return impl(*args, **kwargs)


class PthMonitor:
    @classmethod
    def from_install_args(cls, *args, **kwargs):
        from secpipw.pth_monitor import PthMonitor as monitor_class

        return monitor_class.from_install_args(*args, **kwargs)


def gate_suspicious_pth_alerts(*args, **kwargs):
    from secpipw.pth_monitor import gate_suspicious_pth_alerts as impl

    return impl(*args, **kwargs)


def handle_suspicious_pth_alerts(*args, **kwargs):
    from secpipw.pth_monitor import handle_suspicious_pth_alerts as impl

    return impl(*args, **kwargs)


def inspect_install_artifacts(*args, **kwargs):
    from secpipw.pth_monitor import inspect_install_artifacts as impl

    return impl(*args, **kwargs)


def inspect_package_artifact_history(*args, **kwargs):
    from secpipw.pth_monitor import inspect_package_artifact_history as impl

    return impl(*args, **kwargs)


def handle_package_artifact_history_alerts(*args, **kwargs):
    from secpipw.pth_monitor import handle_package_artifact_history_alerts as impl

    return impl(*args, **kwargs)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["refresh-cache"]:
        return _refresh_caches()
    if args[:1] and args[0] in DEDICATED_TOOL_ENTRYPOINTS:
        shortcut = DEDICATED_TOOL_ENTRYPOINTS[args[0]]
        sys.stderr.write(
            f"ERROR: spip {args[0]} is no longer supported; use {shortcut} instead.\n"
        )
        return 2
    if args[:1] == ["install"]:
        try:
            (
                pip_args,
                ignore_warning,
                debug,
                spip_status,
                sensitivity,
                ignore_severity,
            ) = _split_wrapper_args(args[1:])
        except ValueError as exc:
            sys.stderr.write(f"ERROR: {exc}\n")
            return 2
        if spip_status:
            sys.stderr.write(f"spip {__version__} guard enabled.\n")
        return _install_with_guard(
            pip_args,
            ignore_warning=ignore_warning,
            ignore_severity=ignore_severity,
            debug=debug,
            sensitivity=sensitivity,
        )
    return run_pip(args)


def pipx_main(argv: list[str] | None = None) -> int:
    return _tool_with_guard("pipx", list(sys.argv[1:] if argv is None else argv))


def poetry_main(argv: list[str] | None = None) -> int:
    return _tool_with_guard("poetry", list(sys.argv[1:] if argv is None else argv))


def uv_main(argv: list[str] | None = None) -> int:
    return _tool_with_guard("uv", list(sys.argv[1:] if argv is None else argv))


def _split_wrapper_args(
    args: list[str],
) -> tuple[list[str], bool, bool, bool, Severity, Severity | None]:
    return _split_guarded_args(args, stop_at_first_non_wrapper=False)


def _split_tool_wrapper_args(
    args: list[str],
) -> tuple[list[str], bool, bool, bool, Severity, Severity | None]:
    return _split_guarded_args(args, stop_at_first_non_wrapper=True)


def _split_guarded_args(
    args: list[str],
    *,
    stop_at_first_non_wrapper: bool,
) -> tuple[list[str], bool, bool, bool, Severity, Severity | None]:
    forwarded_args: list[str] = []
    ignore_warning = False
    ignore_severity: Severity | None = None
    debug = False
    spip_status = False
    sensitivity = _severity_low()

    i = 0
    while i < len(args):
        arg = args[i]
        if stop_at_first_non_wrapper and arg == "--":
            forwarded_args.extend(args[i + 1 :])
            break
        if arg == "--spip-ignore-warning":
            ignore_warning = True
            i += 1
            continue
        if arg == "--spip-ignore":
            if i + 1 >= len(args):
                raise ValueError("--spip-ignore requires low, medium, or high")
            ignore_severity = _parse_ignore_severity(args[i + 1])
            i += 2
            continue
        if arg.startswith("--spip-ignore="):
            ignore_severity = _parse_ignore_severity(arg.split("=", 1)[1])
            i += 1
            continue
        if arg == "--spip-debug":
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

        if stop_at_first_non_wrapper:
            forwarded_args.extend(args[i:])
            break
        forwarded_args.append(arg)
        i += 1

    return forwarded_args, ignore_warning, debug, spip_status, sensitivity, ignore_severity


def _parse_sensitivity(value: str) -> Severity:
    from secpipw.severity import Severity, parse_severity

    try:
        sensitivity = parse_severity(value)
    except ValueError as exc:
        raise ValueError("--sensitivity must be low, medium, or high") from exc
    if sensitivity not in {Severity.LOW, Severity.MEDIUM, Severity.HIGH}:
        raise ValueError("--sensitivity must be low, medium, or high")
    return sensitivity


def _parse_ignore_severity(value: str) -> Severity:
    from secpipw.severity import Severity, parse_severity

    try:
        severity = parse_severity(value)
    except ValueError as exc:
        raise ValueError("--spip-ignore must be low, medium, or high") from exc
    if severity not in {Severity.LOW, Severity.MEDIUM, Severity.HIGH}:
        raise ValueError("--spip-ignore must be low, medium, or high")
    return severity


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
    ignore_severity: Severity | None = None,
    debug: bool,
    sensitivity: Severity,
) -> int:
    monitor_required = not _severity_ignored(ignore_severity, _severity_medium())
    monitor = _create_pth_monitor(pip_args, debug=debug) if monitor_required else None
    if monitor_required and monitor is None:
        sys.stderr.write(
            "ERROR: spip could not initialize .pth monitoring for this install path.\n"
        )
        sys.stderr.write(
            "Refusing to continue because post-install .pth protection would be disabled.\n"
        )
        return 2
    resolved_plan = None

    def plan_hook(plan):
        nonlocal resolved_plan
        resolved_plan = plan
        return run_install_checks(
            plan,
            pip_args,
            ignore_warning=ignore_warning,
            ignore_severity=ignore_severity,
            sensitivity=sensitivity,
            debug=debug,
        )

    def artifact_hook(requirements):
        if _severity_ignored(ignore_severity, _severity_medium()):
            return _allow_install_decision()
        return gate_suspicious_pth_alerts(
            inspect_install_artifacts(requirements),
            ignore_warning=ignore_warning,
            ignore_severity=ignore_severity,
            sensitivity=sensitivity,
        )

    try:
        rc = run_guarded_pip_install(pip_args, plan_hook, artifact_hook)
    except Exception as exc:
        sys.stderr.write(f"ERROR: spip failed to run guarded pip install: {exc}\n")
        return 1
    if rc != 0:
        return rc
    if monitor is None:
        decision_exit_code = 0
    else:
        pth_alerts = monitor.inspect()
        if pth_alerts:
            decision = handle_suspicious_pth_alerts(
                pth_alerts,
                ignore_warning=ignore_warning,
                ignore_severity=ignore_severity,
            )
            if not decision.allow_install:
                return decision.exit_code
            decision_exit_code = decision.exit_code
        else:
            decision_exit_code = 0

    if resolved_plan is None or _severity_ignored(
        ignore_severity,
        _severity_medium(),
    ):
        return decision_exit_code
    history_alerts = inspect_package_artifact_history(
        resolved_plan.packages,
        getattr(monitor, "directories", ()),
        pip_args=pip_args,
    )
    if not history_alerts:
        return decision_exit_code
    history_decision = handle_package_artifact_history_alerts(
        history_alerts,
        ignore_warning=ignore_warning,
        ignore_severity=ignore_severity,
        sensitivity=sensitivity,
    )
    return history_decision.exit_code


def _tool_with_guard(tool: str, args: list[str]) -> int:
    if _tool_passthrough_fast_path(tool, args):
        return run_tool(tool, args)

    try:
        (
            tool_args,
            ignore_warning,
            debug,
            spip_status,
            sensitivity,
            ignore_severity,
        ) = _split_tool_wrapper_args(args)
    except ValueError as exc:
        sys.stderr.write(f"ERROR: {exc}\n")
        return 2

    if spip_status:
        sys.stderr.write(f"spip {__version__} guard enabled for {tool}.\n")

    pip_args = preflight_pip_args_for_tool(tool, tool_args)
    if pip_args is None:
        if tool_command_requires_preflight(tool, tool_args):
            sys.stderr.write(
                f"ERROR: spip could not derive a pip install plan for this {tool} "
                "command.\n"
            )
            sys.stderr.write(
                "Refusing to continue because supply-chain checks would be disabled.\n"
            )
            return 2
        return run_tool(tool, tool_args)

    decision = _preflight_external_install(
        tool,
        pip_args,
        tool_args,
        ignore_warning=ignore_warning,
        ignore_severity=ignore_severity,
        debug=debug,
        sensitivity=sensitivity,
    )
    if not decision.allow_install:
        return decision.exit_code
    return run_tool(tool, tool_args)


def _preflight_external_install(
    tool: str,
    pip_args: list[str],
    tool_args: list[str],
    *,
    ignore_warning: bool,
    ignore_severity: Severity | None,
    debug: bool,
    sensitivity: Severity,
):
    from secpipw.warning_gate import GateDecision

    try:
        plan = resolve_install_plan(pip_args)
    except Exception as exc:
        if _install_plan_error_has_returncode(exc):
            stderr = getattr(exc, "stderr", "")
            stdout = getattr(exc, "stdout", "")
            if stderr:
                sys.stderr.write(stderr)
            if stdout:
                sys.stdout.write(stdout)
            return GateDecision(allow_install=False, exit_code=exc.returncode)
        sys.stderr.write(
            f"ERROR: spip failed to resolve guarded install plan for {tool}: {exc}\n"
        )
        return GateDecision(allow_install=False, exit_code=1)

    decision = run_install_checks(
        plan,
        pip_args,
        ignore_warning=ignore_warning,
        ignore_severity=ignore_severity,
        sensitivity=sensitivity,
        debug=debug,
    )
    if not decision.allow_install:
        return decision

    if _severity_ignored(ignore_severity, _severity_medium()):
        return decision

    try:
        artifact_alerts = inspect_install_plan_artifacts(plan)
    except Exception as exc:
        sys.stderr.write(
            f"ERROR: spip failed to inspect resolved {tool} artifacts: {exc}\n"
        )
        return GateDecision(allow_install=False, exit_code=1)

    artifact_decision = gate_suspicious_pth_alerts(
        artifact_alerts,
        ignore_warning=ignore_warning,
        ignore_severity=ignore_severity,
        sensitivity=sensitivity,
    )
    if not artifact_decision.allow_install:
        return artifact_decision
    return artifact_decision


def _install_plan_error_has_returncode(exc: Exception) -> bool:
    return hasattr(exc, "returncode")


def _severity_ignored(
    ignore_severity: Severity | None,
    severity: Severity,
) -> bool:
    return ignore_severity is not None and severity <= ignore_severity


def _severity_low() -> Severity:
    from secpipw.severity import Severity

    return Severity.LOW


def _severity_medium() -> Severity:
    from secpipw.severity import Severity

    return Severity.MEDIUM


def _tool_passthrough_fast_path(tool: str, args: list[str]) -> bool:
    if _has_wrapper_options(args):
        return False
    if tool == "pipx":
        command = _first_non_option(args, value_options=PIPX_FAST_VALUE_OPTIONS)
        return command is None or command in PIPX_FAST_PASSTHROUGH_COMMANDS
    if tool == "poetry":
        command = _first_non_option(args, value_options=POETRY_FAST_VALUE_OPTIONS)
        return command is None or command in POETRY_FAST_PASSTHROUGH_COMMANDS
    if tool == "uv":
        return _uv_fast_passthrough(args)
    return False


def _has_wrapper_options(args: list[str]) -> bool:
    return any(
        arg.startswith("--spip-")
        or arg == "--sensitivity"
        or arg.startswith("--sensitivity=")
        for arg in args
    )


def _first_non_option(args: list[str], *, value_options: set[str]) -> str | None:
    found = _first_non_option_with_index(args, value_options=value_options)
    if found is None:
        return None
    return found[0]


def _first_non_option_with_index(
    args: list[str],
    *,
    value_options: set[str],
) -> tuple[str, int] | None:
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            return None
        if arg in value_options:
            i += 2
            continue
        if any(arg.startswith(f"{option}=") for option in value_options):
            i += 1
            continue
        if arg.startswith("-"):
            i += 1
            continue
        return arg, i
    return None


def _uv_fast_passthrough(args: list[str]) -> bool:
    found = _first_non_option_with_index(args, value_options=UV_FAST_VALUE_OPTIONS)
    if found is None:
        return True
    command, command_index = found
    if command in UV_FAST_TOP_LEVEL_COMMANDS:
        return True
    if command not in {"pip", "tool"}:
        return False

    nested = _first_non_option(
        args[command_index + 1 :],
        value_options=UV_FAST_VALUE_OPTIONS,
    )
    return nested is not None and (command, nested) in UV_FAST_NESTED_COMMANDS
