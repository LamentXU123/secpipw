from __future__ import annotations

import sys

from spip.cache_refresh import refresh_all_caches
from spip import __version__
from spip.install_plan import InstallPlanError, render_install_plan, resolve_install_plan
from spip.pip_bridge import run_pip
from spip.pth_monitor import PthMonitor, handle_suspicious_pth_alerts
from spip.pypi_api import OfficialPyPIClient, client_from_pip_args
from spip.release_checks import (
    detect_disposable_email_alerts,
    detect_recent_release_alerts,
    detect_zero_version_alerts,
    render_disposable_email_alerts,
    render_release_age_alerts,
    render_version_alerts,
)
from spip.typo import detect_typos_in_resolved_packages, render_alerts
from spip.warning_gate import enforce_warning_policy


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] in (["refresh-cache"], ["refresh-package-cache"]):
        return _refresh_caches()
    if args[:1] == ["install"]:
        sys.stderr.write(f"spip {__version__} guard enabled.\n")
        pip_args, ignore_warning, debug = _split_wrapper_args(args[1:])
        try:
            plan = resolve_install_plan(pip_args)
        except InstallPlanError as exc:
            if exc.stderr:
                sys.stderr.write(exc.stderr)
            if exc.stdout:
                sys.stdout.write(exc.stdout)
            sys.stderr.write(
                "spip could not resolve the install plan. try the original command with "
                f"`pip install {' '.join(pip_args)}`.\n"
            )
            return exc.returncode

        if debug:
            sys.stderr.write(render_install_plan(plan) + "\n")

        typo_alerts = detect_typos_in_resolved_packages(plan.packages)
        release_client = client_from_pip_args(pip_args)
        recent_release_alerts = detect_recent_release_alerts(
            plan.packages,
            client=release_client,
        )
        disposable_email_alerts = detect_disposable_email_alerts(
            plan.packages,
            client=release_client,
        )
        zero_version_alerts = detect_zero_version_alerts(plan.packages)
        all_alerts = [
            *typo_alerts,
            *recent_release_alerts,
            *disposable_email_alerts,
            *zero_version_alerts,
        ]

        if all_alerts:
            rendered = []
            if typo_alerts:
                rendered.append(render_alerts(typo_alerts))
            if recent_release_alerts:
                rendered.append(render_release_age_alerts(recent_release_alerts))
            if disposable_email_alerts:
                rendered.append(render_disposable_email_alerts(disposable_email_alerts))
            if zero_version_alerts:
                rendered.append(render_version_alerts(zero_version_alerts))
            sys.stderr.write("\n".join(rendered) + "\n")
            decision = enforce_warning_policy(
                all_alerts, ignore_warning=ignore_warning
            )
            if not decision.allow_install:
                return decision.exit_code
        return _install_resolved_plan(
            plan,
            pip_args,
            ignore_warning=ignore_warning,
            debug=debug,
        )
    return run_pip(args)


def _split_wrapper_args(args: list[str]) -> tuple[list[str], bool, bool]:
    pip_args: list[str] = []
    ignore_warning = False
    debug = False

    for arg in args:
        if arg == "--ignore-warning":
            ignore_warning = True
            continue
        if arg == "--debug":
            debug = True
            continue
        pip_args.append(arg)

    return pip_args, ignore_warning, debug


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


def _install_resolved_plan(
    plan,
    pip_args: list[str],
    *,
    ignore_warning: bool,
    debug: bool,
) -> int:
    monitor = _create_pth_monitor(pip_args, debug=debug)
    rc = run_pip(["install", *pip_args])
    if rc != 0:
        return rc
    if monitor is None:
        return 0
    decision = handle_suspicious_pth_alerts(
        monitor.inspect(),
        ignore_warning=ignore_warning,
    )
    return decision.exit_code
