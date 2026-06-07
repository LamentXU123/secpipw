from __future__ import annotations

import io
import unittest
from dataclasses import dataclass, field
from types import SimpleNamespace
from unittest.mock import patch

from secpipw import Severity
from secpipw import cli
from secpipw.install_plan import InstallPlan
from secpipw.pip_bridge import (
    OutputEvent,
    build_pip_command,
    collect_pip_output,
    replay_events,
)
from secpipw.warning_gate import GateDecision


class TtyInput(io.StringIO):
    def isatty(self) -> bool:
        return True


class FakeMonitor:
    def inspect(self):
        return []


@dataclass(frozen=True)
class FakePackage:
    name: str
    version: str
    requested: bool = False
    is_direct: bool = False
    download_url: str | None = None
    artifact_name: str | None = None
    requires_dist: tuple[str, ...] = ()
    metadata: dict = field(default_factory=dict)


def _plan(*packages: FakePackage) -> InstallPlan:
    return InstallPlan(packages=tuple(packages), raw_report={"install": []})


def _guarded_install_for(plan: InstallPlan, returncode: int = 0):
    def run_guarded(pip_args, plan_hook, artifact_hook=None):
        decision = plan_hook(plan)
        if not decision.allow_install:
            return decision.exit_code
        if artifact_hook is not None:
            artifact_decision = artifact_hook([])
            if not artifact_decision.allow_install:
                return artifact_decision.exit_code
        return returncode

    return run_guarded


class PipBridgeTests(unittest.TestCase):
    def test_collect_pip_output_wraps_lines_as_info(self) -> None:
        completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": "line one\nline two\n",
                "stderr": "warning\n",
            },
        )()

        with patch("secpipw.pip_bridge.subprocess.run", return_value=completed):
            result = collect_pip_output(["--version"])

        self.assertEqual(result.returncode, 0)
        self.assertEqual(
            [event.severity for event in result.events],
            [Severity.INFO, Severity.INFO, Severity.INFO],
        )
        self.assertEqual(
            [event.stream for event in result.events], ["stdout", "stdout", "stderr"]
        )
        self.assertEqual(
            [event.text for event in result.events],
            ["line one\n", "line two\n", "warning\n"],
        )

    def test_replay_events_writes_to_matching_streams(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        events = (
            OutputEvent(severity=Severity.INFO, stream="stdout", text="ok\n"),
            OutputEvent(severity=Severity.INFO, stream="stderr", text="warn\n"),
        )

        replay_events(events, stdout=stdout, stderr=stderr)

        self.assertEqual(stdout.getvalue(), "ok\n")
        self.assertEqual(stderr.getvalue(), "warn\n")

    def test_cli_forwards_to_bridge(self) -> None:
        with patch("secpipw.cli.run_pip", return_value=7) as run_pip:
            rc = cli.main(["--version"])

        self.assertEqual(rc, 7)
        run_pip.assert_called_once_with(["--version"])

    def test_cli_install_emits_typo_alerts_before_bridge(self) -> None:
        stderr = io.StringIO()
        plan = _plan(FakePackage(name="requsets", version="2.31.0", requested=True))
        alert = SimpleNamespace(
            severity=Severity.HIGH,
            message="'requsets' is similar to popular package 'requests'",
        )
        with patch("secpipw.cli._create_pth_monitor", return_value=FakeMonitor()):
            with patch(
                "secpipw.install_checks.detect_typos_in_resolved_packages",
                return_value=[alert],
            ):
                with patch(
                    "secpipw.install_checks.detect_recent_release_alerts",
                    return_value=[],
                ):
                    with patch(
                        "secpipw.install_checks.detect_empty_description_alerts",
                        return_value=[],
                    ):
                        with patch(
                            "secpipw.cli.run_guarded_pip_install",
                            side_effect=_guarded_install_for(plan),
                        ) as guarded:
                            with patch("sys.stderr", stderr):
                                rc = cli.main(["install", "requsets==2.31.0"])

        self.assertEqual(rc, 2)
        self.assertIn("[HIGH] typo-suspect:", stderr.getvalue())
        self.assertIn("rerun with --spip-ignore-warning", stderr.getvalue())
        self.assertIn("\x1b[", stderr.getvalue())
        guarded.assert_called_once()

    def test_cli_install_high_warning_can_be_ignored(self) -> None:
        stderr = io.StringIO()
        plan = _plan(FakePackage(name="requsets", version="2.31.0", requested=True))
        alert = SimpleNamespace(
            severity=Severity.HIGH,
            message="'requsets' is similar to popular package 'requests'",
        )
        with patch("secpipw.cli._create_pth_monitor", return_value=FakeMonitor()):
            with patch(
                "secpipw.install_checks.detect_typos_in_resolved_packages",
                return_value=[alert],
            ):
                with patch(
                    "secpipw.install_checks.detect_recent_release_alerts",
                    return_value=[],
                ):
                    with patch(
                        "secpipw.install_checks.detect_empty_description_alerts",
                        return_value=[],
                    ):
                        with patch(
                            "secpipw.cli.run_guarded_pip_install",
                            side_effect=_guarded_install_for(plan),
                        ) as guarded:
                            with patch("sys.stderr", stderr):
                                rc = cli.main(
                                    ["install", "requsets==2.31.0", "--spip-ignore-warning"]
                                )

        self.assertEqual(rc, 0)
        self.assertIn("[HIGH] typo-suspect:", stderr.getvalue())
        self.assertIn("\x1b[", stderr.getvalue())
        guarded.assert_called_once()

    def test_cli_install_medium_warning_prompts_and_continues_on_yes(self) -> None:
        stderr = io.StringIO()
        stdin = TtyInput("y\n")
        plan = _plan(FakePackage(name="reqeusts", version="2.31.0", requested=True))
        alert = SimpleNamespace(
            severity=Severity.MEDIUM,
            message="'reqeusts' is similar to popular package 'requests'",
        )
        with patch("secpipw.cli._create_pth_monitor", return_value=FakeMonitor()):
            with patch(
                "secpipw.install_checks.detect_typos_in_resolved_packages",
                return_value=[alert],
            ):
                with patch(
                    "secpipw.install_checks.detect_recent_release_alerts",
                    return_value=[],
                ):
                    with patch(
                        "secpipw.install_checks.detect_empty_description_alerts",
                        return_value=[],
                    ):
                        with patch(
                            "secpipw.cli.run_guarded_pip_install",
                            side_effect=_guarded_install_for(plan),
                        ) as guarded:
                            with patch("sys.stderr", stderr), patch("sys.stdin", stdin):
                                rc = cli.main(["install", "reqeusts==2.31.0"])

        self.assertEqual(rc, 0)
        self.assertIn(
            "continue install? enter y/n [y/N] "
            "(rerun with --spip-ignore-warning to ignore this warning):",
            stderr.getvalue(),
        )
        self.assertIn("\x1b[", stderr.getvalue())
        guarded.assert_called_once()

    def test_cli_install_medium_warning_cancels_on_no(self) -> None:
        stderr = io.StringIO()
        stdin = TtyInput("n\n")
        plan = _plan(FakePackage(name="reqeusts", version="2.31.0", requested=True))
        alert = SimpleNamespace(
            severity=Severity.MEDIUM,
            message="'reqeusts' is similar to popular package 'requests'",
        )
        with patch("secpipw.cli._create_pth_monitor", return_value=FakeMonitor()):
            with patch(
                "secpipw.install_checks.detect_typos_in_resolved_packages",
                return_value=[alert],
            ):
                with patch(
                    "secpipw.install_checks.detect_recent_release_alerts",
                    return_value=[],
                ):
                    with patch(
                        "secpipw.install_checks.detect_empty_description_alerts",
                        return_value=[],
                    ):
                        with patch(
                            "secpipw.cli.run_guarded_pip_install",
                            side_effect=_guarded_install_for(plan),
                        ) as guarded:
                            with patch("sys.stderr", stderr), patch("sys.stdin", stdin):
                                rc = cli.main(["install", "reqeusts==2.31.0"])

        self.assertEqual(rc, 1)
        self.assertIn("installation cancelled.", stderr.getvalue())
        guarded.assert_called_once()

    def test_cli_install_medium_warning_blocks_when_not_interactive(self) -> None:
        stderr = io.StringIO()
        stdin = io.StringIO("y\n")
        plan = _plan(FakePackage(name="reqeusts", version="2.31.0", requested=True))
        alert = SimpleNamespace(
            severity=Severity.MEDIUM,
            message="'reqeusts' is similar to popular package 'requests'",
        )
        with patch("secpipw.cli._create_pth_monitor", return_value=FakeMonitor()):
            with patch(
                "secpipw.install_checks.detect_typos_in_resolved_packages",
                return_value=[alert],
            ):
                with patch(
                    "secpipw.install_checks.detect_recent_release_alerts",
                    return_value=[],
                ):
                    with patch(
                        "secpipw.install_checks.detect_empty_description_alerts",
                        return_value=[],
                    ):
                        with patch(
                            "secpipw.cli.run_guarded_pip_install",
                            side_effect=_guarded_install_for(plan),
                        ) as guarded:
                            with patch("sys.stderr", stderr), patch("sys.stdin", stdin):
                                rc = cli.main(["install", "reqeusts==2.31.0"])

        self.assertEqual(rc, 2)
        self.assertIn("run interactively and answer y/n", stderr.getvalue())
        guarded.assert_called_once()

    def test_cli_install_medium_sensitivity_blocks_medium_warning(self) -> None:
        stderr = io.StringIO()
        plan = _plan(FakePackage(name="reqeusts", version="2.31.0", requested=True))
        alert = SimpleNamespace(
            severity=Severity.MEDIUM,
            message="'reqeusts' is similar to popular package 'requests'",
        )
        with patch("secpipw.cli._create_pth_monitor", return_value=FakeMonitor()):
            with patch(
                "secpipw.install_checks.detect_typos_in_resolved_packages",
                return_value=[alert],
            ):
                with patch(
                    "secpipw.install_checks.detect_recent_release_alerts",
                    return_value=[],
                ):
                    with patch(
                        "secpipw.install_checks.detect_empty_description_alerts",
                        return_value=[],
                    ):
                        with patch(
                            "secpipw.cli.run_guarded_pip_install",
                            side_effect=_guarded_install_for(plan),
                        ) as guarded:
                            with patch("sys.stderr", stderr):
                                rc = cli.main(
                                    [
                                        "install",
                                        "reqeusts==2.31.0",
                                        "--sensitivity",
                                        "medium",
                                    ]
                                )

        self.assertEqual(rc, 2)
        self.assertIn("medium severity warning detected", stderr.getvalue())
        guarded.assert_called_once()

    def test_cli_install_medium_warning_can_be_ignored_without_prompt(self) -> None:
        stderr = io.StringIO()
        plan = _plan(FakePackage(name="reqeusts", version="2.31.0", requested=True))
        alert = SimpleNamespace(
            severity=Severity.MEDIUM,
            message="'reqeusts' is similar to popular package 'requests'",
        )
        with patch("secpipw.cli._create_pth_monitor", return_value=FakeMonitor()):
            with patch(
                "secpipw.install_checks.detect_typos_in_resolved_packages",
                return_value=[alert],
            ):
                with patch(
                    "secpipw.install_checks.detect_recent_release_alerts",
                    return_value=[],
                ):
                    with patch(
                        "secpipw.install_checks.detect_empty_description_alerts",
                        return_value=[],
                    ):
                        with patch(
                            "secpipw.cli.run_guarded_pip_install",
                            side_effect=_guarded_install_for(plan),
                        ) as guarded:
                            with patch("sys.stderr", stderr):
                                rc = cli.main(
                                    ["install", "reqeusts==2.31.0", "--spip-ignore-warning"]
                                )

        self.assertEqual(rc, 0)
        guarded.assert_called_once()

    def test_cli_install_ignore_severity_suppresses_matching_warning(self) -> None:
        stderr = io.StringIO()
        plan = _plan(FakePackage(name="reqeusts", version="2.31.0", requested=True))
        alert = SimpleNamespace(
            severity=Severity.MEDIUM,
            message="'reqeusts' is similar to popular package 'requests'",
        )
        with patch("secpipw.cli._create_pth_monitor", return_value=FakeMonitor()):
            with patch(
                "secpipw.install_checks.detect_typos_in_resolved_packages",
                return_value=[alert],
            ):
                with patch(
                    "secpipw.install_checks.detect_recent_release_alerts",
                    return_value=[],
                ):
                    with patch(
                        "secpipw.install_checks.detect_empty_description_alerts",
                        return_value=[],
                    ):
                        with patch(
                            "secpipw.cli.run_guarded_pip_install",
                            side_effect=_guarded_install_for(plan),
                        ) as guarded:
                            with patch("sys.stderr", stderr):
                                rc = cli.main(
                                    [
                                        "install",
                                        "reqeusts==2.31.0",
                                        "--spip-ignore",
                                        "MeDiUm",
                                    ]
                                )

        self.assertEqual(rc, 0)
        self.assertNotIn("[MEDIUM] typo-suspect:", stderr.getvalue())
        self.assertNotIn("continue install?", stderr.getvalue())
        guarded.assert_called_once()

    def test_cli_install_ignore_medium_skips_pth_monitor(self) -> None:
        with patch(
            "secpipw.cli._create_pth_monitor",
            side_effect=AssertionError("pth monitor should not be created"),
        ):
            with patch(
                "secpipw.cli.run_guarded_pip_install",
                side_effect=_guarded_install_for(_plan()),
            ) as guarded:
                rc = cli.main(["install", "requests", "--spip-ignore", "medium"])

        self.assertEqual(rc, 0)
        guarded.assert_called_once()

    def test_split_wrapper_args_removes_ignore_warning(self) -> None:
        pip_args, ignore_warning, debug, spip_status, sensitivity, ignore_severity = (
            cli._split_wrapper_args(
                ["requests==2.31.0", "--spip-ignore-warning", "--target", "vendor"]
            )
        )
        self.assertEqual(pip_args, ["requests==2.31.0", "--target", "vendor"])
        self.assertTrue(ignore_warning)
        self.assertFalse(debug)
        self.assertFalse(spip_status)
        self.assertEqual(sensitivity, Severity.LOW)
        self.assertIsNone(ignore_severity)

    def test_split_wrapper_args_removes_ignore(self) -> None:
        pip_args, ignore_warning, debug, spip_status, sensitivity, ignore_severity = (
            cli._split_wrapper_args(
                ["requests==2.31.0", "--spip-ignore", "MEDIUM", "--target", "vendor"]
            )
        )
        self.assertEqual(pip_args, ["requests==2.31.0", "--target", "vendor"])
        self.assertFalse(ignore_warning)
        self.assertFalse(debug)
        self.assertFalse(spip_status)
        self.assertEqual(sensitivity, Severity.LOW)
        self.assertEqual(ignore_severity, Severity.MEDIUM)

    def test_split_wrapper_args_removes_ignore_equals_case_insensitive(self) -> None:
        pip_args, ignore_warning, debug, spip_status, sensitivity, ignore_severity = (
            cli._split_wrapper_args(["requests==2.31.0", "--spip-ignore=low"])
        )
        self.assertEqual(pip_args, ["requests==2.31.0"])
        self.assertFalse(ignore_warning)
        self.assertFalse(debug)
        self.assertFalse(spip_status)
        self.assertEqual(sensitivity, Severity.LOW)
        self.assertEqual(ignore_severity, Severity.LOW)

    def test_split_wrapper_args_removes_spip_debug(self) -> None:
        pip_args, ignore_warning, debug, spip_status, sensitivity, ignore_severity = (
            cli._split_wrapper_args(
                ["requests==2.31.0", "--spip-debug", "--target", "vendor"]
            )
        )
        self.assertEqual(pip_args, ["requests==2.31.0", "--target", "vendor"])
        self.assertFalse(ignore_warning)
        self.assertTrue(debug)
        self.assertFalse(spip_status)
        self.assertEqual(sensitivity, Severity.LOW)
        self.assertIsNone(ignore_severity)

    def test_split_wrapper_args_removes_spip_status(self) -> None:
        pip_args, ignore_warning, debug, spip_status, sensitivity, ignore_severity = (
            cli._split_wrapper_args(
                ["requests==2.31.0", "--spip-status", "--target", "vendor"]
            )
        )
        self.assertEqual(pip_args, ["requests==2.31.0", "--target", "vendor"])
        self.assertFalse(ignore_warning)
        self.assertFalse(debug)
        self.assertTrue(spip_status)
        self.assertEqual(sensitivity, Severity.LOW)
        self.assertIsNone(ignore_severity)

    def test_split_wrapper_args_removes_sensitivity(self) -> None:
        pip_args, ignore_warning, debug, spip_status, sensitivity, ignore_severity = (
            cli._split_wrapper_args(
                ["requests==2.31.0", "--sensitivity", "medium", "--target", "vendor"]
            )
        )
        self.assertEqual(pip_args, ["requests==2.31.0", "--target", "vendor"])
        self.assertFalse(ignore_warning)
        self.assertFalse(debug)
        self.assertFalse(spip_status)
        self.assertEqual(sensitivity, Severity.MEDIUM)
        self.assertIsNone(ignore_severity)

    def test_split_wrapper_args_removes_sensitivity_equals(self) -> None:
        pip_args, ignore_warning, debug, spip_status, sensitivity, ignore_severity = (
            cli._split_wrapper_args(["requests==2.31.0", "--sensitivity=high"])
        )
        self.assertEqual(pip_args, ["requests==2.31.0"])
        self.assertFalse(ignore_warning)
        self.assertFalse(debug)
        self.assertFalse(spip_status)
        self.assertEqual(sensitivity, Severity.HIGH)
        self.assertIsNone(ignore_severity)

    def test_split_wrapper_args_rejects_invalid_sensitivity(self) -> None:
        with self.assertRaises(ValueError):
            cli._split_wrapper_args(["requests==2.31.0", "--sensitivity", "info"])

    def test_split_wrapper_args_rejects_invalid_ignore(self) -> None:
        with self.assertRaises(ValueError):
            cli._split_wrapper_args(["requests==2.31.0", "--spip-ignore", "info"])

    def test_cli_install_rejects_invalid_sensitivity(self) -> None:
        stderr = io.StringIO()

        with patch("sys.stderr", stderr):
            rc = cli.main(["install", "requests", "--sensitivity", "info"])

        self.assertEqual(rc, 2)
        self.assertIn("--sensitivity must be low, medium, or high", stderr.getvalue())

    def test_cli_install_rejects_invalid_ignore(self) -> None:
        stderr = io.StringIO()

        with patch("sys.stderr", stderr):
            rc = cli.main(["install", "requests", "--spip-ignore", "info"])

        self.assertEqual(rc, 2)
        self.assertIn("--spip-ignore must be low, medium, or high", stderr.getvalue())

    def test_cli_install_preserves_requirements_and_dependency_related_args(
        self,
    ) -> None:
        plan = _plan(
            FakePackage(name="requests", version="2.31.0", requested=True),
            FakePackage(name="urllib3", version="2.2.1"),
        )
        with patch("secpipw.cli._create_pth_monitor", return_value=FakeMonitor()):
            with patch(
                "secpipw.install_checks.detect_typos_in_resolved_packages",
                return_value=[],
            ):
                with patch(
                    "secpipw.install_checks.detect_recent_release_alerts",
                    return_value=[],
                ):
                    with patch(
                        "secpipw.install_checks.detect_empty_description_alerts",
                        return_value=[],
                    ):
                        with patch(
                            "secpipw.cli.run_guarded_pip_install",
                            side_effect=_guarded_install_for(plan),
                        ) as guarded:
                            rc = cli.main(
                                [
                                    "install",
                                    "-r",
                                    "requirements.txt",
                                    "--upgrade",
                                    "--upgrade-strategy",
                                    "eager",
                                    "--target",
                                    "vendor",
                                ]
                            )

        self.assertEqual(rc, 0)
        guarded.assert_called_once()
        self.assertEqual(
            guarded.call_args.args[0],
            [
                "-r",
                "requirements.txt",
                "--upgrade",
                "--upgrade-strategy",
                "eager",
                "--target",
                "vendor",
            ],
        )

    def test_install_with_guard_uses_guarded_pip_then_checks_pth(self) -> None:
        monitor = SimpleNamespace(inspect=lambda: ["alert"])
        with patch("secpipw.cli._create_pth_monitor", return_value=monitor):
            with patch(
                "secpipw.cli.run_guarded_pip_install", return_value=0
            ) as guarded:
                with patch(
                    "secpipw.cli.handle_suspicious_pth_alerts"
                ) as handle_post:
                    handle_post.return_value = GateDecision(
                        allow_install=True,
                        exit_code=0,
                    )

                    rc = cli._install_with_guard(
                        ["requests", "--target", "vendor"],
                        ignore_warning=False,
                        debug=False,
                        sensitivity=Severity.LOW,
                    )

        self.assertEqual(rc, 0)
        guarded.assert_called_once()
        self.assertEqual(guarded.call_args.args[0], ["requests", "--target", "vendor"])
        self.assertEqual(len(guarded.call_args.args), 3)
        handle_post.assert_called_once_with(
            ["alert"],
            ignore_warning=False,
            ignore_severity=None,
        )

    def test_install_with_guard_skips_empty_pth_alert_handler(self) -> None:
        with patch("secpipw.cli._create_pth_monitor", return_value=FakeMonitor()):
            with patch("secpipw.cli.run_guarded_pip_install", return_value=0):
                with patch("secpipw.cli.handle_suspicious_pth_alerts") as handle_post:
                    rc = cli._install_with_guard(
                        ["requests", "--target", "vendor"],
                        ignore_warning=False,
                        debug=False,
                        sensitivity=Severity.LOW,
                    )

        self.assertEqual(rc, 0)
        handle_post.assert_not_called()

    def test_install_with_guard_skips_empty_history_alert_handler(self) -> None:
        plan = _plan(FakePackage(name="requests", version="2.31.0", requested=True))

        def guarded(pip_args, plan_hook, artifact_hook=None):
            decision = plan_hook(plan)
            if not decision.allow_install:
                return decision.exit_code
            return 0

        with patch("secpipw.cli._create_pth_monitor", return_value=FakeMonitor()):
            with patch("secpipw.cli.run_install_checks") as run_checks:
                run_checks.return_value = GateDecision(allow_install=True, exit_code=0)
                with patch(
                    "secpipw.cli.run_guarded_pip_install",
                    side_effect=guarded,
                ):
                    with patch(
                        "secpipw.cli.inspect_package_artifact_history",
                        return_value=[],
                    ) as inspect_history:
                        with patch(
                            "secpipw.cli.handle_package_artifact_history_alerts"
                        ) as handle_history:
                            rc = cli._install_with_guard(
                                ["requests", "--target", "vendor"],
                                ignore_warning=False,
                                debug=False,
                                sensitivity=Severity.LOW,
                            )

        self.assertEqual(rc, 0)
        inspect_history.assert_called_once_with(
            plan.packages,
            (),
            pip_args=["requests", "--target", "vendor"],
        )
        handle_history.assert_not_called()

    def test_install_with_guard_refuses_to_run_without_pth_monitor(self) -> None:
        stderr = io.StringIO()

        with patch("secpipw.cli._create_pth_monitor", return_value=None):
            with patch("secpipw.cli.run_guarded_pip_install") as guarded:
                with patch("sys.stderr", stderr):
                    rc = cli._install_with_guard(
                        ["requests"],
                        ignore_warning=False,
                        debug=False,
                        sensitivity=Severity.LOW,
                    )

        self.assertEqual(rc, 2)
        guarded.assert_not_called()
        self.assertIn("could not initialize .pth monitoring", stderr.getvalue())
        self.assertIn("Refusing to continue", stderr.getvalue())

    def test_cli_install_allows_empty_plan(self) -> None:
        with patch("secpipw.cli._create_pth_monitor", return_value=FakeMonitor()):
            with patch(
                "secpipw.install_checks.detect_typos_in_resolved_packages",
                return_value=[],
            ):
                with patch(
                    "secpipw.install_checks.detect_recent_release_alerts",
                    return_value=[],
                ):
                    with patch(
                        "secpipw.install_checks.detect_empty_description_alerts",
                        return_value=[],
                    ):
                        with patch(
                            "secpipw.cli.run_guarded_pip_install",
                            side_effect=_guarded_install_for(_plan()),
                        ) as guarded:
                            rc = cli.main(["install", "requests"])

        self.assertEqual(rc, 0)
        guarded.assert_called_once()

    def test_cli_create_pth_monitor_logs_debug_message_on_error(self) -> None:
        stderr = io.StringIO()
        with patch(
            "secpipw.cli.PthMonitor.from_install_args",
            side_effect=RuntimeError("boom"),
        ):
            with patch("sys.stderr", stderr):
                monitor = cli._create_pth_monitor(["requests==2.31.0"], debug=True)

        self.assertIsNone(monitor)
        self.assertIn("pth-monitor unavailable: boom", stderr.getvalue())

    def test_refresh_package_cache_command_reports_success(self) -> None:
        stdout = io.StringIO()
        fake_client = SimpleNamespace(
            cache_path="cache.json",
        )
        with patch(
            "secpipw.cli.refresh_all_caches",
            return_value=[
                SimpleNamespace(
                    description="PyPI project name cache",
                    count=123,
                    location="cache.json",
                ),
            ],
        ):
            with patch("secpipw.cli.OfficialPyPIClient", return_value=fake_client):
                with patch("sys.stdout", stdout):
                    rc = cli.main(["refresh-cache"])

        self.assertEqual(rc, 0)
        self.assertIn(
            "refreshed PyPI project name cache with 123 entries", stdout.getvalue()
        )

    def test_refresh_package_cache_is_no_longer_a_spip_command(self) -> None:
        with patch("secpipw.cli.run_pip", return_value=7) as run_pip:
            rc = cli.main(["refresh-package-cache"])

        self.assertEqual(rc, 7)
        run_pip.assert_called_once_with(["refresh-package-cache"])

    def test_collect_pip_output_invokes_python_m_pip(self) -> None:
        completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": "",
                "stderr": "",
            },
        )()

        with patch(
            "secpipw.pip_bridge.subprocess.run", return_value=completed
        ) as run:
            collect_pip_output(["list"])

        command = run.call_args.args[0]
        self.assertEqual(command[1:3], ["-m", "pip"])
        self.assertEqual(command[3:], ["list"])

    def test_cli_install_prints_resolved_packages_before_checks(self) -> None:
        stderr = io.StringIO()
        plan = _plan(
            FakePackage(name="requests", version="2.31.0", requested=True),
            FakePackage(name="urllib3", version="2.2.1"),
        )
        with patch("secpipw.cli._create_pth_monitor", return_value=FakeMonitor()):
            with patch(
                "secpipw.install_checks.detect_typos_in_resolved_packages",
                return_value=[],
            ):
                with patch(
                    "secpipw.install_checks.detect_recent_release_alerts",
                    return_value=[],
                ):
                    with patch(
                        "secpipw.install_checks.detect_empty_description_alerts",
                        return_value=[],
                    ):
                        with patch(
                            "secpipw.cli.run_guarded_pip_install",
                            side_effect=_guarded_install_for(plan),
                        ):
                            with patch("sys.stderr", stderr):
                                rc = cli.main(["install", "requests==2.31.0"])

        self.assertEqual(rc, 0)
        self.assertNotIn("resolved packages to download (2)", stderr.getvalue())
        self.assertNotIn("guard enabled", stderr.getvalue())

    def test_cli_install_prints_guard_status_only_when_requested(self) -> None:
        stderr = io.StringIO()
        plan = _plan(FakePackage(name="requests", version="2.31.0", requested=True))
        with patch("secpipw.cli._create_pth_monitor", return_value=FakeMonitor()):
            with patch(
                "secpipw.install_checks.detect_typos_in_resolved_packages",
                return_value=[],
            ):
                with patch(
                    "secpipw.install_checks.detect_recent_release_alerts",
                    return_value=[],
                ):
                    with patch(
                        "secpipw.install_checks.detect_empty_description_alerts",
                        return_value=[],
                    ):
                        with patch(
                            "secpipw.cli.run_guarded_pip_install",
                            side_effect=_guarded_install_for(plan),
                        ) as guarded:
                            with patch("sys.stderr", stderr):
                                rc = cli.main(
                                    ["install", "requests==2.31.0", "--spip-status"]
                                )

        self.assertEqual(rc, 0)
        self.assertIn("guard enabled.", stderr.getvalue())
        guarded.assert_called_once()
        self.assertEqual(guarded.call_args.args[0], ["requests==2.31.0"])

    def test_cli_install_prints_resolved_packages_in_debug_mode(self) -> None:
        stderr = io.StringIO()
        plan = _plan(
            FakePackage(name="requests", version="2.31.0", requested=True),
            FakePackage(name="urllib3", version="2.2.1"),
        )
        with patch("secpipw.cli._create_pth_monitor", return_value=FakeMonitor()):
            with patch(
                "secpipw.install_checks.detect_typos_in_resolved_packages",
                return_value=[],
            ):
                with patch(
                    "secpipw.install_checks.detect_recent_release_alerts",
                    return_value=[],
                ):
                    with patch(
                        "secpipw.install_checks.detect_empty_description_alerts",
                        return_value=[],
                    ):
                        with patch(
                            "secpipw.cli.run_guarded_pip_install",
                            side_effect=_guarded_install_for(plan),
                        ):
                            with patch("sys.stderr", stderr):
                                rc = cli.main(
                                    ["install", "requests==2.31.0", "--spip-debug"]
                                )

        self.assertEqual(rc, 0)
        self.assertIn("resolved packages to download (2)", stderr.getvalue())
        self.assertIn("requests==2.31.0", stderr.getvalue())
        self.assertIn("urllib3==2.2.1", stderr.getvalue())

    def test_cli_install_returns_resolution_error_code(self) -> None:
        with patch("secpipw.cli._create_pth_monitor", return_value=FakeMonitor()):
            with patch(
                "secpipw.cli.run_guarded_pip_install", return_value=2
            ) as guarded:
                rc = cli.main(["install", "badpkg"])

        self.assertEqual(rc, 2)
        guarded.assert_called_once()
        self.assertEqual(guarded.call_args.args[0], ["badpkg"])

    def test_cli_install_resolution_failure_does_not_print_spip_suggestion(
        self,
    ) -> None:
        stderr = io.StringIO()

        with patch("secpipw.cli._create_pth_monitor", return_value=FakeMonitor()):
            with patch("secpipw.cli.run_guarded_pip_install", return_value=1):
                with patch("sys.stderr", stderr):
                    rc = cli.main(["install", "badpkg"])

        self.assertEqual(rc, 1)
        self.assertNotIn("spip could not resolve the install plan", stderr.getvalue())

    def test_cli_install_internal_guard_error_uses_spip_error_prefix(self) -> None:
        stderr = io.StringIO()

        with patch("secpipw.cli._create_pth_monitor", return_value=FakeMonitor()):
            with patch(
                "secpipw.cli.run_guarded_pip_install",
                side_effect=RuntimeError("boom"),
            ):
                with patch("sys.stderr", stderr):
                    rc = cli.main(["install", "badpkg"])

        self.assertEqual(rc, 1)
        self.assertIn(
            "ERROR: spip failed to run guarded pip install: boom", stderr.getvalue()
        )

    def test_run_pip_uses_direct_passthrough_execution(self) -> None:
        completed = type("Completed", (), {"returncode": 9})()

        with patch(
            "secpipw.pip_bridge.subprocess.run", return_value=completed
        ) as run:
            from secpipw.pip_bridge import run_pip

            rc = run_pip(["install", "-r", "requirements.txt", "--target", "vendor"])

        self.assertEqual(rc, 9)
        self.assertEqual(
            run.call_args.args[0],
            build_pip_command(
                ["install", "-r", "requirements.txt", "--target", "vendor"]
            ),
        )
        self.assertNotIn("capture_output", run.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()
