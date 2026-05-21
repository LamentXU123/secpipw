from __future__ import annotations

import io
import unittest
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import patch

from spip import Severity
from spip import cli
from spip.install_plan import InstallPlan
from spip.pip_bridge import OutputEvent, build_pip_command, collect_pip_output, replay_events


class TtyInput(io.StringIO):
    def isatty(self) -> bool:
        return True


@dataclass(frozen=True)
class FakePackage:
    name: str
    version: str
    requested: bool = False
    is_direct: bool = False
    download_url: str | None = None
    artifact_name: str | None = None
    requires_dist: tuple[str, ...] = ()


def _plan(*packages: FakePackage) -> InstallPlan:
    return InstallPlan(packages=tuple(packages), raw_report={"install": []})


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

        with patch("spip.pip_bridge.subprocess.run", return_value=completed):
            result = collect_pip_output(["--version"])

        self.assertEqual(result.returncode, 0)
        self.assertEqual([event.severity for event in result.events], [Severity.INFO, Severity.INFO, Severity.INFO])
        self.assertEqual([event.stream for event in result.events], ["stdout", "stdout", "stderr"])
        self.assertEqual([event.text for event in result.events], ["line one\n", "line two\n", "warning\n"])

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
        with patch("spip.cli.run_pip", return_value=7) as run_pip:
            rc = cli.main(["--version"])

        self.assertEqual(rc, 7)
        run_pip.assert_called_once_with(["--version"])

    def test_cli_install_emits_typo_alerts_before_bridge(self) -> None:
        stderr = io.StringIO()
        alert = SimpleNamespace(
            severity=Severity.HIGH,
            message="'requsets' is similar to popular package 'requests'",
        )
        with patch(
            "spip.cli.resolve_install_plan",
            return_value=_plan(FakePackage(name="requsets", version="2.31.0", requested=True)),
        ):
            with patch("spip.cli.detect_typos_in_resolved_packages", return_value=[alert]):
                with patch("spip.cli.detect_recent_release_alerts", return_value=[]):
                    with patch("spip.cli._install_resolved_plan", return_value=0) as install_plan:
                        with patch("sys.stderr", stderr):
                            rc = cli.main(["install", "requsets==2.31.0"])

        self.assertEqual(rc, 2)
        self.assertIn("[HIGH] typo-suspect:", stderr.getvalue())
        self.assertIn("rerun with --ignore-warning", stderr.getvalue())
        self.assertIn("\x1b[", stderr.getvalue())
        install_plan.assert_not_called()

    def test_cli_install_high_warning_can_be_ignored(self) -> None:
        stderr = io.StringIO()
        alert = SimpleNamespace(
            severity=Severity.HIGH,
            message="'requsets' is similar to popular package 'requests'",
        )
        with patch(
            "spip.cli.resolve_install_plan",
            return_value=_plan(FakePackage(name="requsets", version="2.31.0", requested=True)),
        ):
            with patch("spip.cli.detect_typos_in_resolved_packages", return_value=[alert]):
                with patch("spip.cli.detect_recent_release_alerts", return_value=[]):
                    with patch("spip.cli._install_resolved_plan", return_value=0) as install_plan:
                        with patch("sys.stderr", stderr):
                            rc = cli.main(["install", "requsets==2.31.0", "--ignore-warning"])

        self.assertEqual(rc, 0)
        self.assertIn("[HIGH] typo-suspect:", stderr.getvalue())
        self.assertIn("\x1b[", stderr.getvalue())
        install_plan.assert_called_once()

    def test_cli_install_medium_warning_prompts_and_continues_on_yes(self) -> None:
        stderr = io.StringIO()
        stdin = TtyInput("y\n")
        alert = SimpleNamespace(
            severity=Severity.MEDIUM,
            message="'reqeusts' is similar to popular package 'requests'",
        )
        with patch(
            "spip.cli.resolve_install_plan",
            return_value=_plan(FakePackage(name="reqeusts", version="2.31.0", requested=True)),
        ):
            with patch("spip.cli.detect_typos_in_resolved_packages", return_value=[alert]):
                with patch("spip.cli.detect_recent_release_alerts", return_value=[]):
                    with patch("spip.cli._install_resolved_plan", return_value=0) as install_plan:
                        with patch("sys.stderr", stderr), patch("sys.stdin", stdin):
                            rc = cli.main(["install", "reqeusts==2.31.0"])

        self.assertEqual(rc, 0)
        self.assertIn("continue install? enter y/n [y/N]:", stderr.getvalue())
        self.assertIn("\x1b[", stderr.getvalue())
        install_plan.assert_called_once()

    def test_cli_install_medium_warning_cancels_on_no(self) -> None:
        stderr = io.StringIO()
        stdin = TtyInput("n\n")
        alert = SimpleNamespace(
            severity=Severity.MEDIUM,
            message="'reqeusts' is similar to popular package 'requests'",
        )
        with patch(
            "spip.cli.resolve_install_plan",
            return_value=_plan(FakePackage(name="reqeusts", version="2.31.0", requested=True)),
        ):
            with patch("spip.cli.detect_typos_in_resolved_packages", return_value=[alert]):
                with patch("spip.cli.detect_recent_release_alerts", return_value=[]):
                    with patch("spip.cli._install_resolved_plan", return_value=0) as install_plan:
                        with patch("sys.stderr", stderr), patch("sys.stdin", stdin):
                            rc = cli.main(["install", "reqeusts==2.31.0"])

        self.assertEqual(rc, 1)
        self.assertIn("installation cancelled.", stderr.getvalue())
        install_plan.assert_not_called()

    def test_cli_install_medium_warning_blocks_when_not_interactive(self) -> None:
        stderr = io.StringIO()
        stdin = io.StringIO("y\n")
        alert = SimpleNamespace(
            severity=Severity.MEDIUM,
            message="'reqeusts' is similar to popular package 'requests'",
        )
        with patch(
            "spip.cli.resolve_install_plan",
            return_value=_plan(FakePackage(name="reqeusts", version="2.31.0", requested=True)),
        ):
            with patch("spip.cli.detect_typos_in_resolved_packages", return_value=[alert]):
                with patch("spip.cli.detect_recent_release_alerts", return_value=[]):
                    with patch("spip.cli._install_resolved_plan", return_value=0) as install_plan:
                        with patch("sys.stderr", stderr), patch("sys.stdin", stdin):
                            rc = cli.main(["install", "reqeusts==2.31.0"])

        self.assertEqual(rc, 2)
        self.assertIn("run interactively and answer y/n", stderr.getvalue())
        install_plan.assert_not_called()

    def test_cli_install_medium_warning_can_be_ignored_without_prompt(self) -> None:
        stderr = io.StringIO()
        alert = SimpleNamespace(
            severity=Severity.MEDIUM,
            message="'reqeusts' is similar to popular package 'requests'",
        )
        with patch(
            "spip.cli.resolve_install_plan",
            return_value=_plan(FakePackage(name="reqeusts", version="2.31.0", requested=True)),
        ):
            with patch("spip.cli.detect_typos_in_resolved_packages", return_value=[alert]):
                with patch("spip.cli.detect_recent_release_alerts", return_value=[]):
                    with patch("spip.cli._install_resolved_plan", return_value=0) as install_plan:
                        with patch("sys.stderr", stderr):
                            rc = cli.main(["install", "reqeusts==2.31.0", "--ignore-warning"])

        self.assertEqual(rc, 0)
        install_plan.assert_called_once()

    def test_split_wrapper_args_removes_ignore_warning(self) -> None:
        pip_args, ignore_warning, debug = cli._split_wrapper_args(
            ["requests==2.31.0", "--ignore-warning", "--target", "vendor"]
        )
        self.assertEqual(pip_args, ["requests==2.31.0", "--target", "vendor"])
        self.assertTrue(ignore_warning)
        self.assertFalse(debug)

    def test_split_wrapper_args_removes_debug(self) -> None:
        pip_args, ignore_warning, debug = cli._split_wrapper_args(
            ["requests==2.31.0", "--debug", "--target", "vendor"]
        )
        self.assertEqual(pip_args, ["requests==2.31.0", "--target", "vendor"])
        self.assertFalse(ignore_warning)
        self.assertTrue(debug)

    def test_cli_install_preserves_requirements_and_dependency_related_args(self) -> None:
        plan = _plan(
            FakePackage(name="requests", version="2.31.0", requested=True),
            FakePackage(name="urllib3", version="2.2.1"),
        )
        with patch(
            "spip.cli.resolve_install_plan",
            return_value=plan,
        ):
            with patch("spip.cli.detect_typos_in_resolved_packages", return_value=[]):
                with patch("spip.cli.detect_recent_release_alerts", return_value=[]):
                    with patch("spip.cli._install_resolved_plan", return_value=0) as install_plan:
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
        install_plan.assert_called_once_with(
            plan,
            ["-r", "requirements.txt", "--upgrade", "--upgrade-strategy", "eager", "--target", "vendor"],
            ignore_warning=False,
            debug=False,
        )

    def test_install_resolved_plan_runs_plain_pip_once_then_checks_pth(self) -> None:
        monitor = SimpleNamespace(inspect=lambda: ["alert"])
        with patch("spip.cli._create_pth_monitor", return_value=monitor):
            with patch("spip.cli.run_pip", return_value=0) as run_pip:
                with patch("spip.cli.handle_suspicious_pth_alerts") as handle_post:
                    handle_post.return_value = SimpleNamespace(exit_code=0)

                    rc = cli._install_resolved_plan(
                        _plan(FakePackage(name="requests", version="2.31.0", requested=True)),
                        ["requests", "--target", "vendor"],
                        ignore_warning=False,
                        debug=False,
                    )

        self.assertEqual(rc, 0)
        run_pip.assert_called_once_with(["install", "requests", "--target", "vendor"])
        handle_post.assert_called_once_with(["alert"], ignore_warning=False)

    def test_cli_install_falls_back_to_plain_pip_when_plan_is_empty(self) -> None:
        with patch("spip.cli.resolve_install_plan", return_value=_plan()):
            with patch("spip.cli.detect_typos_in_resolved_packages", return_value=[]):
                with patch("spip.cli.detect_recent_release_alerts", return_value=[]):
                    with patch("spip.cli.run_pip", return_value=0) as run_pip:
                        rc = cli.main(["install", "requests"])

        self.assertEqual(rc, 0)
        run_pip.assert_called_once_with(["install", "requests"])

    def test_cli_create_pth_monitor_falls_back_to_none_on_error(self) -> None:
        stderr = io.StringIO()
        with patch("spip.cli.PthMonitor.from_install_args", side_effect=RuntimeError("boom")):
            with patch("sys.stderr", stderr):
                monitor = cli._create_pth_monitor(["requests==2.31.0"], debug=True)

        self.assertIsNone(monitor)
        self.assertIn("pth-monitor unavailable: boom", stderr.getvalue())

    def test_refresh_package_cache_command_reports_success(self) -> None:
        stdout = io.StringIO()
        fake_client = SimpleNamespace(
            cache_path="cache.json",
            refresh_project_name_cache=lambda: 123,
        )
        with patch("spip.cli.OfficialPyPIClient", return_value=fake_client):
            with patch("sys.stdout", stdout):
                rc = cli.main(["refresh-package-cache"])

        self.assertEqual(rc, 0)
        self.assertIn("refreshed local package cache with 123 project names", stdout.getvalue())

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

        with patch("spip.pip_bridge.subprocess.run", return_value=completed) as run:
            collect_pip_output(["list"])

        command = run.call_args.args[0]
        self.assertEqual(command[1:3], ["-m", "pip"])
        self.assertEqual(command[3:], ["list"])

    def test_cli_install_prints_resolved_packages_before_checks(self) -> None:
        stderr = io.StringIO()
        with patch(
            "spip.cli.resolve_install_plan",
            return_value=_plan(
                FakePackage(name="requests", version="2.31.0", requested=True),
                FakePackage(name="urllib3", version="2.2.1"),
            ),
        ):
            with patch("spip.cli.detect_typos_in_resolved_packages", return_value=[]):
                with patch("spip.cli.detect_recent_release_alerts", return_value=[]):
                    with patch("spip.cli._install_resolved_plan", return_value=0):
                        with patch("sys.stderr", stderr):
                            rc = cli.main(["install", "requests==2.31.0"])

        self.assertEqual(rc, 0)
        self.assertNotIn("resolved packages to download (2)", stderr.getvalue())

    def test_cli_install_prints_resolved_packages_in_debug_mode(self) -> None:
        stderr = io.StringIO()
        with patch(
            "spip.cli.resolve_install_plan",
            return_value=_plan(
                FakePackage(name="requests", version="2.31.0", requested=True),
                FakePackage(name="urllib3", version="2.2.1"),
            ),
        ):
            with patch("spip.cli.detect_typos_in_resolved_packages", return_value=[]):
                with patch("spip.cli.detect_recent_release_alerts", return_value=[]):
                    with patch("spip.cli._install_resolved_plan", return_value=0):
                        with patch("sys.stderr", stderr):
                            rc = cli.main(["install", "requests==2.31.0", "--debug"])

        self.assertEqual(rc, 0)
        self.assertIn("resolved packages to download (2)", stderr.getvalue())
        self.assertIn("requests==2.31.0", stderr.getvalue())
        self.assertIn("urllib3==2.2.1", stderr.getvalue())

    def test_cli_install_returns_resolution_error_code(self) -> None:
        stderr = io.StringIO()
        from spip.install_plan import InstallPlanError

        with patch(
            "spip.cli.resolve_install_plan",
            side_effect=InstallPlanError(2, "resolve failed\n", ""),
        ):
            with patch("sys.stderr", stderr):
                rc = cli.main(["install", "badpkg"])

        self.assertEqual(rc, 2)
        self.assertIn("resolve failed", stderr.getvalue())
        self.assertIn("pip install badpkg", stderr.getvalue())

    def test_cli_install_suggests_plain_pip_when_resolution_fails(self) -> None:
        stderr = io.StringIO()
        from spip.install_plan import InstallPlanError

        with patch(
            "spip.cli.resolve_install_plan",
            side_effect=InstallPlanError(1, "No matching distribution found\n", ""),
        ):
            with patch("sys.stderr", stderr):
                rc = cli.main(["install", "badpkg"])

        self.assertEqual(rc, 1)
        self.assertIn("No matching distribution found", stderr.getvalue())
        self.assertIn("pip install badpkg", stderr.getvalue())

    def test_run_pip_uses_direct_passthrough_execution(self) -> None:
        completed = type("Completed", (), {"returncode": 9})()

        with patch("spip.pip_bridge.subprocess.run", return_value=completed) as run:
            from spip.pip_bridge import run_pip

            rc = run_pip(["install", "-r", "requirements.txt", "--target", "vendor"])

        self.assertEqual(rc, 9)
        self.assertEqual(
            run.call_args.args[0],
            build_pip_command(["install", "-r", "requirements.txt", "--target", "vendor"]),
        )
        self.assertNotIn("capture_output", run.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()
