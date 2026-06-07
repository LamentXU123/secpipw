from __future__ import annotations

import os
import subprocess
import sys
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import patch

from secpipw.install_checks import detect_install_alerts
from secpipw.install_plan import InstallPlan
from secpipw.severity import Severity


@dataclass(frozen=True)
class FakePackage:
    name: str
    version: str
    requested: bool = False
    is_direct: bool = False
    download_url: str | None = None
    artifact_name: str | None = None
    archive_hash: str | None = None
    requires_dist: tuple[str, ...] = ()
    metadata: dict = field(default_factory=dict)
    yanked: bool = False
    yanked_reason: str | None = None


def _plan(*packages: FakePackage) -> InstallPlan:
    return InstallPlan(packages=tuple(packages), raw_report={"install": []})


def _src_env() -> dict[str, str]:
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "src") + os.pathsep + env.get("PYTHONPATH", "")
    return env


class InstallCheckIgnoreTests(unittest.TestCase):
    def test_cli_guard_modules_are_loaded_lazily(self) -> None:
        code = (
            "import secpipw.cli, sys; "
            "loaded = ["
            "name for name in ("
            "'secpipw.warning_gate', "
            "'secpipw.install_checks', "
            "'secpipw.pth_monitor', "
            "'secpipw.pypi_api'"
            ") if name in sys.modules"
            "]; "
            "print('\\n'.join(loaded)); "
            "raise SystemExit(1 if loaded else 0)"
        )

        completed = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            env=_src_env(),
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_check_modules_are_loaded_lazily(self) -> None:
        code = (
            "import secpipw.install_checks, sys; "
            "loaded = ["
            "name for name in ("
            "'secpipw.release_checks', "
            "'secpipw.pypi_api', "
            "'secpipw.typo', "
            "'secpipw.install_plan'"
            ") if name in sys.modules"
            "]; "
            "print('\\n'.join(loaded)); "
            "raise SystemExit(1 if loaded else 0)"
        )

        completed = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            env=_src_env(),
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_pip_guard_imports_pip_internals_lazily(self) -> None:
        code = (
            "import secpipw.pip_guard, sys; "
            "loaded = [name for name in sys.modules if name.startswith('pip._internal')]; "
            "print('\\n'.join(loaded)); "
            "raise SystemExit(1 if loaded else 0)"
        )

        completed = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            env=_src_env(),
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_guarded_install_command_keeps_public_class_identity(self) -> None:
        code = (
            "from secpipw.pip_guard import GuardedInstallCommand; "
            "print(GuardedInstallCommand.__module__); "
            "print(GuardedInstallCommand.__qualname__); "
            "raise SystemExit("
            "0 if GuardedInstallCommand.__module__ == 'secpipw.pip_guard' "
            "and GuardedInstallCommand.__qualname__ == 'GuardedInstallCommand' "
            "else 1)"
        )

        completed = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            env=_src_env(),
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_ignore_low_skips_low_only_checks(self) -> None:
        plan = _plan(
            FakePackage(
                name="demo",
                version="1.0.0",
                metadata={"name": "demo", "version": "1.0.0"},
            )
        )

        with patch(
            "secpipw.install_checks.detect_empty_description_alerts",
            side_effect=AssertionError("empty-description should be skipped"),
        ):
            with patch(
                "secpipw.install_checks.detect_recent_release_alerts",
                return_value=[],
            ) as recent_release:
                with patch(
                    "secpipw.install_checks.detect_suspicious_metadata_url_alerts",
                    side_effect=AssertionError("suspicious-url should be skipped"),
                ):
                    with patch(
                        "secpipw.install_checks.detect_repository_mismatch_alerts",
                        side_effect=AssertionError(
                            "repository-mismatch should be skipped"
                        ),
                    ):
                        with patch(
                            "secpipw.install_checks.detect_email_domain_drift_alerts",
                            side_effect=AssertionError(
                                "email-domain-drift should be skipped"
                            ),
                        ):
                            with patch(
                                "secpipw.install_checks.detect_zero_version_alerts",
                                side_effect=AssertionError(
                                    "zero-version should be skipped"
                                ),
                            ):
                                alerts = detect_install_alerts(
                                    plan,
                                    ["demo"],
                                    ignore_severity=Severity.LOW,
                                )

        recent_release.assert_called_once()
        self.assertEqual(alerts.empty_description_alerts, ())
        self.assertEqual(alerts.suspicious_metadata_url_alerts, ())
        self.assertEqual(alerts.repository_mismatch_alerts, ())
        self.assertEqual(alerts.email_domain_drift_alerts, ())
        self.assertEqual(alerts.zero_version_alerts, ())

    def test_ignore_medium_skips_ignored_checks_without_loading_hash_check(
        self,
    ) -> None:
        plan = _plan(FakePackage(name="demo", version="1.0.0"))

        with patch(
            "secpipw.install_checks.client_from_pip_args",
            side_effect=AssertionError("registry client should not be created"),
        ):
            with patch(
                "secpipw.install_checks.detect_typos_in_resolved_packages",
                side_effect=AssertionError("typo check should be skipped"),
            ):
                with patch(
                    "secpipw.install_checks.detect_archive_hash_mismatch_alerts",
                    side_effect=AssertionError(
                        "hash check should not load heavy checks"
                    ),
                ):
                    alerts = detect_install_alerts(
                        plan,
                        ["demo"],
                        ignore_severity=Severity.MEDIUM,
                    )

        self.assertEqual(alerts.all_alerts, ())

    def test_ignore_medium_keeps_high_hash_mismatch_check(self) -> None:
        plan = _plan(
            FakePackage(
                name="demo",
                version="1.0.0",
                download_url="https://files.pythonhosted.org/packages/demo-1.0.0.whl",
                artifact_name="demo-1.0.0.whl",
                archive_hash="sha256=badcafe",
                metadata={
                    "urls": [
                        {
                            "filename": "demo-1.0.0.whl",
                            "digests": {"sha256": "goodcafe"},
                        }
                    ]
                },
            )
        )

        alerts = detect_install_alerts(
            plan,
            ["demo"],
            ignore_severity=Severity.MEDIUM,
        )

        self.assertEqual(len(alerts.archive_hash_mismatch_alerts), 1)
        self.assertEqual(
            alerts.archive_hash_mismatch_alerts[0].severity,
            Severity.HIGH,
        )


if __name__ == "__main__":
    unittest.main()
