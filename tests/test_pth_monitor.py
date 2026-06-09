import io
import shutil
import tarfile
import unittest
import uuid
import zipfile
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from secpipw import Severity
from secpipw import pth_monitor
from secpipw.pth_monitor import (
    PthMonitor,
    collect_package_artifact_records,
    compare_package_artifact_record,
    handle_package_artifact_history_alerts,
    find_import_lines,
    gate_suspicious_pth_alerts,
    handle_suspicious_pth_alerts,
    inspect_package_artifact_history,
    inspect_install_artifacts,
    inspect_source_artifact_for_suspicious_pth,
    inspect_wheel_for_suspicious_pth,
    resolve_watch_directories,
)

TMP_ROOT = Path(".tmp-tests")
TMP_ROOT.mkdir(exist_ok=True)


@contextmanager
def temporary_workspace_dir():
    path = TMP_ROOT / f"tmp-{uuid.uuid4().hex}"
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


class FlushingStringIO(io.StringIO):
    def __init__(self) -> None:
        super().__init__()
        self.flush_calls = 0

    def flush(self) -> None:
        self.flush_calls += 1
        super().flush()


class FakePackage:
    def __init__(self, name: str, version: str) -> None:
        self.name = name
        self.version = version


class PthMonitorTests(unittest.TestCase):
    def test_inspect_wheel_detects_import_pth(self) -> None:
        with temporary_workspace_dir() as tmp:
            path = tmp / "demo.whl"
            _write_zip_archive(
                path,
                {
                    "suspicious-demo.pth": "import spip_pth_demo_marker\n",
                    "pkg/__init__.py": "",
                },
            )

            alerts = inspect_wheel_for_suspicious_pth(path)

            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0].severity, Severity.MEDIUM)
            self.assertIn("suspicious-demo.pth", str(alerts[0].path))
            self.assertEqual(alerts[0].import_lines, ("import spip_pth_demo_marker",))

    def test_inspect_wheel_ignores_wheel_without_pth(self) -> None:
        with temporary_workspace_dir() as tmp:
            path = tmp / "demo.whl"
            _write_zip_archive(path, {"pkg/__init__.py": ""})

            alerts = inspect_wheel_for_suspicious_pth(path)

            self.assertEqual(alerts, [])

    def test_remote_zip_tail_detector_finds_pth_member(self) -> None:
        with temporary_workspace_dir() as tmp:
            path = tmp / "demo.whl"
            _write_zip_archive(
                path,
                {
                    "suspicious-demo.pth": "import spip_pth_demo_marker\n",
                    "pkg/__init__.py": "",
                },
            )

            payload = path.read_bytes()
            contains_pth = pth_monitor._zip_tail_contains_pth(
                payload[-4096:],
                total_size=len(payload),
            )

        self.assertTrue(contains_pth)

    def test_remote_zip_tail_detector_ignores_archive_without_pth(self) -> None:
        with temporary_workspace_dir() as tmp:
            path = tmp / "demo.whl"
            _write_zip_archive(path, {"pkg/__init__.py": ""})

            payload = path.read_bytes()
            contains_pth = pth_monitor._zip_tail_contains_pth(
                payload[-4096:],
                total_size=len(payload),
            )

        self.assertFalse(contains_pth)

    def test_remote_zip_detector_reuses_cached_result(self) -> None:
        with temporary_workspace_dir() as tmp:
            path = tmp / "demo.whl"
            cache_root = tmp / "cache"
            _write_zip_archive(path, {"pkg/__init__.py": ""})
            payload = path.read_bytes()
            response = pth_monitor._SuffixRangeResponse(
                payload=payload,
                partial=False,
                total_size=len(payload),
            )

            with patch.object(
                pth_monitor,
                "_remote_zip_pth_cache_root",
                return_value=cache_root,
            ):
                with patch.object(
                    pth_monitor,
                    "_fetch_http_suffix_range",
                    return_value=response,
                ) as fetch_range:
                    first = pth_monitor.remote_zip_artifact_contains_pth(
                        "https://example.test/demo.whl"
                    )

                with patch.object(
                    pth_monitor,
                    "_fetch_http_suffix_range",
                    side_effect=AssertionError("cached result should avoid network"),
                ):
                    second = pth_monitor.remote_zip_artifact_contains_pth(
                        "https://example.test/demo.whl"
                    )

        self.assertFalse(first)
        self.assertFalse(second)
        fetch_range.assert_called_once()

    def test_inspect_uv_cached_wheel_uses_extracted_uv_cache(self) -> None:
        with temporary_workspace_dir() as tmp:
            uv_cache = tmp / "uv-cache"
            package_dir = uv_cache / "wheels-v6" / "pypi" / "demo-package"
            package_dir.mkdir(parents=True, exist_ok=True)
            archive_dir = uv_cache / "archive-v0" / "cachekey"
            archive_dir.mkdir(parents=True, exist_ok=True)
            (package_dir / "1.0.0-py3-none-any").write_text(
                "archive-v0/cachekey",
                encoding="utf-8",
            )
            (archive_dir / "demo_package.pth").write_text(
                "import demo_bootstrap\n",
                encoding="utf-8",
            )

            with patch.object(
                pth_monitor,
                "_uv_cache_root",
                return_value=uv_cache,
            ):
                alerts = pth_monitor.inspect_uv_cached_wheel_for_suspicious_pth(
                    "demo_package",
                    "demo_package-1.0.0-py3-none-any.whl",
                )

        self.assertIsNotNone(alerts)
        self.assertEqual(len(alerts), 1)
        self.assertIn("demo_package.pth", str(alerts[0].path))

    def test_inspect_install_artifacts_scans_local_file_paths(self) -> None:
        with temporary_workspace_dir() as tmp:
            sdist_path = tmp / "demo.tar.gz"
            _write_tar_archive(
                sdist_path,
                {"demo-1.0.0/suspicious-demo.pth": "import spip_pth_demo_marker\n"},
            )
            requirement = type("Req", (), {"local_file_path": str(sdist_path)})()

            alerts = inspect_install_artifacts([requirement])

            self.assertEqual(len(alerts), 1)
            self.assertIn("suspicious-demo.pth", str(alerts[0].path))

    def test_inspect_source_artifact_detects_import_pth_in_zip(self) -> None:
        with temporary_workspace_dir() as tmp:
            path = tmp / "demo.zip"
            _write_zip_archive(
                path,
                {"demo-1.0.0/suspicious-demo.pth": "import spip_pth_demo_marker\n"},
            )

            alerts = inspect_source_artifact_for_suspicious_pth(path)

        self.assertEqual(len(alerts), 1)
        self.assertIn("suspicious-demo.pth", str(alerts[0].path))

    def test_monitor_detects_new_import_pth(self) -> None:
        with temporary_workspace_dir() as site_packages:
            monitor = PthMonitor(directories=(site_packages,), snapshot={})
            suspicious = site_packages / "evil.pth"
            suspicious.write_text("import os\n", encoding="utf-8")

            alerts = monitor.inspect()

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, Severity.MEDIUM)
        self.assertEqual(alerts[0].path.name, "evil.pth")

    def test_monitor_ignores_non_import_pth(self) -> None:
        with temporary_workspace_dir() as site_packages:
            monitor = PthMonitor(directories=(site_packages,), snapshot={})
            harmless = site_packages / "harmless.pth"
            harmless.write_text("some_package\n", encoding="utf-8")

            alerts = monitor.inspect()

        self.assertEqual(alerts, [])

    def test_monitor_ignores_unchanged_existing_pth(self) -> None:
        with temporary_workspace_dir() as site_packages:
            existing = site_packages / "existing.pth"
            existing.write_text("import sys\n", encoding="utf-8")
            monitor = PthMonitor.from_install_args(["--target", str(site_packages)])

            alerts = monitor.inspect()

        self.assertEqual(alerts, [])

    def test_find_import_lines_returns_only_import_statements(self) -> None:
        with temporary_workspace_dir() as tmp:
            path = tmp / "sample.pth"
            path.write_text("pkg\n  import os\nimport sys\n", encoding="utf-8")

            lines = find_import_lines(path)

        self.assertEqual(lines, ["import os", "import sys"])

    def test_handle_alerts_deletes_pth_on_yes(self) -> None:
        with temporary_workspace_dir() as tmp:
            path = tmp / "evil.pth"
            path.write_text("import os\n", encoding="utf-8")
            alert = _alert_for(path)
            stderr = FlushingStringIO()
            stdin = io.StringIO("y\n")

            decision = handle_suspicious_pth_alerts(
                [alert],
                ignore_warning=False,
                stdin=stdin,
                stderr=stderr,
                is_tty=lambda: True,
            )

        self.assertTrue(decision.allow_install)
        self.assertEqual(decision.exit_code, 0)
        self.assertFalse(path.exists())
        self.assertIn(
            "delete suspicious .pth file(s)? enter y/n [y/N] "
            "(rerun with --spip-ignore-warning to ignore this warning):",
            stderr.getvalue(),
        )
        self.assertIn("deleted 1 suspicious .pth file(s).", stderr.getvalue())
        self.assertIn("\x1b[", stderr.getvalue())
        self.assertEqual(stderr.flush_calls, 1)
        self.assertIn(f"path: {path}", stderr.getvalue())

    def test_handle_alerts_keeps_pth_on_no(self) -> None:
        with temporary_workspace_dir() as tmp:
            path = tmp / "evil.pth"
            path.write_text("import os\n", encoding="utf-8")
            alert = _alert_for(path)
            stderr = io.StringIO()
            stdin = io.StringIO("n\n")

            decision = handle_suspicious_pth_alerts(
                [alert],
                ignore_warning=False,
                stdin=stdin,
                stderr=stderr,
                is_tty=lambda: True,
            )

            exists_after = path.exists()

        self.assertTrue(decision.allow_install)
        self.assertEqual(decision.exit_code, 0)
        self.assertTrue(exists_after)
        self.assertIn("keeping suspicious .pth file(s).", stderr.getvalue())

    def test_handle_alerts_blocks_in_non_interactive_mode(self) -> None:
        with temporary_workspace_dir() as tmp:
            path = tmp / "evil.pth"
            path.write_text("import os\n", encoding="utf-8")
            alert = _alert_for(path)
            stderr = io.StringIO()

            decision = handle_suspicious_pth_alerts(
                [alert],
                ignore_warning=False,
                stderr=stderr,
                is_tty=lambda: False,
            )

        self.assertFalse(decision.allow_install)
        self.assertEqual(decision.exit_code, 2)
        self.assertIn(
            "installation completed, but suspicious .pth files were found.",
            stderr.getvalue(),
        )
        self.assertIn("--spip-ignore-warning to ignore this warning", stderr.getvalue())
        self.assertIn("\x1b[", stderr.getvalue())

    def test_handle_alerts_ignore_warning_skips_prompt(self) -> None:
        with temporary_workspace_dir() as tmp:
            path = tmp / "evil.pth"
            path.write_text("import os\n", encoding="utf-8")
            alert = _alert_for(path)
            stderr = io.StringIO()

            decision = handle_suspicious_pth_alerts(
                [alert], ignore_warning=True, stderr=stderr
            )
            exists_after = path.exists()

        self.assertTrue(decision.allow_install)
        self.assertEqual(decision.exit_code, 0)
        self.assertTrue(exists_after)

    def test_handle_alerts_ignore_severity_suppresses_output(self) -> None:
        with temporary_workspace_dir() as tmp:
            path = tmp / "evil.pth"
            path.write_text("import os\n", encoding="utf-8")
            alert = _alert_for(path)
            stderr = io.StringIO()

            decision = handle_suspicious_pth_alerts(
                [alert],
                ignore_warning=False,
                ignore_severity=Severity.MEDIUM,
                stderr=stderr,
            )
            exists_after = path.exists()

        self.assertTrue(decision.allow_install)
        self.assertEqual(decision.exit_code, 0)
        self.assertTrue(exists_after)
        self.assertEqual(stderr.getvalue(), "")

    def test_gate_alerts_blocks_before_install_in_non_interactive_mode(self) -> None:
        alert = _alert_for(Path("artifact.whl") / "suspicious-demo.pth")
        stderr = io.StringIO()

        decision = gate_suspicious_pth_alerts(
            [alert],
            ignore_warning=False,
            sensitivity=Severity.LOW,
            stderr=stderr,
            is_tty=lambda: False,
        )

        self.assertFalse(decision.allow_install)
        self.assertEqual(decision.exit_code, 2)
        self.assertIn("suspicious-pth", stderr.getvalue())
        self.assertIn("requires confirmation", stderr.getvalue())

    def test_gate_alerts_ignore_warning_allows_install(self) -> None:
        alert = _alert_for(Path("artifact.whl") / "suspicious-demo.pth")
        stderr = io.StringIO()

        decision = gate_suspicious_pth_alerts(
            [alert],
            ignore_warning=True,
            sensitivity=Severity.LOW,
            stderr=stderr,
        )

        self.assertTrue(decision.allow_install)
        self.assertEqual(decision.exit_code, 0)
        self.assertIn("suspicious-pth", stderr.getvalue())

    def test_gate_alerts_ignore_severity_suppresses_output(self) -> None:
        alert = _alert_for(Path("artifact.whl") / "suspicious-demo.pth")
        stderr = io.StringIO()

        decision = gate_suspicious_pth_alerts(
            [alert],
            ignore_warning=False,
            ignore_severity=Severity.MEDIUM,
            sensitivity=Severity.HIGH,
            stderr=stderr,
        )

        self.assertTrue(decision.allow_install)
        self.assertEqual(decision.exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")

    def test_resolve_watch_directories_prefers_target(self) -> None:
        directories = resolve_watch_directories(["--target", "vendor"])
        self.assertEqual(directories, [Path("vendor").resolve()])

    def test_collect_package_artifact_records_reads_pth_and_entry_files(self) -> None:
        with temporary_workspace_dir() as tmp:
            site_packages = tmp / "site-packages"
            scripts = tmp / "Scripts"
            _write_installed_distribution(
                site_packages,
                scripts,
                pth_text="import demo_bootstrap\n",
                entry_point="demo:main",
            )

            records = collect_package_artifact_records(
                [FakePackage("demo", "1.0.0")],
                [site_packages],
                script_directories=[scripts],
            )

        record = records["demo"]
        self.assertEqual(record["name"], "demo")
        self.assertEqual(record["version"], "1.0.0")
        self.assertIn("site/demo.pth", record["pth_files"])
        self.assertEqual(
            record["pth_files"]["site/demo.pth"]["import_lines"],
            ["import demo_bootstrap"],
        )
        self.assertEqual(
            record["entry_points"],
            ["console_scripts:demo=demo:main"],
        )
        self.assertEqual(record["script_files"], ["scripts/demo-cli"])

    def test_collect_package_artifact_records_skips_record_for_empty_artifacts(
        self,
    ) -> None:
        with temporary_workspace_dir() as tmp:
            site_packages = tmp / "site-packages"
            dist_info = site_packages / "demo-1.0.0.dist-info"
            dist_info.mkdir(parents=True)
            (dist_info / "METADATA").write_text(
                "Name: demo\nVersion: 1.0.0\n",
                encoding="utf-8",
            )
            (dist_info / "RECORD").write_text(
                "demo-1.0.0.dist-info/METADATA,,\n",
                encoding="utf-8",
            )

            from secpipw import pth_monitor

            with patch.object(
                pth_monitor,
                "_record_paths",
                side_effect=AssertionError(
                    "empty artifact record should not read RECORD"
                ),
            ):
                records = collect_package_artifact_records(
                    [FakePackage("demo", "1.0.0")],
                    [site_packages],
                    script_directories=[],
                )

        self.assertEqual(
            records["demo"],
            {
                "name": "demo",
                "version": "1.0.0",
                "pth_files": {},
                "entry_points": [],
                "script_files": [],
            },
        )

    def test_collect_package_artifact_records_uses_exact_dist_info_without_metadata(
        self,
    ) -> None:
        with temporary_workspace_dir() as tmp:
            site_packages = tmp / "site-packages"
            dist_info = site_packages / "demo-1.0.0.dist-info"
            dist_info.mkdir(parents=True)

            from secpipw import pth_monitor

            with patch.object(
                pth_monitor,
                "_read_distribution_metadata",
                side_effect=AssertionError("exact dist-info should not read metadata"),
            ):
                records = collect_package_artifact_records(
                    [FakePackage("demo", "1.0.0")],
                    [site_packages],
                    script_directories=[],
                )

        self.assertEqual(
            records["demo"],
            {
                "name": "demo",
                "version": "1.0.0",
                "pth_files": {},
                "entry_points": [],
                "script_files": [],
            },
        )

    def test_collect_package_artifact_records_skips_unrelated_dist_info(self) -> None:
        with temporary_workspace_dir() as tmp:
            site_packages = tmp / "site-packages"
            scripts = tmp / "Scripts"
            unrelated = site_packages / "unrelated-1.0.0.dist-info"
            unrelated.mkdir(parents=True)
            (unrelated / "METADATA").write_text(
                "Name: unrelated\nVersion: 1.0.0\n",
                encoding="utf-8",
            )
            _write_installed_distribution(
                site_packages,
                scripts,
                pth_text="import demo_bootstrap\n",
                entry_point="demo:main",
            )

            from secpipw import pth_monitor

            original = pth_monitor._read_distribution_metadata

            def fail_on_unrelated(dist_info: Path) -> dict[str, str]:
                if dist_info == unrelated:
                    raise AssertionError("unrelated dist-info should not be read")
                return original(dist_info)

            with patch.object(
                pth_monitor,
                "_read_distribution_metadata",
                side_effect=fail_on_unrelated,
            ):
                records = collect_package_artifact_records(
                    [FakePackage("demo", "1.0.0")],
                    [site_packages],
                    script_directories=[scripts],
                )

        self.assertIn("demo", records)
        self.assertEqual(records["demo"]["version"], "1.0.0")

    def test_package_artifact_history_alerts_on_changed_pth_and_entry_points(
        self,
    ) -> None:
        with temporary_workspace_dir() as tmp:
            site_packages = tmp / "site-packages"
            scripts = tmp / "Scripts"
            history_path = tmp / "history.json"
            package = FakePackage("demo", "1.0.0")
            _write_installed_distribution(
                site_packages,
                scripts,
                pth_text="import demo_bootstrap\n",
                entry_point="demo:main",
            )

            first = inspect_package_artifact_history(
                [package],
                [site_packages],
                pip_args=[],
                history_path=history_path,
            )
            _write_installed_distribution(
                site_packages,
                scripts,
                pth_text="import changed_bootstrap\n",
                entry_point="demo:changed",
            )
            second = inspect_package_artifact_history(
                [package],
                [site_packages],
                pip_args=[],
                history_path=history_path,
            )

        self.assertEqual(first, [])
        self.assertEqual([alert.change_type for alert in second], ["pth", "entry"])
        self.assertEqual(second[0].severity, Severity.MEDIUM)
        self.assertEqual(second[1].severity, Severity.LOW)
        self.assertIn("changed site/demo.pth", second[0].message)
        self.assertIn("demo:changed", second[1].message)

    def test_package_artifact_history_accepts_old_record_shape(self) -> None:
        previous = {
            "name": "demo",
            "version": "1.0.0",
            "pth_files": {
                "site/demo.pth": {
                    "digest": "abc",
                    "import_lines": ["import demo_bootstrap"],
                    "size": 128,
                }
            },
            "entry_points": ["console_scripts:demo=demo:main"],
            "script_files": {
                "scripts/demo-cli": {
                    "digest": "def",
                    "size": 256,
                }
            },
        }
        current = {
            "name": "demo",
            "version": "1.0.0",
            "pth_files": {
                "site/demo.pth": {
                    "digest": "abc",
                    "import_lines": ["import demo_bootstrap"],
                }
            },
            "entry_points": ["console_scripts:demo=demo:main"],
            "script_files": ["scripts/demo-cli"],
        }

        self.assertEqual(compare_package_artifact_record(previous, current), [])

    def test_handle_package_artifact_history_alerts_renders_and_gates(self) -> None:
        stderr = io.StringIO()
        alert = _history_alert()

        decision = handle_package_artifact_history_alerts(
            [alert],
            ignore_warning=False,
            sensitivity=Severity.LOW,
            stderr=stderr,
            is_tty=lambda: False,
        )

        self.assertFalse(decision.allow_install)
        self.assertEqual(decision.exit_code, 2)
        self.assertIn("artifact-history", stderr.getvalue())
        self.assertIn("requires confirmation", stderr.getvalue())

    def test_handle_package_artifact_history_ignores_severity(self) -> None:
        stderr = io.StringIO()
        alert = _history_alert()

        decision = handle_package_artifact_history_alerts(
            [alert],
            ignore_warning=False,
            ignore_severity=Severity.MEDIUM,
            sensitivity=Severity.HIGH,
            stderr=stderr,
        )

        self.assertTrue(decision.allow_install)
        self.assertEqual(decision.exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")

    def test_rendered_alert_includes_pth_path(self) -> None:
        with temporary_workspace_dir() as tmp:
            path = tmp / "evil.pth"
            alert = _alert_for(path)

            from secpipw.pth_monitor import render_suspicious_pth_alerts

            rendered = render_suspicious_pth_alerts([alert])

        self.assertIn(f"path: {path}", rendered)


def _alert_for(path: Path):
    from secpipw.pth_monitor import SuspiciousPthAlert

    return SuspiciousPthAlert(
        severity=Severity.MEDIUM,
        path=path,
        import_lines=("import os",),
        message=f"'{path}' contains executable import statements in a .pth file",
        remediation="review and delete the .pth file if it is not expected",
    )


def _history_alert():
    from secpipw.pth_monitor import PackageArtifactHistoryAlert

    return PackageArtifactHistoryAlert(
        severity=Severity.MEDIUM,
        package_name="demo",
        previous_version="1.0.0",
        current_version="1.0.0",
        change_type="pth",
        message="'demo' installed .pth files changed: changed site/demo.pth",
    )


def _write_zip_archive(path: Path, files: dict[str, str]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)


def _write_tar_archive(path: Path, files: dict[str, str]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))


def _write_installed_distribution(
    site_packages: Path,
    scripts: Path,
    *,
    pth_text: str,
    entry_point: str,
) -> None:
    site_packages.mkdir(parents=True, exist_ok=True)
    scripts.mkdir(parents=True, exist_ok=True)
    pth_path = site_packages / "demo.pth"
    script_path = scripts / "demo-cli"
    dist_info = site_packages / "demo-1.0.0.dist-info"
    dist_info.mkdir(parents=True, exist_ok=True)

    pth_path.write_text(pth_text, encoding="utf-8")
    script_path.write_text("#!/usr/bin/env python\n", encoding="utf-8")
    (dist_info / "METADATA").write_text(
        "Name: demo\nVersion: 1.0.0\n",
        encoding="utf-8",
    )
    (dist_info / "entry_points.txt").write_text(
        f"[console_scripts]\ndemo = {entry_point}\n",
        encoding="utf-8",
    )
    (dist_info / "RECORD").write_text(
        "\n".join(
            [
                "demo.pth,,",
                "../Scripts/demo-cli,,",
                "demo-1.0.0.dist-info/METADATA,,",
                "demo-1.0.0.dist-info/entry_points.txt,,",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()
