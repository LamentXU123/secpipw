import io
import shutil
import tarfile
import unittest
import uuid
import zipfile
from contextlib import contextmanager
from pathlib import Path

from secured_pip import Severity
from secured_pip.pth_monitor import (
    PthMonitor,
    find_import_lines,
    gate_suspicious_pth_alerts,
    handle_suspicious_pth_alerts,
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
            "(rerun with --ignore-warning to ignore this warning):",
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
        self.assertIn("--ignore-warning to ignore this warning", stderr.getvalue())
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

    def test_resolve_watch_directories_prefers_target(self) -> None:
        directories = resolve_watch_directories(["--target", "vendor"])
        self.assertEqual(directories, [Path("vendor").resolve()])

    def test_rendered_alert_includes_pth_path(self) -> None:
        with temporary_workspace_dir() as tmp:
            path = tmp / "evil.pth"
            alert = _alert_for(path)

            from secured_pip.pth_monitor import render_suspicious_pth_alerts

            rendered = render_suspicious_pth_alerts([alert])

        self.assertIn(f"path: {path}", rendered)


def _alert_for(path: Path):
    from secured_pip.pth_monitor import SuspiciousPthAlert

    return SuspiciousPthAlert(
        severity=Severity.MEDIUM,
        path=path,
        import_lines=("import os",),
        message=f"'{path}' contains executable import statements in a .pth file",
        remediation="review and delete the .pth file if it is not expected",
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


if __name__ == "__main__":
    unittest.main()
