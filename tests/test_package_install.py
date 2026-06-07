from __future__ import annotations

import shutil
import unittest
from pathlib import Path
from uuid import uuid4

from secpipw.package_install import (
    download_artifact,
    forwarded_install_args,
    install_resolved_packages,
    topological_install_order,
)


class FakePackage:
    def __init__(
        self,
        name: str,
        version: str,
        *,
        download_url: str | None = None,
        artifact_name: str | None = None,
        archive_hash: str | None = None,
        requires_dist: tuple[str, ...] = (),
    ) -> None:
        self.name = name
        self.version = version
        self.download_url = download_url
        self.artifact_name = artifact_name
        self.archive_hash = archive_hash
        self.requires_dist = requires_dist


class PackageInstallTests(unittest.TestCase):
    def test_topological_install_order_installs_dependencies_first(self) -> None:
        urllib3 = FakePackage("urllib3", "2.0.0")
        charset = FakePackage("charset-normalizer", "3.0.0")
        requests = FakePackage(
            "requests",
            "2.31.0",
            requires_dist=("urllib3>=2", "charset-normalizer>=3"),
        )

        ordered = topological_install_order((requests, urllib3, charset))

        self.assertEqual(
            [package.name for package in ordered],
            ["urllib3", "charset-normalizer", "requests"],
        )

    def test_topological_install_order_preserves_input_order_for_ready_packages(
        self,
    ) -> None:
        packages = tuple(
            FakePackage(f"package-{index}", "1.0.0") for index in range(50)
        )

        ordered = topological_install_order(packages)

        self.assertEqual(ordered, packages)

    def test_forwarded_install_args_strips_resolution_inputs(self) -> None:
        forwarded = forwarded_install_args(
            [
                "-r",
                "requirements.txt",
                "--index-url",
                "https://example.com/simple",
                "--upgrade",
                "--target",
                "vendor",
                "--python",
                "C:\\Python312\\python.exe",
                "--user",
                "requests",
            ]
        )

        self.assertEqual(
            forwarded,
            ["--target", "vendor", "--python", "C:\\Python312\\python.exe", "--user"],
        )

    def test_download_artifact_copies_file_url(self) -> None:
        root = Path(".tmp-package-install-tests") / uuid4().hex
        source_dir = root / "src"
        destination_dir = root / "dst"
        source_dir.mkdir(parents=True, exist_ok=True)
        destination_dir.mkdir(parents=True, exist_ok=True)
        try:
            source_path = source_dir / "demo.whl"
            source_path.write_bytes(b"wheel-bytes")
            package = FakePackage(
                "demo",
                "1.0.0",
                download_url=source_path.resolve().as_uri(),
                artifact_name="demo.whl",
            )

            artifact = download_artifact(package, destination_dir)

            self.assertTrue(artifact.path.exists())
            self.assertEqual(artifact.path.read_bytes(), b"wheel-bytes")
        finally:
            if root.exists():
                shutil.rmtree(root, ignore_errors=True)

    def test_install_resolved_packages_installs_exact_report_urls_without_deps(
        self,
    ) -> None:
        requests = FakePackage(
            "requests",
            "2.31.0",
            download_url="https://files.pythonhosted.org/packages/requests.whl",
            archive_hash="sha256=reqhash",
            requires_dist=("urllib3>=2",),
        )
        urllib3 = FakePackage(
            "urllib3",
            "2.2.1",
            download_url="https://files.pythonhosted.org/packages/urllib3.whl",
            archive_hash="sha256=urlhash",
        )

        from unittest.mock import patch

        with patch(
            "secpipw.package_install._run_pip_internal", return_value=0
        ) as run:
            rc = install_resolved_packages(
                [requests, urllib3],
                [
                    "requests",
                    "--target",
                    "vendor",
                    "--index-url",
                    "https://example/simple",
                ],
            )

        self.assertEqual(rc, 0)
        run.assert_called_once_with(
            [
                "install",
                "--disable-pip-version-check",
                "--no-deps",
                "--target",
                "vendor",
                "https://files.pythonhosted.org/packages/urllib3.whl#sha256=urlhash",
                "https://files.pythonhosted.org/packages/requests.whl#sha256=reqhash",
            ]
        )

    def test_install_resolved_packages_noops_when_plan_is_empty(self) -> None:
        from unittest.mock import patch

        with patch("secpipw.package_install._run_pip_internal") as run:
            rc = install_resolved_packages([], ["requests"])

        self.assertEqual(rc, 0)
        run.assert_not_called()

    def test_install_resolved_packages_requires_report_download_url(self) -> None:
        package = FakePackage("demo", "1.0.0")

        with self.assertRaises(RuntimeError) as context:
            install_resolved_packages([package], [])

        self.assertIn("missing download URL", str(context.exception))


if __name__ == "__main__":
    unittest.main()
