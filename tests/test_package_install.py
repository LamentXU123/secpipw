from __future__ import annotations

import shutil
import unittest
from pathlib import Path
from uuid import uuid4

from spip.package_install import download_artifact, forwarded_install_args, topological_install_order


class FakePackage:
    def __init__(
        self,
        name: str,
        version: str,
        *,
        download_url: str | None = None,
        artifact_name: str | None = None,
        requires_dist: tuple[str, ...] = (),
    ) -> None:
        self.name = name
        self.version = version
        self.download_url = download_url
        self.artifact_name = artifact_name
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


if __name__ == "__main__":
    unittest.main()
