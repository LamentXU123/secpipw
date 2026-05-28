from __future__ import annotations

import threading
import time
import unittest
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import uuid
from unittest.mock import patch

from secured_pip.release_checks import (
    _DESCRIPTION_LOOKUP_CACHE,
    _REPOSITORY_MISMATCH_LOOKUP_CACHE,
    _RELEASE_LOOKUP_CACHE,
    _SUSPICIOUS_URL_LOOKUP_CACHE,
    detect_direct_url_alerts,
    detect_email_domain_drift_alerts,
    detect_empty_description_alerts,
    detect_recent_release_alerts,
    detect_repository_mismatch_alerts,
    detect_suspicious_metadata_url_alerts,
    detect_zero_version_alerts,
)
from secured_pip.pypi_api import OfficialPyPIClient
from secured_pip.severity import Severity


@dataclass(frozen=True)
class FakePackage:
    name: str
    version: str
    download_url: str | None
    artifact_name: str | None
    requested: bool = True
    is_direct: bool = False
    requires_dist: tuple[str, ...] = ()
    metadata: dict | None = None


class FakePyPIClient:
    def __init__(
        self,
        upload_times,
        contact_emails=None,
        description_fields=None,
        metadata=None,
        email_domain_history=None,
    ):
        self.upload_times = dict(upload_times)
        self.contact_emails = dict(contact_emails or {})
        self.description_fields = dict(description_fields or {})
        self.metadata = dict(metadata or {})
        self.email_domain_history = dict(email_domain_history or {})
        self.calls = []

    def fetch_release_upload_time(
        self,
        name: str,
        version: str,
        *,
        download_url: str | None = None,
        filename: str | None = None,
    ):
        self.calls.append((name, version, download_url, filename))
        return self.upload_times.get((name, version, download_url, filename))

    def fetch_release_contact_emails(self, name: str, version: str) -> tuple[str, ...]:
        return self.contact_emails.get((name, version), ())

    def fetch_release_description_fields(
        self, name: str, version: str
    ) -> tuple[str, str]:
        return self.description_fields.get((name, version), ("", ""))

    def fetch_release_metadata(self, name: str, version: str) -> dict:
        return self.metadata.get((name, version), {"info": {}})

    def load_email_domain_history(self) -> dict[str, tuple[str, ...]]:
        return self.email_domain_history

    def store_email_domain_history(self, history) -> None:
        self.email_domain_history = dict(history)

    def load_cached_release_upload_time(
        self,
        name: str,
        version: str,
        *,
        download_url: str | None = None,
        filename: str | None = None,
    ) -> tuple[bool, datetime | None]:
        return False, None

    def store_cached_release_upload_time(
        self,
        name: str,
        version: str,
        published_at: datetime | None,
        *,
        download_url: str | None = None,
        filename: str | None = None,
    ) -> None:
        return None

    @property
    def base_url(self) -> str:
        return "https://pypi.org"


class NoNetworkMetadataClient(FakePyPIClient):
    def __init__(self, *, email_domain_history=None):
        super().__init__({}, email_domain_history=email_domain_history)

    def fetch_release_contact_emails(self, name: str, version: str) -> tuple[str, ...]:
        raise AssertionError("release contact email fetch should not be called")

    def fetch_release_description_fields(
        self, name: str, version: str
    ) -> tuple[str, str]:
        raise AssertionError("release description fetch should not be called")

    def fetch_release_metadata(self, name: str, version: str) -> dict:
        raise AssertionError("release metadata fetch should not be called")


class ReleaseCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        _RELEASE_LOOKUP_CACHE.clear()
        _DESCRIPTION_LOOKUP_CACHE.clear()
        _SUSPICIOUS_URL_LOOKUP_CACHE.clear()
        _REPOSITORY_MISMATCH_LOOKUP_CACHE.clear()

    def make_temp_dir(self) -> Path:
        root = Path.cwd() / ".tmp-tests"
        root.mkdir(exist_ok=True)
        path = root / f"release-checks-{uuid.uuid4().hex}"
        path.mkdir()
        self.addCleanup(shutil.rmtree, path, True)
        return path

    def test_recent_release_raises_medium_alert(self) -> None:
        now = datetime(2026, 5, 19, 12, 0, tzinfo=timezone.utc)
        package = FakePackage(
            name="demo",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/demo-1.0.0.whl",
            artifact_name="demo-1.0.0.whl",
        )
        client = FakePyPIClient(
            {
                (
                    "demo",
                    "1.0.0",
                    "https://files.pythonhosted.org/packages/demo-1.0.0.whl",
                    "demo-1.0.0.whl",
                ): now
                - timedelta(hours=6)
            }
        )

        alerts = detect_recent_release_alerts([package], client=client, now=now)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, Severity.MEDIUM)
        self.assertIn("published 6h 0m ago", alerts[0].message)

    def test_old_release_does_not_alert(self) -> None:
        now = datetime(2026, 5, 19, 12, 0, tzinfo=timezone.utc)
        package = FakePackage(
            name="demo",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/demo-1.0.0.whl",
            artifact_name="demo-1.0.0.whl",
        )
        client = FakePyPIClient(
            {
                (
                    "demo",
                    "1.0.0",
                    "https://files.pythonhosted.org/packages/demo-1.0.0.whl",
                    "demo-1.0.0.whl",
                ): now
                - timedelta(days=2)
            }
        )

        alerts = detect_recent_release_alerts([package], client=client, now=now)

        self.assertEqual(alerts, [])

    def test_two_day_threshold_is_still_recent_but_exact_boundary_is_not(self) -> None:
        now = datetime(2026, 5, 19, 12, 0, tzinfo=timezone.utc)
        recent = FakePackage(
            name="recent",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/recent-1.0.0.whl",
            artifact_name="recent-1.0.0.whl",
        )
        boundary = FakePackage(
            name="boundary",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/boundary-1.0.0.whl",
            artifact_name="boundary-1.0.0.whl",
        )
        client = FakePyPIClient(
            {
                (
                    "recent",
                    "1.0.0",
                    "https://files.pythonhosted.org/packages/recent-1.0.0.whl",
                    "recent-1.0.0.whl",
                ): now
                - timedelta(days=1, hours=23, minutes=59),
                (
                    "boundary",
                    "1.0.0",
                    "https://files.pythonhosted.org/packages/boundary-1.0.0.whl",
                    "boundary-1.0.0.whl",
                ): now
                - timedelta(days=2),
            }
        )

        alerts = detect_recent_release_alerts(
            [recent, boundary],
            client=client,
            now=now,
        )

        self.assertEqual([alert.package_name for alert in alerts], ["recent"])

    def test_recent_release_checks_only_requested_packages(self) -> None:
        now = datetime(2026, 5, 19, 12, 0, tzinfo=timezone.utc)
        requested = FakePackage(
            name="top-level",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/top-level-1.0.0.whl",
            artifact_name="top-level-1.0.0.whl",
            requested=True,
        )
        dependency = FakePackage(
            name="transitive",
            version="2.0.0",
            download_url="https://files.pythonhosted.org/packages/transitive-2.0.0.whl",
            artifact_name="transitive-2.0.0.whl",
            requested=False,
        )
        client = FakePyPIClient(
            {
                (
                    "top-level",
                    "1.0.0",
                    "https://files.pythonhosted.org/packages/top-level-1.0.0.whl",
                    "top-level-1.0.0.whl",
                ): now
                - timedelta(hours=4),
                (
                    "transitive",
                    "2.0.0",
                    "https://files.pythonhosted.org/packages/transitive-2.0.0.whl",
                    "transitive-2.0.0.whl",
                ): now
                - timedelta(hours=8),
            }
        )

        alerts = detect_recent_release_alerts(
            [requested, dependency],
            client=client,
            now=now,
        )

        self.assertEqual(len(alerts), 2)
        self.assertEqual(
            [alert.package_name for alert in alerts],
            ["top-level", "transitive"],
        )
        self.assertEqual(len(client.calls), 2)
        self.assertEqual(
            [call[0] for call in client.calls], ["top-level", "transitive"]
        )

    def test_recent_release_deduplicates_name_version_lookups(self) -> None:
        now = datetime(2026, 5, 19, 12, 0, tzinfo=timezone.utc)
        first = FakePackage(
            name="demo",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/demo-1.0.0.whl",
            artifact_name="demo-1.0.0.whl",
            requested=True,
        )
        second = FakePackage(
            name="demo",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/demo-1.0.0.whl",
            artifact_name="demo-1.0.0.whl",
            requested=False,
        )
        client = FakePyPIClient(
            {
                (
                    "demo",
                    "1.0.0",
                    "https://files.pythonhosted.org/packages/demo-1.0.0.whl",
                    "demo-1.0.0.whl",
                ): now
                - timedelta(hours=5),
            }
        )

        alerts = detect_recent_release_alerts([first, second], client=client, now=now)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            client.calls, [("demo", "1.0.0", first.download_url, first.artifact_name)]
        )

    def test_recent_release_uses_disk_cache_before_network(self) -> None:
        now = datetime(2026, 5, 19, 12, 0, tzinfo=timezone.utc)
        package = FakePackage(
            name="demo",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/demo-1.0.0.whl",
            artifact_name="demo-1.0.0.whl",
        )

        tmpdir = self.make_temp_dir()
        client = OfficialPyPIClient(release_cache_path=tmpdir / "release-times.json")
        client.store_cached_release_upload_time(
            "demo",
            "1.0.0",
            now - timedelta(hours=3),
            download_url=package.download_url,
            filename=package.artifact_name,
        )

        with patch.object(
            OfficialPyPIClient,
            "fetch_release_upload_time",
            side_effect=AssertionError("network should not be used"),
        ):
            alerts = detect_recent_release_alerts([package], client=client, now=now)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, Severity.MEDIUM)

    def test_recent_release_runs_lookups_concurrently(self) -> None:
        now = datetime(2026, 5, 19, 12, 0, tzinfo=timezone.utc)
        packages = [
            FakePackage(
                name=f"demo-{index}",
                version="1.0.0",
                download_url=f"https://files.pythonhosted.org/packages/demo-{index}-1.0.0.whl",
                artifact_name=f"demo-{index}-1.0.0.whl",
            )
            for index in range(3)
        ]

        class SlowClient:
            def __init__(self) -> None:
                self.active = 0
                self.max_active = 0
                self.lock = threading.Lock()

            @property
            def base_url(self) -> str:
                return "https://pypi.org"

            def load_cached_release_upload_time(self, *args, **kwargs):
                return False, None

            def store_cached_release_upload_time(self, *args, **kwargs):
                return None

            def fetch_release_upload_time(self, *args, **kwargs):
                with self.lock:
                    self.active += 1
                    self.max_active = max(self.max_active, self.active)
                try:
                    time.sleep(0.05)
                    return now - timedelta(hours=4)
                finally:
                    with self.lock:
                        self.active -= 1

        client = SlowClient()

        alerts = detect_recent_release_alerts(packages, client=client, now=now)

        self.assertEqual(len(alerts), 3)
        self.assertGreater(client.max_active, 1)

    def test_recent_release_ignores_client_errors(self) -> None:
        now = datetime(2026, 5, 19, 12, 0, tzinfo=timezone.utc)
        package = FakePackage(
            name="demo",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/demo-1.0.0.whl",
            artifact_name="demo-1.0.0.whl",
        )

        class FailingClient:
            @property
            def base_url(self) -> str:
                return "https://pypi.org"

            def load_cached_release_upload_time(self, *args, **kwargs):
                return False, None

            def store_cached_release_upload_time(self, *args, **kwargs):
                return None

            def fetch_release_upload_time(self, *args, **kwargs):
                raise TimeoutError("timed out")

        alerts = detect_recent_release_alerts(
            [package],
            client=FailingClient(),
            now=now,
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, Severity.LOW)
        self.assertIn("PyPI timed out", alerts[0].message)

    def test_recent_release_checks_private_index_artifact_when_not_direct(self) -> None:
        now = datetime(2026, 5, 19, 12, 0, tzinfo=timezone.utc)
        package = FakePackage(
            name="demo",
            version="1.0.0",
            download_url="https://mirror.example/simple/demo-1.0.0.whl",
            artifact_name="demo-1.0.0.whl",
        )
        client = FakePyPIClient(
            {
                (
                    "demo",
                    "1.0.0",
                    "https://mirror.example/simple/demo-1.0.0.whl",
                    "demo-1.0.0.whl",
                ): now
                - timedelta(hours=2)
            }
        )

        alerts = detect_recent_release_alerts([package], client=client, now=now)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, Severity.MEDIUM)

    def test_zero_version_raises_low_alert(self) -> None:
        package = FakePackage(
            name="demo",
            version="0.0.0",
            download_url="https://files.pythonhosted.org/packages/demo-0.0.0.whl",
            artifact_name="demo-0.0.0.whl",
        )

        alerts = detect_zero_version_alerts([package])

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, Severity.LOW)
        self.assertIn("zero release version", alerts[0].message)

    def test_empty_description_raises_low_alert_when_summary_and_description_are_empty(
        self,
    ) -> None:
        package = FakePackage(
            name="demo",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/demo-1.0.0.whl",
            artifact_name="demo-1.0.0.whl",
        )
        client = FakePyPIClient(
            {},
            description_fields={("demo", "1.0.0"): ("", "   ")},
        )

        alerts = detect_empty_description_alerts([package], client=client)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, Severity.LOW)
        self.assertIn("empty description", alerts[0].message)

    def test_empty_description_treats_unknown_as_empty(self) -> None:
        package = FakePackage(
            name="demo",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/demo-1.0.0.whl",
            artifact_name="demo-1.0.0.whl",
        )
        client = FakePyPIClient(
            {},
            description_fields={("demo", "1.0.0"): ("UNKNOWN", "unknown")},
        )

        alerts = detect_empty_description_alerts([package], client=client)

        self.assertEqual(len(alerts), 1)

    def test_empty_description_uses_package_metadata_without_client_fetch(self) -> None:
        package = FakePackage(
            name="demo",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/demo-1.0.0.whl",
            artifact_name="demo-1.0.0.whl",
            metadata={"summary": "UNKNOWN", "description": "   "},
        )

        alerts = detect_empty_description_alerts(
            [package],
            client=NoNetworkMetadataClient(),
        )

        self.assertEqual(len(alerts), 1)
        self.assertIn("empty description", alerts[0].message)

    def test_empty_description_does_not_alert_when_summary_is_present(self) -> None:
        package = FakePackage(
            name="demo",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/demo-1.0.0.whl",
            artifact_name="demo-1.0.0.whl",
        )
        client = FakePyPIClient(
            {},
            description_fields={("demo", "1.0.0"): ("Useful package", "")},
        )

        alerts = detect_empty_description_alerts([package], client=client)

        self.assertEqual(alerts, [])

    def test_direct_url_alerts_for_pip_args_and_transitive_requirements(self) -> None:
        package = FakePackage(
            name="demo",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/demo-1.0.0.whl",
            artifact_name="demo-1.0.0.whl",
            requires_dist=("dep @ https://example.test/dep-1.0.0.whl",),
        )

        alerts = detect_direct_url_alerts(
            ["git+https://example.test/demo.git"], [package]
        )

        self.assertEqual(len(alerts), 2)
        self.assertTrue(all(alert.severity == Severity.MEDIUM for alert in alerts))
        self.assertIn("direct URL", alerts[0].message)
        self.assertIn("declares direct URL dependency", alerts[1].message)

    def test_direct_url_alerts_ignore_index_urls(self) -> None:
        alerts = detect_direct_url_alerts(
            ["-i", "https://mirror.example/simple", "requests"],
            [],
        )

        self.assertEqual(alerts, [])

    def test_suspicious_metadata_url_alerts_for_shortener_and_raw_ip(self) -> None:
        package = FakePackage(
            name="demo",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/demo-1.0.0.whl",
            artifact_name="demo-1.0.0.whl",
        )
        client = FakePyPIClient(
            {},
            metadata={
                ("demo", "1.0.0"): {
                    "info": {
                        "home_page": "https://bit.ly/demo",
                        "project_urls": {"Docs": "https://192.0.2.1/docs"},
                    }
                }
            },
        )

        alerts = detect_suspicious_metadata_url_alerts([package], client=client)

        self.assertEqual(len(alerts), 2)
        self.assertTrue(all(alert.severity == Severity.LOW for alert in alerts))
        self.assertIn("shortener", alerts[0].message)
        self.assertIn("raw IP", alerts[1].message)

    def test_suspicious_metadata_url_uses_package_metadata_without_client_fetch(
        self,
    ) -> None:
        package = FakePackage(
            name="demo",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/demo-1.0.0.whl",
            artifact_name="demo-1.0.0.whl",
            metadata={
                "home_page": "https://bit.ly/demo",
                "project_url": ["Docs, https://192.0.2.1/docs"],
            },
        )

        alerts = detect_suspicious_metadata_url_alerts(
            [package],
            client=NoNetworkMetadataClient(),
        )

        self.assertEqual(len(alerts), 2)
        self.assertIn("shortener", alerts[0].message)
        self.assertIn("raw IP", alerts[1].message)

    def test_repository_mismatch_alerts_when_repo_name_is_unrelated(self) -> None:
        package = FakePackage(
            name="demo-package",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/demo-package-1.0.0.whl",
            artifact_name="demo-package-1.0.0.whl",
        )
        client = FakePyPIClient(
            {},
            metadata={
                ("demo-package", "1.0.0"): {
                    "info": {
                        "project_urls": {
                            "Source": "https://github.com/example/unrelated-tool"
                        }
                    }
                }
            },
        )

        alerts = detect_repository_mismatch_alerts([package], client=client)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, Severity.LOW)
        self.assertIn("appears unrelated", alerts[0].message)

    def test_repository_mismatch_uses_package_metadata_without_client_fetch(
        self,
    ) -> None:
        package = FakePackage(
            name="demo-package",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/demo-package-1.0.0.whl",
            artifact_name="demo-package-1.0.0.whl",
            metadata={
                "project_url": ["Source, https://github.com/example/unrelated-tool"],
            },
        )

        alerts = detect_repository_mismatch_alerts(
            [package],
            client=NoNetworkMetadataClient(),
        )

        self.assertEqual(len(alerts), 1)
        self.assertIn("unrelated-tool", alerts[0].message)

    def test_repository_mismatch_allows_related_repo_name(self) -> None:
        package = FakePackage(
            name="demo-package",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/demo-package-1.0.0.whl",
            artifact_name="demo-package-1.0.0.whl",
        )
        client = FakePyPIClient(
            {},
            metadata={
                ("demo-package", "1.0.0"): {
                    "info": {
                        "project_urls": {
                            "Source": "https://github.com/example/demo-package"
                        }
                    }
                }
            },
        )

        alerts = detect_repository_mismatch_alerts([package], client=client)

        self.assertEqual(alerts, [])

    def test_repository_mismatch_allows_similar_repeated_character_names(self) -> None:
        package = FakePackage(
            name="aaaaab",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/aaaaab-1.0.0.whl",
            artifact_name="aaaaab-1.0.0.whl",
        )
        client = FakePyPIClient(
            {},
            metadata={
                ("aaaaab", "1.0.0"): {
                    "info": {
                        "project_urls": {"Source": "https://github.com/example/aaaaac"}
                    }
                }
            },
        )

        alerts = detect_repository_mismatch_alerts([package], client=client)

        self.assertEqual(alerts, [])

    def test_email_domain_drift_alerts_when_domain_changes(self) -> None:
        package = FakePackage(
            name="demo",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/demo-1.0.0.whl",
            artifact_name="demo-1.0.0.whl",
        )
        client = FakePyPIClient(
            {},
            contact_emails={("demo", "1.0.0"): ("maintainer@example.org",)},
            email_domain_history={"demo": ("old.example",)},
        )

        alerts = detect_email_domain_drift_alerts([package], client=client)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, Severity.LOW)
        self.assertIn("changed from old.example to example.org", alerts[0].message)
        self.assertEqual(client.email_domain_history["demo"], ("example.org",))

    def test_email_domain_drift_uses_package_metadata_without_client_fetch(
        self,
    ) -> None:
        package = FakePackage(
            name="demo",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/demo-1.0.0.whl",
            artifact_name="demo-1.0.0.whl",
            metadata={"maintainer_email": "maintainer@example.org"},
        )
        client = NoNetworkMetadataClient(
            email_domain_history={"demo": ("old.example",)},
        )

        alerts = detect_email_domain_drift_alerts([package], client=client)

        self.assertEqual(len(alerts), 1)
        self.assertIn("changed from old.example to example.org", alerts[0].message)
        self.assertEqual(client.email_domain_history["demo"], ("example.org",))

    def test_email_domain_drift_records_first_seen_domain_without_alert(self) -> None:
        package = FakePackage(
            name="demo",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/demo-1.0.0.whl",
            artifact_name="demo-1.0.0.whl",
        )
        client = FakePyPIClient(
            {},
            contact_emails={("demo", "1.0.0"): ("maintainer@example.org",)},
        )

        alerts = detect_email_domain_drift_alerts([package], client=client)

        self.assertEqual(alerts, [])
        self.assertEqual(client.email_domain_history["demo"], ("example.org",))

    def test_non_zero_major_zero_version_does_not_alert(self) -> None:
        package = FakePackage(
            name="demo",
            version="0.1.0",
            download_url="https://files.pythonhosted.org/packages/demo-0.1.0.whl",
            artifact_name="demo-0.1.0.whl",
        )

        alerts = detect_zero_version_alerts([package])

        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
