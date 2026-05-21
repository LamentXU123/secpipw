from __future__ import annotations

import unittest
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from spip.release_checks import (
    _RELEASE_LOOKUP_CACHE,
    detect_recent_release_alerts,
    detect_zero_version_alerts,
)
from spip.severity import Severity


@dataclass(frozen=True)
class FakePackage:
    name: str
    version: str
    download_url: str | None
    artifact_name: str | None
    requested: bool = True


class FakePyPIClient:
    def __init__(self, upload_times):
        self.upload_times = dict(upload_times)
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


class ReleaseCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        _RELEASE_LOOKUP_CACHE.clear()

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
                ): now - timedelta(hours=6)
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
                ): now - timedelta(days=2)
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
                ): now - timedelta(days=1, hours=23, minutes=59),
                (
                    "boundary",
                    "1.0.0",
                    "https://files.pythonhosted.org/packages/boundary-1.0.0.whl",
                    "boundary-1.0.0.whl",
                ): now - timedelta(days=2),
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
                ): now - timedelta(hours=4),
                (
                    "transitive",
                    "2.0.0",
                    "https://files.pythonhosted.org/packages/transitive-2.0.0.whl",
                    "transitive-2.0.0.whl",
                ): now - timedelta(hours=8),
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
        self.assertEqual([call[0] for call in client.calls], ["top-level", "transitive"])

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
                ): now - timedelta(hours=5),
            }
        )

        alerts = detect_recent_release_alerts([first, second], client=client, now=now)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(client.calls, [("demo", "1.0.0", first.download_url, first.artifact_name)])

    def test_recent_release_ignores_client_errors(self) -> None:
        now = datetime(2026, 5, 19, 12, 0, tzinfo=timezone.utc)
        package = FakePackage(
            name="demo",
            version="1.0.0",
            download_url="https://files.pythonhosted.org/packages/demo-1.0.0.whl",
            artifact_name="demo-1.0.0.whl",
        )

        class FailingClient:
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
