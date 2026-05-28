from __future__ import annotations

import json
import shutil
import socket
import unittest
import uuid
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from urllib.error import HTTPError, URLError
from unittest.mock import patch

from secured_pip import pypi_api
from secured_pip.pypi_api import (
    BOOTSTRAP_PROJECT_NAMES,
    DEFAULT_PYPI_BASE_URL,
    DEFAULT_JSON_API_TIMEOUT_SECONDS,
    OfficialPyPIClient,
    client_from_pip_args,
    resolve_index_url,
)


class FakeHTTPResponse:
    def __init__(self, payload: object | bytes = b"") -> None:
        if isinstance(payload, bytes):
            self._body = payload
        else:
            self._body = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> FakeHTTPResponse:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


def build_http_error(code: int) -> HTTPError:
    return HTTPError(
        url="https://pypi.org/pypi/demo/json",
        code=code,
        msg="error",
        hdrs=None,
        fp=BytesIO(b""),
    )


class OfficialPyPIClientTests(unittest.TestCase):
    def make_temp_dir(self) -> Path:
        root = Path.cwd() / ".tmp-tests"
        root.mkdir(exist_ok=True)
        path = root / f"pypi-api-{uuid.uuid4().hex}"
        path.mkdir()
        self.addCleanup(shutil.rmtree, path, True)
        return path

    def test_load_reference_package_names_merges_remote_with_bootstrap(self) -> None:
        client = OfficialPyPIClient()

        with patch.object(
            OfficialPyPIClient,
            "fetch_reference_package_names",
            return_value=["requests", "demo-package"],
        ):
            names = client.load_reference_package_names()

        self.assertIn("demo-package", names)
        self.assertIn("requests", names)
        self.assertEqual(names, sorted(set(names)))

    def test_load_reference_package_names_falls_back_to_cached_names_on_timeout(
        self,
    ) -> None:
        client = OfficialPyPIClient()

        with (
            patch.object(
                OfficialPyPIClient,
                "fetch_reference_package_names",
                side_effect=URLError(socket.timeout("timed out")),
            ),
            patch.object(
                OfficialPyPIClient,
                "load_cached_project_names",
                return_value=["cached-project"],
            ) as load_cached,
        ):
            names = client.load_reference_package_names()

        self.assertEqual(names, ["cached-project"])
        load_cached.assert_called_once_with()

    def test_load_reference_package_names_reraises_non_timeout_errors(self) -> None:
        client = OfficialPyPIClient()

        with patch.object(
            OfficialPyPIClient,
            "fetch_reference_package_names",
            side_effect=RuntimeError("boom"),
        ):
            with self.assertRaises(RuntimeError):
                client.load_reference_package_names()

    def test_fetch_all_project_names_parses_simple_index_response(self) -> None:
        client = OfficialPyPIClient(base_url="https://example.test")
        payload = {"projects": [{"name": "zeta"}, {"name": "alpha"}]}

        with patch(
            "secured_pip.pypi_api.urlopen", return_value=FakeHTTPResponse(payload)
        ) as mocked:
            names = client.fetch_all_project_names()

        self.assertEqual(names, ["alpha", "zeta"])
        request = mocked.call_args.args[0]
        self.assertEqual(request.full_url, "https://example.test/simple/")

    def test_load_cached_project_names_prefers_explicit_cache_path(self) -> None:
        tmpdir = self.make_temp_dir()
        cache_path = tmpdir / "pypi-project-names.json"
        cache_path.write_text(
            json.dumps({"projects": ["zeta", "alpha"]}),
            encoding="utf-8",
        )
        client = OfficialPyPIClient(cache_path=cache_path)

        names = client.load_cached_project_names()

        self.assertEqual(names, ["alpha", "zeta"])

    def test_load_cached_project_names_falls_back_to_bootstrap_cache_file(self) -> None:
        tmpdir = self.make_temp_dir()
        bootstrap_cache = tmpdir / "bootstrap.json"
        bootstrap_cache.write_text(
            json.dumps({"projects": ["zeta", "alpha"]}),
            encoding="utf-8",
        )
        client = OfficialPyPIClient(cache_path=tmpdir / "missing.json")

        with patch.object(pypi_api, "BOOTSTRAP_CACHE_PATH", bootstrap_cache):
            names = client.load_cached_project_names()

        self.assertEqual(names, ["alpha", "zeta"])

    def test_load_cached_project_names_falls_back_to_embedded_bootstrap_names(
        self,
    ) -> None:
        tmpdir = self.make_temp_dir()
        client = OfficialPyPIClient(cache_path=tmpdir / "missing.json")

        with patch.object(
            pypi_api, "BOOTSTRAP_CACHE_PATH", tmpdir / "also-missing.json"
        ):
            names = client.load_cached_project_names()

        self.assertEqual(names, sorted(BOOTSTRAP_PROJECT_NAMES))

    def test_refresh_project_name_cache_writes_expected_payload(self) -> None:
        tmpdir = self.make_temp_dir()
        cache_path = tmpdir / ".spip-cache" / "pypi-project-names.json"
        client = OfficialPyPIClient(cache_path=cache_path)

        with patch.object(
            OfficialPyPIClient,
            "fetch_all_project_names",
            return_value=["zeta", "alpha"],
        ):
            count = client.refresh_project_name_cache()

        payload = json.loads(cache_path.read_text(encoding="utf-8"))

        self.assertEqual(count, 2)
        self.assertEqual(payload["source"], "https://pypi.org/simple/")
        self.assertEqual(payload["project_count"], 2)
        self.assertEqual(payload["projects"], ["alpha", "zeta"])

    def test_project_exists_returns_true_when_json_endpoint_resolves(self) -> None:
        client = OfficialPyPIClient(base_url="https://example.test")

        with patch("secured_pip.pypi_api.urlopen", return_value=FakeHTTPResponse()):
            self.assertTrue(client.project_exists("demo"))

    def test_project_exists_returns_false_on_404(self) -> None:
        client = OfficialPyPIClient()

        with patch("secured_pip.pypi_api.urlopen", side_effect=build_http_error(404)):
            self.assertFalse(client.project_exists("missing"))

    def test_project_exists_reraises_non_404_http_errors(self) -> None:
        client = OfficialPyPIClient()

        with patch("secured_pip.pypi_api.urlopen", side_effect=build_http_error(500)):
            with self.assertRaises(HTTPError):
                client.project_exists("broken")

    def test_project_exists_with_fallback_uses_cache_on_timeout(self) -> None:
        client = OfficialPyPIClient()

        with (
            patch.object(
                OfficialPyPIClient,
                "project_exists",
                side_effect=URLError(socket.timeout("timed out")),
            ),
            patch.object(
                OfficialPyPIClient,
                "load_cached_project_names",
                return_value=["Requests", "NumPy"],
            ),
        ):
            self.assertTrue(client.project_exists_with_fallback("requests"))
            self.assertFalse(client.project_exists_with_fallback("pandas"))

    def test_release_upload_time_cache_round_trip(self) -> None:
        tmpdir = self.make_temp_dir()
        cache_path = tmpdir / "release-times.json"
        client = OfficialPyPIClient(release_cache_path=cache_path)
        published_at = datetime(2026, 5, 19, 10, 0, tzinfo=timezone.utc)

        client.store_cached_release_upload_time(
            "demo",
            "1.0.0",
            published_at,
            download_url="https://files.example/demo.whl",
            filename="demo.whl",
        )

        hit, loaded = client.load_cached_release_upload_time(
            "demo",
            "1.0.0",
            download_url="https://files.example/demo.whl",
            filename="demo.whl",
        )

        self.assertTrue(hit)
        self.assertEqual(loaded, published_at)

    def test_email_domain_history_round_trip(self) -> None:
        tmpdir = self.make_temp_dir()
        history_path = tmpdir / "email-domains.json"
        client = OfficialPyPIClient(email_domain_history_path=history_path)

        client.store_email_domain_history(
            {
                "Demo": {"Example.org", "example.org"},
                "other": {"maintainer.example"},
            }
        )

        history = client.load_email_domain_history()

        self.assertEqual(
            history,
            {
                "demo": ("example.org",),
                "other": ("maintainer.example",),
            },
        )

    def test_fetch_release_metadata_uses_shorter_timeout(self) -> None:
        client = OfficialPyPIClient(base_url="https://example.test")

        with patch(
            "secured_pip.pypi_api.urlopen", return_value=FakeHTTPResponse({"urls": []})
        ) as mocked:
            client.fetch_release_metadata("demo", "1.0.0")

        self.assertEqual(
            mocked.call_args.kwargs["timeout"], DEFAULT_JSON_API_TIMEOUT_SECONDS
        )

    def test_fetch_release_upload_time_prefers_download_url_match(self) -> None:
        client = OfficialPyPIClient()
        older = "2026-05-18T10:00:00Z"
        newer = "2026-05-19T10:00:00Z"

        with patch.object(
            OfficialPyPIClient,
            "fetch_release_metadata",
            return_value={
                "urls": [
                    {
                        "url": "https://files.example/demo-old.whl",
                        "filename": "demo-old.whl",
                        "upload_time_iso_8601": older,
                    },
                    {
                        "url": "https://files.example/demo-new.whl",
                        "filename": "demo-new.whl",
                        "upload_time_iso_8601": newer,
                    },
                ]
            },
        ):
            upload_time = client.fetch_release_upload_time(
                "demo",
                "1.0.0",
                download_url="https://files.example/demo-old.whl",
            )

        self.assertEqual(
            upload_time,
            datetime(2026, 5, 18, 10, 0, tzinfo=timezone.utc),
        )

    def test_fetch_release_upload_time_prefers_filename_match(self) -> None:
        client = OfficialPyPIClient()

        with patch.object(
            OfficialPyPIClient,
            "fetch_release_metadata",
            return_value={
                "urls": [
                    {
                        "url": "https://files.example/demo-a.whl",
                        "filename": "demo-a.whl",
                        "upload_time_iso_8601": "2026-05-18T10:00:00Z",
                    },
                    {
                        "url": "https://files.example/demo-b.whl",
                        "filename": "demo-b.whl",
                        "upload_time_iso_8601": "2026-05-19T10:00:00Z",
                    },
                ]
            },
        ):
            upload_time = client.fetch_release_upload_time(
                "demo",
                "1.0.0",
                filename="demo-a.whl",
            )

        self.assertEqual(
            upload_time,
            datetime(2026, 5, 18, 10, 0, tzinfo=timezone.utc),
        )

    def test_fetch_release_upload_time_falls_back_to_latest_upload(self) -> None:
        client = OfficialPyPIClient()

        with patch.object(
            OfficialPyPIClient,
            "fetch_release_metadata",
            return_value={
                "urls": [
                    {
                        "url": "https://files.example/demo-a.whl",
                        "filename": "demo-a.whl",
                        "upload_time_iso_8601": "2026-05-18T10:00:00Z",
                    },
                    {
                        "url": "https://files.example/demo-b.whl",
                        "filename": "demo-b.whl",
                        "upload_time_iso_8601": "2026-05-19T10:00:00Z",
                    },
                ]
            },
        ):
            upload_time = client.fetch_release_upload_time("demo", "1.0.0")

        self.assertEqual(
            upload_time,
            datetime(2026, 5, 19, 10, 0, tzinfo=timezone.utc),
        )

    def test_fetch_release_upload_time_returns_none_when_release_has_no_files(
        self,
    ) -> None:
        client = OfficialPyPIClient()

        with patch.object(
            OfficialPyPIClient,
            "fetch_release_metadata",
            return_value={"urls": []},
        ):
            upload_time = client.fetch_release_upload_time("demo", "1.0.0")

        self.assertIsNone(upload_time)

    def test_fetch_release_description_fields_reads_summary_and_description(
        self,
    ) -> None:
        client = OfficialPyPIClient()

        with patch.object(
            OfficialPyPIClient,
            "fetch_release_metadata",
            return_value={
                "info": {
                    "summary": "Short summary",
                    "description": "Long description",
                }
            },
        ):
            summary, description = client.fetch_release_description_fields(
                "demo", "1.0.0"
            )

        self.assertEqual(summary, "Short summary")
        self.assertEqual(description, "Long description")

    def test_fetch_release_metadata_does_not_fall_back_to_official_pypi(
        self,
    ) -> None:
        client = OfficialPyPIClient(base_url="https://mirror.example/simple")
        with patch(
            "secured_pip.pypi_api.urlopen",
            side_effect=build_http_error(404),
        ) as mocked:
            with self.assertRaises(HTTPError):
                client.fetch_release_metadata("demo", "1.0.0")

        self.assertEqual(len(mocked.call_args_list), 1)
        request = mocked.call_args_list[0].args[0]
        self.assertEqual(
            request.full_url,
            "https://mirror.example/simple/pypi/demo/1.0.0/json",
        )

    def test_resolve_index_url_prefers_cli_over_env_and_config(self) -> None:
        tmpdir = self.make_temp_dir()
        config_path = tmpdir / "pip.conf"
        config_path.write_text(
            "[global]\nindex-url = https://config.example/simple\n", encoding="utf-8"
        )

        index_url = resolve_index_url(
            ["install", "-i", "https://cli.example/simple"],
            env={
                "PIP_INDEX_URL": "https://env.example/simple",
                "PIP_CONFIG_FILE": str(config_path),
            },
        )

        self.assertEqual(index_url, "https://cli.example/simple")

    def test_resolve_index_url_reads_pip_config_file(self) -> None:
        tmpdir = self.make_temp_dir()
        config_path = tmpdir / "pip.ini"
        config_path.write_text(
            "[install]\nindex-url = https://config.example/simple\n", encoding="utf-8"
        )

        index_url = resolve_index_url([], env={"PIP_CONFIG_FILE": str(config_path)})

        self.assertEqual(index_url, "https://config.example/simple")

    def test_resolve_index_url_reads_windows_pip_ini_location(self) -> None:
        tmpdir = self.make_temp_dir()
        appdata = tmpdir / "AppData" / "Roaming"
        pip_ini = appdata / "pip" / "pip.ini"
        pip_ini.parent.mkdir(parents=True, exist_ok=True)
        pip_ini.write_text(
            "[global]\nindex-url = https://mirror.example/simple\n", encoding="utf-8"
        )

        index_url = resolve_index_url(
            [],
            env={
                "APPDATA": str(appdata),
                "HOME": str(tmpdir / "home"),
            },
        )

        self.assertEqual(index_url, "https://mirror.example/simple")

    def test_client_from_pip_args_derives_base_url_from_simple_index(self) -> None:
        client = client_from_pip_args(
            ["-i", "https://pypi.tuna.tsinghua.edu.cn/simple"],
            env={},
        )

        self.assertEqual(client.base_url, "https://pypi.tuna.tsinghua.edu.cn")

    def test_client_from_pip_args_disables_network_for_no_index(self) -> None:
        client = client_from_pip_args(
            ["install", "--no-index", "packaging==24.2"],
            env={},
        )

        self.assertFalse(client.network_enabled)

    def test_client_from_pip_args_disables_network_for_find_links(self) -> None:
        client = client_from_pip_args(
            ["install", "--find-links", "wheelhouse", "packaging==24.2"],
            env={},
        )

        self.assertFalse(client.network_enabled)

    def test_client_from_pip_args_disables_network_for_local_path_install(self) -> None:
        client = client_from_pip_args(
            ["install", "."],
            env={},
        )

        self.assertFalse(client.network_enabled)

    def test_client_from_pip_args_keeps_network_for_normal_registry_install(
        self,
    ) -> None:
        client = client_from_pip_args(
            ["install", "requests==2.32.3"],
            env={},
        )

        self.assertTrue(client.network_enabled)


if __name__ == "__main__":
    unittest.main()
