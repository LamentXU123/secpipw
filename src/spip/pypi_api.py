from __future__ import annotations

import configparser
import json
import os
import socket
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_PYPI_BASE_URL = "https://pypi.org"
DEFAULT_JSON_API_TIMEOUT_SECONDS = 2.5
_RELEASE_CACHE_LOCK = threading.RLock()
BOOTSTRAP_CACHE_PATH = Path(__file__).resolve().parent / "data" / "pypi-project-names.json"
BOOTSTRAP_PROJECT_NAMES = [
    "black",
    "build",
    "certifi",
    "celery",
    "charset-normalizer",
    "cryptography",
    "django",
    "fastapi",
    "flask",
    "httpx",
    "idna",
    "jinja2",
    "matplotlib",
    "mypy",
    "numpy",
    "packaging",
    "pandas",
    "pillow",
    "pip",
    "poetry",
    "protobuf",
    "pydantic",
    "pyjwt",
    "pytest",
    "python-dateutil",
    "pyyaml",
    "requests",
    "rich",
    "scikit-learn",
    "scipy",
    "setuptools",
    "six",
    "sqlalchemy",
    "tox",
    "twine",
    "typing-extensions",
    "urllib3",
    "uv",
    "uvicorn",
    "virtualenv",
    "wheel",
]


def _default_cache_path() -> Path:
    return Path.cwd() / ".spip-cache" / "pypi-project-names.json"


def _default_release_cache_path() -> Path:
    return Path.cwd() / ".spip-cache" / "pypi-release-times.json"


@dataclass(frozen=True)
class OfficialPyPIClient:
    base_url: str = DEFAULT_PYPI_BASE_URL
    cache_path: Path = field(default_factory=_default_cache_path)
    release_cache_path: Path = field(default_factory=_default_release_cache_path)

    def fetch_reference_package_names(self) -> list[str]:
        request = Request(
            f"{self.base_url}/stats/",
            headers={"Accept": "application/json"},
        )
        with urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return sorted(payload.get("top_packages", {}).keys())

    def load_reference_package_names(self) -> list[str]:
        try:
            remote_names = self.fetch_reference_package_names()
        except Exception as exc:
            if not _is_timeout_error(exc):
                raise
            return self.load_cached_project_names()
        return sorted(set(remote_names).union(BOOTSTRAP_PROJECT_NAMES))

    def fetch_all_project_names(self) -> list[str]:
        request = Request(
            f"{self.base_url}/simple/",
            headers={"Accept": "application/vnd.pypi.simple.v1+json"},
        )
        with urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return sorted(project["name"] for project in payload.get("projects", []))

    def load_cached_project_names(self) -> list[str]:
        if self.cache_path.exists():
            payload = json.loads(self.cache_path.read_text(encoding="utf-8"))
            return sorted(payload.get("projects", []))
        if BOOTSTRAP_CACHE_PATH.exists():
            payload = json.loads(BOOTSTRAP_CACHE_PATH.read_text(encoding="utf-8"))
            return sorted(payload.get("projects", []))
        return sorted(BOOTSTRAP_PROJECT_NAMES)

    def refresh_project_name_cache(self) -> int:
        names = self.fetch_all_project_names()
        payload = {
            "source": "https://pypi.org/simple/",
            "project_count": len(names),
            "projects": sorted(names),
        }
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return len(names)

    def project_exists(self, name: str) -> bool:
        request = Request(
            f"{self.base_url}/pypi/{name}/json",
            headers={"Accept": "application/json"},
        )
        try:
            with urlopen(request, timeout=10):
                return True
        except HTTPError as exc:
            if exc.code == 404:
                return False
            raise

    def project_exists_with_fallback(self, name: str) -> bool:
        try:
            return self.project_exists(name)
        except Exception as exc:
            if not _is_timeout_error(exc):
                raise
            return name.lower() in {project.lower() for project in self.load_cached_project_names()}

    def fetch_release_metadata(self, name: str, version: str) -> dict:
        request = Request(
            f"{self.base_url}/pypi/{name}/{version}/json",
            headers={"Accept": "application/json"},
        )
        try:
            with urlopen(request, timeout=DEFAULT_JSON_API_TIMEOUT_SECONDS) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            if self.base_url == DEFAULT_PYPI_BASE_URL or _is_timeout_error(exc):
                raise
        fallback = Request(
            f"{DEFAULT_PYPI_BASE_URL}/pypi/{name}/{version}/json",
            headers={"Accept": "application/json"},
        )
        with urlopen(fallback, timeout=DEFAULT_JSON_API_TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode("utf-8"))

    def fetch_release_upload_time(
        self,
        name: str,
        version: str,
        *,
        download_url: str | None = None,
        filename: str | None = None,
    ) -> datetime | None:
        payload = self.fetch_release_metadata(name, version)
        urls = payload.get("urls", [])
        selected = None

        for item in urls:
            if download_url and item.get("url") == download_url:
                selected = item
                break
            if filename and item.get("filename") == filename:
                selected = item
                break

        if selected is None and urls:
            selected = max(
                urls,
                key=lambda item: _parse_upload_time(item.get("upload_time_iso_8601"))
                or datetime.min.replace(tzinfo=timezone.utc),
            )

        if selected is None:
            return None
        return _parse_upload_time(selected.get("upload_time_iso_8601"))

    def load_cached_release_upload_time(
        self,
        name: str,
        version: str,
        *,
        download_url: str | None = None,
        filename: str | None = None,
    ) -> tuple[bool, datetime | None]:
        payload = self._load_release_cache_payload()
        key = self._release_cache_key(
            name,
            version,
            download_url=download_url,
            filename=filename,
        )
        if key not in payload:
            return False, None
        return True, _parse_upload_time(payload[key])

    def store_cached_release_upload_time(
        self,
        name: str,
        version: str,
        published_at: datetime | None,
        *,
        download_url: str | None = None,
        filename: str | None = None,
    ) -> None:
        payload = self._load_release_cache_payload()
        key = self._release_cache_key(
            name,
            version,
            download_url=download_url,
            filename=filename,
        )
        with _RELEASE_CACHE_LOCK:
            payload = self._load_release_cache_payload()
            payload[key] = (
                published_at.isoformat() if published_at is not None else None
            )
            self.release_cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.release_cache_path.write_text(
                json.dumps(payload, indent=2, sort_keys=True),
                encoding="utf-8",
            )

    def _load_release_cache_payload(self) -> dict[str, str | None]:
        with _RELEASE_CACHE_LOCK:
            if not self.release_cache_path.exists():
                return {}
            try:
                payload = json.loads(self.release_cache_path.read_text(encoding="utf-8"))
            except Exception:
                return {}
        entries = payload.get("entries") if isinstance(payload, dict) else None
        if isinstance(entries, dict):
            return entries
        if isinstance(payload, dict):
            return payload
        return {}

    def _release_cache_key(
        self,
        name: str,
        version: str,
        *,
        download_url: str | None = None,
        filename: str | None = None,
    ) -> str:
        return json.dumps(
            {
                "base_url": self.base_url.rstrip("/").lower(),
                "name": name.lower(),
                "version": version,
                "download_url": download_url or "",
                "filename": filename or "",
            },
            sort_keys=True,
        )


def _is_timeout_error(exc: Exception) -> bool:
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return True
    if isinstance(exc, URLError):
        reason = getattr(exc, "reason", None)
        return isinstance(reason, (TimeoutError, socket.timeout))
    return False


def _parse_upload_time(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)


def client_from_pip_args(
    pip_args: list[str],
    *,
    env: dict[str, str] | None = None,
) -> OfficialPyPIClient:
    index_url = resolve_index_url(pip_args, env=env)
    if not index_url:
        return OfficialPyPIClient()
    return OfficialPyPIClient(base_url=_base_url_from_index_url(index_url))


def resolve_index_url(
    pip_args: list[str],
    *,
    env: dict[str, str] | None = None,
) -> str | None:
    env = os.environ if env is None else env

    cli_index_url = _index_url_from_pip_args(pip_args)
    if cli_index_url:
        return cli_index_url

    env_index_url = env.get("PIP_INDEX_URL")
    if env_index_url:
        return env_index_url

    config_file = env.get("PIP_CONFIG_FILE")
    if config_file:
        configured = _index_url_from_config_file(Path(config_file))
        if configured:
            return configured

    for path in _pip_config_paths(env):
        configured = _index_url_from_config_file(path)
        if configured:
            return configured

    return None


def _index_url_from_pip_args(args: list[str]) -> str | None:
    result: str | None = None
    skip_next = False

    for index, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if arg == "--no-index":
            result = None
            continue
        if arg == "-i" or arg == "--index-url":
            if index + 1 < len(args):
                result = args[index + 1]
                skip_next = True
            continue
        if arg.startswith("--index-url="):
            result = arg.split("=", 1)[1]
            continue
    return result


def _pip_config_paths(env: dict[str, str]) -> list[Path]:
    paths: list[Path] = []
    home = Path(env.get("HOME") or env.get("USERPROFILE") or Path.home())
    virtual_env = env.get("VIRTUAL_ENV")
    appdata = env.get("APPDATA")
    programdata = env.get("PROGRAMDATA")
    xdg_config_home = env.get("XDG_CONFIG_HOME")

    if programdata:
        paths.append(Path(programdata) / "pip" / "pip.ini")
    paths.append(Path("/etc/pip.conf"))

    if appdata:
        paths.append(Path(appdata) / "pip" / "pip.ini")
    if xdg_config_home:
        paths.append(Path(xdg_config_home) / "pip" / "pip.conf")
    else:
        paths.append(home / ".config" / "pip" / "pip.conf")

    paths.append(home / "pip" / "pip.ini")
    paths.append(home / ".pip" / "pip.conf")

    if virtual_env:
        paths.append(Path(virtual_env) / "pip.ini")
        paths.append(Path(virtual_env) / "pip.conf")

    deduped: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)
    return deduped


def _index_url_from_config_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None

    parser = configparser.RawConfigParser()
    try:
        parser.read(path, encoding="utf-8")
    except Exception:
        return None

    for section in ("global", "install"):
        if parser.has_option(section, "index-url"):
            value = parser.get(section, "index-url").strip()
            if value:
                return value
    return None


def _base_url_from_index_url(index_url: str) -> str:
    parsed = urlparse(index_url)
    if not parsed.scheme or not parsed.netloc:
        return DEFAULT_PYPI_BASE_URL

    path = parsed.path.rstrip("/")
    for suffix in ("/simple", "/simple/", "/pypi", "/pypi/"):
        if path.endswith(suffix.rstrip("/")):
            path = path[: -len(suffix.rstrip("/"))]
            break
    return f"{parsed.scheme}://{parsed.netloc}{path}".rstrip("/")
