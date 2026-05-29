from __future__ import annotations

import configparser
import json
import os
import socket
import threading
from email.utils import getaddresses
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from packaging.requirements import InvalidRequirement, Requirement

DEFAULT_PYPI_BASE_URL = "https://pypi.org"
DEFAULT_JSON_API_TIMEOUT_SECONDS = 2.5
_RELEASE_CACHE_LOCK = threading.RLock()
_EMAIL_DOMAIN_HISTORY_LOCK = threading.RLock()
_METADATA_CACHE_LOCK = threading.RLock()
_PROJECT_NAME_CACHE_LOCK = threading.RLock()
_PROJECT_NAME_CACHE: dict[
    tuple[str, tuple[int, int] | None],
    tuple[str, ...],
] = {}
_EMAIL_DOMAIN_HISTORY_CACHE: dict[
    tuple[str, tuple[int, int] | None],
    dict[str, tuple[str, ...]],
] = {}
_RELEASE_CACHE_PAYLOAD_CACHE: dict[
    tuple[str, tuple[int, int] | None],
    dict[str, str | None],
] = {}
_METADATA_CACHE: dict[tuple[str, str, str], dict] = {}
BOOTSTRAP_CACHE_PATH = (
    Path(__file__).resolve().parent / "data" / "pypi-project-names.json"
)
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


def _default_cache_root() -> Path:
    configured = os.environ.get("SPIP_CACHE_DIR")
    if configured:
        return Path(configured).expanduser()

    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if local_app_data:
            return Path(local_app_data) / "spip" / "cache"

    xdg_cache_home = os.environ.get("XDG_CACHE_HOME")
    if xdg_cache_home:
        return Path(xdg_cache_home) / "spip"
    return Path.home() / ".cache" / "spip"


def _default_cache_path() -> Path:
    return _default_cache_root() / "pypi-project-names.json"


def _default_release_cache_path() -> Path:
    return _default_cache_root() / "pypi-release-times.json"


def _default_email_domain_history_path() -> Path:
    return _default_cache_root() / "pypi-email-domains.json"


@dataclass(frozen=True)
class OfficialPyPIClient:
    base_url: str = DEFAULT_PYPI_BASE_URL
    network_enabled: bool = True
    cache_path: Path = field(default_factory=_default_cache_path)
    release_cache_path: Path = field(default_factory=_default_release_cache_path)
    email_domain_history_path: Path = field(
        default_factory=_default_email_domain_history_path
    )

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
        cached = _load_cached_project_names_for_path(self.cache_path)
        if cached is not None:
            return list(cached)
        cached = _load_cached_project_names_for_path(BOOTSTRAP_CACHE_PATH)
        if cached is not None:
            return list(cached)
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
        with _PROJECT_NAME_CACHE_LOCK:
            signature = _path_signature(self.cache_path)
            if signature is not None:
                _PROJECT_NAME_CACHE[(str(self.cache_path.resolve()), signature)] = tuple(
                    sorted(names)
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
            cached_names = self.load_cached_project_names()
            return name.lower() in {project.lower() for project in cached_names}

    def fetch_release_metadata(self, name: str, version: str) -> dict:
        if not self.network_enabled:
            raise RuntimeError("registry metadata requests are disabled")
        cache_key = (self.base_url.rstrip("/").lower(), name.lower(), version)
        with _METADATA_CACHE_LOCK:
            cached = _METADATA_CACHE.get(cache_key)
        if cached is not None:
            return cached
        request = Request(
            f"{self.base_url}/pypi/{name}/{version}/json",
            headers={"Accept": "application/json"},
        )
        try:
            with urlopen(request, timeout=DEFAULT_JSON_API_TIMEOUT_SECONDS) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            raise
        with _METADATA_CACHE_LOCK:
            _METADATA_CACHE[cache_key] = payload
        return payload

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

    def fetch_release_contact_emails(self, name: str, version: str) -> tuple[str, ...]:
        payload = self.fetch_release_metadata(name, version)
        info = payload.get("info") or {}
        raw_values = [
            info.get("author_email") or "",
            info.get("maintainer_email") or "",
        ]
        emails: list[str] = []
        seen: set[str] = set()
        for _, address in getaddresses(raw_values):
            normalized = address.strip().lower()
            if not normalized or "@" not in normalized or normalized in seen:
                continue
            seen.add(normalized)
            emails.append(normalized)
        return tuple(emails)

    def fetch_release_description_fields(
        self, name: str, version: str
    ) -> tuple[str, str]:
        payload = self.fetch_release_metadata(name, version)
        info = payload.get("info") or {}
        return (
            str(info.get("summary") or ""),
            str(info.get("description") or ""),
        )

    def load_email_domain_history(self) -> dict[str, tuple[str, ...]]:
        cached = _load_email_domain_history_for_path(self.email_domain_history_path)
        if cached is None:
            return {}
        return dict(cached)

    def store_email_domain_history(self, history: dict[str, Iterable[str]]) -> None:
        projects = {
            name.lower(): sorted(
                {domain.strip().lower() for domain in domains if domain.strip()}
            )
            for name, domains in history.items()
        }
        payload = {"projects": projects}
        with _EMAIL_DOMAIN_HISTORY_LOCK:
            self.email_domain_history_path.parent.mkdir(parents=True, exist_ok=True)
            self.email_domain_history_path.write_text(
                json.dumps(payload, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            signature = _path_signature(self.email_domain_history_path)
            if signature is not None:
                _EMAIL_DOMAIN_HISTORY_CACHE[
                    (str(self.email_domain_history_path.resolve()), signature)
                ] = {
                    name: tuple(domains) for name, domains in projects.items()
                }

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
            signature = _path_signature(self.release_cache_path)
            if signature is not None:
                _RELEASE_CACHE_PAYLOAD_CACHE[
                    (str(self.release_cache_path.resolve()), signature)
                ] = dict(payload)

    def _load_release_cache_payload(self) -> dict[str, str | None]:
        cached = _load_release_cache_payload_for_path(self.release_cache_path)
        if cached is None:
            return {}
        return dict(cached)

    def _release_cache_key(
        self,
        name: str,
        version: str,
        *,
        download_url: str | None = None,
        filename: str | None = None,
    ) -> str:
        return (
            f"{self.base_url.rstrip('/').lower()}"
            f"|{name.lower()}"
            f"|{version}"
            f"|{download_url or ''}"
            f"|{filename or ''}"
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


def _path_signature(path: Path) -> tuple[int, int] | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    return stat.st_mtime_ns, stat.st_size


def _load_cached_project_names_for_path(path: Path) -> tuple[str, ...] | None:
    signature = _path_signature(path)
    key = (str(path.resolve()), signature)
    with _PROJECT_NAME_CACHE_LOCK:
        cached = _PROJECT_NAME_CACHE.get(key)
    if cached is not None:
        return cached
    if signature is None:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    projects = payload.get("projects") if isinstance(payload, dict) else None
    if not isinstance(projects, list):
        return None
    names = tuple(sorted(str(name) for name in projects if str(name)))
    with _PROJECT_NAME_CACHE_LOCK:
        _PROJECT_NAME_CACHE[key] = names
    return names


def _load_email_domain_history_for_path(
    path: Path,
) -> dict[str, tuple[str, ...]] | None:
    signature = _path_signature(path)
    key = (str(path.resolve()), signature)
    with _EMAIL_DOMAIN_HISTORY_LOCK:
        cached = _EMAIL_DOMAIN_HISTORY_CACHE.get(key)
    if cached is not None:
        return cached
    if signature is None:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    projects = payload.get("projects") if isinstance(payload, dict) else None
    if not isinstance(projects, dict):
        return None
    result: dict[str, tuple[str, ...]] = {}
    for name, domains in projects.items():
        if not isinstance(name, str) or not isinstance(domains, list):
            continue
        cleaned = tuple(
            sorted(
                {
                    str(domain).strip().lower()
                    for domain in domains
                    if str(domain).strip()
                }
            )
        )
        if cleaned:
            result[name.lower()] = cleaned
    with _EMAIL_DOMAIN_HISTORY_LOCK:
        _EMAIL_DOMAIN_HISTORY_CACHE[key] = result
    return result


def _load_release_cache_payload_for_path(
    path: Path,
) -> dict[str, str | None] | None:
    signature = _path_signature(path)
    key = (str(path.resolve()), signature)
    with _RELEASE_CACHE_LOCK:
        cached = _RELEASE_CACHE_PAYLOAD_CACHE.get(key)
    if cached is not None:
        return cached
    if signature is None:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    entries = payload.get("entries") if isinstance(payload, dict) else None
    if isinstance(entries, dict):
        payload = entries
    if not isinstance(payload, dict):
        return None
    with _RELEASE_CACHE_LOCK:
        _RELEASE_CACHE_PAYLOAD_CACHE[key] = payload
    return payload


def client_from_pip_args(
    pip_args: list[str],
    *,
    env: dict[str, str] | None = None,
) -> OfficialPyPIClient:
    network_enabled = not _disable_registry_requests_for_install_args(pip_args)
    index_url = resolve_index_url(pip_args, env=env)
    if not index_url:
        return OfficialPyPIClient(network_enabled=network_enabled)
    return OfficialPyPIClient(
        base_url=_base_url_from_index_url(index_url),
        network_enabled=network_enabled,
    )


def _disable_registry_requests_for_install_args(args: list[str]) -> bool:
    i = 0
    while i < len(args):
        arg = args[i]
        option_name = arg.split("=", 1)[0]

        if arg == "--":
            for trailing in args[i + 1 :]:
                if _is_local_install_target(trailing):
                    return True
            return False
        if arg == "--no-index":
            return True
        if arg.startswith("--find-links="):
            return True
        if arg in {"-f", "--find-links"}:
            return True
        if arg in {"-e", "--editable"}:
            if i + 1 < len(args) and _is_local_install_target(args[i + 1]):
                return True
            i += 2
            continue
        if arg.startswith("--editable="):
            if _is_local_install_target(arg.split("=", 1)[1]):
                return True
            i += 1
            continue
        if option_name in {
            "-c",
            "-C",
            "-f",
            "-i",
            "-r",
            "-t",
            "--abi",
            "--cache-dir",
            "--cert",
            "--client-cert",
            "--config-settings",
            "--constraint",
            "--editable",
            "--exists-action",
            "--extra-index-url",
            "--find-links",
            "--global-option",
            "--implementation",
            "--index-url",
            "--keyring-provider",
            "--log",
            "--platform",
            "--prefix",
            "--progress-bar",
            "--proxy",
            "--python",
            "--python-version",
            "--requirement",
            "--report",
            "--retries",
            "--root",
            "--root-user-action",
            "--src",
            "--target",
            "--timeout",
            "--trusted-host",
            "--upgrade-strategy",
            "--use-deprecated",
            "--use-feature",
        }:
            i += 2 if "=" not in arg else 1
            continue
        if arg.startswith("-"):
            i += 1
            continue
        if _is_local_install_target(arg):
            return True
        i += 1
    return False


def _is_local_install_target(value: str) -> bool:
    try:
        requirement = Requirement(value)
    except InvalidRequirement:
        requirement = None

    if requirement is not None:
        if requirement.url:
            parsed = urlparse(requirement.url)
            return parsed.scheme == "file"
        return False

    parsed = urlparse(value)
    if parsed.scheme == "file":
        return True
    if parsed.scheme:
        return False

    if value in {".", ".."}:
        return True
    if value.startswith((".\\", "./", "..\\", "../")):
        return True

    path = Path(value)
    if path.is_absolute() or path.exists():
        return True

    suffixes = path.suffixes
    if suffixes[-1:] == [".whl"]:
        return True
    if suffixes[-2:] == [".tar", ".gz"] or suffixes[-1:] == [".zip"]:
        return True
    return False


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
