from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from secured_pip.pypi_api import OfficialPyPIClient


@dataclass(frozen=True)
class CacheRefreshResult:
    key: str
    description: str
    count: int
    location: str


@dataclass(frozen=True)
class CacheRefreshTask:
    key: str
    description: str
    run: Callable[[OfficialPyPIClient], CacheRefreshResult]


def _refresh_project_name_cache(client: OfficialPyPIClient) -> CacheRefreshResult:
    count = client.refresh_project_name_cache()
    return CacheRefreshResult(
        key="pypi-project-names",
        description="PyPI project name cache",
        count=count,
        location=str(client.cache_path),
    )


def _refresh_disposable_email_cache(client: OfficialPyPIClient) -> CacheRefreshResult:
    count = client.refresh_disposable_email_domain_cache()
    return CacheRefreshResult(
        key="disposable-email-domains",
        description="disposable email domain cache",
        count=count,
        location=str(client.disposable_email_cache_path),
    )


REFRESH_TASKS: tuple[CacheRefreshTask, ...] = (
    CacheRefreshTask(
        key="pypi-project-names",
        description="PyPI project name cache",
        run=_refresh_project_name_cache,
    ),
    CacheRefreshTask(
        key="disposable-email-domains",
        description="disposable email domain cache",
        run=_refresh_disposable_email_cache,
    ),
)


def refresh_all_caches(
    client: OfficialPyPIClient | None = None,
) -> list[CacheRefreshResult]:
    client = client or OfficialPyPIClient()
    return [task.run(client) for task in REFRESH_TASKS]
