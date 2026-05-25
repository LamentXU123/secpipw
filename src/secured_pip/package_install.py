from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import unquote, urlparse, urlunparse
from urllib.request import url2pathname, urlopen

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from secured_pip.install_plan import ResolvedPackage

INSTALL_OPTIONS_WITH_VALUE = {
    "-t",
    "--target",
    "--prefix",
    "--root",
    "--python",
    "--progress-bar",
    "--root-user-action",
    "--config-settings",
    "--global-option",
    "--install-option",
}
RESOLUTION_ONLY_OPTIONS_WITH_VALUE = {
    "-c",
    "-e",
    "-f",
    "-i",
    "-r",
    "--abi",
    "--constraint",
    "--editable",
    "--extra-index-url",
    "--find-links",
    "--implementation",
    "--index-url",
    "--platform",
    "--python-version",
    "--report",
    "--src",
    "--trusted-host",
    "--upgrade-strategy",
    "--use-deprecated",
    "--use-feature",
}
RESOLUTION_ONLY_FLAGS = {
    "--dry-run",
    "--no-deps",
    "--no-index",
    "--pre",
    "--prefer-binary",
    "--require-hashes",
    "--upgrade",
}


@dataclass(frozen=True)
class DownloadedArtifact:
    package: ResolvedPackage
    path: Path


def install_resolved_packages(
    packages: tuple[ResolvedPackage, ...] | list[ResolvedPackage],
    pip_args: list[str],
) -> int:
    package_list = tuple(packages)
    if not package_list:
        return 0

    install_inputs = [
        _install_input_for(package)
        for package in topological_install_order(package_list)
    ]
    command = [
        "install",
        "--disable-pip-version-check",
        "--no-deps",
        *forwarded_install_args(pip_args),
        *install_inputs,
    ]
    return _run_pip_internal(command)


def topological_install_order(
    packages: tuple[ResolvedPackage, ...] | list[ResolvedPackage],
) -> tuple[ResolvedPackage, ...]:
    package_list = list(packages)
    if len(package_list) < 2:
        return tuple(package_list)

    by_name = {canonicalize_name(package.name): package for package in package_list}
    dependency_names: dict[str, set[str]] = {
        canonicalize_name(package.name): _internal_dependencies(package, by_name)
        for package in package_list
    }
    incoming = {name: len(deps) for name, deps in dependency_names.items()}
    reverse_edges: dict[str, list[str]] = {name: [] for name in by_name}
    order_index = {
        canonicalize_name(package.name): index
        for index, package in enumerate(package_list)
    }

    for package_name, deps in dependency_names.items():
        for dep_name in deps:
            reverse_edges[dep_name].append(package_name)

    ready = sorted(
        [name for name, count in incoming.items() if count == 0],
        key=order_index.get,
    )
    ordered: list[ResolvedPackage] = []

    while ready:
        current = ready.pop(0)
        ordered.append(by_name[current])
        for dependent in sorted(reverse_edges[current], key=order_index.get):
            incoming[dependent] -= 1
            if incoming[dependent] == 0:
                ready.append(dependent)
        ready.sort(key=order_index.get)

    if len(ordered) == len(package_list):
        return tuple(ordered)

    remaining = [
        package
        for package in package_list
        if canonicalize_name(package.name)
        not in {canonicalize_name(item.name) for item in ordered}
    ]
    return tuple([*ordered, *remaining])


def forwarded_install_args(pip_args: list[str]) -> list[str]:
    forwarded: list[str] = []
    i = 0

    while i < len(pip_args):
        arg = pip_args[i]
        option_name = arg.split("=", 1)[0]

        if arg == "--":
            break
        if arg in RESOLUTION_ONLY_FLAGS:
            i += 1
            continue
        if option_name in RESOLUTION_ONLY_OPTIONS_WITH_VALUE:
            i += 2 if "=" not in arg else 1
            continue
        if option_name in INSTALL_OPTIONS_WITH_VALUE:
            forwarded.append(arg)
            if "=" not in arg and i + 1 < len(pip_args):
                forwarded.append(pip_args[i + 1])
                i += 2
                continue
            i += 1
            continue
        if arg.startswith("-"):
            forwarded.append(arg)
            i += 1
            continue
        i += 1

    return forwarded


def download_artifact(
    package: ResolvedPackage, destination: Path
) -> DownloadedArtifact:
    download_url = package.download_url
    if not download_url:
        raise RuntimeError(
            f"missing download URL for {package.name}=={package.version}"
        )

    parsed = urlparse(download_url)
    artifact_name = package.artifact_name or _artifact_name_from_path(parsed.path)
    destination.mkdir(parents=True, exist_ok=True)
    target_path = destination / artifact_name

    if parsed.scheme == "file":
        source_path = Path(url2pathname(unquote(parsed.path)))
        shutil.copy2(source_path, target_path)
        return DownloadedArtifact(package=package, path=target_path)

    with urlopen(download_url, timeout=30) as response:
        with target_path.open("wb") as handle:
            shutil.copyfileobj(response, handle)
    return DownloadedArtifact(package=package, path=target_path)


def temporary_artifact_directory() -> TemporaryDirectory[str]:
    return TemporaryDirectory(prefix="spip-artifacts-")


def _internal_dependencies(
    package: ResolvedPackage, package_by_name: dict[str, ResolvedPackage]
) -> set[str]:
    dependencies: set[str] = set()
    for requirement_text in package.requires_dist:
        try:
            dependency_name = canonicalize_name(Requirement(requirement_text).name)
        except InvalidRequirement:
            continue
        if dependency_name in package_by_name:
            dependencies.add(dependency_name)
    return dependencies


def _artifact_name_from_path(path: str) -> str:
    name = Path(unquote(path)).name
    if not name:
        raise RuntimeError(f"could not derive artifact filename from URL path: {path}")
    return name


def _install_input_for(package: ResolvedPackage) -> str:
    if package.download_url:
        return _url_with_archive_hash(package.download_url, package.archive_hash)
    raise RuntimeError(
        f"missing download URL for resolved package {package.name}=={package.version}"
    )


def _run_pip_internal(argv: list[str]) -> int:
    from pip._internal.cli.main import main as pip_main

    return int(pip_main(argv))


def _url_with_archive_hash(download_url: str, archive_hash: str | None) -> str:
    if not archive_hash:
        return download_url
    parsed = urlparse(download_url)
    if parsed.fragment:
        return download_url
    return urlunparse(parsed._replace(fragment=archive_hash))
