from __future__ import annotations

import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from secpipw.install_plan import InstallPlan
from packaging.version import Version


@dataclass(frozen=True)
class ToolCommand:
    name: str
    index: int


@dataclass(frozen=True)
class UvCommand:
    path: tuple[str, ...]
    index: int
    args_index: int
    unsupported: bool = False


PIPX_COMMANDS = {
    "install",
    "inject",
    "reinstall",
    "reinstall-all",
    "run",
    "upgrade",
    "upgrade-all",
}
PIPX_GLOBAL_OPTIONS_WITH_VALUE = {
    "--default-python",
}
PIPX_OPTIONS_WITH_VALUE = {
    "--backend",
    "--fetch-python",
    "--index-url",
    "-i",
    "--pip-args",
    "--preinstall",
    "--python",
    "--requirement",
    "-r",
    "--spec",
    "--suffix",
    "--with",
}
PIPX_VALUE_ALIASES = {
    "-i": "--index-url",
    "-r": "--requirement",
}
PIPX_FLAGS = {
    "--editable",
    "-e",
    "--fetch-missing-python",
    "--force",
    "-f",
    "--global",
    "--include-apps",
    "--include-deps",
    "--install",
    "--no-cache",
    "--path",
    "--pypackages",
    "--quiet",
    "-q",
    "--system-site-packages",
    "--verbose",
    "-v",
    "--with-suffix",
}

POETRY_COMMANDS = {
    "add",
    "self",
}
POETRY_GLOBAL_OPTIONS_WITH_VALUE = {
    "--directory",
    "-C",
    "--project",
    "-P",
}
POETRY_ADD_OPTIONS_WITH_VALUE = {
    "--extras",
    "-E",
    "--group",
    "-G",
    "--markers",
    "--platform",
    "--python",
    "--source",
}
POETRY_ADD_VALUE_ALIASES = {
    "-E": "--extras",
    "-G": "--group",
}
POETRY_ADD_FLAGS = {
    "--allow-prereleases",
    "--dev",
    "-D",
    "--dry-run",
    "--editable",
    "-e",
    "--lock",
    "--optional",
    "--quiet",
    "-q",
    "--verbose",
    "-v",
}

UV_TOP_LEVEL_COMMANDS = {
    "add",
    "pip",
    "run",
    "sync",
    "tool",
}
UV_GUARDED_COMMANDS = {
    ("add",),
    ("pip", "install"),
    ("tool", "install"),
    ("tool", "run"),
}
UV_INSTALL_COMMANDS = {
    *UV_GUARDED_COMMANDS,
    ("pip", "sync"),
    ("run",),
    ("sync",),
    ("tool", "upgrade"),
    ("tool", "upgrade-all"),
}
UV_GLOBAL_OPTIONS_WITH_VALUE = {
    "--allow-insecure-host",
    "--cache-dir",
    "--color",
    "--config-file",
    "--directory",
    "--project",
}
UV_GLOBAL_FLAGS = {
    "--help",
    "-h",
    "--managed-python",
    "--no-cache",
    "-n",
    "--no-config",
    "--no-managed-python",
    "--no-progress",
    "--no-python-downloads",
    "--offline",
    "--quiet",
    "-q",
    "--refresh",
    "--system-certs",
    "--verbose",
    "-v",
    "--version",
}
UV_INDEX_OPTIONS_WITH_VALUE = {
    "--default-index",
    "--extra-index-url",
    "--find-links",
    "-f",
    "--index",
    "--index-url",
    "-i",
}
UV_INDEX_VALUE_ALIASES = {
    "-f": "--find-links",
    "-i": "--index-url",
}
UV_RESOLVER_OPTIONS_WITH_VALUE = {
    "--exclude-newer",
    "--exclude-newer-package",
    "--fork-strategy",
    "--extra-index-url",
    "--index",
    "--index-strategy",
    "--keyring-provider",
    "--link-mode",
    "--prerelease",
    "--refresh-package",
    "--reinstall-package",
    "--resolution",
    "--upgrade-group",
    "--upgrade-package",
    "-P",
}
UV_RESOLVER_VALUE_ALIASES = {
    "-P": "--upgrade-package",
}
UV_BUILD_OPTIONS_WITH_VALUE = {
    "--build-constraints",
    "-b",
    "--config-setting",
    "-C",
    "--config-settings-package",
    "--excludes",
    "--no-binary-package",
    "--no-build-isolation-package",
    "--no-build-package",
    "--no-sources-package",
    "--overrides",
    "--torch-backend",
}
UV_BUILD_VALUE_ALIASES = {
    "-b": "--build-constraints",
    "-C": "--config-setting",
}
UV_PYTHON_OPTIONS_WITH_VALUE = {
        "--python",
        "-p",
        "--python-platform",
        "--python-version",
        *UV_GLOBAL_OPTIONS_WITH_VALUE,
    }
UV_PYTHON_VALUE_ALIASES = {
    "-p": "--python",
}
UV_COMMON_FLAGS = {
    *UV_GLOBAL_FLAGS,
    "--break-system-packages",
    "--compile-bytecode",
    "--dry-run",
    "--force",
    "--lfs",
    "--no-build",
    "--no-build-isolation",
    "--no-deps",
    "--no-index",
    "--no-sources",
    "--reinstall",
    "--require-hashes",
    "--strict",
    "--system",
    "--upgrade",
    "-U",
    "--user",
}
UV_UNSUPPORTED_VALUE_OPTIONS = {
    "--build-constraints",
    "--config-settings-package",
    "--exclude-newer",
    "--exclude-newer-package",
    "--excludes",
    "--fork-strategy",
    "--index-strategy",
    "--keyring-provider",
    "--link-mode",
    "--no-build-isolation-package",
    "--no-build-package",
    "--overrides",
    "--python-platform",
    "--python-version",
    "--resolution",
    "--torch-backend",
    "--upgrade-group",
}
PEP_440_OPERATORS = (">=", "<=", "==", "!=", "~=", "===", ">", "<")
DIRECT_REFERENCE_PREFIXES = (
    "git+",
    "hg+",
    "svn+",
    "bzr+",
    "http://",
    "https://",
    "file://",
)
SOURCE_ARCHIVE_SUFFIXES = (
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tar.xz",
    ".tar",
    ".zip",
)


def run_tool(tool: str, argv: list[str] | None = None) -> int:
    try:
        completed = subprocess.run([tool, *(argv or [])], check=False)
    except FileNotFoundError:
        sys.stderr.write(
            f"ERROR: spip could not find '{tool}' on PATH. Install it or use "
            f"the original command directly.\n"
        )
        return 127
    return completed.returncode


def preflight_pip_args_for_tool(
    tool: str,
    argv: list[str],
) -> list[str] | None:
    if tool == "pipx":
        return _pipx_preflight_pip_args(argv)
    if tool == "poetry":
        return _poetry_preflight_pip_args(argv)
    if tool == "uv":
        return _uv_preflight_pip_args(argv)
    return None


def tool_command_requires_preflight(tool: str, argv: list[str]) -> bool:
    if tool == "pipx":
        return (
            _find_command(
                argv,
                commands=PIPX_COMMANDS,
                options_with_value=PIPX_GLOBAL_OPTIONS_WITH_VALUE,
            )
            is not None
        )
    if tool == "uv":
        command = _find_uv_command(argv)
        return (
            command is not None
            and (command.unsupported or command.path in UV_INSTALL_COMMANDS)
        )

    if tool != "poetry":
        return False

    command = _find_command(
        argv,
        commands=POETRY_COMMANDS,
        options_with_value=POETRY_GLOBAL_OPTIONS_WITH_VALUE,
    )
    if command is None:
        return False
    if command.name == "add":
        return True
    if command.name != "self":
        return False
    return (
        _find_command(
            argv[command.index + 1 :],
            commands={"add"},
            options_with_value=set(),
        )
        is not None
    )


def inspect_install_plan_artifacts(plan: InstallPlan) -> list[object]:
    from secpipw.package_install import download_artifact, temporary_artifact_directory
    from secpipw.pth_monitor import (
        inspect_source_artifact_for_suspicious_pth,
        inspect_wheel_for_suspicious_pth,
    )

    alerts: list[object] = []
    with temporary_artifact_directory() as directory:
        destination = Path(directory)
        for package in plan.packages:
            if not package.download_url:
                continue
            artifact = download_artifact(package, destination)
            artifact_name = artifact.path.name.lower()
            if artifact_name.endswith(".whl"):
                alerts.extend(inspect_wheel_for_suspicious_pth(artifact.path))
                continue
            if artifact_name.endswith(SOURCE_ARCHIVE_SUFFIXES):
                alerts.extend(inspect_source_artifact_for_suspicious_pth(artifact.path))
    return alerts


def _pipx_preflight_pip_args(argv: list[str]) -> list[str] | None:
    command = _find_command(
        argv,
        commands=PIPX_COMMANDS,
        options_with_value=PIPX_GLOBAL_OPTIONS_WITH_VALUE,
    )
    if command is None:
        return None
    command_args = argv[command.index + 1 :]
    parsed = _parse_pipx_options(command_args)
    if parsed.unsupported:
        return None

    if command.name == "install":
        main_requirements = parsed.specs or parsed.positionals
        return _pipx_pip_args(
            parsed.pip_args,
            normal_requirements=parsed.preinstall,
            editable_requirements=main_requirements if parsed.editable else (),
            plain_requirements=() if parsed.editable else main_requirements,
        )

    if command.name in {"reinstall", "reinstall-all", "upgrade", "upgrade-all"}:
        return None

    if command.name == "inject":
        dependencies = parsed.positionals[1:]
        return _pipx_pip_args(
            parsed.pip_args,
            normal_requirements=(),
            editable_requirements=dependencies if parsed.editable else (),
            plain_requirements=() if parsed.editable else dependencies,
        )

    if command.name == "run":
        main_requirement = parsed.specs[:1] or parsed.positionals[:1]
        return _pipx_pip_args(
            parsed.pip_args,
            normal_requirements=(*parsed.preinstall, *parsed.with_requirements),
            editable_requirements=main_requirement if parsed.editable else (),
            plain_requirements=() if parsed.editable else main_requirement,
        )

    return None


def _poetry_preflight_pip_args(argv: list[str]) -> list[str] | None:
    command = _find_command(
        argv,
        commands=POETRY_COMMANDS,
        options_with_value=POETRY_GLOBAL_OPTIONS_WITH_VALUE,
    )
    if command is None:
        return None

    if command.name == "add":
        return _poetry_add_pip_args(argv[command.index + 1 :])

    if command.name == "self":
        nested = _find_command(
            argv[command.index + 1 :],
            commands={"add"},
            options_with_value=set(),
        )
        if nested is None:
            return None
        add_index = command.index + 1 + nested.index
        return _poetry_add_pip_args(argv[add_index + 1 :])

    return None


def _uv_preflight_pip_args(argv: list[str]) -> list[str] | None:
    command = _find_uv_command(argv)
    if command is None or command.path not in UV_GUARDED_COMMANDS:
        return None

    command_args = argv[command.args_index :]
    if command.path == ("pip", "install"):
        return _uv_pip_install_pip_args(command_args)
    if command.path == ("add",):
        return _uv_add_pip_args(command_args)
    if command.path == ("tool", "install"):
        return _uv_tool_install_pip_args(command_args)
    if command.path == ("tool", "run"):
        return _uv_tool_run_pip_args(command_args)
    return None


@dataclass(frozen=True)
class ParsedPipxOptions:
    positionals: tuple[str, ...]
    pip_args: tuple[str, ...]
    specs: tuple[str, ...]
    preinstall: tuple[str, ...]
    with_requirements: tuple[str, ...]
    editable: bool
    unsupported: bool


def _parse_pipx_options(args: list[str]) -> ParsedPipxOptions:
    positionals: list[str] = []
    pip_args: list[str] = []
    specs: list[str] = []
    preinstall: list[str] = []
    with_requirements: list[str] = []
    editable = False
    unsupported = False

    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            break

        consumed = _consume_option_value(
            args,
            i,
            options_with_value=PIPX_OPTIONS_WITH_VALUE,
            aliases=PIPX_VALUE_ALIASES,
        )
        if consumed is not None:
            option, value, i = consumed
            if option == "--pip-args":
                pip_args.extend(_split_pip_args(value))
                continue
            if option == "--index-url":
                pip_args.extend(["--index-url", value])
                continue
            if option == "--requirement":
                pip_args.extend(["-r", value])
                continue
            if option == "--python":
                pip_args.extend(["--python", value])
                continue
            if option == "--spec":
                specs.append(value)
                continue
            if option == "--preinstall":
                preinstall.append(value)
                continue
            if option == "--with":
                with_requirements.append(value)
                continue
            continue

        if arg in {"--editable", "-e"}:
            editable = True
            i += 1
            continue
        if arg in PIPX_FLAGS:
            i += 1
            continue
        if arg.startswith("-"):
            unsupported = True
            i += 1
            continue

        positionals.append(arg)
        i += 1

    return ParsedPipxOptions(
        positionals=tuple(positionals),
        pip_args=tuple(pip_args),
        specs=tuple(specs),
        preinstall=tuple(preinstall),
        with_requirements=tuple(with_requirements),
        editable=editable,
        unsupported=unsupported,
    )


def _pipx_pip_args(
    base_args: Iterable[str],
    *,
    normal_requirements: Iterable[str],
    editable_requirements: Iterable[str],
    plain_requirements: Iterable[str],
) -> list[str] | None:
    pip_args = list(base_args)
    pip_args.extend(_non_empty(normal_requirements))
    for requirement in _non_empty(editable_requirements):
        pip_args.extend(["--editable", requirement])
    pip_args.extend(_non_empty(plain_requirements))
    if not pip_args:
        return None
    return pip_args


def _poetry_add_pip_args(args: list[str]) -> list[str] | None:
    positionals: list[str] = []
    pip_args: list[str] = []
    editable = False
    unsupported_source = False
    unsupported = False

    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            positionals.extend(args[i + 1 :])
            break

        consumed = _consume_option_value(
            args,
            i,
            options_with_value=POETRY_ADD_OPTIONS_WITH_VALUE,
            aliases=POETRY_ADD_VALUE_ALIASES,
        )
        if consumed is not None:
            option, value, i = consumed
            if option == "--source" and value.lower() != "pypi":
                unsupported_source = True
            continue

        if arg == "--allow-prereleases":
            pip_args.append("--pre")
            i += 1
            continue
        if arg in {"--editable", "-e"}:
            editable = True
            i += 1
            continue
        if arg in POETRY_ADD_FLAGS:
            i += 1
            continue
        if arg.startswith("-"):
            unsupported = True
            i += 1
            continue

        positionals.append(arg)
        i += 1

    if unsupported_source or unsupported:
        return None

    requirements = [
        _poetry_dependency_to_pip_requirement(dependency)
        for dependency in positionals
        if dependency
    ]
    if not requirements:
        return None

    result = list(pip_args)
    for requirement in requirements:
        if editable:
            result.extend(["--editable", requirement])
        else:
            result.append(requirement)
    return result


def _uv_pip_install_pip_args(args: list[str]) -> list[str] | None:
    parsed = _parse_uv_package_options(
        args,
        value_options={
            "--extra",
            "--group",
            "--no-binary",
            "--no-sources-package",
            "--only-binary",
        },
        unsupported_value_options={"--group"},
        flags={"--all-extras"},
    )
    if parsed is None:
        return None
    return _pip_args_from_uv_package_options(parsed)


def _uv_add_pip_args(args: list[str]) -> list[str] | None:
    parsed = _parse_uv_package_options(
        args,
        value_options={
            "--bounds",
            "--extra",
            "--group",
            "--marker",
            "-m",
            "--no-install-package",
            "--no-sources-package",
            "--optional",
            "--package",
            "--script",
        },
        value_aliases={"-m": "--marker"},
        flags={
            "--active",
            "--dev",
            "--editable",
            "--frozen",
            "--locked",
            "--no-install-local",
            "--no-install-project",
            "--no-install-workspace",
            "--no-sync",
            "--no-workspace",
            "--raw",
            "--workspace",
        },
        unsupported_value_options={"--branch", "--rev", "--tag"},
        unsupported_flags={"--lfs"},
        editable_flag=True,
    )
    if parsed is None:
        return None
    return _pip_args_from_uv_package_options(parsed)


def _uv_tool_install_pip_args(args: list[str]) -> list[str] | None:
    parsed = _parse_uv_package_options(
        args,
        value_options={
            "--with",
            "-w",
            "--with-editable",
            "--with-executables-from",
            "--with-requirements",
        },
        value_aliases={"-w": "--with"},
        flags={"--editable", "-e", "--force"},
        editable_flag=True,
    )
    if parsed is None:
        return None
    pip_args = _pip_args_from_uv_package_options(parsed)
    if pip_args is None:
        return None
    return pip_args


def _uv_tool_run_pip_args(args: list[str]) -> list[str] | None:
    parsed = _parse_uv_tool_run_options(args)
    if parsed is None:
        return None
    return _pip_args_from_uv_package_options(parsed)


@dataclass(frozen=True)
class ParsedUvPackageOptions:
    positionals: tuple[str, ...]
    editable_requirements: tuple[str, ...]
    requirement_files: tuple[str, ...]
    with_requirements: tuple[str, ...]
    with_editable_requirements: tuple[str, ...]
    with_requirement_files: tuple[str, ...]
    pip_args: tuple[str, ...]
    editable: bool


def _parse_uv_package_options(
    args: list[str],
    *,
    value_options: set[str] | None = None,
    value_aliases: dict[str, str] | None = None,
    flags: set[str] | None = None,
    unsupported_value_options: set[str] | None = None,
    unsupported_flags: set[str] | None = None,
    editable_flag: bool = False,
) -> ParsedUvPackageOptions | None:
    positionals: list[str] = []
    editable_requirements: list[str] = []
    requirement_files: list[str] = []
    with_requirements: list[str] = []
    with_editable_requirements: list[str] = []
    with_requirement_files: list[str] = []
    pip_args: list[str] = []
    editable = False
    editable_value_options = set() if editable_flag else {"--editable", "-e"}

    allowed_value_options = {
        *UV_INDEX_OPTIONS_WITH_VALUE,
        *UV_RESOLVER_OPTIONS_WITH_VALUE,
        *UV_BUILD_OPTIONS_WITH_VALUE,
        *UV_PYTHON_OPTIONS_WITH_VALUE,
        "--constraints",
        "-c",
        *editable_value_options,
        "--requirements",
        "-r",
        "--target",
        "-t",
        "--prefix",
        *(value_options or set()),
    }
    aliases = {
        **UV_INDEX_VALUE_ALIASES,
        **UV_RESOLVER_VALUE_ALIASES,
        **UV_BUILD_VALUE_ALIASES,
        **UV_PYTHON_VALUE_ALIASES,
        "-c": "--constraints",
        "-e": "--editable",
        "-r": "--requirements",
        "-t": "--target",
        **(value_aliases or {}),
    }
    allowed_flags = {
        *UV_COMMON_FLAGS,
        "--all-extras",
        "--exact",
        "--managed-python",
        "--no-break-system-packages",
        "--no-editable",
        "--no-managed-python",
        "--no-python-downloads",
        "--no-sources",
        "--no-verify-hashes",
        *(flags or set()),
    }
    blocked_value_options = {
        *UV_UNSUPPORTED_VALUE_OPTIONS,
        *(unsupported_value_options or set()),
    }
    blocked_flags = {
        *(unsupported_flags or set()),
    }

    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            positionals.extend(args[i + 1 :])
            break

        consumed = _consume_option_value(
            args,
            i,
            options_with_value=allowed_value_options,
            aliases=aliases,
        )
        if consumed is not None:
            option, value, i = consumed
            if option in blocked_value_options:
                return None
            if not value:
                return None
            if not _append_uv_value_option(
                option,
                value,
                pip_args=pip_args,
                requirement_files=requirement_files,
                editable_requirements=editable_requirements,
                with_requirements=with_requirements,
                with_editable_requirements=with_editable_requirements,
                with_requirement_files=with_requirement_files,
            ):
                return None
            continue

        if arg in blocked_flags:
            return None
        if arg in allowed_flags:
            if not _append_uv_flag(arg, pip_args=pip_args, editable_flag=editable_flag):
                return None
            if editable_flag and arg in {"--editable", "-e"}:
                editable = True
            i += 1
            continue
        if arg.startswith("-"):
            return None

        positionals.append(arg)
        i += 1

    return ParsedUvPackageOptions(
        positionals=tuple(positionals),
        editable_requirements=tuple(editable_requirements),
        requirement_files=tuple(requirement_files),
        with_requirements=tuple(with_requirements),
        with_editable_requirements=tuple(with_editable_requirements),
        with_requirement_files=tuple(with_requirement_files),
        pip_args=tuple(pip_args),
        editable=editable,
    )


def _parse_uv_tool_run_options(args: list[str]) -> ParsedUvPackageOptions | None:
    positionals: list[str] = []
    requirement_files: list[str] = []
    with_requirements: list[str] = []
    with_editable_requirements: list[str] = []
    with_requirement_files: list[str] = []
    pip_args: list[str] = []
    from_requirement: str | None = None

    value_options = {
        *UV_INDEX_OPTIONS_WITH_VALUE,
        *UV_RESOLVER_OPTIONS_WITH_VALUE,
        *UV_BUILD_OPTIONS_WITH_VALUE,
        *UV_PYTHON_OPTIONS_WITH_VALUE,
        "--constraints",
        "-c",
        "--env-file",
        "--from",
        "--with",
        "-w",
        "--with-editable",
        "--with-requirements",
        *UV_GLOBAL_OPTIONS_WITH_VALUE,
    }
    aliases = {
        **UV_INDEX_VALUE_ALIASES,
        **UV_RESOLVER_VALUE_ALIASES,
        **UV_BUILD_VALUE_ALIASES,
        **UV_PYTHON_VALUE_ALIASES,
        "-c": "--constraints",
        "-w": "--with",
    }
    unsupported_value_options = {
        *UV_UNSUPPORTED_VALUE_OPTIONS,
        "--build-constraints",
        "--env-file",
    }

    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            break

        consumed = _consume_option_value(
            args,
            i,
            options_with_value=value_options,
            aliases=aliases,
        )
        if consumed is not None:
            option, value, i = consumed
            if option in unsupported_value_options or not value:
                return None
            if option == "--from":
                from_requirement = value
                continue
            if not _append_uv_value_option(
                option,
                value,
                pip_args=pip_args,
                requirement_files=requirement_files,
                editable_requirements=[],
                with_requirements=with_requirements,
                with_editable_requirements=with_editable_requirements,
                with_requirement_files=with_requirement_files,
            ):
                return None
            continue

        if arg in {
            *UV_COMMON_FLAGS,
            "--isolated",
            "--managed-python",
            "--no-env-file",
            "--no-managed-python",
            "--no-python-downloads",
            "--no-sources",
        }:
            if not _append_uv_flag(arg, pip_args=pip_args, editable_flag=False):
                return None
            i += 1
            continue
        if arg.startswith("-"):
            return None

        positionals.append(from_requirement or arg)
        break

    if from_requirement and not positionals:
        positionals.append(from_requirement)

    return ParsedUvPackageOptions(
        positionals=tuple(positionals),
        editable_requirements=(),
        requirement_files=tuple(requirement_files),
        with_requirements=tuple(with_requirements),
        with_editable_requirements=tuple(with_editable_requirements),
        with_requirement_files=tuple(with_requirement_files),
        pip_args=tuple(pip_args),
        editable=False,
    )


def _append_uv_value_option(
    option: str,
    value: str,
    *,
    pip_args: list[str],
    requirement_files: list[str],
    editable_requirements: list[str],
    with_requirements: list[str],
    with_editable_requirements: list[str],
    with_requirement_files: list[str],
) -> bool:
    if option == "--default-index":
        pip_args.extend(["--index-url", value])
        return True
    if option == "--index-url":
        pip_args.extend(["--index-url", value])
        return True
    if option == "--find-links":
        pip_args.extend(["--find-links", value])
        return True
    if option == "--constraints":
        pip_args.extend(["-c", value])
        return True
    if option == "--requirements":
        requirement_files.append(value)
        return True
    if option == "--editable":
        editable_requirements.append(value)
        return True
    if option == "--python":
        pip_args.extend(["--python", value])
        return True
    if option == "--target":
        pip_args.extend(["--target", value])
        return True
    if option == "--prefix":
        pip_args.extend(["--prefix", value])
        return True
    if option == "--only-binary":
        pip_args.extend(["--only-binary", value])
        return True
    if option == "--no-binary":
        pip_args.extend(["--no-binary", value])
        return True
    if option == "--config-setting":
        pip_args.extend(["--config-settings", value])
        return True
    if option == "--prerelease":
        if value == "allow":
            pip_args.append("--pre")
        return True
    if option in {"--upgrade-package", "--refresh-package", "--reinstall-package"}:
        return True
    if option in {
        "--allow-insecure-host",
        "--bounds",
        "--cache-dir",
        "--color",
        "--config-file",
        "--directory",
        "--extra",
        "--marker",
        "--no-install-package",
        "--no-sources-package",
        "--optional",
        "--package",
        "--script",
        *UV_GLOBAL_OPTIONS_WITH_VALUE,
    }:
        return True
    if option == "--with":
        with_requirements.append(value)
        return True
    if option == "--with-editable":
        with_editable_requirements.append(value)
        return True
    if option == "--with-requirements":
        with_requirement_files.append(value)
        return True
    if option == "--with-executables-from":
        with_requirements.append(value)
        return True
    return False


def _append_uv_flag(
    option: str,
    *,
    pip_args: list[str],
    editable_flag: bool,
) -> bool:
    if editable_flag and option in {"--editable", "-e"}:
        return True
    if option in {"--no-deps", "--require-hashes", "--no-index", "--user"}:
        pip_args.append(option)
        return True
    if option in {"--upgrade", "-U"}:
        pip_args.append("--upgrade")
        return True
    if option == "--no-build-isolation":
        pip_args.append("--no-build-isolation")
        return True
    if option == "--no-build":
        pip_args.append("--only-binary=:all:")
        return True
    if option in {
        *UV_GLOBAL_FLAGS,
        "--active",
        "--all-extras",
        "--break-system-packages",
        "--compile-bytecode",
        "--dev",
        "--dry-run",
        "--exact",
        "--force",
        "--frozen",
        "--isolated",
        "--locked",
        "--managed-python",
        "--no-break-system-packages",
        "--no-editable",
        "--no-env-file",
        "--no-install-local",
        "--no-install-project",
        "--no-install-workspace",
        "--no-managed-python",
        "--no-python-downloads",
        "--no-sources",
        "--no-sync",
        "--no-verify-hashes",
        "--no-workspace",
        "--raw",
        "--reinstall",
        "--strict",
        "--system",
        "--workspace",
    }:
        return True
    return False


def _pip_args_from_uv_package_options(
    parsed: ParsedUvPackageOptions,
) -> list[str] | None:
    result = list(parsed.pip_args)
    for requirement_file in _non_empty(
        (*parsed.requirement_files, *parsed.with_requirement_files)
    ):
        result.extend(["-r", requirement_file])
    for requirement in _non_empty(
        (*parsed.editable_requirements, *parsed.with_editable_requirements)
    ):
        result.extend(["--editable", requirement])
    result.extend(_non_empty(parsed.with_requirements))
    plain_requirements = _non_empty(parsed.positionals)
    if parsed.editable:
        for requirement in plain_requirements:
            result.extend(["--editable", requirement])
    else:
        result.extend(plain_requirements)
    if not result:
        return None
    return result


def _poetry_dependency_to_pip_requirement(dependency: str) -> str:
    if _looks_like_direct_reference_or_path(dependency) or " @ " in dependency:
        return dependency

    name, separator, constraint = dependency.partition("@")
    if not separator or not name or not constraint:
        return dependency

    if constraint == "*":
        return name
    if constraint.lower() == "latest":
        return name
    if _looks_like_direct_reference_or_path(constraint):
        return f"{name} @ {constraint}"
    if constraint.startswith("^"):
        return f"{name}{_caret_constraint_to_pep440(constraint[1:])}"
    if constraint.startswith("~") and not constraint.startswith("~="):
        return f"{name}{_tilde_constraint_to_pep440(constraint[1:])}"
    if constraint.startswith(PEP_440_OPERATORS):
        return f"{name}{constraint}"
    return f"{name}=={constraint}"


def _caret_constraint_to_pep440(version_text: str) -> str:
    release = _release_parts(version_text)
    if release is None:
        return ""

    part_count = _release_part_count(version_text)
    specified = release[:part_count]
    upper = release.copy()
    significant_index = _first_non_zero_index(specified)
    if significant_index is None:
        significant_index = min(part_count, len(upper)) - 1
    upper[significant_index] += 1
    upper = upper[: significant_index + 1]
    return f">={version_text},<{'.'.join(str(part) for part in upper)}"


def _tilde_constraint_to_pep440(version_text: str) -> str:
    release = _release_parts(version_text)
    if release is None:
        return ""

    original_part_count = _release_part_count(version_text)
    if original_part_count >= 2:
        upper = release[:2]
        upper[1] += 1
    else:
        upper = [release[0] + 1]
    return f">={version_text},<{'.'.join(str(part) for part in upper)}"


def _release_parts(version_text: str) -> list[int] | None:
    try:
        release = list(Version(version_text).release)
    except Exception:
        return None
    if not release:
        return None
    while len(release) < 3:
        release.append(0)
    return release


def _release_part_count(version_text: str) -> int:
    return max(1, version_text.split("+", 1)[0].split("-", 1)[0].count(".") + 1)


def _first_non_zero_index(release: list[int]) -> int | None:
    for index, part in enumerate(release):
        if part != 0:
            return index
    return None


def _looks_like_direct_reference_or_path(value: str) -> bool:
    if value.startswith(DIRECT_REFERENCE_PREFIXES):
        return True
    if value.startswith(("./", "../", "/", ".\\")):
        return True
    if len(value) >= 3 and value[1:3] in {":\\", ":/"}:
        return True
    return False


def _find_command(
    args: list[str],
    *,
    commands: set[str],
    options_with_value: set[str],
) -> ToolCommand | None:
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            return None
        if arg in commands:
            return ToolCommand(name=arg, index=i)
        consumed = _consume_option_value(
            args,
            i,
            options_with_value=options_with_value,
            aliases={},
        )
        if consumed is not None:
            _, _, i = consumed
            continue
        if arg.startswith("-"):
            i += 1
            continue
        return None
    return None


def _find_uv_command(args: list[str]) -> UvCommand | None:
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            return None
        consumed = _consume_option_value(
            args,
            i,
            options_with_value=UV_GLOBAL_OPTIONS_WITH_VALUE,
            aliases={},
        )
        if consumed is not None:
            _, _, i = consumed
            continue
        if arg in UV_GLOBAL_FLAGS:
            i += 1
            continue
        if arg == "pip":
            return _find_uv_nested_command(args, i, parent="pip")
        if arg == "tool":
            return _find_uv_nested_command(args, i, parent="tool")
        if arg in UV_TOP_LEVEL_COMMANDS:
            return UvCommand(path=(arg,), index=i, args_index=i + 1)
        if arg.startswith("-"):
            return None
        return None
    return None


def _find_uv_nested_command(args: list[str], index: int, *, parent: str) -> UvCommand:
    i = index + 1
    while i < len(args):
        arg = args[i]
        if arg == "--":
            return UvCommand(path=(parent,), index=index, args_index=i)
        consumed = _consume_option_value(
            args,
            i,
            options_with_value=UV_GLOBAL_OPTIONS_WITH_VALUE,
            aliases={},
        )
        if consumed is not None:
            _, _, i = consumed
            continue
        if arg in UV_GLOBAL_FLAGS:
            i += 1
            continue
        if arg.startswith("-"):
            return UvCommand(path=(parent,), index=index, args_index=i, unsupported=True)
        return UvCommand(path=(parent, arg), index=index, args_index=i + 1)
    return UvCommand(path=(parent,), index=index, args_index=i)


def _consume_option_value(
    args: list[str],
    index: int,
    *,
    options_with_value: set[str],
    aliases: dict[str, str],
) -> tuple[str, str, int] | None:
    arg = args[index]
    option = arg
    value: str | None = None
    if arg.startswith("--") and "=" in arg:
        option, value = arg.split("=", 1)

    canonical_option = aliases.get(option, option)
    if canonical_option not in options_with_value and option not in options_with_value:
        return None
    canonical_option = aliases.get(option, canonical_option)

    if value is not None:
        return canonical_option, value, index + 1
    if index + 1 >= len(args):
        return canonical_option, "", index + 1
    return canonical_option, args[index + 1], index + 2


def _split_pip_args(value: str) -> list[str]:
    try:
        return shlex.split(value)
    except ValueError:
        return [value]


def _non_empty(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(value for value in values if value)
