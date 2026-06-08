from __future__ import annotations

from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from secpipw.install_plan import InstallPlan


class _FrozenRecord:
    __slots__ = ()
    _field_names: tuple[str, ...] = ()

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(f"{type(self).__name__} is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f"{type(self).__name__} is immutable")

    def __repr__(self) -> str:
        values = ", ".join(
            f"{name}={getattr(self, name)!r}" for name in self._field_names
        )
        return f"{type(self).__name__}({values})"

    def __eq__(self, other: object) -> bool:
        if type(self) is not type(other):
            return False
        return all(
            getattr(self, name) == getattr(other, name) for name in self._field_names
        )

    def __hash__(self) -> int:
        return hash(tuple(getattr(self, name) for name in self._field_names))


class ToolCommand(_FrozenRecord):
    __slots__ = ("name", "index")
    _field_names = ("name", "index")

    def __init__(self, name: str, index: int) -> None:
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "index", index)

    name: str
    index: int


class UvCommand(_FrozenRecord):
    __slots__ = ("path", "index", "args_index", "unsupported")
    _field_names = ("path", "index", "args_index", "unsupported")

    def __init__(
        self,
        path: tuple[str, ...],
        index: int,
        args_index: int,
        unsupported: bool = False,
    ) -> None:
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "index", index)
        object.__setattr__(self, "args_index", args_index)
        object.__setattr__(self, "unsupported", unsupported)

    path: tuple[str, ...]
    index: int
    args_index: int
    unsupported: bool


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
POETRY_SELF_COMMANDS = {"add"}
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
_UV_EMPTY_SET: frozenset[str] = frozenset()
_UV_EMPTY_DICT: dict[str, str] = {}

UV_PIP_PACKAGE_VALUE_OPTIONS = frozenset(
    {
        *UV_INDEX_OPTIONS_WITH_VALUE,
        *UV_RESOLVER_OPTIONS_WITH_VALUE,
        *UV_BUILD_OPTIONS_WITH_VALUE,
        *UV_PYTHON_OPTIONS_WITH_VALUE,
        "--constraints",
        "-c",
        "--requirements",
        "-r",
        "--target",
        "-t",
        "--prefix",
    }
)
UV_PIP_PACKAGE_VALUE_ALIASES = {
    **UV_INDEX_VALUE_ALIASES,
    **UV_RESOLVER_VALUE_ALIASES,
    **UV_BUILD_VALUE_ALIASES,
    **UV_PYTHON_VALUE_ALIASES,
    "-c": "--constraints",
    "-r": "--requirements",
    "-t": "--target",
}
UV_PIP_PACKAGE_ALLOWED_FLAGS = frozenset(
    UV_COMMON_FLAGS
    | {
        "--all-extras",
        "--exact",
        "--managed-python",
        "--no-break-system-packages",
        "--no-editable",
        "--no-managed-python",
        "--no-python-downloads",
        "--no-sources",
        "--no-verify-hashes",
    }
)

UV_PIP_INSTALL_VALUE_OPTIONS = frozenset(
    {
        "--editable",
        "-e",
        *UV_PIP_PACKAGE_VALUE_OPTIONS,
        "--extra",
        "--group",
        "--no-binary",
        "--no-sources-package",
        "--only-binary",
    }
)
UV_PIP_INSTALL_VALUE_ALIASES = {
    **UV_PIP_PACKAGE_VALUE_ALIASES,
    "-c": "--constraints",
    "-e": "--editable",
    "-r": "--requirements",
    "-t": "--target",
}
UV_PIP_INSTALL_ALLOWED_FLAGS = frozenset(
    UV_PIP_PACKAGE_ALLOWED_FLAGS
)
UV_PIP_INSTALL_BLOCKED_VALUE_OPTIONS = frozenset(
    (*UV_UNSUPPORTED_VALUE_OPTIONS, "--group")
)
UV_PIP_INSTALL_BLOCKED_FLAGS = _UV_EMPTY_SET

UV_ADD_VALUE_OPTIONS = frozenset(
    {
        *UV_PIP_PACKAGE_VALUE_OPTIONS,
        "--bounds",
        "--marker",
        "-m",
        "--extra",
        "--group",
        "--no-install-package",
        "--optional",
        "--package",
        "--script",
    }
)
UV_ADD_VALUE_ALIASES = {
    **UV_PIP_PACKAGE_VALUE_ALIASES,
    "-m": "--marker",
}
UV_ADD_ALLOWED_FLAGS = frozenset(
    UV_PIP_PACKAGE_ALLOWED_FLAGS
    | {
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
    }
)
UV_ADD_BLOCKED_VALUE_OPTIONS = frozenset(
    (*UV_UNSUPPORTED_VALUE_OPTIONS, "--branch", "--rev", "--tag")
)
UV_ADD_BLOCKED_FLAGS = frozenset({"--lfs"})

UV_TOOL_INSTALL_VALUE_OPTIONS = frozenset(
    {
        *UV_PIP_PACKAGE_VALUE_OPTIONS,
        "--with",
        "-w",
        "--with-editable",
        "--with-executables-from",
        "--with-requirements",
    }
)
UV_TOOL_INSTALL_VALUE_ALIASES = {
    **UV_PIP_PACKAGE_VALUE_ALIASES,
    "-w": "--with",
}
UV_TOOL_INSTALL_ALLOWED_FLAGS = frozenset(
    UV_PIP_PACKAGE_ALLOWED_FLAGS | {"--editable", "--force"}
)
UV_TOOL_INSTALL_BLOCKED_VALUE_OPTIONS = frozenset(UV_UNSUPPORTED_VALUE_OPTIONS)
UV_TOOL_INSTALL_BLOCKED_FLAGS = _UV_EMPTY_SET

UV_TOOL_RUN_VALUE_OPTIONS = frozenset(
    {
        *UV_PIP_PACKAGE_VALUE_OPTIONS,
        *UV_GLOBAL_OPTIONS_WITH_VALUE,
        "--env-file",
        "--from",
        "--with",
        "-w",
        "--with-editable",
        "--with-requirements",
    }
)
UV_TOOL_RUN_ALIASES = {
    **UV_PIP_PACKAGE_VALUE_ALIASES,
    "-c": "--constraints",
    "-w": "--with",
}
UV_TOOL_RUN_ALLOWED_FLAGS = frozenset(
    UV_COMMON_FLAGS
    | {
        "--isolated",
        "--managed-python",
        "--no-env-file",
        "--no-managed-python",
        "--no-python-downloads",
        "--no-sources",
    }
)
UV_TOOL_RUN_BLOCKED_VALUE_OPTIONS = frozenset(
    (*UV_UNSUPPORTED_VALUE_OPTIONS, "--build-constraints", "--env-file")
)
UV_TOOL_RUN_BLOCKED_FLAGS = _UV_EMPTY_SET

UV_EDITABLE_FLAGS = frozenset({"--editable", "-e"})
UV_VALUE_OPTION_TO_PIP_OPTION = {
    "--default-index": "--index-url",
    "--index-url": "--index-url",
    "--find-links": "--find-links",
    "--constraints": "-c",
    "--python": "--python",
    "--target": "--target",
    "--prefix": "--prefix",
    "--only-binary": "--only-binary",
    "--no-binary": "--no-binary",
    "--config-setting": "--config-settings",
}
UV_VALUE_OPTION_REQUIREMENT_FILES = frozenset({"--requirements", "--with-requirements"})
UV_VALUE_OPTION_WITH_REQUIREMENTS = frozenset({"--with", "--with-executables-from"})
UV_VALUE_OPTION_WITH_EDITABLE_REQUIREMENTS = frozenset({"--with-editable"})
UV_VALUE_OPTION_NOOP = frozenset(
    {
        "--upgrade-package",
        "--refresh-package",
        "--reinstall-package",
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
    }
) - frozenset(UV_VALUE_OPTION_TO_PIP_OPTION) - UV_VALUE_OPTION_WITH_REQUIREMENTS - UV_VALUE_OPTION_WITH_EDITABLE_REQUIREMENTS
UV_FLAG_TO_PIP_OPTION = {
    "--no-deps": "--no-deps",
    "--require-hashes": "--require-hashes",
    "--no-index": "--no-index",
    "--user": "--user",
    "--upgrade": "--upgrade",
    "-U": "--upgrade",
    "--no-build-isolation": "--no-build-isolation",
    "--no-build": "--only-binary=:all:",
}
UV_FLAG_NOOP = (
    UV_COMMON_FLAGS
    | {
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
    }
) - frozenset(UV_FLAG_TO_PIP_OPTION)

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
    import subprocess
    import sys

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
    from pathlib import Path

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
            commands=POETRY_SELF_COMMANDS,
            options_with_value=_UV_EMPTY_SET,
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


class ParsedPipxOptions(_FrozenRecord):
    __slots__ = (
        "positionals",
        "pip_args",
        "specs",
        "preinstall",
        "with_requirements",
        "editable",
        "unsupported",
    )
    _field_names = __slots__

    def __init__(
        self,
        positionals: tuple[str, ...],
        pip_args: tuple[str, ...],
        specs: tuple[str, ...],
        preinstall: tuple[str, ...],
        with_requirements: tuple[str, ...],
        editable: bool,
        unsupported: bool,
    ) -> None:
        object.__setattr__(self, "positionals", positionals)
        object.__setattr__(self, "pip_args", pip_args)
        object.__setattr__(self, "specs", specs)
        object.__setattr__(self, "preinstall", preinstall)
        object.__setattr__(self, "with_requirements", with_requirements)
        object.__setattr__(self, "editable", editable)
        object.__setattr__(self, "unsupported", unsupported)

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
    for requirement in normal_requirements:
        if requirement:
            pip_args.append(requirement)
    for requirement in editable_requirements:
        if requirement:
            pip_args.extend(["--editable", requirement])
    for requirement in plain_requirements:
        if requirement:
            pip_args.append(requirement)
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
        value_options=UV_PIP_INSTALL_VALUE_OPTIONS,
        value_aliases=UV_PIP_INSTALL_VALUE_ALIASES,
        flags=UV_PIP_INSTALL_ALLOWED_FLAGS,
        blocked_value_options=UV_PIP_INSTALL_BLOCKED_VALUE_OPTIONS,
        blocked_flags=UV_PIP_INSTALL_BLOCKED_FLAGS,
    )
    if parsed is None:
        return None
    return _pip_args_from_uv_package_options(parsed)


def _uv_add_pip_args(args: list[str]) -> list[str] | None:
    parsed = _parse_uv_package_options(
        args,
        value_options=UV_ADD_VALUE_OPTIONS,
        value_aliases=UV_ADD_VALUE_ALIASES,
        flags=UV_ADD_ALLOWED_FLAGS,
        blocked_value_options=UV_ADD_BLOCKED_VALUE_OPTIONS,
        blocked_flags=UV_ADD_BLOCKED_FLAGS,
        editable_flag=True,
    )
    if parsed is None:
        return None
    return _pip_args_from_uv_package_options(parsed)


def _uv_tool_install_pip_args(args: list[str]) -> list[str] | None:
    parsed = _parse_uv_package_options(
        args,
        value_options=UV_TOOL_INSTALL_VALUE_OPTIONS,
        value_aliases=UV_TOOL_INSTALL_VALUE_ALIASES,
        flags=UV_TOOL_INSTALL_ALLOWED_FLAGS,
        blocked_value_options=UV_TOOL_INSTALL_BLOCKED_VALUE_OPTIONS,
        blocked_flags=UV_TOOL_INSTALL_BLOCKED_FLAGS,
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


class ParsedUvPackageOptions(_FrozenRecord):
    __slots__ = (
        "positionals",
        "editable_requirements",
        "requirement_files",
        "with_requirements",
        "with_editable_requirements",
        "with_requirement_files",
        "pip_args",
        "editable",
    )
    _field_names = __slots__

    def __init__(
        self,
        positionals: tuple[str, ...],
        editable_requirements: tuple[str, ...],
        requirement_files: tuple[str, ...],
        with_requirements: tuple[str, ...],
        with_editable_requirements: tuple[str, ...],
        with_requirement_files: tuple[str, ...],
        pip_args: tuple[str, ...],
        editable: bool,
    ) -> None:
        object.__setattr__(self, "positionals", positionals)
        object.__setattr__(self, "editable_requirements", editable_requirements)
        object.__setattr__(self, "requirement_files", requirement_files)
        object.__setattr__(self, "with_requirements", with_requirements)
        object.__setattr__(
            self, "with_editable_requirements", with_editable_requirements
        )
        object.__setattr__(self, "with_requirement_files", with_requirement_files)
        object.__setattr__(self, "pip_args", pip_args)
        object.__setattr__(self, "editable", editable)

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
    value_options: frozenset[str],
    value_aliases: dict[str, str],
    flags: frozenset[str],
    blocked_value_options: frozenset[str],
    blocked_flags: frozenset[str],
    editable_flag: bool = False,
) -> ParsedUvPackageOptions | None:
    args_len = len(args)
    positionals: list[str] = []
    editable_requirements: list[str] = []
    requirement_files: list[str] = []
    with_requirements: list[str] = []
    with_editable_requirements: list[str] = []
    with_requirement_files: list[str] = []
    pip_args: list[str] = []
    editable = False
    i = 0
    while i < args_len:
        arg = args[i]
        if arg == "--":
            positionals.extend(args[i + 1 :])
            break

        consumed = _consume_option_value(
            args,
            i,
            options_with_value=value_options,
            aliases=value_aliases,
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
        if arg in flags:
            if not _append_uv_flag(arg, pip_args=pip_args, editable_flag=editable_flag):
                return None
            if editable_flag and arg in UV_EDITABLE_FLAGS:
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
    args_len = len(args)
    positionals: list[str] = []
    requirement_files: list[str] = []
    with_requirements: list[str] = []
    with_editable_requirements: list[str] = []
    with_requirement_files: list[str] = []
    pip_args: list[str] = []
    from_requirement: str | None = None

    i = 0
    while i < args_len:
        arg = args[i]
        if arg == "--":
            break

        consumed = _consume_option_value(
            args,
            i,
            options_with_value=UV_TOOL_RUN_VALUE_OPTIONS,
            aliases=UV_TOOL_RUN_ALIASES,
        )
        if consumed is not None:
            option, value, i = consumed
            if option in UV_TOOL_RUN_BLOCKED_VALUE_OPTIONS or not value:
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

        if arg in UV_TOOL_RUN_ALLOWED_FLAGS:
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
    if option == "--prerelease":
        if value == "allow":
            pip_args.append("--pre")
        return True
    if option in UV_VALUE_OPTION_REQUIREMENT_FILES:
        target_list = (
            requirement_files
            if option == "--requirements"
            else with_requirement_files
        )
        target_list.append(value)
        return True
    if option in UV_VALUE_OPTION_WITH_REQUIREMENTS:
        with_requirements.append(value)
        return True
    if option in UV_VALUE_OPTION_WITH_EDITABLE_REQUIREMENTS:
        with_editable_requirements.append(value)
        return True
    pip_option = UV_VALUE_OPTION_TO_PIP_OPTION.get(option)
    if pip_option is not None:
        pip_args.extend([pip_option, value])
        return True
    if option in UV_VALUE_OPTION_NOOP:
        return True
    if option in {"--editable"}:
        editable_requirements.append(value)
        return True
    return False


def _append_uv_flag(
    option: str,
    *,
    pip_args: list[str],
    editable_flag: bool,
) -> bool:
    if editable_flag and option in UV_EDITABLE_FLAGS:
        return True
    if option in UV_FLAG_NOOP:
        return True
    mapped = UV_FLAG_TO_PIP_OPTION.get(option)
    if mapped is None:
        return False
    pip_args.append(mapped)
    return True


def _pip_args_from_uv_package_options(
    parsed: ParsedUvPackageOptions,
) -> list[str] | None:
    result = list(parsed.pip_args)
    for requirement_file in parsed.requirement_files:
        if requirement_file:
            result.extend(["-r", requirement_file])
    for requirement_file in parsed.with_requirement_files:
        if requirement_file:
            result.extend(["-r", requirement_file])
    for requirement in parsed.editable_requirements:
        if requirement:
            result.extend(["--editable", requirement])
    for requirement in parsed.with_editable_requirements:
        if requirement:
            result.extend(["--editable", requirement])
    for requirement in parsed.with_requirements:
        if requirement:
            result.append(requirement)
    if parsed.editable:
        for requirement in parsed.positionals:
            if requirement:
                result.extend(["--editable", requirement])
    else:
        for requirement in parsed.positionals:
            if requirement:
                result.append(requirement)
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
    from packaging.version import Version

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
    if not options_with_value:
        i = 0
        while i < len(args):
            arg = args[i]
            if arg == "--":
                return None
            if arg in commands:
                return ToolCommand(name=arg, index=i)
            if arg.startswith("-"):
                i += 1
                continue
            return None
        return None

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
            aliases=_UV_EMPTY_DICT,
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
    if arg.startswith("--") and "=" in arg:
        option, value = arg.split("=", 1)
        canonical_option = aliases.get(option, option)
        if canonical_option not in options_with_value:
            return None
        return canonical_option, value, index + 1

    option = arg
    canonical_option = aliases.get(option)
    if canonical_option is None:
        canonical_option = option
        if option not in options_with_value:
            return None
    elif canonical_option not in options_with_value:
        return None

    if index + 1 >= len(args):
        return canonical_option, "", index + 1
    return canonical_option, args[index + 1], index + 2


def _split_pip_args(value: str) -> list[str]:
    import shlex

    try:
        return shlex.split(value)
    except ValueError:
        return [value]
