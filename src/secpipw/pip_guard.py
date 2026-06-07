from __future__ import annotations

import json
import operator
import os
import inspect
from functools import lru_cache
from optparse import Values
from typing import TYPE_CHECKING, Callable, Iterable, List, Optional

if TYPE_CHECKING:
    from secpipw.install_plan import InstallPlan
    from secpipw.warning_gate import GateDecision

PlanHook = Callable[["InstallPlan"], "GateDecision"]
ArtifactHook = Callable[[list[object]], "GateDecision"]

_REAL_GUARDED_INSTALL_COMMAND: type | None = None

_PIP_IMPORTS_LOADED = False
_PIP_IMPORT_GROUPS_LOADED: set[str] = set()
_PIP_IMPORT_NAMES = {
    "WheelCache",
    "cmdoptions",
    "make_target_python",
    "with_cleanup",
    "ERROR",
    "SUCCESS",
    "InstallCommand",
    "create_os_error_message",
    "decide_user_install",
    "get_lib_location_guesses",
    "CommandError",
    "InstallationError",
    "get_environment",
    "InstallationReport",
    "get_build_tracker",
    "_pip_install_given_reqs",
    "check_externally_managed",
    "get_pip_version",
    "protect_pip_from_modification_on_windows",
    "warn_if_run_as_root",
    "write_output",
    "TempDirectory",
    "canonicalize_name",
    "print_json",
    "logger",
}


def _bind_pip_symbol(name: str, value: object) -> None:
    globals().setdefault(name, value)


def _has_pip_symbols(*names: str) -> bool:
    return all(name in globals() for name in names)


def _ensure_pip_imports() -> None:
    global _PIP_IMPORTS_LOADED
    if _PIP_IMPORTS_LOADED and _has_pip_symbols(*_PIP_IMPORT_NAMES):
        return

    _ensure_guard_command_imports()
    _ensure_run_setup_imports()
    _ensure_status_imports()
    _ensure_report_imports()
    _ensure_print_json_imports()
    _ensure_protect_pip_imports()
    _ensure_installation_error_imports()
    _ensure_install_function_imports()
    _ensure_summary_imports()
    _ensure_os_error_imports()
    _ensure_root_warning_imports()
    _PIP_IMPORTS_LOADED = True


def _ensure_guard_command_imports() -> None:
    if "guard-command" in _PIP_IMPORT_GROUPS_LOADED and _has_pip_symbols(
        "with_cleanup",
        "InstallCommand",
    ):
        return
    from pip._internal.cli.req_command import with_cleanup as imported_with_cleanup
    from pip._internal.commands.install import (
        InstallCommand as imported_install_command,
    )

    _bind_pip_symbol("with_cleanup", imported_with_cleanup)
    _bind_pip_symbol("InstallCommand", imported_install_command)
    _PIP_IMPORT_GROUPS_LOADED.add("guard-command")


def _ensure_run_setup_imports() -> None:
    if "run-setup" in _PIP_IMPORT_GROUPS_LOADED and _has_pip_symbols(
        "WheelCache",
        "cmdoptions",
        "make_target_python",
        "decide_user_install",
        "CommandError",
        "get_build_tracker",
        "check_externally_managed",
        "get_pip_version",
        "TempDirectory",
        "logger",
    ):
        return
    from pip._internal.cache import WheelCache as imported_wheel_cache
    from pip._internal.cli import cmdoptions as imported_cmdoptions
    from pip._internal.cli.cmdoptions import (
        make_target_python as imported_make_target_python,
    )
    from pip._internal.commands.install import (
        decide_user_install as imported_decide_user_install,
    )
    from pip._internal.exceptions import CommandError as imported_command_error
    from pip._internal.operations.build.build_tracker import (
        get_build_tracker as imported_get_build_tracker,
    )
    from pip._internal.utils.logging import getLogger
    from pip._internal.utils.misc import (
        check_externally_managed as imported_check_externally_managed,
        get_pip_version as imported_get_pip_version,
    )
    from pip._internal.utils.temp_dir import TempDirectory as imported_temp_directory

    _bind_pip_symbol("WheelCache", imported_wheel_cache)
    _bind_pip_symbol("cmdoptions", imported_cmdoptions)
    _bind_pip_symbol("make_target_python", imported_make_target_python)
    _bind_pip_symbol("decide_user_install", imported_decide_user_install)
    _bind_pip_symbol("CommandError", imported_command_error)
    _bind_pip_symbol("get_build_tracker", imported_get_build_tracker)
    _bind_pip_symbol("check_externally_managed", imported_check_externally_managed)
    _bind_pip_symbol("get_pip_version", imported_get_pip_version)
    _bind_pip_symbol("TempDirectory", imported_temp_directory)
    _bind_pip_symbol("logger", getLogger(__name__))
    _PIP_IMPORT_GROUPS_LOADED.add("run-setup")


def _ensure_status_imports() -> None:
    if "status" in _PIP_IMPORT_GROUPS_LOADED and _has_pip_symbols(
        "ERROR",
        "SUCCESS",
    ):
        return
    from pip._internal.cli.status_codes import ERROR as imported_error
    from pip._internal.cli.status_codes import SUCCESS as imported_success

    _bind_pip_symbol("ERROR", imported_error)
    _bind_pip_symbol("SUCCESS", imported_success)
    _PIP_IMPORT_GROUPS_LOADED.add("status")


def _ensure_report_imports() -> None:
    if "report" in _PIP_IMPORT_GROUPS_LOADED and _has_pip_symbols(
        "InstallationReport",
    ):
        return
    from pip._internal.models.installation_report import (
        InstallationReport as imported_installation_report,
    )

    _bind_pip_symbol("InstallationReport", imported_installation_report)
    _PIP_IMPORT_GROUPS_LOADED.add("report")


def _ensure_print_json_imports() -> None:
    if "print-json" in _PIP_IMPORT_GROUPS_LOADED and _has_pip_symbols("print_json"):
        return
    from pip._vendor.rich import print_json as imported_print_json

    _bind_pip_symbol("print_json", imported_print_json)
    _PIP_IMPORT_GROUPS_LOADED.add("print-json")


def _ensure_output_imports() -> None:
    if "output" in _PIP_IMPORT_GROUPS_LOADED and _has_pip_symbols("write_output"):
        return
    from pip._internal.utils.misc import write_output as imported_write_output

    _bind_pip_symbol("write_output", imported_write_output)
    _PIP_IMPORT_GROUPS_LOADED.add("output")


def _ensure_protect_pip_imports() -> None:
    if "protect-pip" in _PIP_IMPORT_GROUPS_LOADED and _has_pip_symbols(
        "protect_pip_from_modification_on_windows",
    ):
        return
    from pip._internal.utils.misc import (
        protect_pip_from_modification_on_windows as imported_protect_pip,
    )

    _bind_pip_symbol("protect_pip_from_modification_on_windows", imported_protect_pip)
    _PIP_IMPORT_GROUPS_LOADED.add("protect-pip")


def _ensure_installation_error_imports() -> None:
    if "installation-error" in _PIP_IMPORT_GROUPS_LOADED and _has_pip_symbols(
        "InstallationError",
    ):
        return
    from pip._internal.exceptions import (
        InstallationError as imported_installation_error,
    )

    _bind_pip_symbol("InstallationError", imported_installation_error)
    _PIP_IMPORT_GROUPS_LOADED.add("installation-error")


def _ensure_install_function_imports() -> None:
    if "install-function" in _PIP_IMPORT_GROUPS_LOADED and _has_pip_symbols(
        "_pip_install_given_reqs",
    ):
        return
    from pip._internal.req import install_given_reqs as imported_install_given_reqs

    _bind_pip_symbol("_pip_install_given_reqs", imported_install_given_reqs)
    _PIP_IMPORT_GROUPS_LOADED.add("install-function")


def _ensure_summary_imports() -> None:
    if "summary" in _PIP_IMPORT_GROUPS_LOADED and _has_pip_symbols(
        "get_lib_location_guesses",
        "get_environment",
        "canonicalize_name",
    ):
        return
    from pip._internal.commands.install import (
        get_lib_location_guesses as imported_get_lib_location_guesses,
    )
    from pip._internal.metadata import get_environment as imported_get_environment
    from pip._vendor.packaging.utils import (
        canonicalize_name as imported_canonicalize_name,
    )

    _bind_pip_symbol("get_lib_location_guesses", imported_get_lib_location_guesses)
    _bind_pip_symbol("get_environment", imported_get_environment)
    _bind_pip_symbol("canonicalize_name", imported_canonicalize_name)
    _PIP_IMPORT_GROUPS_LOADED.add("summary")


def _ensure_os_error_imports() -> None:
    if "os-error" in _PIP_IMPORT_GROUPS_LOADED and _has_pip_symbols(
        "ERROR",
        "create_os_error_message",
        "logger",
    ):
        return
    from pip._internal.cli.status_codes import ERROR as imported_error
    from pip._internal.commands.install import (
        create_os_error_message as imported_create_os_error_message,
    )
    from pip._internal.utils.logging import getLogger

    _bind_pip_symbol("ERROR", imported_error)
    _bind_pip_symbol("create_os_error_message", imported_create_os_error_message)
    _bind_pip_symbol("logger", getLogger(__name__))
    _PIP_IMPORT_GROUPS_LOADED.add("os-error")


def _ensure_root_warning_imports() -> None:
    if "root-warning" in _PIP_IMPORT_GROUPS_LOADED and _has_pip_symbols(
        "warn_if_run_as_root",
    ):
        return
    from pip._internal.utils.misc import (
        warn_if_run_as_root as imported_warn_if_run_as_root,
    )

    _bind_pip_symbol("warn_if_run_as_root", imported_warn_if_run_as_root)
    _PIP_IMPORT_GROUPS_LOADED.add("root-warning")


def _ensure_pip_symbol(name: str) -> None:
    if name in {"InstallCommand", "with_cleanup"}:
        _ensure_guard_command_imports()
        return
    if name in {
        "WheelCache",
        "cmdoptions",
        "make_target_python",
        "decide_user_install",
        "CommandError",
        "get_build_tracker",
        "check_externally_managed",
        "get_pip_version",
        "TempDirectory",
        "logger",
    }:
        _ensure_run_setup_imports()
        return
    if name in {"ERROR", "SUCCESS"}:
        _ensure_status_imports()
        return
    if name == "InstallationReport":
        _ensure_report_imports()
        return
    if name == "print_json":
        _ensure_print_json_imports()
        return
    if name == "write_output":
        _ensure_output_imports()
        return
    if name == "protect_pip_from_modification_on_windows":
        _ensure_protect_pip_imports()
        return
    if name == "InstallationError":
        _ensure_installation_error_imports()
        return
    if name == "_pip_install_given_reqs":
        _ensure_install_function_imports()
        return
    if name in {"get_lib_location_guesses", "get_environment", "canonicalize_name"}:
        _ensure_summary_imports()
        return
    if name == "create_os_error_message":
        _ensure_os_error_imports()
        return
    if name == "warn_if_run_as_root":
        _ensure_root_warning_imports()
        return


def __getattr__(name: str):
    if name in _PIP_IMPORT_NAMES:
        _ensure_pip_symbol(name)
        return globals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def run_guarded_pip_install(
    pip_args: list[str],
    plan_hook: PlanHook,
    artifact_hook: ArtifactHook | None = None,
) -> int:
    command = GuardedInstallCommand(
        "install",
        "Install packages.",
        plan_hook=plan_hook,
        artifact_hook=artifact_hook,
    )
    return int(command.main(pip_args))


def _guarded_install_command_class():
    if _REAL_GUARDED_INSTALL_COMMAND is None:
        return _build_guarded_install_command_class()
    return _REAL_GUARDED_INSTALL_COMMAND


def check_legacy_setup_py_options(options: Values, reqs: List[object]) -> None:
    checker = _legacy_setup_py_options_checker()
    if checker is not None:
        checker(options, reqs)


def _legacy_setup_py_options_checker():
    try:
        from pip._internal.req.req_install import (
            check_legacy_setup_py_options as checker,
        )
    except ImportError:
        checker = getattr(
            __import__("pip._internal.commands.install", fromlist=["install"]),
            "check_legacy_setup_py_options",
            None,
        )
    return checker


def check_build_constraints(options: Values) -> None:
    _ensure_run_setup_imports()
    checker = getattr(cmdoptions, "check_build_constraints", None)
    if checker is not None:
        checker(options)


def build(
    requirements: Iterable[object],
    *,
    wheel_cache: WheelCache,
    verify: bool,
    build_options: list[str] | None = None,
    global_options: list[str] | None = None,
):
    requirements = list(requirements)
    if not requirements:
        return [], []

    build_func = _wheel_builder_build()
    parameters = _signature_parameter_names(build_func)
    kwargs = {
        "wheel_cache": wheel_cache,
        "verify": verify,
    }
    if "build_options" in parameters:
        kwargs["build_options"] = build_options or []
    if "global_options" in parameters:
        kwargs["global_options"] = global_options or []
    return build_func(requirements, **kwargs)


def should_build_for_install_command(req: object) -> bool:
    checker = _should_build_for_install_command_checker()
    if checker is not None:
        return bool(checker(req))
    return not bool(getattr(req, "is_wheel", False))


def install_given_reqs(
    requirements: list[object],
    global_options: list[str],
    *,
    root: str | None,
    home: str | None,
    prefix: str | None,
    warn_script_location: bool,
    use_user_site: bool,
    pycompile: bool,
    progress_bar: str,
):
    if not requirements:
        return []

    _ensure_install_function_imports()
    parameters = _signature_parameter_names(_pip_install_given_reqs)
    kwargs = {
        "root": root,
        "home": home,
        "prefix": prefix,
        "warn_script_location": warn_script_location,
        "use_user_site": use_user_site,
        "pycompile": pycompile,
    }
    if "progress_bar" in parameters:
        kwargs["progress_bar"] = progress_bar
    if "global_options" in parameters:
        return _pip_install_given_reqs(
            requirements,
            global_options,
            **kwargs,
        )
    return _pip_install_given_reqs(requirements, **kwargs)


def make_resolver(command, **kwargs):
    parameters = _signature_parameter_names(command.make_resolver)
    resolver_kwargs = {key: value for key, value in kwargs.items() if key in parameters}
    return command.make_resolver(**resolver_kwargs)


@lru_cache(maxsize=None)
def _signature_parameter_names(callable_obj) -> frozenset[str]:
    return frozenset(inspect.signature(callable_obj).parameters)


def prepare_linked_requirements_more(preparer, requirement_set) -> None:
    prepare_more = getattr(preparer, "prepare_linked_requirements_more", None)
    if prepare_more is not None:
        prepare_more(requirement_set.requirements.values())


@lru_cache(maxsize=1)
def _wheel_builder_build():
    return getattr(
        __import__("pip._internal.wheel_builder", fromlist=["build"]),
        "build",
    )


@lru_cache(maxsize=1)
def _should_build_for_install_command_checker():
    return getattr(
        __import__(
            "pip._internal.wheel_builder",
            fromlist=["should_build_for_install_command"],
        ),
        "should_build_for_install_command",
        None,
    )


def _build_guarded_install_command_class():
    global _REAL_GUARDED_INSTALL_COMMAND
    cached = _REAL_GUARDED_INSTALL_COMMAND
    if cached is not None:
        return cached

    _ensure_guard_command_imports()

    class GuardedInstallCommand(InstallCommand):
        def __init__(
            self,
            *args,
            plan_hook: PlanHook,
            artifact_hook: ArtifactHook | None = None,
            **kwargs,
        ) -> None:
            self._plan_hook = plan_hook
            self._artifact_hook = artifact_hook or _allow_install_artifact_hook
            super().__init__(*args, **kwargs)

        @with_cleanup
        def run(self, options: Values, args: List[str]) -> int:
            if options.use_user_site and options.target_dir is not None:
                _ensure_pip_symbol("CommandError")
                raise CommandError("Can not combine '--user' and '--target'")

            _ensure_run_setup_imports()
            installing_into_current_environment = (
                not (options.dry_run and options.json_report_file)
                and options.root_path is None
                and options.target_dir is None
                and options.prefix_path is None
            )
            if (
                installing_into_current_environment
                and not options.override_externally_managed
            ):
                check_externally_managed()

            upgrade_strategy = "to-satisfy-only"
            if options.upgrade:
                upgrade_strategy = options.upgrade_strategy

            check_build_constraints(options)
            cmdoptions.check_dist_restriction(options, check_target=True)

            logger.verbose("Using %s", get_pip_version())
            options.use_user_site = decide_user_install(
                options.use_user_site,
                prefix_path=options.prefix_path,
                target_dir=options.target_dir,
                root_path=options.root_path,
                isolated_mode=options.isolated_mode,
            )

            target_temp_dir: Optional[TempDirectory] = None
            target_temp_dir_path: Optional[str] = None
            if options.target_dir:
                options.ignore_installed = True
                options.target_dir = os.path.abspath(options.target_dir)
                if os.path.exists(options.target_dir) and not os.path.isdir(
                    options.target_dir
                ):
                    raise CommandError(
                        "Target path exists but is not a directory, will not continue."
                    )

                target_temp_dir = TempDirectory(kind="target")
                target_temp_dir_path = target_temp_dir.path
                self.enter_context(target_temp_dir)

            global_options = getattr(options, "global_options", None) or []

            session = self.get_default_session(options)

            target_python = make_target_python(options)
            finder = self._build_package_finder(
                options=options,
                session=session,
                target_python=target_python,
                ignore_requires_python=options.ignore_requires_python,
            )
            build_tracker = self.enter_context(get_build_tracker())

            directory = TempDirectory(
                delete=not options.no_clean,
                kind="install",
                globally_managed=True,
            )

            try:
                reqs = self.get_requirements(args, options, finder, session)
                check_legacy_setup_py_options(options, reqs)

                wheel_cache = WheelCache(options.cache_dir)

                for req in reqs:
                    req.permit_editable_wheels = True

                preparer = self.make_requirement_preparer(
                    temp_build_dir=directory,
                    options=options,
                    build_tracker=build_tracker,
                    session=session,
                    finder=finder,
                    use_user_site=options.use_user_site,
                    verbosity=self.verbosity,
                )
                resolver = make_resolver(
                    self,
                    preparer=preparer,
                    finder=finder,
                    options=options,
                    wheel_cache=wheel_cache,
                    use_user_site=options.use_user_site,
                    ignore_installed=options.ignore_installed,
                    ignore_requires_python=options.ignore_requires_python,
                    force_reinstall=options.force_reinstall,
                    upgrade_strategy=upgrade_strategy,
                    use_pep517=getattr(options, "use_pep517", None),
                    py_version_info=options.python_version,
                )

                self.trace_basic_info(finder)

                requirement_set = resolver.resolve(
                    reqs, check_supported_wheels=not options.target_dir
                )

                _ensure_report_imports()
                report_dict = InstallationReport(
                    requirement_set.requirements_to_install
                ).to_dict()
                if options.json_report_file:
                    if options.json_report_file == "-":
                        _ensure_print_json_imports()
                        print_json(data=report_dict)
                    else:
                        with open(
                            options.json_report_file,
                            "w",
                            encoding="utf-8",
                        ) as f:
                            json.dump(report_dict, f, indent=2, ensure_ascii=False)

                from secpipw.install_plan import install_plan_from_report

                decision = self._plan_hook(install_plan_from_report(report_dict))
                if not decision.allow_install:
                    return decision.exit_code

                if options.dry_run:
                    would_install_items = sorted(
                        (r.metadata["name"], r.metadata["version"])
                        for r in requirement_set.requirements_to_install
                    )
                    if would_install_items:
                        _ensure_output_imports()
                        write_output(
                            "Would install %s",
                            " ".join("-".join(item) for item in would_install_items),
                        )
                    _ensure_status_imports()
                    return SUCCESS

                prepare_linked_requirements_more(preparer, requirement_set)

                for req in requirement_set.requirements_to_install:
                    local_file_path = getattr(req, "local_file_path", None)
                    if local_file_path and not hasattr(
                        req, "_spip_prebuild_local_file_path"
                    ):
                        req._spip_prebuild_local_file_path = local_file_path

                try:
                    pip_req = requirement_set.get_requirement("pip")
                except KeyError:
                    modifying_pip = False
                else:
                    modifying_pip = pip_req.satisfied_by is None
                _ensure_pip_symbol("protect_pip_from_modification_on_windows")
                protect_pip_from_modification_on_windows(modifying_pip=modifying_pip)

                reqs_to_build = [
                    r
                    for r in requirement_set.requirements_to_install
                    if should_build_for_install_command(r)
                ]

                if reqs_to_build:
                    _, build_failures = build(
                        reqs_to_build,
                        wheel_cache=wheel_cache,
                        verify=True,
                        build_options=[],
                        global_options=global_options,
                    )
                else:
                    build_failures = []

                if build_failures:
                    _ensure_pip_symbol("InstallationError")
                    raise InstallationError(
                        "Failed to build installable wheels for some "
                        "pyproject.toml based projects ({})".format(
                            ", ".join(r.name for r in build_failures)
                        )
                    )

                artifact_decision = self._artifact_hook(
                    list(requirement_set.requirements_to_install)
                )
                if not artifact_decision.allow_install:
                    return artifact_decision.exit_code

                to_install = resolver.get_installation_order(requirement_set)

                conflicts = None
                should_warn_about_conflicts = (
                    not options.ignore_dependencies and options.warn_about_conflicts
                )
                if should_warn_about_conflicts:
                    conflicts = self._determine_conflicts(to_install)

                warn_script_location = options.warn_script_location
                if options.target_dir or options.prefix_path:
                    warn_script_location = False

                installed = install_given_reqs(
                    to_install,
                    global_options,
                    root=options.root_path,
                    home=target_temp_dir_path,
                    prefix=options.prefix_path,
                    warn_script_location=warn_script_location,
                    use_user_site=options.use_user_site,
                    pycompile=options.compile,
                    progress_bar=options.progress_bar,
                )

                installed.sort(key=operator.attrgetter("name"))
                summary = []
                if installed:
                    _ensure_summary_imports()
                    lib_locations = get_lib_location_guesses(
                        user=options.use_user_site,
                        home=target_temp_dir_path,
                        root=options.root_path,
                        prefix=options.prefix_path,
                        isolated=options.isolated_mode,
                    )
                    env = get_environment(lib_locations)

                    installed_versions = {}
                    for distribution in env.iter_all_distributions():
                        installed_versions[distribution.canonical_name] = (
                            distribution.version
                        )
                    for package in installed:
                        display_name = package.name
                        version = installed_versions.get(
                            canonicalize_name(display_name), None
                        )
                        if version:
                            text = f"{display_name}-{version}"
                        else:
                            text = display_name
                        summary.append(text)

                if conflicts is not None:
                    self._warn_about_conflicts(
                        conflicts,
                        resolver_variant=self.determine_resolver_variant(options),
                    )

                installed_desc = " ".join(summary)
                if installed_desc:
                    _ensure_output_imports()
                    write_output(
                        "Successfully installed %s",
                        installed_desc,
                    )
            except OSError as error:
                show_traceback = self.verbosity >= 1

                _ensure_os_error_imports()
                message = create_os_error_message(
                    error,
                    show_traceback,
                    options.use_user_site,
                )
                logger.error(message, exc_info=show_traceback)

                return ERROR

            if options.target_dir:
                assert target_temp_dir
                self._handle_target_dir(
                    options.target_dir, target_temp_dir, options.upgrade
                )
            if options.root_user_action == "warn":
                _ensure_root_warning_imports()
                warn_if_run_as_root()
            _ensure_status_imports()
            return SUCCESS

    GuardedInstallCommand.__module__ = __name__
    GuardedInstallCommand.__qualname__ = "GuardedInstallCommand"
    _REAL_GUARDED_INSTALL_COMMAND = GuardedInstallCommand
    return GuardedInstallCommand


class GuardedInstallCommand:
    """Lazy public class that delegates construction to the real command class."""

    def __new__(cls, *args, **kwargs) -> object:
        return _guarded_install_command_class()(*args, **kwargs)


def _allow_install_artifact_hook(requirements: list[object]) -> GateDecision:
    from secpipw.warning_gate import GateDecision

    return GateDecision(allow_install=True, exit_code=0)
