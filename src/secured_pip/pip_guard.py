from __future__ import annotations

import json
import operator
import os
import inspect
from optparse import Values
from typing import Callable, Iterable, List, Optional

from pip._internal.cache import WheelCache
from pip._internal.cli import cmdoptions
from pip._internal.cli.cmdoptions import make_target_python
from pip._internal.cli.req_command import with_cleanup
from pip._internal.cli.status_codes import ERROR, SUCCESS
from pip._internal.commands.install import (
    InstallCommand,
    create_os_error_message,
    decide_user_install,
    get_lib_location_guesses,
)
from pip._internal.exceptions import CommandError, InstallationError
from pip._internal.metadata import get_environment
from pip._internal.models.installation_report import InstallationReport
from pip._internal.operations.build.build_tracker import get_build_tracker
from pip._internal.req import install_given_reqs as _pip_install_given_reqs
from pip._internal.utils.logging import getLogger
from pip._internal.utils.misc import (
    check_externally_managed,
    get_pip_version,
    protect_pip_from_modification_on_windows,
    warn_if_run_as_root,
    write_output,
)
from pip._internal.utils.temp_dir import TempDirectory
from pip._vendor.packaging.utils import canonicalize_name
from pip._vendor.rich import print_json

from secured_pip.install_plan import InstallPlan, install_plan_from_report
from secured_pip.warning_gate import GateDecision

logger = getLogger(__name__)


PlanHook = Callable[[InstallPlan], GateDecision]
ArtifactHook = Callable[[list[object]], GateDecision]


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
    build_func = _wheel_builder_build()
    parameters = inspect.signature(build_func).parameters
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
    parameters = inspect.signature(_pip_install_given_reqs).parameters
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
    parameters = inspect.signature(command.make_resolver).parameters
    resolver_kwargs = {key: value for key, value in kwargs.items() if key in parameters}
    return command.make_resolver(**resolver_kwargs)


def prepare_linked_requirements_more(preparer, requirement_set) -> None:
    prepare_more = getattr(preparer, "prepare_linked_requirements_more", None)
    if prepare_more is not None:
        prepare_more(requirement_set.requirements.values())


def _wheel_builder_build():
    return getattr(
        __import__("pip._internal.wheel_builder", fromlist=["build"]),
        "build",
    )


def _should_build_for_install_command_checker():
    return getattr(
        __import__(
            "pip._internal.wheel_builder",
            fromlist=["should_build_for_install_command"],
        ),
        "should_build_for_install_command",
        None,
    )


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
            raise CommandError("Can not combine '--user' and '--target'")

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

            report_dict = InstallationReport(
                requirement_set.requirements_to_install
            ).to_dict()
            if options.json_report_file:
                if options.json_report_file == "-":
                    print_json(data=report_dict)
                else:
                    with open(
                        options.json_report_file,
                        "w",
                        encoding="utf-8",
                    ) as f:
                        json.dump(report_dict, f, indent=2, ensure_ascii=False)

            decision = self._plan_hook(install_plan_from_report(report_dict))
            if not decision.allow_install:
                return decision.exit_code

            if options.dry_run:
                would_install_items = sorted(
                    (r.metadata["name"], r.metadata["version"])
                    for r in requirement_set.requirements_to_install
                )
                if would_install_items:
                    write_output(
                        "Would install %s",
                        " ".join("-".join(item) for item in would_install_items),
                    )
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
            protect_pip_from_modification_on_windows(modifying_pip=modifying_pip)

            reqs_to_build = [
                r
                for r in requirement_set.requirements_to_install
                if should_build_for_install_command(r)
            ]

            _, build_failures = build(
                reqs_to_build,
                wheel_cache=wheel_cache,
                verify=True,
                build_options=[],
                global_options=global_options,
            )

            if build_failures:
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

            lib_locations = get_lib_location_guesses(
                user=options.use_user_site,
                home=target_temp_dir_path,
                root=options.root_path,
                prefix=options.prefix_path,
                isolated=options.isolated_mode,
            )
            env = get_environment(lib_locations)

            installed.sort(key=operator.attrgetter("name"))
            summary = []
            installed_versions = {}
            for distribution in env.iter_all_distributions():
                installed_versions[distribution.canonical_name] = distribution.version
            for package in installed:
                display_name = package.name
                version = installed_versions.get(canonicalize_name(display_name), None)
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
                write_output(
                    "Successfully installed %s",
                    installed_desc,
                )
        except OSError as error:
            show_traceback = self.verbosity >= 1

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
            warn_if_run_as_root()
        return SUCCESS


def _allow_install_artifact_hook(requirements: list[object]) -> GateDecision:
    return GateDecision(allow_install=True, exit_code=0)
