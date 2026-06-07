from __future__ import annotations

import json
import unittest
import builtins
import os
from contextlib import contextmanager, nullcontext
from io import StringIO
from types import SimpleNamespace
from unittest.mock import Mock, patch, mock_open

from pip._internal.cli.status_codes import SUCCESS, ERROR

from secpipw.install_plan import InstallPlan, ResolvedPackage
from secpipw.pip_guard import (
    GuardedInstallCommand,
    _legacy_setup_py_options_checker,
    build,
    check_build_constraints,
    check_legacy_setup_py_options,
    install_given_reqs,
    make_resolver,
    prepare_linked_requirements_more,
    run_guarded_pip_install,
    should_build_for_install_command,
)
from secpipw.warning_gate import GateDecision


@contextmanager
def patch_guarded_install(command, reqs, requirement_set, resolver, report_dict, **extra_patches):
    patches = [
        patch("secpipw.pip_guard.cmdoptions.check_dist_restriction"),
        patch("secpipw.pip_guard.decide_user_install", return_value=False),
        patch("secpipw.pip_guard.make_target_python", return_value=object()),
        patch("secpipw.pip_guard.get_build_tracker", return_value=nullcontext(object())),
        patch("secpipw.pip_guard.WheelCache"),
        patch("secpipw.pip_guard.TempDirectory", return_value=SimpleNamespace(path="tmp")),
        patch.object(command, "get_default_session", return_value=object()),
        patch.object(command, "_build_package_finder", return_value=object()),
        patch.object(command, "get_requirements", return_value=reqs),
        patch.object(command, "make_requirement_preparer", return_value=object()),
        patch.object(command, "make_resolver", return_value=resolver),
        patch.object(command, "trace_basic_info"),
    ]

    for key, value in extra_patches.items():
        if isinstance(value, str):
            patches.append(patch(value))
        elif isinstance(value, tuple) and len(value) == 2:
            patches.append(patch(value[0], value[1]))

    cm = patch("secpipw.pip_guard.InstallationReport")

    all_patches = patches + [cm]

    with contextlib_nested(all_patches) as values:
        report_class = values[-1]
        report_class.return_value.to_dict.return_value = report_dict
        yield values


@contextmanager
def contextlib_nested(patches):
    if not patches:
        yield []
        return
    with patches[0] as value:
        with contextlib_nested(patches[1:]) as rest:
            yield [value] + rest


class PipGuardTests(unittest.TestCase):
    def test_run_guarded_pip_install_invokes_guarded_command(self) -> None:
        hook = Mock(return_value=GateDecision(allow_install=True, exit_code=0))
        with patch("secpipw.pip_guard.GuardedInstallCommand") as command_class:
            command_class.return_value.main.return_value = 7

            rc = run_guarded_pip_install(["requests"], hook)

        self.assertEqual(rc, 7)
        command_class.assert_called_once_with(
            "install",
            "Install packages.",
            plan_hook=hook,
            artifact_hook=None,
        )
        command_class.return_value.main.assert_called_once_with(["requests"])

    def test_legacy_setup_py_checker_falls_back_when_req_install_lacks_symbol(
        self,
    ) -> None:
        real_import = builtins.__import__
        fallback_checker = Mock()

        def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "pip._internal.req.req_install":
                raise ImportError("missing")
            if name == "pip._internal.commands.install":
                return SimpleNamespace(
                    check_legacy_setup_py_options=fallback_checker,
                )
            return real_import(name, globals, locals, fromlist, level)

        with patch("builtins.__import__", side_effect=fake_import):
            checker = _legacy_setup_py_options_checker()

        self.assertIs(checker, fallback_checker)

    def test_should_build_falls_back_to_not_wheel_when_pip_checker_is_missing(
        self,
    ) -> None:
        with patch("secpipw.pip_guard._should_build_for_install_command_checker", return_value=None):
            self.assertTrue(should_build_for_install_command(SimpleNamespace(is_wheel=False)))
            self.assertFalse(should_build_for_install_command(SimpleNamespace(is_wheel=True)))

    def test_should_build_uses_pip_checker_when_available(self) -> None:
        checker = Mock(return_value=True)

        with patch(
            "secpipw.pip_guard._should_build_for_install_command_checker",
            return_value=checker,
        ):
            req = SimpleNamespace(is_wheel=True)
            self.assertTrue(should_build_for_install_command(req))

        checker.assert_called_once_with(req)

    def test_wheel_build_wrapper_omits_removed_options(self) -> None:
        build_func = Mock(return_value=([], []))

        with patch("secpipw.pip_guard._wheel_builder_build", return_value=build_func):
            result = build(
                [SimpleNamespace()],
                wheel_cache=SimpleNamespace(),
                verify=True,
                build_options=[],
                global_options=[],
            )

        self.assertEqual(result, ([], []))
        self.assertNotIn("build_options", build_func.call_args.kwargs)
        self.assertNotIn("global_options", build_func.call_args.kwargs)

    def test_install_given_reqs_wrapper_omits_removed_global_options(self) -> None:
        pip_install = Mock(return_value=[])

        with patch("secpipw.pip_guard._pip_install_given_reqs", pip_install):
            result = install_given_reqs(
                [SimpleNamespace()],
                [],
                root=None,
                home=None,
                prefix=None,
                warn_script_location=True,
                use_user_site=False,
                pycompile=True,
                progress_bar="off",
            )

        self.assertEqual(result, [])
        self.assertEqual(len(pip_install.call_args.args), 1)

    def test_make_resolver_omits_removed_use_pep517(self) -> None:
        class Command:
            def make_resolver(
                self,
                preparer,
                finder,
                options,
                wheel_cache=None,
                use_user_site=False,
                py_version_info=None,
            ):
                return {
                    "preparer": preparer,
                    "finder": finder,
                    "options": options,
                    "wheel_cache": wheel_cache,
                    "use_user_site": use_user_site,
                    "py_version_info": py_version_info,
                }

        resolver = make_resolver(
            Command(),
            preparer="preparer",
            finder="finder",
            options="options",
            wheel_cache="cache",
            use_user_site=True,
            use_pep517=True,
            py_version_info=(3, 10),
        )

        self.assertEqual(resolver["preparer"], "preparer")
        self.assertEqual(resolver["finder"], "finder")
        self.assertNotIn("use_pep517", resolver)

    def test_prepare_linked_requirements_more_is_optional(self) -> None:
        requirement_set = SimpleNamespace(requirements={"a": object()})
        prepare_more = Mock()
        preparer = SimpleNamespace(prepare_linked_requirements_more=prepare_more)

        prepare_linked_requirements_more(preparer, requirement_set)
        prepare_linked_requirements_more(SimpleNamespace(), requirement_set)

        prepare_more.assert_called_once()
        self.assertEqual(
            list(prepare_more.call_args.args[0]),
            list(requirement_set.requirements.values()),
        )

    def _make_command_and_mocks(self, hook, reqs=None, requirement_set=None, resolver=None):
        command = GuardedInstallCommand(
            "install",
            "Install packages.",
            plan_hook=hook,
        )
        command.tempdir_registry = object()
        command.verbosity = 0
        if reqs is None:
            reqs = [SimpleNamespace()]
        if requirement_set is None:
            requirement_set = SimpleNamespace(requirements_to_install=[object()])
        if resolver is None:
            resolver = SimpleNamespace(resolve=Mock(return_value=requirement_set))
        return command, reqs, requirement_set, resolver

    def _apply_base_patches(self):
        return [
            patch("secpipw.pip_guard.cmdoptions.check_dist_restriction"),
            patch("secpipw.pip_guard.decide_user_install", return_value=False),
            patch("secpipw.pip_guard.make_target_python", return_value=object()),
            patch("secpipw.pip_guard.get_build_tracker", return_value=nullcontext(object())),
            patch("secpipw.pip_guard.WheelCache"),
            patch("secpipw.pip_guard.TempDirectory", return_value=SimpleNamespace(path="tmp")),
        ]

    def test_plan_hook_blocks_before_build_or_install(self) -> None:
        report = {
            "version": "1",
            "install": [
                {
                    "requested": True,
                    "is_direct": False,
                    "metadata": {"name": "requests", "version": "2.31.0"},
                    "download_info": {"url": "https://example.test/requests.whl"},
                }
            ],
        }
        hook = Mock(return_value=GateDecision(allow_install=False, exit_code=2))
        command, reqs, requirement_set, resolver = self._make_command_and_mocks(hook)
        options = _install_options()

        report_patch = patch("secpipw.pip_guard.InstallationReport")
        build_mock = patch("secpipw.pip_guard.build")
        install_mock = patch("secpipw.pip_guard.install_given_reqs")

        patches = self._apply_base_patches() + [
            patch.object(command, "get_default_session", return_value=object()),
            patch.object(command, "_build_package_finder", return_value=object()),
            patch.object(command, "get_requirements", return_value=reqs),
            patch.object(command, "make_requirement_preparer", return_value=object()),
            patch.object(command, "make_resolver", return_value=resolver),
            patch.object(command, "trace_basic_info"),
            report_patch,
            build_mock,
            install_mock,
        ]

        with command.main_context():
            with contextlib_nested(patches) as values:
                report_class = values[-3]
                build_m = values[-2]
                install_m = values[-1]
                report_class.return_value.to_dict.return_value = report
                rc = command.run(options, ["requests"])

        self.assertEqual(rc, 2)
        hook.assert_called_once()
        checked_plan = hook.call_args.args[0]
        self.assertIsInstance(checked_plan, InstallPlan)
        self.assertEqual(checked_plan.packages[0].name, "requests")
        build_m.assert_not_called()
        install_m.assert_not_called()

    def test_user_and_target_combined_raises_command_error(self) -> None:
        hook = Mock(return_value=GateDecision(allow_install=True, exit_code=0))
        command = GuardedInstallCommand(
            "install",
            "Install packages.",
            plan_hook=hook,
        )
        command.tempdir_registry = object()
        command.verbosity = 0
        options = _install_options()
        options.use_user_site = True
        options.target_dir = "/tmp/target"

        with self.assertRaises(Exception):
            command.run(options, ["pkg"])

    def test_dry_run_returns_success_without_installing(self) -> None:
        report = {
            "version": "1",
            "install": [
                {
                    "requested": True,
                    "is_direct": False,
                    "metadata": {"name": "requests", "version": "2.31.0"},
                    "download_info": {"url": "https://example.test/requests.whl"},
                }
            ],
        }
        hook = Mock(return_value=GateDecision(allow_install=True, exit_code=0))
        req_obj = SimpleNamespace(metadata={"name": "requests", "version": "2.31.0"})
        requirement_set = SimpleNamespace(requirements_to_install=[req_obj])
        resolver = SimpleNamespace(resolve=Mock(return_value=requirement_set))
        command, reqs, _, _ = self._make_command_and_mocks(hook, requirement_set=requirement_set, resolver=resolver)
        options = _install_options()
        options.dry_run = True

        report_patch = patch("secpipw.pip_guard.InstallationReport")
        build_mock = patch("secpipw.pip_guard.build")
        install_mock = patch("secpipw.pip_guard.install_given_reqs")
        write_mock = patch("secpipw.pip_guard.write_output")

        patches = self._apply_base_patches() + [
            patch.object(command, "get_default_session", return_value=object()),
            patch.object(command, "_build_package_finder", return_value=object()),
            patch.object(command, "get_requirements", return_value=reqs),
            patch.object(command, "make_requirement_preparer", return_value=object()),
            patch.object(command, "make_resolver", return_value=resolver),
            patch.object(command, "trace_basic_info"),
            report_patch,
            build_mock,
            install_mock,
            write_mock,
        ]

        with command.main_context():
            with contextlib_nested(patches) as values:
                values[-4].return_value.to_dict.return_value = report
                rc = command.run(options, ["requests"])

        self.assertEqual(rc, SUCCESS)
        hook.assert_called_once()
        values[-3].assert_not_called()
        values[-2].assert_not_called()

    def test_json_report_file_writes_report_to_stdout_when_dash(self) -> None:
        report = {
            "version": "1",
            "install": [
                {
                    "requested": True,
                    "is_direct": False,
                    "metadata": {"name": "flask", "version": "3.0.0"},
                    "download_info": {"url": "https://example.test/flask.whl"},
                }
            ],
        }
        hook = Mock(return_value=GateDecision(allow_install=False, exit_code=2))
        command, reqs, requirement_set, resolver = self._make_command_and_mocks(hook)
        options = _install_options()
        options.json_report_file = "-"

        report_patch = patch("secpipw.pip_guard.InstallationReport")
        print_mock = patch("secpipw.pip_guard.print_json")
        build_mock = patch("secpipw.pip_guard.build")
        install_mock = patch("secpipw.pip_guard.install_given_reqs")

        patches = self._apply_base_patches() + [
            patch.object(command, "get_default_session", return_value=object()),
            patch.object(command, "_build_package_finder", return_value=object()),
            patch.object(command, "get_requirements", return_value=reqs),
            patch.object(command, "make_requirement_preparer", return_value=object()),
            patch.object(command, "make_resolver", return_value=resolver),
            patch.object(command, "trace_basic_info"),
            report_patch,
            print_mock,
            build_mock,
            install_mock,
        ]

        with command.main_context():
            with contextlib_nested(patches) as values:
                values[-4].return_value.to_dict.return_value = report
                command.run(options, ["flask"])

        values[-3].assert_called_once_with(data=report)

    def test_json_report_file_writes_report_to_file(self) -> None:
        report = {
            "version": "1",
            "install": [
                {
                    "requested": True,
                    "is_direct": False,
                    "metadata": {"name": "flask", "version": "3.0.0"},
                    "download_info": {"url": "https://example.test/flask.whl"},
                }
            ],
        }
        hook = Mock(return_value=GateDecision(allow_install=False, exit_code=2))
        command, reqs, requirement_set, resolver = self._make_command_and_mocks(hook)
        options = _install_options()
        options.json_report_file = "/tmp/report.json"

        report_patch = patch("secpipw.pip_guard.InstallationReport")
        file_mock = patch("builtins.open", mock_open())
        dump_mock = patch("json.dump")
        build_mock = patch("secpipw.pip_guard.build")
        install_mock = patch("secpipw.pip_guard.install_given_reqs")

        patches = self._apply_base_patches() + [
            patch.object(command, "get_default_session", return_value=object()),
            patch.object(command, "_build_package_finder", return_value=object()),
            patch.object(command, "get_requirements", return_value=reqs),
            patch.object(command, "make_requirement_preparer", return_value=object()),
            patch.object(command, "make_resolver", return_value=resolver),
            patch.object(command, "trace_basic_info"),
            report_patch,
            file_mock,
            dump_mock,
            build_mock,
            install_mock,
        ]

        with command.main_context():
            with contextlib_nested(patches) as values:
                values[-5].return_value.to_dict.return_value = report
                command.run(options, ["flask"])

        values[-4].assert_called_once_with("/tmp/report.json", "w", encoding="utf-8")
        values[-3].assert_called_once()

    def test_build_failure_raises_installation_error(self) -> None:
        report = {
            "version": "1",
            "install": [
                {
                    "requested": True,
                    "is_direct": False,
                    "metadata": {"name": "requests", "version": "2.31.0"},
                    "download_info": {"url": "https://example.test/requests.whl"},
                }
            ],
        }
        hook = Mock(return_value=GateDecision(allow_install=True, exit_code=0))
        requirement_set = SimpleNamespace(
            requirements_to_install=[object()],
            get_requirement=Mock(side_effect=KeyError),
        )
        resolver = SimpleNamespace(
            resolve=Mock(return_value=requirement_set),
            get_installation_order=Mock(return_value=[]),
        )
        command, reqs, _, _ = self._make_command_and_mocks(hook, requirement_set=requirement_set, resolver=resolver)
        failing_req = SimpleNamespace(name="requests")
        options = _install_options()

        report_patch = patch("secpipw.pip_guard.InstallationReport")
        prepare_mock = patch("secpipw.pip_guard.prepare_linked_requirements_more")
        should_build_mock = patch("secpipw.pip_guard.should_build_for_install_command", return_value=True)
        build_mock = patch("secpipw.pip_guard.build", return_value=([], [failing_req]))
        install_mock = patch("secpipw.pip_guard.install_given_reqs")
        get_req_mock = patch.object(requirement_set, "get_requirement", side_effect=KeyError)

        patches = self._apply_base_patches() + [
            patch.object(command, "get_default_session", return_value=object()),
            patch.object(command, "_build_package_finder", return_value=object()),
            patch.object(command, "get_requirements", return_value=reqs),
            patch.object(command, "make_requirement_preparer", return_value=object()),
            patch.object(command, "make_resolver", return_value=resolver),
            patch.object(command, "trace_basic_info"),
            report_patch,
            prepare_mock,
            should_build_mock,
            build_mock,
            install_mock,
            get_req_mock,
        ]

        with command.main_context():
            with contextlib_nested(patches) as values:
                values[-6].return_value.to_dict.return_value = report
                with self.assertRaises(Exception):
                    command.run(options, ["requests"])

    def test_oserror_returns_error_code(self) -> None:
        report = {
            "version": "1",
            "install": [
                {
                    "requested": True,
                    "is_direct": False,
                    "metadata": {"name": "requests", "version": "2.31.0"},
                    "download_info": {"url": "https://example.test/requests.whl"},
                }
            ],
        }
        hook = Mock(return_value=GateDecision(allow_install=True, exit_code=0))
        requirement_set = SimpleNamespace(
            requirements_to_install=[object()],
            get_requirement=Mock(side_effect=KeyError),
        )
        resolver = SimpleNamespace(
            resolve=Mock(return_value=requirement_set),
            get_installation_order=Mock(return_value=[]),
        )
        command, reqs, _, _ = self._make_command_and_mocks(hook, requirement_set=requirement_set, resolver=resolver)
        options = _install_options()

        report_patch = patch("secpipw.pip_guard.InstallationReport")
        prepare_mock = patch("secpipw.pip_guard.prepare_linked_requirements_more")
        should_build_mock = patch("secpipw.pip_guard.should_build_for_install_command", return_value=False)
        build_mock = patch("secpipw.pip_guard.build", return_value=([], []))
        install_mock = patch("secpipw.pip_guard.install_given_reqs", side_effect=OSError("disk full"))
        logger_mock = patch("secpipw.pip_guard.logger")

        patches = self._apply_base_patches() + [
            patch.object(command, "get_default_session", return_value=object()),
            patch.object(command, "_build_package_finder", return_value=object()),
            patch.object(command, "get_requirements", return_value=reqs),
            patch.object(command, "make_requirement_preparer", return_value=object()),
            patch.object(command, "make_resolver", return_value=resolver),
            patch.object(command, "trace_basic_info"),
            report_patch,
            prepare_mock,
            should_build_mock,
            build_mock,
            install_mock,
            logger_mock,
        ]

        with command.main_context():
            with contextlib_nested(patches) as values:
                values[-6].return_value.to_dict.return_value = report
                rc = command.run(options, ["requests"])

        self.assertEqual(rc, ERROR)
        values[-1].error.assert_called_once()

    def test_plan_hook_allows_install_proceeds_to_build_and_install(self) -> None:
        report = {
            "version": "1",
            "install": [
                {
                    "requested": True,
                    "is_direct": False,
                    "metadata": {"name": "requests", "version": "2.31.0"},
                    "download_info": {"url": "https://example.test/requests.whl"},
                }
            ],
        }
        hook = Mock(return_value=GateDecision(allow_install=True, exit_code=0))
        installed_pkg = SimpleNamespace(name="requests")
        requirement_set = SimpleNamespace(
            requirements_to_install=[SimpleNamespace(name="requests")],
            get_requirement=Mock(side_effect=KeyError),
        )
        resolver = SimpleNamespace(
            resolve=Mock(return_value=requirement_set),
            get_installation_order=Mock(return_value=[installed_pkg]),
        )
        command, reqs, _, _ = self._make_command_and_mocks(hook, requirement_set=requirement_set, resolver=resolver)
        options = _install_options()

        dist_mock = Mock()
        dist_mock.canonical_name = "requests"
        dist_mock.version = "2.31.0"

        report_patch = patch("secpipw.pip_guard.InstallationReport")
        prepare_mock = patch("secpipw.pip_guard.prepare_linked_requirements_more")
        should_build_mock = patch("secpipw.pip_guard.should_build_for_install_command", return_value=False)
        build_mock = patch("secpipw.pip_guard.build", return_value=([], []))
        install_mock = patch("secpipw.pip_guard.install_given_reqs", return_value=[installed_pkg])
        env_mock = patch("secpipw.pip_guard.get_environment")
        write_mock = patch("secpipw.pip_guard.write_output")
        canonicalize_mock = patch("secpipw.pip_guard.canonicalize_name", side_effect=lambda x: x)
        conflicts_mock = patch.object(command, "_determine_conflicts", return_value=None)
        warn_conflicts_mock = patch.object(command, "_warn_about_conflicts")
        lib_loc_mock = patch("secpipw.pip_guard.get_lib_location_guesses", return_value=[])

        patches = self._apply_base_patches() + [
            patch.object(command, "get_default_session", return_value=object()),
            patch.object(command, "_build_package_finder", return_value=object()),
            patch.object(command, "get_requirements", return_value=reqs),
            patch.object(command, "make_requirement_preparer", return_value=object()),
            patch.object(command, "make_resolver", return_value=resolver),
            patch.object(command, "trace_basic_info"),
            report_patch,
            prepare_mock,
            should_build_mock,
            build_mock,
            install_mock,
            env_mock,
            write_mock,
            canonicalize_mock,
            conflicts_mock,
            warn_conflicts_mock,
            lib_loc_mock,
        ]

        with command.main_context():
            with contextlib_nested(patches) as values:
                values[-12].return_value.to_dict.return_value = report
                values[-6].return_value.iter_all_distributions.return_value = [dist_mock]
                rc = command.run(options, ["requests"])

        self.assertEqual(rc, SUCCESS)
        hook.assert_called_once()
        self.assertIsInstance(hook.call_args.args[0], InstallPlan)

    def test_check_build_constraints_delegates_to_cmdoptions(self) -> None:
        mock_checker = Mock()
        import secpipw.pip_guard as pg
        orig = getattr(pg.cmdoptions, "check_build_constraints", None)
        try:
            pg.cmdoptions.check_build_constraints = mock_checker
            options = Mock()
            check_build_constraints(options)
            mock_checker.assert_called_once_with(options)
        finally:
            if orig is not None:
                pg.cmdoptions.check_build_constraints = orig

    def test_check_build_constraints_is_noop_when_missing(self) -> None:
        import secpipw.pip_guard as pg
        orig = getattr(pg.cmdoptions, "check_build_constraints", None)
        try:
            pg.cmdoptions.check_build_constraints = None
            options = Mock()
            check_build_constraints(options)
        finally:
            if orig is not None:
                pg.cmdoptions.check_build_constraints = orig

    def test_check_legacy_setup_py_options_delegates(self) -> None:
        mock_checker = Mock()
        with patch("secpipw.pip_guard._legacy_setup_py_options_checker", return_value=mock_checker):
            options = Mock()
            reqs = [object()]
            check_legacy_setup_py_options(options, reqs)
            mock_checker.assert_called_once_with(options, reqs)

    def test_check_legacy_setup_py_options_is_noop_when_missing(self) -> None:
        with patch("secpipw.pip_guard._legacy_setup_py_options_checker", return_value=None):
            options = Mock()
            reqs = [object()]
            check_legacy_setup_py_options(options, reqs)

    def test_wheel_build_wrapper_passes_build_options_when_signature_allows(self) -> None:
        build_func = Mock(return_value=([], []))

        def build_with_options(requirements, *, wheel_cache, verify, build_options, global_options):
            return build_func(requirements, wheel_cache=wheel_cache, verify=verify, build_options=build_options, global_options=global_options)

        with patch("secpipw.pip_guard._wheel_builder_build", return_value=build_with_options):
            result = build(
                [SimpleNamespace()],
                wheel_cache=SimpleNamespace(),
                verify=True,
                build_options=["--no-deps"],
                global_options=["--verbose"],
            )

        self.assertEqual(result, ([], []))
        call_kwargs = build_func.call_args.kwargs
        self.assertEqual(call_kwargs["build_options"], ["--no-deps"])
        self.assertEqual(call_kwargs["global_options"], ["--verbose"])

    def test_install_given_reqs_passes_global_options_when_signature_allows(self) -> None:
        pip_install = Mock(return_value=[])

        def pip_with_global_options(requirements, global_options, **kwargs):
            return pip_install(requirements, global_options, **kwargs)

        with patch("secpipw.pip_guard._pip_install_given_reqs", pip_with_global_options):
            result = install_given_reqs(
                [SimpleNamespace()],
                ["--verbose"],
                root=None,
                home=None,
                prefix=None,
                warn_script_location=True,
                use_user_site=False,
                pycompile=True,
                progress_bar="off",
            )

        self.assertEqual(result, [])
        self.assertEqual(pip_install.call_args.args[1], ["--verbose"])


def _install_options() -> SimpleNamespace:
    return SimpleNamespace(
        use_user_site=False,
        target_dir=None,
        dry_run=False,
        json_report_file=None,
        root_path=None,
        prefix_path=None,
        override_externally_managed=True,
        upgrade=False,
        upgrade_strategy="to-satisfy-only",
        isolated_mode=False,
        ignore_requires_python=False,
        no_clean=False,
        global_options=[],
        cache_dir=None,
        ignore_installed=False,
        force_reinstall=False,
        use_pep517=None,
        python_version=None,
        ignore_dependencies=False,
        warn_about_conflicts=False,
        warn_script_location=True,
        compile=True,
        progress_bar="off",
        root_user_action="ignore",
    )


if __name__ == "__main__":
    unittest.main()
