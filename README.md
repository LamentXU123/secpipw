<p align="center">
  <img src="doc/assets/logo.png" alt="secpipw logo" width="160">
</p>

English | [简体中文](./README.zh-CN.md)

[![Test](https://github.com/LamentXU123/spip/actions/workflows/test.yml/badge.svg)](https://github.com/LamentXU123/spip/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python_version](https://img.shields.io/pypi/pyversions/secpipw.svg?logo=python&logoColor=FBE071)
![PyPI Version](https://img.shields.io/pypi/v/secpipw)
[![Codecov](https://codecov.io/gh/LamentXU123/spip/graph/badge.svg)](https://codecov.io/gh/LamentXU123/spip)

An open-source, free, powerful, light-weight guard for your pip to avoid supply-chain attacks.

By using this, you can avoid being screwed by the poisoned LiteLLM, etc. just because you type `pip install`

Although `secpipw` is designed for low learning budget, we still recommend you to read our [docs](https://spip.lamentxu.top/docs) before you try this product in your production environment.

## What?

Currently, supply chain attacks are one of the major security concerns all over the world. The `secpipw` project is a future `pip` wrapper focused on supply-chain risk controls.

## Wait, What?

You can use

```bash
spip install requests
```

Instead of

```bash
pip install requests
```

To install a package more safely in the scope of supply chain security.

You do not need to configure. You do not need to learn. Just pure install-to-master.

In other words, you can completely replace `pip install` with `spip install` to make your installation safer :)

## Package manager support

secpipw now has diversified package-manager support:

- [x] `pip`: `spip install requests`
- [x] `pipx`: `spipx install black`
- [x] `poetry`: `spoetry add requests`
- [x] `uv`: `suv pip install requests`
- [ ] `conda`: planned

You can guard common `pipx`, `poetry`, and `uv` package additions:

```bash
spipx install black
spoetry add requests
suv pip install requests
```

The package installs `spipx`, `spoetry`, and `suv` dedicated entry points.
Supported guarded commands are
`pipx install`, `pipx inject`, `pipx run`, `poetry add`, `poetry self add`,
`uv pip install`, `uv add`, `uv tool install`, and `uv tool run`. Other
non-install commands are passed through unchanged. Commands that would install
packages but cannot be translated into a pip install plan, such as
`pipx upgrade`, `poetry add --source internal ...`, or `uv run ...`, are refused
instead of running without checks.

If you want a near drop-in experience, you can set a shell alias from `pip` to `spip`.

Command Prompt (Windows):

```cmd
pip install secpipw
doskey pip=spip $*
```

Bash (Linux):

```bash
pip install secpipw
echo "alias pip='spip'" >> ~/.bashrc
source ~/.bashrc
```

Zsh (macOS):

```zsh
pip install secpipw
echo "alias pip='spip'" >> ~/.zshrc
source ~/.zshrc
```

The `secpipw` project will actively check for all the supply chain risks and avoid you installing potentially malicious packages when typing `spip install`

For `install`, `secpipw` uses pip's own resolver and then checks the selected install plan before pip builds or installs the resolved distributions. If the checks pass, the same pip install flow continues; `secpipw` does not run a second `pip install` for the already-resolved packages.

Except for the `install` commands, the project behaves exactly the same as the original `pip` program. That is, you can always use `spip` instead of `pip` in any case :)

For `pipx`, `poetry`, and `uv`, secpipw runs a pip-compatible preflight
resolution and artifact check before handing control to the original tool. The
original tool still performs the actual environment update.

For more details, please see our docs: https://spip.lamentxu.top/docs

## What problem do secpipw solved?

Supply-chain poisoning has always been a persistent security problem. Existing solutions include mature but expensive-to-run tools like GuardDog, and lightweight tools like sfw that rely entirely on a paid Socket API. GuardDog is too heavy for everyday CI usage and is better suited to static analysis by security researchers. Running GuardDog against every artifact downloaded by `pip install`, including all dependencies, would slow installs down. sfw is lighter, but its dependence on a paid API creates another cost for everyday developers.

secpipw solves this by hooking into pip's installer and merging security checks directly into the pip install download and installation flow. At the same time, the performance impact is usually small. secpipw is completely free for everyone.

Today, many independent developers have suffered CI server compromises that leak secret keys and cause serious damage. With secpipw installed, that risk is greatly reduced, while requiring no payment, no extra performance budget, and no learning or configuration. Install it once with `pip install secpipw`, set an alias once, and keep using pip while gaining an important protection layer in the background.

## Warning policies

## TODO

Contributions welcome:

- Framework
    - [x] Support guarded `uv pip install`, `uv add`, `uv tool install`, and `uv tool run`
    - [x] Support guarded `pipx install`, `pipx inject`, and `pipx run`
    - [x] Support guarded `poetry add` and `poetry self add`
    - [ ] Support `conda`
- CI
    - [x] Write a benchmark CI in the github workflow to compare the performance of `spip install` and `pip install`
- Documentation
    - [ ] Use some modern documentation framework to refactor the /doc/docs directory.
    - [ ] Support website view on mobile phones. @didongji91
- Checks
    - [x] Record and compare installed package entry-point and `.pth` baselines across `spip` installs
        - [x] If new or changed `.pth` file is added
        - [x] If entry-point metadata or script files change
    - [x] Detect yanked releases from pip's resolved install report
    - [x] Compare archive hashes with already available PyPI release metadata
    - [ ] Add check of the diff between the last version of the package and the to-be-installed version, search for malicious changes
        - [ ] If setup.py has been changed

We currently have three install warning policies:

- `HIGH`: pause installation and require `--spip-ignore-warning`
- `MEDIUM`: prompt `y/n` before continuing
- `LOW`: warn and continue

The default sensitivity is `low`, which uses the policy above. You can make
the gate stricter with `--sensitivity medium` or `--sensitivity high`:

- `--sensitivity medium`: `MEDIUM` and above pause installation; `LOW` prompts.
- `--sensitivity high`: `LOW` and above pause installation.

Use `--spip-ignore <level>` to completely ignore warnings at that severity and below.
For example, `--spip-ignore LOW` suppresses `LOW` warnings, while `--spip-ignore MEDIUM`
suppresses both `LOW` and `MEDIUM` warnings. Ignored warnings are not printed,
and checks that can only produce ignored severities are skipped.

## Caches

secpipw stores PyPI name, release-time, and maintainer email history caches in
the user's cache directory by default, so the same cache is reused across projects.
Set `SPIP_CACHE_DIR` to override the cache directory.

## Benchmark

Run the local benchmark with:

```bash
python scripts/benchmark_install.py --runs 5 --warmups 0
```

Add `--viztracer --viztracer-dir .tmp-perf/install-benchmark` to generate
per-run flame graphs for the measured install commands.

Run the package-manager benchmark used by the docs with:

```bash
python scripts/benchmark_package_managers.py --runs 10
```

Run the local VizTracer hot-path benchmark with:

```bash
python scripts/benchmark_viztracer.py --runs 3
```

The default install benchmark compares `pip install requests` and
`spip install requests`, timing package download and installation together.
It uses a local wheelhouse, `--no-index`, `--no-deps`, and a fresh `--target`
directory for each measured run, so the result focuses on repeated installs of
one well-known package body rather than a dependency tree. A separate
package-manager benchmark records guarded `uv`, `pipx`, and `poetry` route
startup/preflight cost for the docs page only. The Benchmark GitHub Actions
workflow runs on relevant `main` changes, on a weekly schedule, or by manual
dispatch. It publishes the latest `benchmark.json` and
`manager-benchmark.json` to the remote `benchmark-data` branch. Benchmark
updates do not advance `main`.

When `secpipw` detects a potential risk, a warning will be raised, with the level depending on the severity the risk is.

For now, the project has several major check points:

- [x] Fake typo checks: Hackers often use "fake typos" to inject a malicious dependency package into the poisoned source file. `secpipw` detects this by first resolving all the packages that `pip install` is going to download, and then comparing non-popular resolved package names with a local hot-package list. Warning levels:
    - Medium severity: `requsets` vs `requests`
    - Medium severity: `panda` vs `pandas`
    - Low severity: `sixth` vs `six`
- [x] Direct URL dependency checks: If the install target or a resolved dependency uses a direct URL, VCS URL, or PEP 508 direct reference, `secpipw` will raise a `MEDIUM` warning.
- [x] Fresh release checks: If the selected PyPI release was published less than 8 hours ago, `secpipw` will raise a `MEDIUM` warning; if it was published less than 48 hours ago, `secpipw` will raise a `LOW` warning.
- [x] Yanked release checks: If pip resolves a release that is marked as yanked, `secpipw` will raise a `MEDIUM` warning using pip's install report.
- [x] Archive hash checks: If PyPI release metadata is already available and the selected wheel/sdist digest does not match the resolved archive hash, `secpipw` will raise a `HIGH` warning.
- [x] Empty description checks: If the selected PyPI release metadata has no summary and no long description, `secpipw` will raise a `LOW` warning.
- [x] Suspicious metadata URL checks: If PyPI metadata points to a shortener, raw IP, embedded credentials, or similar suspicious URL, `secpipw` will raise a `LOW` warning.
- [x] Repository mismatch checks: If PyPI metadata points to a GitHub/GitLab repository whose repo name appears unrelated to the package name, `secpipw` will raise a `LOW` warning.
- [x] Maintainer email domain drift checks: If a package's maintainer email domain changes compared with the local `secpipw` history cache, `secpipw` will raise a `LOW` warning.
- [x] Zero-version checks: If the selected package version is `0.0` or `0.0.0`, `secpipw` will raise a `LOW` warning.
- [x] `.pth` file detection: Instead of directly injecting malicious code inside the package, today most hackers will place their bad stuff under a `.pth` file, with an `import` as the beginning. `secpipw` only checks the installed file-system diff after installation. The warning level is always `MEDIUM`, and `secpipw` will ask whether to delete the suspicious installed `.pth` file.
- [ ] TODO ...
