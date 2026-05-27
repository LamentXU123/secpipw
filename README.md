*Not Finished Yet. Contribution Welcome. Site at https://spip.lamentxu.top/*

# secured_pip

[![Test](https://github.com/LamentXU123/spip/actions/workflows/test.yml/badge.svg)](https://github.com/LamentXU123/spip/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python_version](https://img.shields.io/pypi/pyversions/secured_pip.svg?logo=python&logoColor=FBE071)
![PyPI Version](https://img.shields.io/pypi/v/secured_pip)
[![Codecov](https://codecov.io/gh/LamentXU123/spip/graph/badge.svg)](https://codecov.io/gh/LamentXU123/spip)

An open-source, free, powerful, light-weight guard for your pip to avoid supply-chain attacks.

By using this, you can avoid being screwed by the poisoned LiteLLM, etc. just because you type `pip install`

Although `secured_pip` is designed for low learning budget, we still recommend you to read our [docs](https://spip.lamentxu.top/docs) before you try this product in your production environment.

## What?

Currently, supply chain attacks are one of the major security concerns all over the world. The `secured_pip` project is a future `pip` wrapper focused on supply-chain risk controls.

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

If you want a near drop-in experience, you can set a shell alias from `pip` to `spip`.

Command Prompt (Windows):

```cmd
pip install secured_pip
doskey pip=spip $*
```

Bash (Linux):

```bash
pip install secured_pip
echo "alias pip='spip'" >> ~/.bashrc
source ~/.bashrc
```

Zsh (macOS):

```zsh
pip install secured_pip
echo "alias pip='spip'" >> ~/.zshrc
source ~/.zshrc
```

The `secured_pip` project will actively check for all the supply chain risks and avoid you installing potentially malicious packages when typing `spip install`

For `install`, `secured_pip` uses pip's own resolver and then checks the selected install plan before pip builds or installs the resolved distributions. If the checks pass, the same pip install flow continues; `secured_pip` does not run a second `pip install` for the already-resolved packages.

Except for the `install` commands, the project behaves exactly the same as the original `pip` program. That is, you can always use `spip` instead of `pip` in any case :)

For more details, please see our docs: https://spip.lamentxu.top/docs

## What problem do secured_pip solved?

Supply-chain poisoning has always been a persistent security problem. Existing solutions include mature but expensive-to-run tools like GuardDog, and lightweight tools like sfw that rely entirely on a paid Socket API. GuardDog is too heavy for everyday CI usage and is better suited to static analysis by security researchers. Running GuardDog against every artifact downloaded by pip install, including all dependencies, would slow installs down. sfw is lighter, but its dependence on a paid API creates another cost for everyday developers.

secured_pip solves this by hooking into pip's installer and merging security checks directly into the pip install download and installation flow. At the same time, the performance impact is almost invisible (~0.04%). secured_pip is completely free for everyone.

Today, many independent developers have suffered CI server compromises that leak secret keys and cause serious damage. With secured_pip installed, that risk is greatly reduced, while requiring no payment, no extra performance budget, and no learning or configuration. Install it once with pip install secured_pip, set an alias once, and keep using pip while gaining an important protection layer in the background.

## Warning policies

We currently have three install warning policies:

- `HIGH`: pause installation and require `--ignore-warning`
- `MEDIUM`: prompt `y/n` before continuing
- `LOW`: warn and continue

The default sensitivity is `low`, which uses the policy above. You can make
the gate stricter with `--sensitivity medium` or `--sensitivity high`:

- `--sensitivity medium`: `MEDIUM` and above pause installation; `LOW` prompts.
- `--sensitivity high`: `LOW` and above pause installation.

When `secured_pip` detects a potential risk, a warning will be raised, with the level depending on the severity the risk is.

For now, the project has several major check points:

- [x] Fake typo checks: Hackers often use "fake typos" to inject a malicious dependency package into the poisoned source file. `secured_pip` detects this by first resolving all the packages that `pip install` is going to download, and then comparing non-popular resolved package names with a local hot-package list. Warning levels:
    - Medium severity: `requsets` vs `requests`
    - Medium severity: `pandaz` vs `pandas`
    - Low severity: `sixth` vs `six`
- [x] Direct URL dependency checks: If the install target or a resolved dependency uses a direct URL, VCS URL, or PEP 508 direct reference, `secured_pip` will raise a `MEDIUM` warning.
- [x] Fresh release checks: If the selected PyPI release was published less than 2 days ago, `secured_pip` will raise a `MEDIUM` warning.
- [x] Disposable email checks: If the PyPI release metadata uses a known disposable author or maintainer email domain, `secured_pip` will raise a `LOW` warning. The built-in blocklist is vendored from `disposable/disposable-email-domains` strict mode.
- [x] Empty description checks: If the selected PyPI release metadata has no summary and no long description, `secured_pip` will raise a `LOW` warning.
- [x] Suspicious metadata URL checks: If PyPI metadata points to a shortener, raw IP, suspicious TLD, embedded credentials, or similar suspicious URL, `secured_pip` will raise a `LOW` warning.
- [x] Repository mismatch checks: If PyPI metadata points to a GitHub/GitLab repository whose repo name appears unrelated to the package name, `secured_pip` will raise a `LOW` warning.
- [x] Maintainer email domain drift checks: If a package's maintainer email domain changes compared with the local `secured_pip` history cache, `secured_pip` will raise a `LOW` warning.
- [x] Zero-version checks: If the selected package version is `0.0` or `0.0.0`, `secured_pip` will raise a `LOW` warning.
- [x] `.pth` file detection: Instead of directly injecting malicious code inside the package, today most hackers will place their bad stuff under a `.pth` file, with an `import` as the beginning. `secured_pip` only checks the installed file-system diff after installation. The warning level is always `MEDIUM`, and `secured_pip` will ask whether to delete the suspicious installed `.pth` file.
- [ ] TODO ...
