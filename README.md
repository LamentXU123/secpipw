*Not Finished Yet. Contribution Welcome. Site at https://spip.lamentxu.top/*

# secured_pip

[![Test](https://github.com/LamentXU123/spip/actions/workflows/test.yml/badge.svg)](https://github.com/LamentXU123/spip/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python_version](https://img.shields.io/pypi/pyversions/secured_pip.svg?logo=python&logoColor=FBE072)
![PyPI Version](https://img.shields.io/pypi/v/secured_pip)
[![Codecov](https://codecov.io/gh/LamentXU123/spip/graph/badge.svg)](https://codecov.io/gh/LamentXU123/spip)

An open-source, free guard for your pip to avoid supply-chain attacks.

By using this, you can avoid being screwed by the poisoned LiteLLM, etc. just because you type `pip install`

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
doskey pip=spip $*
```

Bash (Linux):

```bash
echo "alias pip='spip'" >> ~/.bashrc
source ~/.bashrc
```

Zsh (macOS):

```zsh
echo "alias pip='spip'" >> ~/.zshrc
source ~/.zshrc
```

The `secured_pip` project will actively check for all the supply chain risks and avoid you installing potentially malicious packages when typing `spip install`

Except for the `install` commands, the project behaves exactly the same as the original `pip` program. That is, you can always use `spip` instead of `pip` in any case :)

If you want to refresh local caches used by `spip`, run:

```bash
spip refresh-cache
```

## Why not SFW / GuardDog?

There are already good supply-chain tools out there. `secured_pip` is not trying to replace all of them. The point is different: keep the protection path as light as possible for everyday Python installs.

- Compared with Socket Firewall (`sfw`): Socket Firewall works as a wrapper/proxy layer in front of package-manager network requests and uses Socket's security intelligence to block packages before download. `secured_pip` is much smaller in scope: it is a local Python-only `pip` wrapper, with no proxy service, no organization dashboard, and no extra infrastructure to run. Official Socket docs: <https://docs.socket.dev/docs/socket-firewall-overview>
- Compared with GuardDog: GuardDog is a scanning CLI that downloads package source archives and applies source-code and metadata heuristics, including Semgrep-based rules. `secured_pip` is intentionally lighter: it stays close to `pip install`, does quick local checks around the install flow, and does not try to be a full package-code scanner. Official GuardDog README: <https://github.com/DataDog/guarddog>

In short, `secured_pip` optimizes for:

- near-drop-in use with `spip install`
- local, lightweight checks
- minimal workflow change
- Python / pip focus instead of broad multi-ecosystem coverage

Current minimum Python version: `3.10`

We currently have three install warning policies:

- `HIGH`: pause installation and require `--ignore-warning`
- `MEDIUM`: prompt `y/n` before continuing
- `LOW`: warn and continue

When `spip` detects a potential risk, a warning will be raised, with the level depending on the severity the risk is.

For now, the project has several major check points:

- [x] Fake typo checks: Hackers often use "fake typos" to inject a malicious dependency package into the poisoned source file. `spip` detects this by first resolving all the packages that `pip install` is going to download, and then comparing non-popular resolved package names with a local hot-package list. Warning levels:
    - Medium severity: `requsets` vs `requests`
    - Medium severity: `pandaz` vs `pandas`
    - Low severity: `sixth` vs `six`
- [x] Fresh release checks: If the selected PyPI release was published less than 2 days ago, `spip` will raise a `MEDIUM` warning.
- [x] Disposable email checks: If the PyPI release metadata uses a known disposable author or maintainer email domain, `spip` will raise a `LOW` warning. The built-in blocklist is vendored from `disposable/disposable-email-domains` strict mode.
- [x] Zero-version checks: If the selected package version is `0.0` or `0.0.0`, `spip` will raise a `LOW` warning.
- [x] `.pth` file detection: Instead of directly injecting malicious code inside the package, today most hackers will place their bad stuff under a `.pth` file, with an `import` as the beginning. `spip` only checks the installed file-system diff after installation. The warning level is always `MEDIUM`, and `spip` will ask whether to delete the suspicious installed `.pth` file.
- [ ] TODO ...
