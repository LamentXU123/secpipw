*Not Finished Yet. Contribution Welcome. Site at https://spip.lamentxu.top/*

# secured_pip

[![Test](https://github.com/LamentXU123/spip/actions/workflows/test.yml/badge.svg)](https://github.com/LamentXU123/spip/actions/workflows/test.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
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
- [x] Zero-version checks: If the selected package version is `0.0` or `0.0.0`, `spip` will raise a `LOW` warning.
- [x] `.pth` file detection: Instead of directly injecting malicious code inside the package, today most hackers will place their bad stuff under a `.pth` file, with an `import` as the beginning. `spip` only checks the installed file-system diff after installation. The warning level is always `MEDIUM`, and `spip` will ask whether to delete the suspicious installed `.pth` file.
- [ ] TODO ...
