from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
DOC_ROOT = ROOT / "doc"
BRAND_LOGO_PATTERN = re.compile(
    r'(<img class="brand-logo" src="/assets/logo\.png" alt="secpipw" />)'
    r'(?:\s*<span class="brand-version" data-project-version>v[^<]+</span>)?'
)
VERSION_PATTERN = re.compile(r'^version\s*=\s*"([^"]+)"\s*$', re.MULTILINE)


def main() -> int:
    version = _read_project_version()
    label = f"v{version}"
    updated = 0

    for path in sorted(DOC_ROOT.rglob("*.html")):
        original = path.read_text(encoding="utf-8")
        rendered = BRAND_LOGO_PATTERN.sub(
            (
                r"\1"
                "\n"
                f'          <span class="brand-version" data-project-version>{label}</span>'
            ),
            original,
        )
        if rendered == original:
            continue
        path.write_text(rendered, encoding="utf-8")
        updated += 1

    print(f"synced doc version {label} in {updated} file(s)")
    return 0


def _read_project_version() -> str:
    content = PYPROJECT.read_text(encoding="utf-8")
    match = VERSION_PATTERN.search(content)
    if not match:
        raise RuntimeError(f"could not find project.version in {PYPROJECT}")
    return match.group(1)


if __name__ == "__main__":
    raise SystemExit(main())
