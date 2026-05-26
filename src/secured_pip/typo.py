from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Iterable, Protocol

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from secured_pip.pypi_api import BOOTSTRAP_PROJECT_NAMES, OfficialPyPIClient
from secured_pip.severity import Severity
from secured_pip.terminal import colorize

try:
    from Levenshtein import distance as levenshtein_distance
    from Levenshtein import ratio as levenshtein_ratio
except ImportError:
    levenshtein_distance = None
    levenshtein_ratio = None

PIP_OPTIONS_WITH_VALUE = {
    "-C",
    "-c",
    "-e",
    "-f",
    "-i",
    "-r",
    "-t",
    "--abi",
    "--cache-dir",
    "--cert",
    "--client-cert",
    "--config-settings",
    "--constraint",
    "--editable",
    "--exists-action",
    "--extra-index-url",
    "--find-links",
    "--global-option",
    "--implementation",
    "--index-url",
    "--keyring-provider",
    "--log",
    "--platform",
    "--prefix",
    "--progress-bar",
    "--proxy",
    "--python",
    "--python-version",
    "--requirement",
    "--report",
    "--retries",
    "--root",
    "--root-user-action",
    "--src",
    "--target",
    "--timeout",
    "--trusted-host",
    "--upgrade-strategy",
    "--use-deprecated",
    "--use-feature",
}


class PackageLike(Protocol):
    name: str


@dataclass(frozen=True)
class TypoAlert:
    severity: Severity
    package_name: str
    matched_name: str
    score: float
    requested_exists: bool
    message: str


@dataclass(frozen=True)
class _Candidate:
    original_name: str
    canonical_name: str


class TypoDetector:
    def __init__(self, client: OfficialPyPIClient | None = None) -> None:
        self.client = client or OfficialPyPIClient()
        self._project_name_set: set[str] | None = None
        self._candidates: tuple[_Candidate, ...] | None = None
        self._first_char_index: dict[str, tuple[_Candidate, ...]] | None = None
        self._last_char_index: dict[str, tuple[_Candidate, ...]] | None = None
        self._popular_exact_names = {
            canonicalize_name(name) for name in BOOTSTRAP_PROJECT_NAMES
        }

    def detect(self, package_name: str) -> TypoAlert | None:
        requested = canonicalize_name(package_name)
        if not requested:
            return None

        project_name_set = self._load_project_name_set()
        if requested in self._popular_exact_names:
            return None
        best_match, score, distance = _search_best_match(
            requested,
            self._candidate_pool_for(requested),
        )
        if best_match is None:
            return None
        if best_match.canonical_name == requested:
            return None

        requested_exists = requested in project_name_set
        severity = _severity_for_similarity(score, distance, requested_exists)
        if severity is None:
            return None

        message = (
            f"'{package_name}' is similar to package '{best_match.original_name}' "
            f"(score={score:.3f}, distance={distance}, requested package "
            f"{'exists' if requested_exists else 'does not exist'} on PyPI)"
        )
        return TypoAlert(
            severity=severity,
            package_name=package_name,
            matched_name=best_match.original_name,
            score=score,
            requested_exists=requested_exists,
            message=message,
        )

    def _load_project_name_set(self) -> set[str]:
        if self._project_name_set is None:
            self._ensure_candidates_loaded()
        return self._project_name_set

    def _candidate_pool_for(self, requested: str) -> tuple[_Candidate, ...]:
        self._ensure_candidates_loaded()
        assert self._candidates is not None
        assert self._first_char_index is not None
        assert self._last_char_index is not None

        pools = [self._first_char_index.get(requested[0], ())]
        if requested[-1] != requested[0]:
            pools.append(self._last_char_index.get(requested[-1], ()))

        seen: set[str] = set()
        combined: list[_Candidate] = []
        for pool in pools:
            for candidate in pool:
                if candidate.canonical_name in seen:
                    continue
                seen.add(candidate.canonical_name)
                combined.append(candidate)

        if combined:
            return tuple(combined)
        return self._candidates

    def _ensure_candidates_loaded(self) -> None:
        if self._candidates is not None:
            return

        try:
            names = self.client.load_cached_project_names()
        except Exception:
            names = list(BOOTSTRAP_PROJECT_NAMES)

        candidate_names = _candidate_names_from_project_names(names)
        candidates: list[_Candidate] = []
        project_name_set: set[str] = {
            canonicalize_name(name)
            for name in set(names).union(BOOTSTRAP_PROJECT_NAMES)
        }
        first_char_index: dict[str, list[_Candidate]] = {}
        last_char_index: dict[str, list[_Candidate]] = {}

        for name in candidate_names:
            canonical_name = canonicalize_name(name)
            if not canonical_name:
                continue
            candidate = _Candidate(original_name=name, canonical_name=canonical_name)
            candidates.append(candidate)
            first_char_index.setdefault(canonical_name[0], []).append(candidate)
            last_char_index.setdefault(canonical_name[-1], []).append(candidate)

        self._project_name_set = project_name_set
        self._candidates = tuple(candidates)
        self._first_char_index = {
            key: tuple(value) for key, value in first_char_index.items()
        }
        self._last_char_index = {
            key: tuple(value) for key, value in last_char_index.items()
        }


def _candidate_names_from_project_names(
    names: Iterable[str],
) -> list[str]:
    canonical_to_original: dict[str, str] = {}
    popular_names = {canonicalize_name(item) for item in BOOTSTRAP_PROJECT_NAMES}
    for name in sorted(set(names).union(BOOTSTRAP_PROJECT_NAMES)):
        canonical_name = canonicalize_name(name)
        if not canonical_name:
            continue
        existing = canonical_to_original.get(canonical_name)
        if existing is None or len(name) < len(existing):
            canonical_to_original[canonical_name] = name

    ranked = sorted(
        canonical_to_original.values(),
        key=lambda name: (
            0 if canonicalize_name(name) in popular_names else 1,
            len(name),
            name,
        ),
    )
    return ranked


def detect_typos_in_resolved_packages(
    packages: Iterable[PackageLike],
    detector: TypoDetector | None = None,
) -> list[TypoAlert]:
    detector = detector or TypoDetector()
    alerts: list[TypoAlert] = []
    seen: set[str] = set()

    for package in packages:
        canonical_name = canonicalize_name(package.name)
        if canonical_name in seen:
            continue
        seen.add(canonical_name)
        alert = detector.detect(package.name)
        if alert is not None:
            alerts.append(alert)
    return alerts


def detect_typos_in_install_args(
    pip_args: list[str],
    detector: TypoDetector | None = None,
) -> list[TypoAlert]:
    detector = detector or TypoDetector()
    alerts: list[TypoAlert] = []
    seen: set[str] = set()

    for name in extract_requested_package_names(pip_args):
        canonical_name = canonicalize_name(name)
        if canonical_name in seen:
            continue
        seen.add(canonical_name)
        alert = detector.detect(name)
        if alert is not None:
            alerts.append(alert)
    return alerts


def render_alerts(alerts: Iterable[TypoAlert]) -> str:
    lines = []
    for alert in alerts:
        lines.append(
            colorize(
                f"[{alert.severity.label.upper()}] typo-suspect: {alert.message}",
                alert.severity,
            )
        )
    return "\n".join(lines)


def extract_requested_package_names(pip_args: list[str]) -> list[str]:
    names: list[str] = []
    requirement_files: list[str] = []
    i = 0

    while i < len(pip_args):
        arg = pip_args[i]
        if arg == "--":
            for trailing in pip_args[i + 1 :]:
                name = _extract_name_from_requirement(trailing)
                if name is not None:
                    names.append(name)
            break
        if arg.startswith("--requirement="):
            requirement_files.append(arg.split("=", 1)[1])
        elif arg.startswith("--constraint="):
            pass
        elif _starts_with_known_option_prefix(arg):
            pass
        elif arg in {"-r", "--requirement"}:
            if i + 1 < len(pip_args):
                requirement_files.append(pip_args[i + 1])
            i += 1
        elif arg in PIP_OPTIONS_WITH_VALUE:
            i += 1
        elif not arg.startswith("-"):
            name = _extract_name_from_requirement(arg)
            if name is not None:
                names.append(name)
        i += 1

    for path in requirement_files:
        names.extend(_extract_names_from_requirement_file(Path(path).resolve(), set()))
    return names


def _severity_for_similarity(
    score: float, distance: int, requested_exists: bool
) -> Severity | None:
    if distance == 0:
        return None

    strong_similarity = distance == 1 and score >= 0.83
    medium_similarity = distance == 2 and score >= 0.88
    weak_similarity = distance <= 2 and score >= 0.74

    if strong_similarity:
        return Severity.MEDIUM
    if requested_exists and medium_similarity:
        return Severity.LOW
    if requested_exists and weak_similarity:
        return None
    if medium_similarity:
        return Severity.LOW
    if weak_similarity:
        return Severity.LOW
    return None


def _extract_names_from_requirement_file(path: Path, visited: set[Path]) -> list[str]:
    if path in visited or not path.exists():
        return []
    visited.add(path)

    names: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = _strip_comment(raw_line).strip()
        if not line:
            continue
        if line.startswith("--requirement="):
            nested = line.split("=", 1)[1]
            nested_path = (path.parent / nested).resolve()
            names.extend(_extract_names_from_requirement_file(nested_path, visited))
            continue
        if line.startswith(("-r ", "--requirement ")):
            nested = line.split(maxsplit=1)[1]
            nested_path = (path.parent / nested).resolve()
            names.extend(_extract_names_from_requirement_file(nested_path, visited))
            continue
        if line.startswith("-"):
            continue
        name = _extract_name_from_requirement(line)
        if name is not None:
            names.append(name)
    return names


def _extract_name_from_requirement(value: str) -> str | None:
    try:
        return Requirement(value).name
    except InvalidRequirement:
        return None


def _strip_comment(line: str) -> str:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return ""
    if " #" in line and "://" not in line:
        return line.split(" #", 1)[0]
    return line


def _starts_with_known_option_prefix(arg: str) -> bool:
    if not arg.startswith("--") or "=" not in arg:
        return False
    return arg.split("=", 1)[0] in PIP_OPTIONS_WITH_VALUE


def _search_best_match(
    requested: str, references: Iterable[_Candidate]
) -> tuple[_Candidate | None, float, int]:
    best_name = None
    best_score = 0.0
    best_distance = 10**9

    for reference in references:
        candidate = reference.canonical_name
        if candidate == requested:
            continue
        if abs(len(candidate) - len(requested)) > 3:
            continue

        distance = _distance(requested, candidate)
        score = max(
            _normalized_similarity(requested, candidate, distance),
            _ratio(requested, candidate),
        )
        if score > best_score or (
            score == best_score and (distance < best_distance or best_name is None)
        ):
            best_name = reference
            best_score = score
            best_distance = distance

    return best_name, best_score, best_distance


def _normalized_similarity(left: str, right: str, distance: int) -> float:
    return 1.0 - (distance / max(len(left), len(right), 1))


def _distance(left: str, right: str) -> int:
    if _is_single_adjacent_swap(left, right):
        return 1
    if levenshtein_distance is None:
        return _levenshtein_distance_fallback(left, right)
    return levenshtein_distance(left, right)


def _is_single_adjacent_swap(left: str, right: str) -> bool:
    if len(left) != len(right):
        return False

    mismatches = [index for index, (a, b) in enumerate(zip(left, right)) if a != b]
    if len(mismatches) != 2:
        return False
    first, second = mismatches
    if second != first + 1:
        return False
    return left[first] == right[second] and left[second] == right[first]


def _ratio(left: str, right: str) -> float:
    if levenshtein_ratio is not None:
        return levenshtein_ratio(left, right)
    return SequenceMatcher(a=left, b=right).ratio()


def _levenshtein_distance_fallback(left: str, right: str) -> int:
    rows = len(left) + 1
    cols = len(right) + 1
    table = [[0] * cols for _ in range(rows)]

    for i in range(rows):
        table[i][0] = i
    for j in range(cols):
        table[0][j] = j

    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if left[i - 1] == right[j - 1] else 1
            table[i][j] = min(
                table[i - 1][j] + 1,
                table[i][j - 1] + 1,
                table[i - 1][j - 1] + cost,
            )

    return table[-1][-1]
