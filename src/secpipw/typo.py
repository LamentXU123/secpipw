from __future__ import annotations

from difflib import SequenceMatcher
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Iterable, Protocol

from secpipw.pip_args import PIP_OPTIONS_WITH_VALUE
from secpipw.severity import Severity

if TYPE_CHECKING:
    from secpipw.pypi_api import OfficialPyPIClient


class PackageLike(Protocol):
    name: str


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


class TypoAlert(_FrozenRecord):
    __slots__ = (
        "severity",
        "package_name",
        "matched_name",
        "score",
        "requested_exists",
        "message",
    )
    _field_names = __slots__

    def __init__(
        self,
        severity: Severity,
        package_name: str,
        matched_name: str,
        score: float,
        requested_exists: bool,
        message: str,
    ) -> None:
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "package_name", package_name)
        object.__setattr__(self, "matched_name", matched_name)
        object.__setattr__(self, "score", score)
        object.__setattr__(self, "requested_exists", requested_exists)
        object.__setattr__(self, "message", message)

    severity: Severity
    package_name: str
    matched_name: str
    score: float
    requested_exists: bool
    message: str


class _Candidate(_FrozenRecord):
    __slots__ = ("original_name", "canonical_name")
    _field_names = __slots__

    def __init__(self, original_name: str, canonical_name: str) -> None:
        object.__setattr__(self, "original_name", original_name)
        object.__setattr__(self, "canonical_name", canonical_name)

    original_name: str
    canonical_name: str


class TypoDetector:
    def __init__(self, client: OfficialPyPIClient | None = None) -> None:
        self.client = client or _official_pypi_client_class()()
        self._project_name_set: set[str] | None = None
        self._candidates: tuple[_Candidate, ...] | None = None
        self._first_char_index: dict[str, tuple[_Candidate, ...]] | None = None
        self._last_char_index: dict[str, tuple[_Candidate, ...]] | None = None
        self._popular_exact_names = {
            _canonicalize_name(name) for name in _bootstrap_project_names()
        }

    def detect(self, package_name: str) -> TypoAlert | None:
        requested = _canonicalize_name(package_name)
        if not requested:
            return None

        if requested in self._popular_exact_names:
            return None

        project_name_set = self._load_project_name_set()
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
            names = list(_bootstrap_project_names())

        candidate_names = _candidate_names_from_project_names(names)
        candidates: list[_Candidate] = []
        project_name_set: set[str] = {
            _canonicalize_name(name)
            for name in set(names).union(_bootstrap_project_names())
        }
        first_char_index: dict[str, list[_Candidate]] = {}
        last_char_index: dict[str, list[_Candidate]] = {}

        for name in candidate_names:
            canonical_name = _canonicalize_name(name)
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
    popular_names = {_canonicalize_name(item) for item in _bootstrap_project_names()}
    for name in sorted(set(names).union(_bootstrap_project_names())):
        canonical_name = _canonicalize_name(name)
        if not canonical_name:
            continue
        existing = canonical_to_original.get(canonical_name)
        if existing is None or len(name) < len(existing):
            canonical_to_original[canonical_name] = name

    ranked = sorted(
        canonical_to_original.values(),
        key=lambda name: (
            0 if _canonicalize_name(name) in popular_names else 1,
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
        canonical_name = _canonicalize_name(package.name)
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
        canonical_name = _canonicalize_name(name)
        if canonical_name in seen:
            continue
        seen.add(canonical_name)
        alert = detector.detect(name)
        if alert is not None:
            alerts.append(alert)
    return alerts


def render_alerts(alerts: Iterable[TypoAlert]) -> str:
    from secpipw.terminal import colorize

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
    for raw_line in _read_requirement_file_text(path).splitlines():
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


def _read_requirement_file_text(path: Path) -> str:
    signature = _path_signature(path)
    if signature is None:
        return ""
    return _read_requirement_file_text_cached(str(path.resolve()), signature)


@lru_cache(maxsize=2048)
def _read_requirement_file_text_cached(
    path: str,
    signature: tuple[int, int],
) -> str:
    return Path(path).read_text(encoding="utf-8")


def _path_signature(path: Path) -> tuple[int, int] | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    return stat.st_mtime_ns, stat.st_size


def _extract_name_from_requirement(value: str) -> str | None:
    from packaging.requirements import InvalidRequirement, Requirement

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
    distance_func, _ = _levenshtein_functions()
    if _is_single_adjacent_swap(left, right):
        return 1
    if distance_func is None:
        return _levenshtein_distance_fallback(left, right)
    return distance_func(left, right)


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
    _, ratio_func = _levenshtein_functions()
    if ratio_func is not None:
        return ratio_func(left, right)
    return SequenceMatcher(a=left, b=right).ratio()


def _levenshtein_distance_fallback(left: str, right: str) -> int:
    if left == right:
        return 0
    rows = len(left) + 1
    cols = len(right) + 1
    prev = list(range(cols))
    curr = [0] * cols

    for i in range(1, rows):
        curr[0] = i
        row_min = i
        for j in range(1, cols):
            cost = 0 if left[i - 1] == right[j - 1] else 1
            curr[j] = min(
                prev[j] + 1,
                curr[j - 1] + 1,
                prev[j - 1] + cost,
            )
            if curr[j] < row_min:
                row_min = curr[j]
        prev, curr = curr, prev

    return prev[-1]


@lru_cache(maxsize=1)
def _bootstrap_project_names() -> tuple[str, ...]:
    from secpipw.pypi_api import BOOTSTRAP_PROJECT_NAMES

    return tuple(BOOTSTRAP_PROJECT_NAMES)


@lru_cache(maxsize=1)
def _official_pypi_client_class():
    from secpipw.pypi_api import OfficialPyPIClient

    return OfficialPyPIClient


@lru_cache(maxsize=4096)
def _canonicalize_name(value: str) -> str:
    from packaging.utils import canonicalize_name

    return canonicalize_name(value)


@lru_cache(maxsize=1)
def _levenshtein_functions():
    try:
        from Levenshtein import distance as distance_func
        from Levenshtein import ratio as ratio_func
    except ImportError:
        return None, None
    return distance_func, ratio_func
