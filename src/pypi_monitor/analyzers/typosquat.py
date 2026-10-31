"""Search for names that imitate popular packages."""

from collections.abc import Mapping
from dataclasses import dataclass

from rapidfuzz import process
from rapidfuzz.distance import DamerauLevenshtein

SEPARATORS = str.maketrans("", "", "-_.")
PREFIXES = ("python-", "python", "py-", "py")
SUFFIXES = ("-python", "python", "-py", "py", "-lib", "2", "3")
# Short names are a few edits away from everything.
MIN_LENGTH_FOR_ONE_EDIT = 5
MIN_LENGTH_FOR_TWO_EDITS = 9


@dataclass(frozen=True)
class TyposquatMatch:
    target: str
    rank: int
    technique: str
    distance: int


class TyposquatDetector:
    def __init__(self, ranks: Mapping[str, int]) -> None:
        self._ranks = ranks
        self._by_rank = sorted(ranks, key=lambda name: ranks[name])
        self._compact = {name.translate(SEPARATORS): name for name in reversed(self._by_rank)}
        self._tokens = {_token_key(name): name for name in reversed(self._by_rank)}

    def find(self, normalized_name: str) -> TyposquatMatch | None:
        """`normalized_name` must be canonicalized. Popular packages never match."""
        if normalized_name in self._ranks:
            return None
        return (
            self._find_exact_variant(normalized_name)
            or self._find_affix(normalized_name)
            or self._find_edit(normalized_name)
        )

    def _find_exact_variant(self, name: str) -> TyposquatMatch | None:
        target = self._compact.get(name.translate(SEPARATORS))
        if target is not None:
            return self._match(target, "separators", 1)
        target = self._tokens.get(_token_key(name))
        if target is not None and "-" in name:
            return self._match(target, "token order", 1)
        return None

    def _find_affix(self, name: str) -> TyposquatMatch | None:
        stems = [name.removeprefix(prefix) for prefix in PREFIXES if name.startswith(prefix)]
        stems += [name.removesuffix(suffix) for suffix in SUFFIXES if name.endswith(suffix)]
        hits = [stem for stem in stems if len(stem) >= MIN_LENGTH_FOR_ONE_EDIT]
        for stem in sorted(hits, key=lambda s: self._ranks.get(s, len(self._ranks) + 1)):
            if stem in self._ranks:
                return self._match(stem, "affix", 1)
        return None

    def _find_edit(self, name: str) -> TyposquatMatch | None:
        if len(name) < MIN_LENGTH_FOR_ONE_EDIT:
            return None
        cutoff = 2 if len(name) >= MIN_LENGTH_FOR_TWO_EDITS else 1
        candidates = process.extract(
            name, self._by_rank, scorer=DamerauLevenshtein.distance, score_cutoff=cutoff, limit=5
        )
        for target, distance, _ in candidates:
            if (
                len(target) >= MIN_LENGTH_FOR_ONE_EDIT
                and not _differ_by_digits(name, target)
                and not _are_namespace_siblings(name, target)
            ):
                return self._match(target, "edit distance", int(distance))
        return None

    def _match(self, target: str, technique: str, distance: int) -> TyposquatMatch:
        return TyposquatMatch(target, self._ranks[target], technique, distance)


def _token_key(name: str) -> tuple[str, ...]:
    return tuple(sorted(name.split("-")))


def _differ_by_digits(left: str, right: str) -> bool:
    """`foo2` and `foo3` are usually a family of packages, not a typo."""
    return _letters(left) == _letters(right)


def _are_namespace_siblings(left: str, right: str) -> bool:
    """`django-crm` and `django-csp`: one short token apart, which is what plugins look like."""
    left_tokens, right_tokens = left.split("-"), right.split("-")
    if len(left_tokens) != len(right_tokens) or len(left_tokens) == 1:
        return False
    different = [pair for pair in zip(left_tokens, right_tokens, strict=True) if pair[0] != pair[1]]
    return len(different) == 1 and len(different[0][1]) < MIN_LENGTH_FOR_ONE_EDIT


def _letters(name: str) -> str:
    return "".join(char for char in name if not char.isdigit())
