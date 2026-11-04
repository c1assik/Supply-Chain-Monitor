"""Version diff: what appeared in a release compared with the previous one.

The diff compares like with like, sdist with sdist and wheel with wheel. Formatting, comments,
docstrings and version stamps do not count as changes. Code moved between ordinary modules is not
new either; files that run by themselves are compared one by one, because for them the place is
the point: an `exec` that lived in a helper and moved into `__init__.py` is a new fact.
"""

import tomllib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import ClassVar

from pypi_monitor.analyzers import content
from pypi_monitor.analyzers.base import Analyzer, ReleaseContext, Signal
from pypi_monitor.analyzers.facts import Fact, FactKind
from pypi_monitor.analyzers.tree import (
    SDIST,
    WHEEL,
    CodeReader,
    Role,
    Tree,
    all_trees,
    archive_name,
    artifact_trees,
    content_key,
    installed_paths,
    matching_wheel,
    overlaid,
    read_source,
    role_of,
)
from pypi_monitor.domain import Severity

NOISE_RULE_PREFIX = "noise."
_NOISY_CONFIDENCE_FACTOR = 0.2
_MAX_SIGNALS_PER_RULE = 10
_MAX_SNIPPET = 200
_SEVERITY_ORDER = list(Severity)

# (severity, confidence) of a new fact: in code that runs by itself / anywhere else.
_FACT_RULES: dict[FactKind, tuple[str, tuple[Severity, float], tuple[Severity, float]]] = {
    FactKind.IMPORT: ("new_import", (Severity.MEDIUM, 0.7), (Severity.LOW, 0.5)),
    FactKind.CALL: ("new_dangerous_call", (Severity.HIGH, 0.8), (Severity.MEDIUM, 0.5)),
    FactKind.URL: ("new_url", (Severity.MEDIUM, 0.7), (Severity.LOW, 0.5)),
    FactKind.IP: ("new_ip", (Severity.MEDIUM, 0.8), (Severity.MEDIUM, 0.6)),
}


@dataclass
class _Baseline:
    """Lazily read previous version: most releases never need all of it."""

    tree: Tree
    reader: CodeReader
    _facts: set[tuple[FactKind, str]] | None = None
    _contents: set[bytes] = field(default_factory=set)

    def _load(self) -> set[tuple[FactKind, str]]:
        facts: set[tuple[FactKind, str]] = set()
        for path, real in self.tree.files.items():
            role = role_of(path)
            source = read_source(real) if path.endswith(".py") else None
            if source is None or role is Role.IGNORED:
                continue
            self._contents.add(content_key(source))
            # What tests do says nothing about the package: their subprocess.run must not make
            # a subprocess.run in the installed code look familiar.
            if role is not Role.NOISY:
                facts.update(fact.key for fact in self.reader.facts(source) or [])
        self._facts = facts
        return facts

    @property
    def facts(self) -> set[tuple[FactKind, str]]:
        return self._load() if self._facts is None else self._facts

    def has_file(self, source: bytes) -> bool:
        """A file with this exact content existed, under any name."""
        if self._facts is None:
            self._load()
        return content_key(source) in self._contents


class DiffAnalyzer(Analyzer):
    name: ClassVar[str] = "diff"
    version: ClassVar[str] = "4"

    def analyze(self, release: ReleaseContext) -> list[Signal]:
        if release.artifact_dir is None or release.previous_artifact_dir is None:
            return []
        current = artifact_trees(release.artifact_dir)
        previous = artifact_trees(release.previous_artifact_dir)
        known_versions = {release.version, release.metadata.get("previous_version")}
        reader = CodeReader({version for version in known_versions if version})
        signals: list[Signal] = []
        common = current.keys() & previous.keys()
        for kind in common:
            installed = None
            if kind == SDIST:
                installed = installed_paths(current[SDIST], current.get(WHEEL))
            signals += _diff(previous[kind], current[kind], reader, installed)
        if not common and current and previous:
            # A change of format must not switch the diff off: a wheel uploaded to a project that
            # only had sdists is compared with them. Paths may differ, and facts are not bound to
            # paths, so moved code stays known.
            old = next(iter(previous.values()))
            for tree in current.values():
                signals += _diff(old, tree, reader, None)
        if release.extra_wheels_dir is not None:
            signals += _diff_extra_wheels(release, current, previous, reader)
        return _limited(signals)


def _diff_extra_wheels(
    release: ReleaseContext, current: dict[str, Tree], previous: dict[str, Tree], reader: CodeReader
) -> Iterator[Signal]:
    """The files that only another wheel of the release has, against everything known before.

    A file is compared with the same path in the previous build for the same platform, then in
    the first wheel of this release, then in the first wheel of the previous one. The first two
    tell what is particular to the platform, so a Windows-only module is not new on every release.
    """
    assert release.extra_wheels_dir is not None  # noqa: S101
    old_extras = []
    if release.previous_extra_wheels_dir is not None:
        old_extras = all_trees(release.previous_extra_wheels_dir)
    old_wheel = previous.get(WHEEL) or previous.get(SDIST)
    new_wheel = current.get(WHEEL)
    for tree in all_trees(release.extra_wheels_dir):
        layers = [old_wheel, new_wheel]
        match = matching_wheel(archive_name(tree), old_extras)
        if match is not None:
            layers.append(overlaid(match, previous.get(WHEEL)))
        files: dict[str, Path] = {}
        for layer in layers:
            if layer is not None:
                files.update(layer.files)
        reference = Tree(WHEEL, tree.pure, tree.base, files)
        yield from _diff(reference, tree, reader, None)


def _diff(old: Tree, new: Tree, reader: CodeReader, installed: set[str] | None) -> Iterator[Signal]:
    baseline = _Baseline(old, reader)
    # A platform wheel rebuilds its binaries on every release, so they are told as one fact.
    rebuilt: list[str] = []
    for path, real in sorted(new.files.items()):
        role = role_of(path)
        if role is Role.IGNORED:
            continue
        if role is not Role.AUTORUN and installed is not None and path not in installed:
            role = Role.NOISY
        before = old.files.get(path)
        if (
            before is not None
            and before.stat().st_size == real.stat().st_size
            and before.read_bytes() == real.read_bytes()
        ):
            continue
        suffix = PurePosixPath(path).suffix
        if suffix not in _HANDLED_SUFFIXES and PurePosixPath(path).name != "entry_points.txt":
            yield from _diff_other(new, path, real, before, role, rebuilt)
            continue
        source = read_source(real)
        if source is None:
            yield _too_big(new, path)
            continue
        old_source = None if before is None else read_source(before)
        if suffix == ".py":
            yield from _diff_python(new, path, role, source, old_source, baseline)
        elif suffix == ".pth":
            yield from _diff_pth(new, path, source, old_source, reader)
        elif PurePosixPath(path).name == "entry_points.txt":
            yield from _diff_entry_points(new, path, source, old_source)
        elif path == "pyproject.toml":
            yield from _diff_pyproject(new, path, source, old_source)
    if rebuilt:
        yield _signal(
            "diff.file.platform_binaries_changed",
            Severity.LOW,
            0.5,
            f"{len(rebuilt)} binaries changed: {', '.join(rebuilt[:5])}",
            new,
            rebuilt[0],
            Role.NORMAL,
        )


_HANDLED_SUFFIXES = frozenset({".py", ".pth", ".toml"})


def _diff_other(
    tree: Tree, path: str, real: Path, before: Path | None, role: Role, rebuilt: list[str]
) -> Iterator[Signal]:
    """Files the diff cannot read as code: binaries, scripts, data and archives of them."""
    found = content.classify(path, real)
    is_new = before is None
    where = "" if found.member is None else f" inside an archive: {found.member.partition('!')[2]}"
    if found.kind is content.Kind.BINARY:
        if not tree.pure and not is_new:
            rebuilt.append(path)
        elif not tree.pure:
            # Evidence for the context combos: a new native module is ordinary development.
            yield _signal(
                "diff.file.new_platform_binary",
                Severity.LOW,
                0.5,
                f"new binary{where}",
                tree,
                path,
                role,
            )
        elif is_new:
            yield _signal(
                "diff.file.new_binary", Severity.MEDIUM, 0.6, f"new binary{where}", tree, path, role
            )
        else:
            # Pure artifacts that bundle a tool rebuild it too, so alone this is only evidence;
            # with a hijacked account or lost attestations it is a swapped binary.
            yield _signal(
                "diff.file.binary_changed",
                Severity.LOW,
                0.6,
                f"binary changed{where}",
                tree,
                path,
                role,
            )
    elif found.kind is content.Kind.SCRIPT:
        yield from _diff_script(tree, path, real, before, role, found, where)
    elif found.kind is content.Kind.OPAQUE and is_new:
        yield _signal(
            "diff.file.new_blob",
            Severity.MEDIUM,
            0.6,
            f"opaque data{where}: {found.reason or ''}",
            tree,
            path,
            role,
        )


def _fetch_lines(text: bytes) -> dict[str, int]:
    """Lines of a script that download or decode, normalized, with the number of the first."""
    lines: dict[str, int] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if content.SCRIPT_FETCHES.search(line):
            lines.setdefault(" ".join(line.decode("utf-8", "replace").split()), number)
    return lines


def _diff_script(
    tree: Tree,
    path: str,
    real: Path,
    before: Path | None,
    role: Role,
    found: content.Content,
    where: str,
) -> Iterator[Signal]:
    """A new script, or an old one that has started to download or decode.

    `install.sh` that pipes `curl` into `sh` in the new release is a dropper whether the file is
    new or not, so the downloading lines are compared with those of the old file.
    """
    if found.member is not None:
        text, old = found.head, b""
    else:
        text = read_source(real) or found.head
        old = (read_source(before) or b"") if before is not None else b""
    known = _fetch_lines(old)
    added = {line: number for line, number in _fetch_lines(text).items() if line not in known}
    if added:
        snippet, line = min(added.items(), key=lambda item: item[1])
        what = "new script" if before is None else "script"
        yield _signal(
            "diff.file.new_script_fetches",
            Severity.MEDIUM,
            0.7,
            f"{what}{where} that downloads or decodes\n{snippet[:_MAX_SNIPPET]}",
            tree,
            path,
            role,
            None if found.member is not None else line,
        )
    elif before is None:
        yield _signal(
            "diff.file.new_script", Severity.LOW, 0.5, f"new script{where}", tree, path, role
        )


def _diff_python(
    tree: Tree, path: str, role: Role, source: bytes, old_source: bytes | None, baseline: _Baseline
) -> Iterator[Signal]:
    reader = baseline.reader
    # Only here the place of a fact matters and the whole file has to be compared. Elsewhere a
    # change without new facts gives no signals anyway, so most of a big update is not compared.
    autorun = role is Role.AUTORUN
    facts = reader.facts(source)
    old_facts = None if old_source is None else reader.facts(old_source)
    if facts is None:
        if old_facts is not None or (old_source is None and autorun):
            yield _signal(
                "diff.file.unparseable",
                Severity.MEDIUM,
                0.7,
                "a file that used to parse does not",
                tree,
                path,
                role,
            )
        return

    if old_source is None:
        if not autorun and baseline.has_file(source):
            return  # A renamed file.
        yield _signal("diff.file.new_python", Severity.LOW, 0.5, "new module", tree, path, role)
    elif autorun and not _same_code(reader, source, old_source):
        yield _signal(
            "diff.file.autorun_changed",
            Severity.LOW,
            0.5,
            "code that runs on install or import has changed",
            tree,
            path,
            role,
        )

    known = {fact.key for fact in old_facts or []}
    if not autorun:  # Code that runs by itself is compared with itself: see the module docstring.
        known |= baseline.facts
    lines = source.decode("utf-8", "replace").splitlines()
    for fact in facts:
        if fact.key not in known:
            yield _fact_signal(fact, tree, path, role, lines)


def _same_code(reader: CodeReader, source: bytes, old_source: bytes) -> bool:
    """Formatting, comments and a version stamp do not make a different code."""
    parsed, old_parsed = reader.parse(source), reader.parse(old_source)
    return (
        parsed is not None
        and old_parsed is not None
        and (parsed.fingerprint == old_parsed.fingerprint)
    )


def _fact_signal(fact: Fact, tree: Tree, path: str, role: Role, lines: list[str]) -> Signal:
    snippet = lines[fact.line - 1].strip()[:_MAX_SNIPPET] if fact.line <= len(lines) else ""
    evidence = f"new {fact.kind.value} {fact.value}\n{snippet}"
    if fact.kind is FactKind.DECODED_EXEC:
        # No legitimate update starts doing this, so its place does not lower the confidence.
        return Signal(
            rule_id="diff.exec_decoded",
            severity=Severity.CRITICAL,
            confidence=0.9,
            evidence=evidence,
            file_path=tree.display(path),
            line=fact.line,
        )
    rule, autorun_grade, usual_grade = _FACT_RULES[fact.kind]
    # A function in a file that runs by itself is still only code that may run later. And a call
    # at the top level of any module runs once it is imported, which `__init__.py` may well do;
    # imports and strings are at the top level everywhere, so that says nothing about them.
    runs_by_itself = role is Role.AUTORUN or (role is Role.NORMAL and fact.kind is FactKind.CALL)
    if runs_by_itself and fact.at_import:
        return _signal(
            f"diff.install.{rule}", *autorun_grade, evidence, tree, path, role, fact.line
        )
    return _signal(f"diff.{rule}", *usual_grade, evidence, tree, path, role, fact.line)


def _diff_pth(
    tree: Tree, path: str, source: bytes, old_source: bytes | None, reader: CodeReader
) -> Iterator[Signal]:
    if old_source is not None and reader.text_fingerprint(source) == reader.text_fingerprint(
        old_source
    ):
        return
    # site.py executes the lines of a .pth that start with `import`, on every interpreter start.
    lines = source.decode("utf-8", "replace").splitlines()
    executable = [line for line in lines if line.startswith(("import ", "import\t"))]
    if executable:
        yield _signal(
            "diff.file.pth_code",
            Severity.CRITICAL,
            0.9,
            executable[0][:_MAX_SNIPPET],
            tree,
            path,
            Role.AUTORUN,
        )
    else:
        yield _signal(
            "diff.file.pth_changed", Severity.MEDIUM, 0.6, "path file", tree, path, Role.AUTORUN
        )


def _entry_lines(source: bytes) -> set[str]:
    lines = (line.strip() for line in source.decode("utf-8", "replace").splitlines())
    return {"".join(line.split()) for line in lines if "=" in line}


def _diff_entry_points(
    tree: Tree, path: str, source: bytes, old_source: bytes | None
) -> Iterator[Signal]:
    known = _entry_lines(old_source or b"")
    for line in sorted(_entry_lines(source) - known):
        yield _signal(
            "diff.file.new_entry_point", Severity.MEDIUM, 0.6, line, tree, path, Role.NORMAL
        )


def _build_table(source: bytes | None) -> tuple[object, object]:
    if source is None:
        return None, None
    try:
        build = tomllib.loads(source.decode("utf-8", "replace")).get("build-system", {})
    except tomllib.TOMLDecodeError:
        return None, None
    return build.get("build-backend"), build.get("backend-path")


def _diff_pyproject(
    tree: Tree, path: str, source: bytes, old_source: bytes | None
) -> Iterator[Signal]:
    backend, backend_path = _build_table(source)
    old_backend, old_backend_path = _build_table(old_source)
    # backend-path means an in-tree backend: code from the sdist runs on every install.
    if backend_path != old_backend_path or (old_source is not None and backend != old_backend):
        yield _signal(
            "diff.file.build_backend_changed",
            Severity.MEDIUM,
            0.7,
            f"{old_backend} -> {backend} (path: {backend_path})",
            tree,
            path,
            Role.NORMAL,
        )


def _too_big(tree: Tree, path: str) -> Signal:
    return _signal("diff.file.too_big", Severity.LOW, 0.6, "not compared", tree, path, Role.NORMAL)


def _signal(
    rule_id: str,
    severity: Severity,
    confidence: float,
    evidence: str,
    tree: Tree,
    path: str,
    role: Role,
    line: int | None = None,
) -> Signal:
    if role is Role.NOISY:
        # Kept as evidence, but under its own prefix, so that combos do not fire on a test file.
        rule_id = f"{NOISE_RULE_PREFIX}{rule_id}"
        confidence *= _NOISY_CONFIDENCE_FACTOR
    return Signal(
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        file_path=tree.display(path),
        line=line,
    )


def _limited(signals: list[Signal]) -> list[Signal]:
    """The strongest signals of each rule: a big update must not flood the signals table."""
    ranked = sorted(
        signals, key=lambda s: (_SEVERITY_ORDER.index(s.severity), s.confidence), reverse=True
    )
    per_rule: dict[str, int] = {}
    kept = []
    for signal in ranked:
        per_rule[signal.rule_id] = per_rule.get(signal.rule_id, 0) + 1
        if per_rule[signal.rule_id] <= _MAX_SIGNALS_PER_RULE:
            kept.append(signal)
    return kept
