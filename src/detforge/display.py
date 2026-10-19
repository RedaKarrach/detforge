"""Read-only views over the rule set: a per-rule summary for `detforge list` and
`detforge show`, and the tactic-by-tactic matrix for `detforge matrix`."""

from dataclasses import dataclass
from pathlib import Path

from sigma.rule import SigmaRule

from detforge.coverage import TACTIC_ORDER, Coverage, compute_coverage, rule_techniques
from detforge.harness import logsource_key
from detforge.loader import (
    FIXTURES_DIR,
    RULES_DIR,
    FixtureError,
    fixture_dir,
    load_rules,
    read_jsonl,
    rule_path,
)


@dataclass(frozen=True)
class RuleInfo:
    path: Path
    title: str
    id: str
    status: str
    level: str
    author: str
    date: str
    logsource: str
    tactics: tuple[str, ...]
    techniques: tuple[str, ...]
    tp_events: int
    tn_events: int

    @property
    def name(self) -> str:
        return self.path.stem

    @property
    def tactic_folder(self) -> str:
        return self.path.parent.name


def rule_info(rule: SigmaRule, fixtures_root: Path = FIXTURES_DIR) -> RuleInfo:
    pairs = rule_techniques(rule)
    tactics: list[str] = []
    for _, tactic in pairs:
        if tactic and tactic not in tactics:
            tactics.append(tactic)
    techniques = tuple(dict.fromkeys(technique for technique, _ in pairs))
    return RuleInfo(
        path=rule_path(rule),
        title=rule.title,
        id=str(rule.id),
        status=str(rule.status.name).lower() if rule.status else "",
        level=str(rule.level.name).lower() if rule.level else "",
        author=rule.author or "",
        date=rule.date.isoformat() if rule.date else "",
        logsource=logsource_key(rule) or "",
        tactics=tuple(tactics),
        techniques=techniques,
        tp_events=_count(fixture_dir(rule, fixtures_root) / "tp.jsonl"),
        tn_events=_count(fixture_dir(rule, fixtures_root) / "tn.jsonl"),
    )


def collect(
    rules_root: Path = RULES_DIR, fixtures_root: Path = FIXTURES_DIR
) -> tuple[list[RuleInfo], list[str]]:
    """Every rule's summary, sorted by tactic folder then name, plus load errors as text."""
    rules, errors = load_rules(rules_root)
    infos = sorted(
        (rule_info(rule, fixtures_root) for rule in rules),
        key=lambda info: (info.tactic_folder, info.name),
    )
    return infos, [f"{error.path}: {error.message}" for error in errors]


def find_rule(rules_root: Path, query: str) -> Path | None:
    """Resolve a rule by path, file stem, or a unique substring of the stem."""
    candidate = Path(query)
    if candidate.is_file():
        return candidate
    files = sorted([*rules_root.rglob("*.yml"), *rules_root.rglob("*.yaml")])
    exact = [path for path in files if path.stem == query]
    if len(exact) == 1:
        return exact[0]
    partial = [path for path in files if query.lower() in path.stem.lower()]
    return partial[0] if len(partial) == 1 else None


@dataclass(frozen=True)
class MatrixRow:
    tactic: str
    techniques: tuple[tuple[str, int], ...]  # (technique id, number of rules)

    @property
    def rule_count(self) -> int:
        return sum(count for _, count in self.techniques)

    @property
    def covered(self) -> bool:
        return bool(self.techniques)


def matrix_rows(coverage: Coverage) -> list[MatrixRow]:
    """One row per ATT&CK tactic in matrix order, covered or not."""
    rows = []
    for tactic in TACTIC_ORDER:
        techniques = tuple(
            (technique, len(coverage.techniques[technique]))
            for technique in sorted(coverage.tactics.get(tactic, set()))
        )
        rows.append(MatrixRow(tactic, techniques))
    return rows


def matrix(rules_root: Path = RULES_DIR) -> tuple[list[MatrixRow], Coverage]:
    rules, _ = load_rules(rules_root)
    coverage = compute_coverage(rules)
    return matrix_rows(coverage), coverage


def _count(path: Path) -> int:
    if not path.is_file():
        return 0
    try:
        return len(read_jsonl(path))
    except FixtureError:
        return 0
