"""Unit-test rules: run each rule's SQLite query over its TP, TN and baseline events."""

import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sigma.backends.sqlite import sqliteBackend
from sigma.exceptions import SigmaError
from sigma.rule import SigmaDetection, SigmaRule

from detforge.loader import (
    FIXTURES_DIR,
    RULES_DIR,
    FixtureError,
    fixture_dir,
    load_rules,
    read_jsonl,
    rule_path,
)

Event = dict[str, Any]
BASELINE_DIR = "baseline"


@dataclass
class RuleResult:
    path: Path
    title: str
    tp_matched: int = 0
    tp_total: int = 0
    tn_fp: int = 0
    baseline_fp: int = 0
    failures: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.failures


def run_tests(rules_root: Path = RULES_DIR, fixtures_root: Path = FIXTURES_DIR) -> list[RuleResult]:
    """Test every rule under rules_root (or the single rule file rules_root points to)."""
    rules, load_errors = load_rules(rules_root)
    results = [
        RuleResult(error.path, error.path.name, failures=[f"cannot load rule: {error.message}"])
        for error in load_errors
    ]
    try:
        baseline = load_baseline(fixtures_root)
    except FixtureError as exc:
        return [*results, RuleResult(fixtures_root / BASELINE_DIR, "baseline", failures=[str(exc)])]
    results += [check_rule(rule, fixtures_root, baseline) for rule in rules]
    return results


def check_rule(rule: SigmaRule, fixtures_root: Path, baseline: list[Event]) -> RuleResult:
    result = RuleResult(rule_path(rule), rule.title)
    try:
        queries = sqliteBackend().convert_rule(rule)
        tp = read_jsonl(fixture_dir(rule, fixtures_root) / "tp.jsonl")
        tn = read_jsonl(fixture_dir(rule, fixtures_root) / "tn.jsonl")
    except (SigmaError, OSError, FixtureError) as exc:
        result.failures.append(f"{type(exc).__name__}: {exc}")
        return result

    baseline = [event for event in baseline if event.get("_logsource") == logsource_key(rule)]
    events = [*tp, *tn, *baseline]
    try:
        matched = match_events(queries, rule_fields(rule), events)
    except sqlite3.Error as exc:
        result.failures.append(f"SQLite error: {exc}")
        return result

    result.tp_total = len(tp)
    if not tp:
        result.failures.append("no TP events: the rule is not tested")
    for number, event in enumerate(tp, start=1):
        if number - 1 in matched:
            result.tp_matched += 1
        else:
            result.failures.append(f"TP #{number} not matched: {describe(event)}")
    for number, event in enumerate(tn, start=1):
        if len(tp) + number - 1 in matched:
            result.tn_fp += 1
            result.failures.append(f"TN #{number} matched: {describe(event)}")
    for number, event in enumerate(baseline, start=1):
        if len(tp) + len(tn) + number - 1 in matched:
            result.baseline_fp += 1
            result.failures.append(f"baseline event matched: {describe(event)}")
    return result


def match_events(queries: list[str], fields: set[str], events: list[Event]) -> set[int]:
    """Load events into an in-memory `logs` table and return the indexes the queries match."""
    columns = _columns(fields, events)
    with sqlite3.connect(":memory:") as conn:
        conn.create_function("REGEXP", 2, _regexp, deterministic=True)
        # NOCASE because Sigma matches case-insensitively and SQLite `=` does not.
        column_defs = ", ".join(f"{_quote(name)} TEXT COLLATE NOCASE" for name in columns)
        conn.execute(f"CREATE TABLE logs (_idx INTEGER, {column_defs})")
        placeholders = ", ".join("?" * (len(columns) + 1))
        rows = []
        for idx, event in enumerate(events):
            lowered = {key.lower(): value for key, value in event.items()}
            rows.append([idx, *(_cell(lowered.get(name.lower())) for name in columns)])
        conn.executemany(f"INSERT INTO logs VALUES ({placeholders})", rows)
        matched: set[int] = set()
        for query in queries:
            matched.update(row[0] for row in conn.execute(f"SELECT _idx FROM ({query})"))
    conn.close()
    return matched


def rule_fields(rule: SigmaRule) -> set[str]:
    fields: set[str] = set()

    def walk(detection: SigmaDetection) -> None:
        for item in detection.detection_items:
            if isinstance(item, SigmaDetection):
                walk(item)
            elif item.field is not None:
                fields.add(item.field)

    for detection in rule.detection.detections.values():
        walk(detection)
    return fields


def logsource_key(rule: SigmaRule) -> str | None:
    return rule.logsource.category or rule.logsource.service


def load_baseline(fixtures_root: Path) -> list[Event]:
    events: list[Event] = []
    for path in sorted((fixtures_root / BASELINE_DIR).glob("*.jsonl")):
        try:
            events += read_jsonl(path)
        except FixtureError as exc:
            raise FixtureError(f"{path}: {exc}") from exc
    return events


def describe(event: Event) -> str:
    return str(event.get("_description") or json.dumps(event))


def _columns(fields: set[str], events: list[Event]) -> list[str]:
    """Rule fields plus every non-metadata fixture key, deduplicated the way SQLite
    compares column names: case-insensitively."""
    names: dict[str, str] = {}
    for name in [*sorted(fields), *(key for event in events for key in event)]:
        if not name.startswith("_"):
            names.setdefault(name.lower(), name)
    return list(names.values())


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _cell(value: Any) -> str | None:
    if value is None or isinstance(value, str):
        return value
    return json.dumps(value)


def _regexp(pattern: str, value: str | None) -> bool:
    return value is not None and re.search(pattern, value) is not None
