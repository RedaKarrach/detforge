"""Unit-test rules: run each rule's SQLite query over its TP, TN and baseline events.

All events (every rule's fixtures plus the shared baseline) are loaded once into a single
in-memory table; each rule's query then runs against that table and only the rows belonging
to the rule (its own TP/TN rows and the baseline rows of its logsource) are judged.
"""

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


@dataclass
class _Prepared:
    rule: SigmaRule
    queries: list[str]
    tp: list[Event]
    tn: list[Event]
    offset: int = 0  # index of the rule's first TP event in the shared table


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

    prepared: list[_Prepared] = []
    backend = sqliteBackend()
    for rule in rules:
        try:
            directory = fixture_dir(rule, fixtures_root)
            prepared.append(
                _Prepared(
                    rule,
                    backend.convert_rule(rule),
                    read_jsonl(directory / "tp.jsonl"),
                    read_jsonl(directory / "tn.jsonl"),
                )
            )
        except (SigmaError, OSError, FixtureError) as exc:
            results.append(
                RuleResult(rule_path(rule), rule.title, failures=[f"{type(exc).__name__}: {exc}"])
            )

    if not prepared:
        return results

    events = list(baseline)
    fields: set[str] = set()
    for item in prepared:
        item.offset = len(events)
        events += item.tp + item.tn
        fields |= rule_fields(item.rule)

    store = EventStore(fields, events)
    try:
        results += [_judge(item, store, baseline) for item in prepared]
    finally:
        store.close()
    return results


def _judge(item: _Prepared, store: "EventStore", baseline: list[Event]) -> RuleResult:
    rule = item.rule
    result = RuleResult(rule_path(rule), rule.title, tp_total=len(item.tp))
    try:
        matched = store.matches(item.queries)
    except sqlite3.Error as exc:
        result.failures.append(f"SQLite error: {exc}")
        return result

    if not item.tp:
        result.failures.append("no TP events: the rule is not tested")
    for number, event in enumerate(item.tp, start=1):
        if item.offset + number - 1 in matched:
            result.tp_matched += 1
        else:
            result.failures.append(f"TP #{number} not matched: {describe(event)}")
    tn_offset = item.offset + len(item.tp)
    for number, event in enumerate(item.tn, start=1):
        if tn_offset + number - 1 in matched:
            result.tn_fp += 1
            result.failures.append(f"TN #{number} matched: {describe(event)}")
    key = logsource_key(rule)
    for idx in sorted(i for i in matched if i < len(baseline)):
        event = baseline[idx]
        if event.get("_logsource") == key:
            result.baseline_fp += 1
            result.failures.append(f"baseline event matched: {describe(event)}")
    return result


class EventStore:
    """An in-memory SQLite table `logs` holding the events, one TEXT COLLATE NOCASE column per
    field, plus an INTEGER `_idx` that is the event's position in the list given."""

    def __init__(self, fields: set[str], events: list[Event]) -> None:
        self.columns = _columns(fields, events)
        self.conn = sqlite3.connect(":memory:")
        self.conn.create_function("REGEXP", 2, _regexp, deterministic=True)
        # NOCASE because Sigma matches case-insensitively and SQLite `=` does not.
        column_defs = "".join(f", {_quote(name)} TEXT COLLATE NOCASE" for name in self.columns)
        self.conn.execute(f"CREATE TABLE logs (_idx INTEGER PRIMARY KEY{column_defs})")
        lowered_columns = [name.lower() for name in self.columns]
        rows = []
        for idx, event in enumerate(events):
            lowered = {key.lower(): value for key, value in event.items()}
            rows.append([idx, *(_cell(lowered.get(name)) for name in lowered_columns)])
        placeholders = ", ".join("?" * (len(self.columns) + 1))
        self.conn.executemany(f"INSERT INTO logs VALUES ({placeholders})", rows)

    def matches(self, queries: list[str]) -> set[int]:
        matched: set[int] = set()
        for query in queries:
            matched.update(row[0] for row in self.conn.execute(f"SELECT _idx FROM ({query})"))
        return matched

    def close(self) -> None:
        self.conn.close()


def match_events(queries: list[str], fields: set[str], events: list[Event]) -> set[int]:
    """Run the queries over the events and return the indexes they match."""
    store = EventStore(fields, events)
    try:
        return store.matches(queries)
    finally:
        store.close()


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
    for name in sorted(fields):
        if name and name[0] != "_":
            names.setdefault(name.lower(), name)
    for event in events:
        for name in event:
            if name and name[0] != "_":
                names.setdefault(name.lower(), name)
    return list(names.values())


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _cell(value: Any) -> str | None:
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return json.dumps(value)


def _regexp(pattern: str, value: str | None) -> bool:
    return value is not None and re.search(pattern, value) is not None
