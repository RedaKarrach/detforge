"""Load Sigma rules and JSONL fixtures from disk."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaRuleLocation
from sigma.rule import SigmaRule

RULES_DIR = Path("rules")
FIXTURES_DIR = Path("tests/fixtures")


@dataclass(frozen=True)
class LoadError:
    path: Path
    message: str


class FixtureError(ValueError):
    """A fixture file contains a line that is not a JSON object."""


def rule_files(rules_root: Path) -> list[Path]:
    if rules_root.is_file():
        return [rules_root]
    return sorted([*rules_root.rglob("*.yml"), *rules_root.rglob("*.yaml")])


def load_rules(rules_root: Path = RULES_DIR) -> tuple[list[SigmaRule], list[LoadError]]:
    """Load one rule file, or every rule file under a folder, each file on its own
    so one broken file cannot hide the others."""
    rules: list[SigmaRule] = []
    errors: list[LoadError] = []
    for path in rule_files(rules_root):
        try:
            collection = SigmaCollection.from_yaml(
                path.read_text(encoding="utf-8"),
                collect_errors=True,
                source=SigmaRuleLocation(path),
            )
        except yaml.YAMLError as exc:  # pySigma's collect_errors does not cover YAML syntax
            errors.append(LoadError(path, f"invalid YAML: {exc}"))
            continue
        except AttributeError:  # pySigma calls .get() on each document, so a non-mapping fails
            errors.append(LoadError(path, "top level of the file must be a YAML mapping"))
            continue
        errors.extend(LoadError(path, str(error)) for error in collection.errors)
        if len(collection.rules) != 1:
            errors.append(
                LoadError(path, f"expected one rule per file, found {len(collection.rules)}")
            )
        rules.extend(rule for rule in collection.rules if isinstance(rule, SigmaRule))
    return rules, errors


def rule_path(rule: SigmaRule) -> Path:
    if rule.source is None:
        raise ValueError(f"rule {rule.title!r} was not loaded from a file")
    return rule.source.path


def fixture_dir(rule: SigmaRule, fixtures_root: Path = FIXTURES_DIR) -> Path:
    return fixtures_root / str(rule.id)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read one JSON object per line, skipping blank lines."""
    events: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise FixtureError(f"line {number}: invalid JSON ({exc.msg})") from exc
        if not isinstance(event, dict):
            raise FixtureError(f"line {number}: expected a JSON object, got {type(event).__name__}")
        events.append(event)
    return events
