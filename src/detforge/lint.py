"""Lint rules: pySigma core validators plus DetForge project conventions."""

import dataclasses
import re
from dataclasses import dataclass
from pathlib import Path

from sigma.rule import SigmaRule
from sigma.validation import SigmaValidator
from sigma.validators.base import SigmaValidationIssue
from sigma.validators.core import validators

from detforge.loader import (
    FIXTURES_DIR,
    RULES_DIR,
    FixtureError,
    fixture_dir,
    load_rules,
    read_jsonl,
    rule_path,
)

# These two download MITRE data at runtime and crash without network.
NETWORK_VALIDATORS = frozenset({"attacktag", "d3_fendtag"})

REQUIRED_FIELDS = (
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "logsource",
    "detection",
    "falsepositives",
    "level",
    "tags",
)
AUTHOR = "Reda"
TACTICS = frozenset(
    {
        "reconnaissance",
        "resource-development",
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
    }
)
TECHNIQUE_TAG = re.compile(r"t\d{4}(\.\d{3})?")
SNAKE_CASE_FILE = re.compile(r"[a-z0-9]+(_[a-z0-9]+)*\.yml")
MIN_FIXTURE_EVENTS = 2


@dataclass(frozen=True)
class LintIssue:
    path: Path
    check: str
    message: str


def lint_rules(
    rules_root: Path = RULES_DIR,
    fixtures_root: Path = FIXTURES_DIR,
    offline: bool = False,
) -> list[LintIssue]:
    rules, load_errors = load_rules(rules_root)
    issues = [LintIssue(error.path, "parse", error.message) for error in load_errors]
    issues += pysigma_issues(rules, offline)
    for rule in rules:
        issues += layout_issues(rule, rules_root)
        issues += field_issues(rule)
        issues += tag_issues(rule)
        issues += fixture_issues(rule, fixtures_root)
    return issues


def pysigma_issues(rules: list[SigmaRule], offline: bool) -> list[LintIssue]:
    selected = [
        validator
        for name, validator in validators.items()
        if not (offline and name in NETWORK_VALIDATORS)
    ]
    issues: list[LintIssue] = []
    for issue in SigmaValidator(selected).validate_rules(rules):
        check = "sigma:" + type(issue).__name__.removesuffix("Issue")
        for rule in issue.rules:
            issues.append(LintIssue(rule_path(rule), check, _describe(issue)))
    return issues


def _describe(issue: SigmaValidationIssue) -> str:
    details = ", ".join(
        f"{field.name}={getattr(issue, field.name)}"
        for field in dataclasses.fields(issue)
        if field.name not in ("rules", "severity")
    )
    return f"{issue.description} ({details})" if details else issue.description


def layout_issues(rule: SigmaRule, rules_root: Path) -> list[LintIssue]:
    path = rule_path(rule)
    issues: list[LintIssue] = []
    if not SNAKE_CASE_FILE.fullmatch(path.name):
        issues.append(LintIssue(path, "filename", "file name must be snake_case and end in .yml"))

    parts = path.relative_to(rules_root).parts
    if len(parts) != 3 or parts[0] != "windows":
        issues.append(
            LintIssue(path, "layout", "rule must live in rules/windows/<tactic>/<rule_name>.yml")
        )
        return issues
    folder_tactic = parts[1].replace("_", "-")
    if folder_tactic not in TACTICS:
        issues.append(LintIssue(path, "layout", f"'{parts[1]}' is not an ATT&CK tactic folder"))
    elif folder_tactic not in _attack_tags(rule):
        issues.append(
            LintIssue(path, "layout", f"folder '{parts[1]}' does not match any tactic tag")
        )
    return issues


def field_issues(rule: SigmaRule) -> list[LintIssue]:
    path = rule_path(rule)
    issues = [
        LintIssue(path, "required-field", f"missing or empty field '{name}'")
        for name in REQUIRED_FIELDS
        if getattr(rule, name, None) in (None, "", [])
    ]
    if rule.author and rule.author != AUTHOR:
        issues.append(LintIssue(path, "required-field", f"author must be '{AUTHOR}'"))
    return issues


def tag_issues(rule: SigmaRule) -> list[LintIssue]:
    path = rule_path(rule)
    tags = _attack_tags(rule)
    issues: list[LintIssue] = []
    if not any(TECHNIQUE_TAG.fullmatch(tag) for tag in tags):
        issues.append(LintIssue(path, "tags", "needs an ATT&CK technique tag (attack.tNNNN)"))
    if not tags & TACTICS:
        issues.append(LintIssue(path, "tags", "needs an ATT&CK tactic tag (attack.<tactic>)"))
    return issues


def fixture_issues(rule: SigmaRule, fixtures_root: Path) -> list[LintIssue]:
    if rule.id is None:
        return []  # the invalid id is already reported as a parse error
    directory = fixture_dir(rule, fixtures_root)
    issues: list[LintIssue] = []
    for kind in ("tp", "tn"):
        path = directory / f"{kind}.jsonl"
        if not path.is_file():
            issues.append(LintIssue(path, "fixtures", f"missing {kind}.jsonl for this rule"))
            continue
        try:
            events = read_jsonl(path)
        except FixtureError as exc:
            issues.append(LintIssue(path, "fixtures", str(exc)))
            continue
        if len(events) < MIN_FIXTURE_EVENTS:
            issues.append(
                LintIssue(
                    path,
                    "fixtures",
                    f"needs at least {MIN_FIXTURE_EVENTS} events, has {len(events)}",
                )
            )
    return issues


def _attack_tags(rule: SigmaRule) -> set[str]:
    return {tag.name.lower() for tag in rule.tags if tag.namespace == "attack"}
