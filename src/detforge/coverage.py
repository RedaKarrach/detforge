"""ATT&CK coverage: a Navigator layer and a Markdown summary of which techniques the rules cover."""

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from sigma.rule import SigmaRule

from detforge.convert import DIST_DIR
from detforge.loader import RULES_DIR, load_rules

TECHNIQUE_TAG = re.compile(r"t(\d{4})(?:\.(\d{3}))?")

# Navigator tactic ids are the ATT&CK tactic names; this is the order the matrix shows them in.
TACTIC_ORDER = [
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
]


@dataclass(frozen=True)
class Coverage:
    """technique id (T1059.001) -> rule titles, and tactic -> technique ids."""

    techniques: dict[str, list[str]]
    tactics: dict[str, set[str]]

    @property
    def rule_count(self) -> int:
        return len({title for titles in self.techniques.values() for title in titles})


def compute_coverage(rules: list[SigmaRule]) -> Coverage:
    techniques: dict[str, list[str]] = defaultdict(list)
    tactics: dict[str, set[str]] = defaultdict(set)
    for rule in sorted(rules, key=lambda r: r.title):
        for technique, tactic in rule_techniques(rule):
            techniques[technique].append(rule.title)
            if tactic:
                tactics[tactic].add(technique)
    return Coverage(dict(techniques), dict(tactics))


def rule_techniques(rule: SigmaRule) -> list[tuple[str, str | None]]:
    """(technique, tactic) pairs. Sigma tags list a tactic followed by its techniques, so each
    technique belongs to the nearest tactic tag above it; a technique with no tactic above it
    gets the rule's first tactic, or None when the rule has no tactic tag."""
    attack = [tag.name.lower() for tag in rule.tags if tag.namespace == "attack"]
    first_tactic = next((t for t in attack if t in TACTIC_ORDER), None)
    pairs: list[tuple[str, str | None]] = []
    current = first_tactic
    for tag in attack:
        if tag in TACTIC_ORDER:
            current = tag
        elif TECHNIQUE_TAG.fullmatch(tag):
            pairs.append((tag.upper(), current))
    return pairs


def navigator_layer(coverage: Coverage, name: str = "DetForge coverage") -> dict:
    techniques = [
        {
            "techniqueID": technique,
            "score": len(titles),
            "comment": "\n".join(titles),
            "enabled": True,
        }
        for technique, titles in sorted(coverage.techniques.items())
    ]
    max_score = max((t["score"] for t in techniques), default=1)
    return {
        "name": name,
        "versions": {"attack": "15", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"{coverage.rule_count} rules covering {len(techniques)} techniques",
        "sorting": 0,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffe766", "#8ec843"],
            "minValue": 1,
            "maxValue": max_score,
        },
        "legendItems": [{"label": "number of rules", "color": "#8ec843"}],
    }


def coverage_markdown(coverage: Coverage) -> str:
    lines = [
        "# ATT&CK coverage",
        "",
        (
            f"{coverage.rule_count} rules cover {len(coverage.techniques)} techniques "
            f"across {len(coverage.tactics)} tactics."
        ),
        "",
    ]
    for tactic in TACTIC_ORDER:
        techniques = coverage.tactics.get(tactic)
        if not techniques:
            continue
        lines += [f"## {tactic}", ""]
        for technique in sorted(techniques):
            lines.append(f"- {technique}")
            lines += [f"  - {title}" for title in coverage.techniques[technique]]
        lines.append("")
    return "\n".join(lines)


def write_coverage(rules_root: Path = RULES_DIR, out_dir: Path = DIST_DIR) -> Coverage:
    rules, _ = load_rules(rules_root)
    coverage = compute_coverage(rules)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "attack-layer.json").write_text(
        json.dumps(navigator_layer(coverage), indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "coverage.md").write_text(coverage_markdown(coverage), encoding="utf-8")
    return coverage
