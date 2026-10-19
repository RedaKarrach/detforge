"""`detforge new`: scaffold a rule file and its fixture files so a new detection
starts with the layout, the required fields and the test contract already in place."""

import json
import re
import uuid
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from detforge.lint import SNAKE_CASE_FILE, TACTICS, TECHNIQUE_TAG
from detforge.loader import FIXTURES_DIR, RULES_DIR

LOGSOURCES = {
    "process_creation": {"product": "windows", "category": "process_creation"},
    "registry_set": {"product": "windows", "category": "registry_set"},
    "process_access": {"product": "windows", "category": "process_access"},
    "image_load": {"product": "windows", "category": "image_load"},
    "network_connection": {"product": "windows", "category": "network_connection"},
    "file_event": {"product": "windows", "category": "file_event"},
    "system": {"product": "windows", "service": "system"},
    "security": {"product": "windows", "service": "security"},
}

_RULE_TEMPLATE = """\
title: {title}
id: {id}
status: experimental
description: |
    What the rule detects and why an attacker does it. Two or three sentences.
references:
    - https://attack.mitre.org/techniques/{technique_url}/
author: {author}
date: {date}
tags:
    - attack.{tactic}
    - attack.{technique}
logsource:
{logsource}
detection:
    selection:
        # FieldName|modifier: value   (Sysmon / Windows Security field names)
        Image|endswith: '\\example.exe'
    condition: selection
falsepositives:
    - Who legitimately trips this, and how to tune it
level: medium
"""


@dataclass(frozen=True)
class Scaffold:
    rule: Path
    tp: Path
    tn: Path
    rule_id: str


def scaffold(
    tactic: str,
    name: str,
    technique: str,
    title: str | None = None,
    logsource: str = "process_creation",
    author: str = "Reda",
    rules_root: Path = RULES_DIR,
    fixtures_root: Path = FIXTURES_DIR,
) -> Scaffold:
    tactic = tactic.lower().replace("_", "-")
    if tactic not in TACTICS:
        raise ValueError(f"'{tactic}' is not an ATT&CK tactic; use one of {sorted(TACTICS)}")
    filename = f"{name}.yml"
    if not SNAKE_CASE_FILE.fullmatch(filename):
        raise ValueError("rule name must be snake_case: letters, digits and single underscores")
    technique = technique.lower().removeprefix("attack.")
    if not TECHNIQUE_TAG.fullmatch(technique):
        raise ValueError("technique must look like t1059 or t1059.001")
    if logsource not in LOGSOURCES:
        raise ValueError(f"unknown logsource '{logsource}'; use one of {sorted(LOGSOURCES)}")

    rule_path = rules_root / "windows" / tactic.replace("-", "_") / filename
    if rule_path.exists():
        raise FileExistsError(f"{rule_path} already exists")
    rule_id = str(uuid.uuid4())
    fixtures = fixtures_root / rule_id

    rule_path.parent.mkdir(parents=True, exist_ok=True)
    rule_path.write_text(
        _RULE_TEMPLATE.format(
            title=title or _title_from_name(name),
            id=rule_id,
            technique_url=technique.upper().replace(".", "/"),
            author=author,
            date=date.today().isoformat(),
            tactic=tactic,
            technique=technique,
            logsource="\n".join(f"    {k}: {v}" for k, v in LOGSOURCES[logsource].items()),
        ),
        encoding="utf-8",
    )
    fixtures.mkdir(parents=True, exist_ok=True)
    tp = fixtures / "tp.jsonl"
    tn = fixtures / "tn.jsonl"
    tp.write_text(_events("TODO attack event that MUST match"), encoding="utf-8")
    tn.write_text(_events("TODO near-miss benign event that must NOT match"), encoding="utf-8")
    return Scaffold(rule_path, tp, tn, rule_id)


def _title_from_name(name: str) -> str:
    return " ".join(word.capitalize() for word in re.split(r"_+", name))


def _events(description: str) -> str:
    lines = [
        json.dumps(
            {"_description": f"{description} #{n}", "EventID": 1, "Image": "", "CommandLine": ""}
        )
        for n in (1, 2)
    ]
    return "\n".join(lines) + "\n"
