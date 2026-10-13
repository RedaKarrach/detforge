import json
from pathlib import Path

from sigma.collection import SigmaCollection

from detforge.coverage import (
    compute_coverage,
    coverage_markdown,
    navigator_layer,
    write_coverage,
)

REPO = Path(__file__).resolve().parents[1]


def rule(title: str, tags: list[str]):
    tag_lines = "".join(f"    - {tag}\n" for tag in tags)
    return SigmaCollection.from_yaml(
        f"""title: {title}
logsource: {{category: process_creation, product: windows}}
tags:
{tag_lines}detection:
    sel:
        Image: x
    condition: sel
"""
    ).rules[0]


def test_techniques_map_to_rule_titles_and_tactics() -> None:
    rules = [
        rule("B rule", ["attack.execution", "attack.t1059.001"]),
        rule(
            "A rule",
            ["attack.execution", "attack.t1059.001", "attack.persistence", "attack.t1053.005"],
        ),
        rule("No tags", ["cve.2024.1234"]),
    ]
    coverage = compute_coverage(rules)
    assert coverage.techniques == {
        "T1059.001": ["A rule", "B rule"],
        "T1053.005": ["A rule"],
    }
    assert coverage.tactics == {
        "execution": {"T1059.001"},
        "persistence": {"T1053.005"},
    }
    assert coverage.rule_count == 2


def test_technique_belongs_to_the_tactic_tag_listed_above_it() -> None:
    ordered = rule(
        "PsExec",
        ["attack.lateral-movement", "attack.t1021.002", "attack.execution", "attack.t1569.002"],
    )
    assert compute_coverage([ordered]).tactics == {
        "lateral-movement": {"T1021.002"},
        "execution": {"T1569.002"},
    }
    technique_first = rule("Tech first", ["attack.t1059.001", "attack.execution"])
    assert compute_coverage([technique_first]).tactics == {"execution": {"T1059.001"}}
    no_tactic = rule("No tactic", ["attack.t1059.001"])
    assert compute_coverage([no_tactic]).tactics == {}
    assert compute_coverage([no_tactic]).techniques == {"T1059.001": ["No tactic"]}


def test_navigator_layer_shape() -> None:
    coverage = compute_coverage(
        [
            rule("One", ["attack.execution", "attack.t1059.001"]),
            rule("Two", ["attack.execution", "attack.t1059.001"]),
            rule("Three", ["attack.impact", "attack.t1490"]),
        ]
    )
    layer = navigator_layer(coverage)
    assert layer["versions"]["layer"] == "4.5"
    assert layer["domain"] == "enterprise-attack"
    assert layer["techniques"] == [
        {"techniqueID": "T1059.001", "score": 2, "comment": "One\nTwo", "enabled": True},
        {"techniqueID": "T1490", "score": 1, "comment": "Three", "enabled": True},
    ]
    assert layer["gradient"]["maxValue"] == 2


def test_markdown_groups_by_tactic_in_matrix_order() -> None:
    coverage = compute_coverage(
        [
            rule("Wipe", ["attack.impact", "attack.t1490"]),
            rule("Shell", ["attack.execution", "attack.t1059.001"]),
        ]
    )
    text = coverage_markdown(coverage)
    assert text.index("## execution") < text.index("## impact")
    assert "- T1059.001\n  - Shell" in text


def test_write_coverage_for_repository(tmp_path: Path) -> None:
    coverage = write_coverage(REPO / "rules", tmp_path)
    layer = json.loads((tmp_path / "attack-layer.json").read_text(encoding="utf-8"))
    assert {t["techniqueID"] for t in layer["techniques"]} == set(coverage.techniques)
    assert "T1021.002" in coverage.techniques
    assert (tmp_path / "coverage.md").read_text(encoding="utf-8").startswith("# ATT&CK coverage")
