from pathlib import Path

import pytest

from detforge.harness import run_tests
from detforge.lint import lint_rules
from detforge.scaffold import scaffold


def test_scaffold_creates_rule_and_fixtures(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    fixtures = tmp_path / "tests" / "fixtures"
    made = scaffold(
        "execution",
        "my_new_rule",
        "t1059.001",
        rules_root=rules,
        fixtures_root=fixtures,
    )
    assert made.rule.exists() and made.tp.exists() and made.tn.exists()
    assert made.rule == rules / "windows" / "execution" / "my_new_rule.yml"
    # the fixture dir is named after the generated rule id
    assert made.tp.parent.name == made.rule_id
    text = made.rule.read_text(encoding="utf-8")
    assert "attack.execution" in text and "attack.t1059.001" in text
    assert made.rule_id in text


def test_scaffold_output_lints_clean_apart_from_todo_fixtures(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    fixtures = tmp_path / "tests" / "fixtures"
    scaffold("persistence", "demo_rule", "t1547.001", rules_root=rules, fixtures_root=fixtures)
    issues = lint_rules(rules, fixtures, offline=True)
    # the scaffold has all required fields, correct folder and two fixture events:
    # a clean lint is the contract for `detforge new`.
    assert issues == [], [str(i) for i in issues]


def test_scaffold_rejects_bad_input(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        scaffold("not-a-tactic", "x", "t1059", rules_root=tmp_path)
    with pytest.raises(ValueError):
        scaffold("execution", "Bad Name", "t1059", rules_root=tmp_path)
    with pytest.raises(ValueError):
        scaffold("execution", "ok_name", "not-a-technique", rules_root=tmp_path)


def test_scaffold_refuses_to_overwrite(tmp_path: Path) -> None:
    scaffold("execution", "dup", "t1059", rules_root=tmp_path / "r", fixtures_root=tmp_path / "f")
    with pytest.raises(FileExistsError):
        scaffold(
            "execution", "dup", "t1059", rules_root=tmp_path / "r", fixtures_root=tmp_path / "f"
        )


def test_scaffolded_rule_is_testable_once_filled(tmp_path: Path) -> None:
    """A scaffold runs through the harness (it will FAIL on the TODO events, but it
    must run, not crash: the plumbing is correct)."""
    rules = tmp_path / "rules"
    fixtures = tmp_path / "tests" / "fixtures"
    scaffold("execution", "runnable", "t1059.001", rules_root=rules, fixtures_root=fixtures)
    results = run_tests(rules, fixtures)
    assert len(results) == 1
