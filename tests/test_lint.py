import re
import shutil
from pathlib import Path

from detforge.lint import LintIssue, lint_rules

REPO = Path(__file__).resolve().parents[1]
DATA = REPO / "tests" / "data"
EVENT = '{"EventID": 1, "Image": "C:\\\\Windows\\\\System32\\\\whoami.exe"}\n'


def add_rule(
    root: Path,
    data_file: str,
    tactic: str = "discovery",
    name: str | None = None,
    fixtures: bool = True,
) -> Path:
    """Copy a rule from tests/data into a scratch repo, with two-event fixtures by default."""
    source = DATA / data_file
    target = root / "rules" / "windows" / tactic / (name or data_file)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(source, target)
    if fixtures:
        match = re.search(r"^id: (\S+)", source.read_text(), re.MULTILINE)
        assert match, f"{data_file} has no id"
        fixture_dir = root / "fixtures" / match.group(1)
        fixture_dir.mkdir(parents=True, exist_ok=True)
        for kind in ("tp", "tn"):
            (fixture_dir / f"{kind}.jsonl").write_text(EVENT * 2)
    return target


def lint(root: Path) -> list[LintIssue]:
    return lint_rules(root / "rules", root / "fixtures", offline=True)


def checks(issues: list[LintIssue]) -> set[str]:
    return {issue.check for issue in issues}


def test_repository_rules_lint_clean() -> None:
    assert lint_rules(REPO / "rules", REPO / "tests" / "fixtures", offline=True) == []


def test_valid_rule_has_no_issues(tmp_path: Path) -> None:
    add_rule(tmp_path, "valid_discovery_rule.yml")
    assert lint(tmp_path) == []


def test_missing_required_fields_are_reported(tmp_path: Path) -> None:
    add_rule(tmp_path, "missing_required_fields.yml")
    messages = {i.message for i in lint(tmp_path) if i.check == "required-field"}
    assert messages == {
        "missing or empty field 'description'",
        "missing or empty field 'author'",
        "missing or empty field 'falsepositives'",
        "missing or empty field 'level'",
    }


def test_wrong_author_is_reported(tmp_path: Path) -> None:
    path = add_rule(tmp_path, "valid_discovery_rule.yml")
    path.write_text(path.read_text().replace("author: Reda", "author: Someone Else"))
    assert "author must be 'Reda'" in {i.message for i in lint(tmp_path)}


def test_non_snake_case_filename_is_reported(tmp_path: Path) -> None:
    add_rule(tmp_path, "BadlyNamedRule.yml")
    assert checks(lint(tmp_path)) == {"filename"}


def test_folder_must_match_a_tactic_tag(tmp_path: Path) -> None:
    add_rule(tmp_path, "valid_discovery_rule.yml", tactic="execution")
    issues = lint(tmp_path)
    assert checks(issues) == {"layout"}
    assert "does not match any tactic tag" in issues[0].message


def test_folder_must_be_a_tactic(tmp_path: Path) -> None:
    add_rule(tmp_path, "valid_discovery_rule.yml", tactic="misc")
    assert "'misc' is not an ATT&CK tactic folder" in {i.message for i in lint(tmp_path)}


def test_rule_outside_windows_tactic_folder_is_reported(tmp_path: Path) -> None:
    target = tmp_path / "rules" / "valid_discovery_rule.yml"
    target.parent.mkdir(parents=True)
    shutil.copy(DATA / "valid_discovery_rule.yml", target)
    assert "layout" in checks(lint(tmp_path))


def test_missing_technique_tag_is_reported(tmp_path: Path) -> None:
    add_rule(tmp_path, "missing_technique_tag.yml")
    issues = lint(tmp_path)
    assert checks(issues) == {"tags"}
    assert "technique tag" in issues[0].message


def test_missing_tactic_tag_is_reported(tmp_path: Path) -> None:
    add_rule(tmp_path, "missing_tactic_tag.yml")
    messages = {i.message for i in lint(tmp_path) if i.check == "tags"}
    assert messages == {"needs an ATT&CK tactic tag (attack.<tactic>)"}


def test_invalid_yaml_is_reported_without_hiding_other_rules(tmp_path: Path) -> None:
    add_rule(tmp_path, "invalid_yaml_syntax.yml", fixtures=False)
    add_rule(tmp_path, "missing_technique_tag.yml")
    assert checks(lint(tmp_path)) == {"parse", "tags"}


def test_duplicate_id_and_title_are_reported(tmp_path: Path) -> None:
    add_rule(tmp_path, "valid_discovery_rule.yml")
    add_rule(tmp_path, "valid_discovery_rule.yml", name="valid_discovery_rule_copy.yml")
    found = checks(lint(tmp_path))
    assert {"sigma:IdentifierCollision", "sigma:DuplicateTitle"} <= found


def test_missing_fixtures_are_reported(tmp_path: Path) -> None:
    add_rule(tmp_path, "valid_discovery_rule.yml", fixtures=False)
    issues = lint(tmp_path)
    assert {i.path.name for i in issues if i.check == "fixtures"} == {"tp.jsonl", "tn.jsonl"}


def test_fixture_with_one_event_is_reported(tmp_path: Path) -> None:
    add_rule(tmp_path, "valid_discovery_rule.yml")
    tp = next((tmp_path / "fixtures").glob("*/tp.jsonl"))
    tp.write_text(EVENT)
    assert [i.message for i in lint(tmp_path)] == ["needs at least 2 events, has 1"]


def test_fixture_with_invalid_line_is_reported(tmp_path: Path) -> None:
    add_rule(tmp_path, "valid_discovery_rule.yml")
    tn = next((tmp_path / "fixtures").glob("*/tn.jsonl"))
    tn.write_text(EVENT + '["not", "an", "object"]\n')
    assert [i.message for i in lint(tmp_path)] == ["line 2: expected a JSON object, got list"]
