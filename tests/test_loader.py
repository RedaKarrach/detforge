from pathlib import Path

import pytest

from detforge.loader import FixtureError, load_rules, read_jsonl

DATA = Path(__file__).resolve().parent / "data"


def test_load_rules_keeps_going_past_broken_yaml(tmp_path: Path) -> None:
    for name in ("invalid_yaml_syntax.yml", "valid_discovery_rule.yml"):
        (tmp_path / name).write_text((DATA / name).read_text())
    rules, errors = load_rules(tmp_path)
    assert [rule.title for rule in rules] == ["Whoami Execution"]
    assert [error.path.name for error in errors] == ["invalid_yaml_syntax.yml"]


def test_load_rules_reports_invalid_id(tmp_path: Path) -> None:
    text = (DATA / "valid_discovery_rule.yml").read_text()
    (tmp_path / "bad_identifier_rule.yml").write_text(
        text.replace("a9596d4d-e475-4e1c-b940-07dfab820096", "not-a-uuid")
    )
    _, errors = load_rules(tmp_path)
    assert len(errors) == 1
    assert "UUID" in errors[0].message


def test_read_jsonl_skips_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text('{"a": 1}\n\n{"b": 2}\n')
    assert read_jsonl(path) == [{"a": 1}, {"b": 2}]


@pytest.mark.parametrize(
    ("line", "message"),
    [
        ("{broken", "line 2: invalid JSON"),
        ("42", "line 2: expected a JSON object, got int"),
    ],
)
def test_read_jsonl_rejects_bad_lines(tmp_path: Path, line: str, message: str) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text('{"ok": true}\n' + line + "\n")
    with pytest.raises(FixtureError, match=message):
        read_jsonl(path)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "expected one rule per file, found 0"),
        ("- just\n- a list\n", "top level of the file must be a YAML mapping"),
    ],
)
def test_load_rules_reports_files_without_one_rule(tmp_path: Path, text: str, message: str) -> None:
    (tmp_path / "not_a_rule_file.yml").write_text(text)
    rules, errors = load_rules(tmp_path)
    assert rules == []
    assert [error.message for error in errors] == [message]


def test_load_rules_reports_two_rules_in_one_file(tmp_path: Path) -> None:
    text = (DATA / "valid_discovery_rule.yml").read_text()
    (tmp_path / "two_rules_in_one_file.yml").write_text(text + "---\n" + text)
    _, errors = load_rules(tmp_path)
    assert [error.message for error in errors] == ["expected one rule per file, found 2"]


def test_read_jsonl_accepts_utf8_bom(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_bytes(b'\xef\xbb\xbf{"a": 1}\n')
    assert read_jsonl(path) == [{"a": 1}]
