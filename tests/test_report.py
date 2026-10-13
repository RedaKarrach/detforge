from pathlib import Path

import pytest

from detforge.report import build_report, write_report

REPO = Path(__file__).resolve().parents[1]


def test_report_lists_every_rule_with_its_result() -> None:
    report = build_report(REPO / "rules", REPO / "tests" / "fixtures")
    assert "- Rules: 2" in report
    assert "- Tests: 2 passed, 0 failed" in report
    assert "| windows/execution/powershell_encoded_command.yml | 3/3 | 0 | 0 | PASS |" in report
    assert "| lateral-movement | 1 | 1 |" in report
    assert "### Failures" not in report


def test_report_shows_failures(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "valid_discovery_rule.yml").write_text(
        (REPO / "tests" / "data" / "valid_discovery_rule.yml").read_text()
    )
    report = build_report(rules, tmp_path / "fixtures")
    assert "- Tests: 0 passed, 1 failed" in report
    assert "### Failures" in report
    assert "tp.jsonl" in report


def test_write_report_appends_to_github_step_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    summary = tmp_path / "summary.md"
    summary.write_text("existing\n")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    path = write_report(REPO / "rules", REPO / "tests" / "fixtures", tmp_path / "dist")
    assert path.read_text(encoding="utf-8").startswith("# DetForge report")
    assert summary.read_text(encoding="utf-8").startswith("existing\n# DetForge report")
