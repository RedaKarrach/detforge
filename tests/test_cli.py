from pathlib import Path

import pytest
from typer.testing import CliRunner

from detforge.cli import app

runner = CliRunner()
REPO = Path(__file__).resolve().parents[1]


def test_help_lists_all_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("lint", "test", "convert", "coverage", "report"):
        assert command in result.output


def test_lint_passes_on_repository(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(REPO)
    result = runner.invoke(app, ["lint", "--offline"])
    assert result.exit_code == 0, result.output
    assert "no issues" in result.output


def test_lint_fails_on_broken_rule(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rule = tmp_path / "rules" / "windows" / "discovery" / "missing_technique_tag.yml"
    rule.parent.mkdir(parents=True)
    rule.write_text((REPO / "tests" / "data" / "missing_technique_tag.yml").read_text())
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["lint", "--offline"])
    assert result.exit_code == 1
    assert "issue(s)" in result.output


def test_test_command_passes_on_repository(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(REPO)
    result = runner.invoke(app, ["test"])
    assert result.exit_code == 0, result.output
    assert "PASS" in result.output


def test_test_command_fails_without_fixtures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rule = tmp_path / "rules" / "windows" / "discovery" / "valid_discovery_rule.yml"
    rule.parent.mkdir(parents=True)
    rule.write_text((REPO / "tests" / "data" / "valid_discovery_rule.yml").read_text())
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["test"])
    assert result.exit_code == 1
    assert "FAIL" in result.output
