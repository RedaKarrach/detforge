from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from detforge import cli
from detforge.cli import app

runner = CliRunner()
REPO = Path(__file__).resolve().parents[1]

# Under pytest the console falls back to an 80-column width and truncates table
# cells; widen it so assertions can match full rule names.
cli.console = Console(width=200)


def test_help_lists_all_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in (
        "lint",
        "test",
        "convert",
        "coverage",
        "report",
        "list",
        "show",
        "matrix",
        "new",
    ):
        assert command in result.output


def test_list_shows_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(REPO)
    result = runner.invoke(app, ["list"])
    assert result.exit_code == 0, result.output
    assert "lsass_memory_access" in result.output
    assert "credential_access" in result.output


def test_show_renders_one_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(REPO)
    result = runner.invoke(app, ["show", "fodhelper"])
    assert result.exit_code == 0, result.output
    assert "T1548.002" in result.output
    assert "detection" in result.output


def test_show_rejects_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(REPO)
    result = runner.invoke(app, ["show", "nonexistent_rule_xyz"])
    assert result.exit_code == 2


def test_matrix_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(REPO)
    result = runner.invoke(app, ["matrix"])
    assert result.exit_code == 0, result.output
    assert "Credential Access" in result.output


def test_new_scaffolds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["new", "execution", "cli_made_rule", "--technique", "t1059.001"])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "rules" / "windows" / "execution" / "cli_made_rule.yml").exists()


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
