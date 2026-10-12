from typer.testing import CliRunner

from detforge.cli import app

runner = CliRunner()


def test_help_lists_all_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("lint", "test", "convert", "coverage", "report"):
        assert command in result.output
