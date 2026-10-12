"""DetForge command-line interface."""

from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from detforge.lint import lint_rules

app = typer.Typer(help="DetForge: lint, test, convert and report on Sigma detection rules.")
console = Console()


class Target(str, Enum):
    splunk = "splunk"
    lucene = "lucene"
    all = "all"


def _display(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd()).as_posix()
    except ValueError:
        return path.as_posix()


def _not_implemented(command: str) -> None:
    console.print(f"[yellow]{command}: not implemented yet[/yellow]")


@app.command()
def lint(
    offline: Annotated[
        bool, typer.Option(help="Skip validators that download MITRE data at runtime.")
    ] = False,
) -> None:
    """Validate every rule with pySigma validators and project checks."""
    issues = lint_rules(offline=offline)
    if not issues:
        console.print("[green]lint: no issues[/green]")
        return
    table = Table(title="Lint issues")
    table.add_column("File", overflow="fold")
    table.add_column("Check")
    table.add_column("Message", overflow="fold")
    for issue in issues:
        table.add_row(_display(issue.path), issue.check, issue.message)
    console.print(table)
    console.print(f"[red]lint: {len(issues)} issue(s)[/red]")
    raise typer.Exit(1)


@app.command()
def test(
    rule: Annotated[
        Path | None, typer.Option(help="Test a single rule file instead of all rules.")
    ] = None,
) -> None:
    """Run each rule against its TP/TN fixtures and the shared baseline."""
    _not_implemented("test")


@app.command()
def convert(
    target: Annotated[Target, typer.Option(help="Backend to convert rules to.")] = Target.all,
) -> None:
    """Convert rules to Splunk SPL and/or Elastic Lucene queries."""
    _not_implemented("convert")


@app.command()
def coverage() -> None:
    """Build the ATT&CK Navigator layer and coverage summary."""
    _not_implemented("coverage")


@app.command()
def report() -> None:
    """Write the Markdown report of counts, test results and coverage."""
    _not_implemented("report")
