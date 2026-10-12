"""DetForge command-line interface."""

from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

app = typer.Typer(help="DetForge: lint, test, convert and report on Sigma detection rules.")
console = Console()


class Target(str, Enum):
    splunk = "splunk"
    lucene = "lucene"
    all = "all"


def _not_implemented(command: str) -> None:
    console.print(f"[yellow]{command}: not implemented yet[/yellow]")


@app.command()
def lint(
    offline: Annotated[
        bool, typer.Option(help="Skip validators that download MITRE data at runtime.")
    ] = False,
) -> None:
    """Validate every rule with pySigma validators and project checks."""
    _not_implemented("lint")


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
