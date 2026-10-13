"""DetForge command-line interface."""

from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from detforge.convert import BACKENDS, convert_rules
from detforge.harness import run_tests
from detforge.lint import lint_rules
from detforge.loader import RULES_DIR

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
    results = run_tests(rule or RULES_DIR)
    table = Table(title="Rule tests")
    table.add_column("Rule", overflow="fold")
    table.add_column("TP", justify="right")
    table.add_column("TN fp", justify="right")
    table.add_column("Baseline fp", justify="right")
    table.add_column("Result")
    for result in results:
        table.add_row(
            _display(result.path),
            f"{result.tp_matched}/{result.tp_total}",
            str(result.tn_fp),
            str(result.baseline_fp),
            "[green]PASS[/green]" if result.passed else "[red]FAIL[/red]",
        )
    console.print(table)
    failed = [result for result in results if not result.passed]
    for result in failed:
        console.print(f"[red]FAIL[/red] {_display(result.path)}")
        for failure in result.failures:
            console.print(f"  - {failure}", markup=False, highlight=False)
    if failed:
        console.print(f"[red]test: {len(failed)} of {len(results)} rule(s) failed[/red]")
        raise typer.Exit(1)
    console.print(f"[green]test: {len(results)} rule(s) passed[/green]")


@app.command()
def convert(
    target: Annotated[Target, typer.Option(help="Backend to convert rules to.")] = Target.all,
) -> None:
    """Convert rules to Splunk SPL and/or Elastic Lucene queries."""
    targets = list(BACKENDS) if target is Target.all else [target.value]
    results = convert_rules(targets)
    table = Table(title="Conversion")
    table.add_column("Rule", overflow="fold")
    table.add_column("Target")
    table.add_column("Output", overflow="fold")
    for result in results:
        table.add_row(
            _display(result.path),
            result.target,
            _display(result.output) if result.output else f"[red]{result.error}[/red]",
        )
    console.print(table)
    failed = [result for result in results if not result.ok]
    if failed:
        console.print(f"[red]convert: {len(failed)} conversion(s) failed[/red]")
        raise typer.Exit(1)
    console.print(f"[green]convert: {len(results)} file(s) written[/green]")


@app.command()
def coverage() -> None:
    """Build the ATT&CK Navigator layer and coverage summary."""
    _not_implemented("coverage")


@app.command()
def report() -> None:
    """Write the Markdown report of counts, test results and coverage."""
    _not_implemented("report")
