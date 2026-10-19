"""DetForge command-line interface."""

from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from detforge.attack import tactic_name, technique_name
from detforge.config import Settings
from detforge.convert import BACKENDS, convert_rules
from detforge.coverage import write_coverage
from detforge.display import collect, find_rule, matrix, rule_info
from detforge.harness import run_tests
from detforge.lint import lint_rules
from detforge.loader import load_rules
from detforge.report import write_report
from detforge.scaffold import LOGSOURCES, scaffold

app = typer.Typer(
    help="DetForge: lint, test, convert and report on Sigma detection rules.",
    context_settings={"help_option_names": ["-h", "--help"]},
)
console = Console()

RulesOpt = Annotated[
    Path | None, typer.Option("--rules", help="Rules folder (default: rules/).", show_default=False)
]
FixturesOpt = Annotated[
    Path | None,
    typer.Option(
        "--fixtures", help="Fixtures folder (default: tests/fixtures/).", show_default=False
    ),
]
OutOpt = Annotated[
    Path | None, typer.Option("--out", help="Output folder (default: dist/).", show_default=False)
]


class Target(str, Enum):
    splunk = "splunk"
    lucene = "lucene"
    all = "all"


def settings(rules: Path | None = None, fixtures: Path | None = None, out: Path | None = None):
    try:
        base = Settings.load()
    except (ValueError, OSError) as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(2) from exc
    cfg = base.override(rules, fixtures, out)
    if not cfg.rules.exists():
        console.print(f"[red]error:[/red] rules path not found: {cfg.rules}")
        raise typer.Exit(2)
    return cfg


def _display(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd()).as_posix()
    except ValueError:
        return path.as_posix()


@app.command()
def lint(
    rules: RulesOpt = None,
    fixtures: FixturesOpt = None,
    offline: Annotated[
        bool, typer.Option(help="Skip validators that download MITRE data at runtime.")
    ] = False,
) -> None:
    """Validate every rule with pySigma validators and project checks."""
    cfg = settings(rules, fixtures)
    issues = lint_rules(cfg.rules, cfg.fixtures, offline=offline, author=cfg.author)
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
    rules: RulesOpt = None,
    fixtures: FixturesOpt = None,
) -> None:
    """Run each rule against its TP/TN fixtures and the shared baseline."""
    cfg = settings(rule or rules, fixtures)
    results = run_tests(cfg.rules, cfg.fixtures)
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
    rules: RulesOpt = None,
    out: OutOpt = None,
) -> None:
    """Convert rules to Splunk SPL and/or Elastic Lucene queries."""
    cfg = settings(rules, out=out)
    targets = list(BACKENDS) if target is Target.all else [target.value]
    results = convert_rules(targets, cfg.rules, cfg.out)
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
def coverage(rules: RulesOpt = None, out: OutOpt = None) -> None:
    """Build the ATT&CK Navigator layer and coverage summary."""
    cfg = settings(rules, out=out)
    result = write_coverage(cfg.rules, cfg.out)
    console.print(
        f"coverage: {result.rule_count} rule(s), {len(result.techniques)} technique(s), "
        f"{len(result.tactics)} tactic(s) -> {_display(cfg.out / 'attack-layer.json')}, "
        f"{_display(cfg.out / 'coverage.md')}"
    )


@app.command()
def report(rules: RulesOpt = None, fixtures: FixturesOpt = None, out: OutOpt = None) -> None:
    """Write the Markdown report of counts, test results and coverage."""
    cfg = settings(rules, fixtures, out)
    path = write_report(cfg.rules, cfg.fixtures, cfg.out)
    console.print(f"report: written to {_display(path)}")


_LEVEL_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "informational": "dim",
}


def _level(level: str) -> str:
    return f"[{_LEVEL_STYLE.get(level, 'white')}]{level or '-'}[/]"


@app.command(name="list")
def list_rules(
    rules: RulesOpt = None,
    fixtures: FixturesOpt = None,
    tactic: Annotated[str | None, typer.Option(help="Only rules in this tactic folder.")] = None,
) -> None:
    """List every rule: tactic, level, technique and how many test events it carries."""
    cfg = settings(rules, fixtures)
    infos, errors = collect(cfg.rules, cfg.fixtures)
    if tactic:
        infos = [info for info in infos if info.tactic_folder == tactic.replace("-", "_")]
    table = Table(title=f"Rules ({len(infos)})")
    table.add_column("Tactic")
    table.add_column("Rule", overflow="fold")
    table.add_column("Level")
    table.add_column("Technique")
    table.add_column("TP/TN", justify="right")
    for info in infos:
        table.add_row(
            info.tactic_folder,
            info.name,
            _level(info.level),
            ", ".join(info.techniques) or "-",
            f"{info.tp_events}/{info.tn_events}",
        )
    console.print(table)
    for error in errors:
        console.print(f"[red]load error:[/red] {error}")
    if errors:
        raise typer.Exit(1)


@app.command()
def show(
    rule: Annotated[str, typer.Argument(help="Rule file, name, or a unique part of the name.")],
    rules: RulesOpt = None,
    fixtures: FixturesOpt = None,
) -> None:
    """Show one rule in full: metadata, ATT&CK mapping, detection logic and its test events."""
    cfg = settings(rules, fixtures)
    path = find_rule(cfg.rules, rule)
    if path is None:
        console.print(f"[red]error:[/red] no single rule matches {rule!r}")
        raise typer.Exit(2)
    loaded, load_errors = load_rules(path)
    if load_errors or not loaded:
        for error in load_errors:
            console.print(f"[red]error:[/red] {error.message}")
        raise typer.Exit(1)
    info = rule_info(loaded[0], cfg.fixtures)
    console.print(f"[bold]{info.title}[/bold]")
    console.print(f"  {_display(info.path)}")
    console.print(f"  id        {info.id}")
    console.print(f"  status    {info.status}    level {_level(info.level)}")
    console.print(f"  author    {info.author}    date {info.date}")
    console.print(f"  logsource {info.logsource}")
    console.print("  ATT&CK:")
    for tactic in info.tactics:
        console.print(f"    {tactic_name(tactic)}")
    for technique in info.techniques:
        console.print(f"      {technique}  {technique_name(technique)}")
    console.print(
        f"  tests     {info.tp_events} true-positive, {info.tn_events} near-miss event(s)"
    )
    console.print("\n[dim]--- detection ---[/dim]")
    import yaml

    doc = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    detection_yaml = yaml.safe_dump(
        {"detection": doc.get("detection", {})}, sort_keys=False, default_flow_style=False
    )
    for line in detection_yaml.rstrip().splitlines():
        console.print(f"  {line}", markup=False, highlight=False)


@app.command(name="matrix")
def matrix_cmd(rules: RulesOpt = None) -> None:
    """Show ATT&CK coverage as a tactic-by-tactic matrix."""
    cfg = settings(rules)
    rows, coverage = matrix(cfg.rules)
    table = Table(title="ATT&CK coverage")
    table.add_column("Tactic")
    table.add_column("Techniques (rules)", overflow="fold")
    for row in rows:
        if row.covered:
            cells = ", ".join(f"{technique} ({count})" for technique, count in row.techniques)
            table.add_row(f"[green]{tactic_name(row.tactic)}[/green]", cells)
        else:
            table.add_row(f"[dim]{tactic_name(row.tactic)}[/dim]", "[dim]-[/dim]")
    console.print(table)
    console.print(
        f"{coverage.rule_count} rule(s) covering {len(coverage.techniques)} technique(s) "
        f"across {len(coverage.tactics)} tactic(s)."
    )


@app.command()
def new(
    tactic: Annotated[str, typer.Argument(help="ATT&CK tactic, e.g. execution, persistence.")],
    name: Annotated[str, typer.Argument(help="Rule name in snake_case, e.g. rundll32_remote_dll.")],
    technique: Annotated[str, typer.Option(help="ATT&CK technique, e.g. t1059.001.")],
    title: Annotated[
        str | None, typer.Option(help="Rule title (default: derived from the name).")
    ] = None,
    logsource: Annotated[
        str, typer.Option(help=f"Logsource: {', '.join(LOGSOURCES)}.")
    ] = "process_creation",
    rules: RulesOpt = None,
    fixtures: FixturesOpt = None,
) -> None:
    """Scaffold a new rule and its tp/tn fixture files, ready to fill in."""
    # `new` creates the rules folder, so it skips the "rules path must exist" guard.
    try:
        base = Settings.load()
    except (ValueError, OSError) as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(2) from exc
    cfg = base.override(rules, fixtures)
    try:
        created = scaffold(
            tactic,
            name,
            technique,
            title=title,
            logsource=logsource,
            author=cfg.author or "Reda",
            rules_root=cfg.rules,
            fixtures_root=cfg.fixtures,
        )
    except (ValueError, FileExistsError) as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(2) from exc
    console.print("[green]created:[/green]")
    for path in (created.rule, created.tp, created.tn):
        console.print(f"  {_display(path)}")
    console.print(
        f"\nFill in the detection and replace the TODO events, then:\n"
        f"  detforge lint --offline\n  detforge test --rule {_display(created.rule)}"
    )
