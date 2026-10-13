"""Markdown report: rule counts, per-rule test results and coverage by tactic."""

import os
from pathlib import Path

from detforge.convert import DIST_DIR
from detforge.coverage import TACTIC_ORDER, compute_coverage
from detforge.harness import RuleResult, run_tests
from detforge.loader import FIXTURES_DIR, RULES_DIR, load_rules


def build_report(rules_root: Path = RULES_DIR, fixtures_root: Path = FIXTURES_DIR) -> str:
    rules, load_errors = load_rules(rules_root)
    results = run_tests(rules_root, fixtures_root)
    coverage = compute_coverage(rules)
    passed = sum(result.passed for result in results)

    lines = [
        "# DetForge report",
        "",
        f"- Rules: {len(rules)}",
        f"- Rules failing to load: {len(load_errors)}",
        f"- Tests: {passed} passed, {len(results) - passed} failed",
        f"- Techniques covered: {len(coverage.techniques)}",
        f"- Tactics covered: {len(coverage.tactics)}",
        "",
        "## Test results",
        "",
        "| Rule | TP | TN false positives | Baseline false positives | Result |",
        "|------|----|--------------------|--------------------------|--------|",
    ]
    lines += [_result_row(result, rules_root) for result in results]
    failures = [result for result in results if not result.passed]
    if failures:
        lines += ["", "### Failures", ""]
        for result in failures:
            lines.append(f"- {_relative(result.path, rules_root)}")
            lines += [f"  - {failure}" for failure in result.failures]
    lines += [
        "",
        "## Coverage by tactic",
        "",
        "| Tactic | Techniques | Rules |",
        "|--------|------------|-------|",
    ]
    for tactic in TACTIC_ORDER:
        techniques = coverage.tactics.get(tactic, set())
        titles = {title for technique in techniques for title in coverage.techniques[technique]}
        lines.append(f"| {tactic} | {len(techniques)} | {len(titles)} |")
    return "\n".join(lines) + "\n"


def write_report(
    rules_root: Path = RULES_DIR, fixtures_root: Path = FIXTURES_DIR, out_dir: Path = DIST_DIR
) -> Path:
    report = build_report(rules_root, fixtures_root)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "report.md"
    path.write_text(report, encoding="utf-8")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(report)
    return path


def _result_row(result: RuleResult, rules_root: Path) -> str:
    status = "PASS" if result.passed else "FAIL"
    return (
        f"| {_relative(result.path, rules_root)} | {result.tp_matched}/{result.tp_total} "
        f"| {result.tn_fp} | {result.baseline_fp} | {status} |"
    )


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name
