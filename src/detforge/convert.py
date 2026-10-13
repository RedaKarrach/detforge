"""Convert rules to Splunk SPL and Elastic Lucene queries."""

import copy
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from sigma.backends.elasticsearch import LuceneBackend
from sigma.backends.splunk import SplunkBackend
from sigma.conversion.base import Backend
from sigma.exceptions import SigmaError
from sigma.pipelines.elasticsearch.windows import ecs_windows
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_logsource_pipeline
from sigma.rule import SigmaRule

from detforge.loader import RULES_DIR, load_rules, rule_path

DIST_DIR = Path("dist")

BACKENDS: dict[str, Callable[[], Backend]] = {
    "splunk": lambda: SplunkBackend(sysmon_pipeline() + windows_logsource_pipeline()),
    "lucene": lambda: LuceneBackend(ecs_windows()),
}


@dataclass(frozen=True)
class ConvertResult:
    path: Path
    target: str
    output: Path | None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def convert_rules(
    targets: list[str], rules_root: Path = RULES_DIR, out_dir: Path = DIST_DIR
) -> list[ConvertResult]:
    rules, load_errors = load_rules(rules_root)
    results = [
        ConvertResult(error.path, target, None, f"cannot load rule: {error.message}")
        for error in load_errors
        for target in targets
    ]
    for target in targets:
        backend = BACKENDS[target]()  # one backend per target, reused for every rule
        target_dir = out_dir / target
        target_dir.mkdir(parents=True, exist_ok=True)
        results += [convert_rule(backend, target, rule, target_dir) for rule in rules]
    return results


def convert_rule(backend: Backend, target: str, rule: SigmaRule, target_dir: Path) -> ConvertResult:
    path = rule_path(rule)
    try:
        # Processing pipelines rewrite the rule in place; convert a copy so the
        # next target does not see the previous target's field names and conditions.
        queries = backend.convert_rule(copy.deepcopy(rule))
    except SigmaError as exc:
        return ConvertResult(path, target, None, f"{type(exc).__name__}: {exc}")
    output = target_dir / f"{path.stem}.txt"
    output.write_text("\n".join(queries) + "\n", encoding="utf-8")
    return ConvertResult(path, target, output)
