import json
from pathlib import Path
from typing import Any

from detforge.harness import RuleResult, match_events, run_tests

REPO = Path(__file__).resolve().parents[1]
RULE_ID = "3f0e6f5c-2b8a-4a51-9a63-6f0b4f2d7c11"
RULE = """title: Harness Test Rule
id: {rule_id}
status: test
description: Rule used by the harness tests.
author: Reda
date: 2026-10-12
tags:
    - attack.discovery
    - attack.t1033
logsource:
    product: windows
    {logsource}
detection:
{detection}
falsepositives:
    - None
level: low
"""


def write_jsonl(path: Path, events: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(event) + "\n" for event in events))


def run(
    tmp_path: Path,
    detection: str,
    tp: list[dict[str, Any]],
    tn: list[dict[str, Any]],
    baseline: list[dict[str, Any]] | None = None,
    logsource: str = "category: process_creation",
) -> RuleResult:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "harness_test_rule.yml").write_text(
        RULE.format(rule_id=RULE_ID, logsource=logsource, detection=detection)
    )
    fixtures = tmp_path / "fixtures"
    write_jsonl(fixtures / RULE_ID / "tp.jsonl", tp)
    write_jsonl(fixtures / RULE_ID / "tn.jsonl", tn)
    write_jsonl(fixtures / "baseline" / "events.jsonl", baseline or [])
    [result] = run_tests(rules, fixtures)
    return result


WHOAMI = """    selection:
        Image|endswith: '\\\\whoami.exe'
    condition: selection"""


def test_repository_rules_pass() -> None:
    results = run_tests(REPO / "rules", REPO / "tests" / "fixtures")
    assert results
    assert [r.failures for r in results if not r.passed] == []


def test_matching_is_case_insensitive(tmp_path: Path) -> None:
    result = run(
        tmp_path,
        WHOAMI,
        tp=[{"Image": "C:\\Windows\\System32\\whoami.exe"}, {"Image": "C:\\WINDOWS\\WHOAMI.EXE"}],
        tn=[{"Image": "C:\\Windows\\System32\\whoami.exe.bak"}, {"Image": "C:\\x\\notwhoami.exe"}],
    )
    assert result.passed, result.failures
    assert (result.tp_matched, result.tp_total, result.tn_fp) == (2, 2, 0)


def test_equality_ignores_case_too(tmp_path: Path) -> None:
    detection = """    selection:
        OriginalFileName: 'whoami.exe'
    condition: selection"""
    result = run(
        tmp_path,
        detection,
        tp=[{"OriginalFileName": "WHOAMI.EXE"}, {"OriginalFileName": "whoami.exe"}],
        tn=[{"OriginalFileName": "whoami.exe2"}, {"OriginalFileName": "hostname.exe"}],
    )
    assert result.passed, result.failures


def test_regex_rules_run_with_registered_regexp(tmp_path: Path) -> None:
    detection = """    selection:
        CommandLine|re: 'whoami\\s+/(priv|groups)'
    condition: selection"""
    result = run(
        tmp_path,
        detection,
        tp=[{"CommandLine": "whoami /priv"}, {"CommandLine": "whoami   /groups"}],
        tn=[{"CommandLine": "whoami"}, {"CommandLine": "whoami /user"}],
    )
    assert result.passed, result.failures


def test_numbers_match_whether_fixtures_use_int_or_string(tmp_path: Path) -> None:
    detection = """    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'
    condition: selection"""
    result = run(
        tmp_path,
        detection,
        tp=[
            {"EventID": 4769, "TicketEncryptionType": "0x17"},
            {"EventID": "4769", "TicketEncryptionType": "0x17"},
        ],
        tn=[
            {"EventID": 4769, "TicketEncryptionType": "0x12"},
            {"EventID": 4768, "TicketEncryptionType": "0x17"},
        ],
        logsource="service: security",
    )
    assert result.passed, result.failures


def test_unmatched_tp_and_matched_tn_fail(tmp_path: Path) -> None:
    result = run(
        tmp_path,
        WHOAMI,
        tp=[{"_description": "missed", "Image": "C:\\x\\hostname.exe"}],
        tn=[{"_description": "false positive", "Image": "C:\\x\\whoami.exe"}],
    )
    assert not result.passed
    assert (result.tp_matched, result.tp_total, result.tn_fp) == (0, 1, 1)
    assert result.failures == ["TP #1 not matched: missed", "TN #1 matched: false positive"]


def test_baseline_only_counts_events_of_the_rules_logsource(tmp_path: Path) -> None:
    hit = {"Image": "C:\\x\\whoami.exe"}
    result = run(
        tmp_path,
        WHOAMI,
        tp=[hit, hit],
        tn=[{"Image": "a.exe"}, {"Image": "b.exe"}],
        baseline=[
            {"_logsource": "process_creation", "_description": "same logsource", **hit},
            {"_logsource": "image_load", "_description": "other logsource", **hit},
        ],
    )
    assert result.baseline_fp == 1
    assert result.failures == ["baseline event matched: same logsource"]


def test_rule_field_missing_from_fixtures_does_not_crash(tmp_path: Path) -> None:
    detection = """    selection_a:
        Image|endswith: '\\\\whoami.exe'
    selection_b:
        OriginalFileName: 'whoami.exe'
    condition: 1 of selection_*"""
    result = run(
        tmp_path,
        detection,
        tp=[{"Image": "C:\\x\\whoami.exe"}, {"Image": "D:\\whoami.exe"}],
        tn=[{"Image": "C:\\x\\a.exe"}, {"Image": "C:\\x\\b.exe"}],
    )
    assert result.passed, result.failures


def test_keyword_rule_is_reported_not_crashed(tmp_path: Path) -> None:
    detection = """    keywords:
        - 'mimikatz'
    condition: keywords"""
    result = run(tmp_path, detection, tp=[{"a": "mimikatz"}], tn=[{"a": "b"}])
    assert not result.passed
    assert "not supported" in result.failures[0]


def test_missing_fixture_file_is_reported(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "harness_test_rule.yml").write_text(
        RULE.format(rule_id=RULE_ID, logsource="category: process_creation", detection=WHOAMI)
    )
    [result] = run_tests(rules, tmp_path / "fixtures")
    assert not result.passed
    assert "tp.jsonl" in result.failures[0]


def test_single_rule_file_can_be_tested(tmp_path: Path) -> None:
    rule = REPO / "rules" / "windows" / "execution" / "powershell_encoded_command.yml"
    [result] = run_tests(rule, REPO / "tests" / "fixtures")
    assert result.passed, result.failures


def test_columns_differing_only_in_case_are_one_column() -> None:
    queries = ["SELECT * FROM logs WHERE Image LIKE '%whoami.exe'"]
    events = [{"image": "c:\\whoami.exe"}, {"Image": "C:\\WHOAMI.EXE"}, {"IMAGE": "x.exe"}]
    assert match_events(queries, {"Image"}, events) == {0, 1}
