from pathlib import Path

from detforge.attack import tactic_name, technique_name
from detforge.coverage import compute_coverage
from detforge.display import collect, find_rule, matrix, matrix_rows
from detforge.loader import load_rules

REPO = Path(__file__).resolve().parents[1]
RULES = REPO / "rules"
FIXTURES = REPO / "tests" / "fixtures"


def test_collect_returns_every_rule_sorted() -> None:
    infos, errors = collect(RULES, FIXTURES)
    assert not errors
    assert len(infos) >= 10
    # sorted by tactic folder then name
    keys = [(info.tactic_folder, info.name) for info in infos]
    assert keys == sorted(keys)
    # each carries its fixture counts
    lsass = next(info for info in infos if info.name == "lsass_memory_access")
    assert lsass.tp_events == 3 and lsass.tn_events == 3
    assert lsass.techniques == ("T1003.001",)
    assert lsass.logsource == "process_access"


def test_find_rule_by_name_and_substring() -> None:
    assert find_rule(RULES, "wevtutil_clear_log") is not None
    assert find_rule(RULES, "fodhelper").name == "uac_bypass_fodhelper.yml"  # unique substring
    assert find_rule(RULES, "encoded_command").name == "powershell_encoded_command.yml"
    assert find_rule(RULES, "does_not_exist") is None
    # "re" is in regsvr32_remote_scriptlet and registry_run_key_persistence: ambiguous -> None
    assert find_rule(RULES, "re") is None


def test_matrix_places_technique_under_folder_tactic() -> None:
    rows, coverage = matrix(RULES)
    by_tactic = {row.tactic: row for row in rows}
    # the fodhelper rule lives in privilege_escalation and must show there
    assert any(t == "T1548.002" for t, _ in by_tactic["privilege-escalation"].techniques)
    assert coverage.rule_count >= 10
    # covered tactics are a subset of the full matrix order and all 14 rows exist
    assert len(rows) == 14


def test_attack_names() -> None:
    assert technique_name("T1059.001").startswith("Command and Scripting")
    assert technique_name("t1003.001") == "OS Credential Dumping: LSASS Memory"
    assert technique_name("T9999") == "T9999"  # unknown falls back to the id
    assert tactic_name("defense-evasion") == "Defense Evasion"


def test_matrix_rows_cover_all_tactics_in_order() -> None:
    rules, _ = load_rules(RULES)
    rows = matrix_rows(compute_coverage(rules))
    assert [row.tactic for row in rows][:2] == ["reconnaissance", "resource-development"]
