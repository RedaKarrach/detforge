from pathlib import Path

from detforge.convert import convert_rules

REPO = Path(__file__).resolve().parents[1]
DATA = REPO / "tests" / "data"


def test_repository_rules_convert_to_both_targets(tmp_path: Path) -> None:
    results = convert_rules(["splunk", "lucene"], REPO / "rules", tmp_path)
    assert results and all(result.ok for result in results), [r.error for r in results]
    for result in results:
        assert result.output is not None
        assert result.output.parent == tmp_path / result.target
        assert result.output.read_text(encoding="utf-8").strip()


def test_splunk_output_uses_sysmon_and_windows_pipelines(tmp_path: Path) -> None:
    convert_rules(["splunk"], REPO / "rules", tmp_path)
    spl = (tmp_path / "splunk" / "powershell_encoded_command.txt").read_text(encoding="utf-8")
    assert 'Channel="Microsoft-Windows-Sysmon/Operational"' in spl
    assert "EventID=1" in spl


def test_lucene_output_uses_ecs_field_names(tmp_path: Path) -> None:
    convert_rules(["lucene"], REPO / "rules", tmp_path)
    lucene = (tmp_path / "lucene" / "powershell_encoded_command.txt").read_text(encoding="utf-8")
    assert "process.command_line:" in lucene
    assert "process.executable" in lucene


def test_each_target_sees_the_original_rule(tmp_path: Path) -> None:
    convert_rules(["lucene"], REPO / "rules", tmp_path / "alone")
    convert_rules(["splunk", "lucene"], REPO / "rules", tmp_path / "both")
    for alone in (tmp_path / "alone" / "lucene").glob("*.txt"):
        both = tmp_path / "both" / "lucene" / alone.name
        assert both.read_text(encoding="utf-8") == alone.read_text(encoding="utf-8")


def test_unsupported_rule_is_reported_and_others_still_convert(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "valid_discovery_rule.yml").write_text((DATA / "valid_discovery_rule.yml").read_text())
    (rules / "invalid_yaml_syntax.yml").write_text((DATA / "invalid_yaml_syntax.yml").read_text())
    results = convert_rules(["splunk"], rules, tmp_path / "dist")
    by_name = {result.path.name: result for result in results}
    assert by_name["valid_discovery_rule.yml"].ok
    assert not by_name["invalid_yaml_syntax.yml"].ok
    assert "cannot load rule" in by_name["invalid_yaml_syntax.yml"].error
