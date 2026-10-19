# DetForge: project spec for Claude Code

DetForge is a Detection-as-Code pipeline by Reda: Windows Sigma rules mapped to MITRE ATT&CK, each
unit-tested against attack (TP) and benign (TN) events, converted to Splunk SPL and Elastic Lucene,
with an ATT&CK Navigator coverage layer, all run by GitHub Actions on every push.
pySigma does parsing and conversion; DetForge's own code does linting, testing, reporting and automation.

## Ground rules
- Never run `git push`. Reda pushes.
- Commits use Reda's git identity. Never add Co-Authored-By, Claude-Session, "Generated with Claude Code"
  or session-link lines to commit messages or PR text.
- Run ruff and pytest and show the output before every commit. Conventional commits (feat, fix, test, docs, ci, chore).
- Never weaken a test, mark it skip, or silence a CI step to get green. Fix the cause and explain it.
- Reda must be able to defend every rule: whenever you write or change a rule, state its logic,
  one false positive and one evasion in your reply.
- Keep it simple: small modules, type hints, no dependencies beyond the list below.
- Before any session that creates many files, show a plan and wait for approval.

## Stack (pin to these major versions)
- Python >= 3.11 (CI uses 3.12)
- pySigma >=1.5,<2
- pySigma-backend-sqlite >=2,<3
- pySigma-backend-splunk >=2,<3
- pySigma-backend-elasticsearch >=2,<3
- pySigma-pipeline-sysmon >=2,<3
- pySigma-pipeline-windows >=2,<3
- typer >=0.12, rich >=13
- [dev] extra: pytest >=8, ruff >=0.6
- Build: hatchling, src layout, console script `detforge = "detforge.cli:app"`

## Layout
- rules/windows/<tactic>/<rule_name>.yml : one rule per file, rule_name is snake_case
- tests/fixtures/<rule-id>/tp.jsonl : events the rule MUST match (at least 2)
- tests/fixtures/<rule-id>/tn.jsonl : near-miss benign events it must NOT match (at least 2)
- tests/fixtures/baseline/*.jsonl : shared benign events no rule may match
- tests/data/ : deliberately broken rules used by the linter's own tests
- src/detforge/ : cli.py, loader.py, lint.py, harness.py, convert.py, coverage.py, report.py,
  display.py (list/show/matrix views), scaffold.py (the `new` command), attack.py (ATT&CK names)
- docs/RULES.md : one row per rule: technique, logic, false positives, evasions
- dist/ : generated output, git-ignored, uploaded as CI artifact

## Rule conventions
- Required fields: title, id (UUID4), status, description, author: Reda, date, logsource, detection,
  falsepositives, level, tags.
- Tags: at least one technique tag (attack.t1059.001) and one tactic tag (attack.execution).
- Fixture events are flat JSON objects, one per line, using Sysmon / Windows Security field names
  (Image, OriginalFileName, CommandLine, ParentImage, User, SourceImage, TargetImage, GrantedAccess,
  TargetObject, Details, EventID, ServiceName, TicketEncryptionType, ...). Keys starting with `_` are metadata.

## Commands
- `detforge lint [--offline]`: load every rule with SigmaCollection, run all pySigma core validators
  (sigma.validators.core.validators), then project checks: unique id and title, snake_case filename inside
  its tactic folder, required fields, technique + tactic tag, fixture dir with non-empty tp.jsonl and tn.jsonl,
  every line a valid JSON object. `--offline` excludes the `d3_fendtag` validator (downloads MITRE data,
  crashes without network). The `attacktag` validator is ALWAYS skipped (BROKEN_VALIDATORS): pySigma 1.5.x
  ships an incomplete ATT&CK table (TA0005 slugged "stealth", no T1070.001) that fails valid, current tags;
  tag_issues + the folder/tactic check validate tagging instead. Rich table output, exit 1 on any error.
- `detforge test [--rule PATH]`: see "How the rule tests work".
- `detforge convert --target splunk|lucene|all`: Splunk = SplunkBackend(sysmon_pipeline() + windows_logsource_pipeline());
  Lucene = LuceneBackend(ecs_windows()) with ecs_windows from sigma.pipelines.elasticsearch.windows.
  Writes dist/<target>/<rule_name>.txt.
- `detforge coverage`: dist/attack-layer.json (ATT&CK Navigator layer, layer version 4.5, domain enterprise-attack,
  one entry per covered technique, score = number of rules, comment = rule titles) and dist/coverage.md
  (tactic -> technique -> rules).
- `detforge report`: dist/report.md with counts, per-rule test results and coverage by tactic;
  in CI also appended to $GITHUB_STEP_SUMMARY.
- `detforge list [--tactic T]`: read-only table of every rule (tactic, level, technique, tp/tn counts).
- `detforge show <rule>`: one rule by path, file stem, or a unique substring of the stem; prints
  metadata, ATT&CK names (from attack.py), test-event counts and the detection block from the YAML.
- `detforge matrix`: ATT&CK coverage as a tactic-by-tactic table, covered tactics in order.
- `detforge new <tactic> <name> --technique tNNNN [--title T] [--logsource L]`: scaffold.py writes
  rules/windows/<tactic>/<name>.yml plus tests/fixtures/<new-id>/{tp,tn}.jsonl; the scaffold lints clean.
  Does not require the rules folder to exist yet.

## How the rule tests work
1. Convert the rule with sigma.backends.sqlite.sqliteBackend(). The output is a full
   `SELECT * FROM logs WHERE ...` query; run it as is.
2. Create an in-memory SQLite table `logs`: an INTEGER `_idx` column plus one `TEXT COLLATE NOCASE` column for
   every field in the rule and every non-metadata key in the fixtures. NOCASE is required: Sigma matches
   case-insensitively and SQLite `=` does not.
3. Before running queries, register REGEXP: conn.create_function("REGEXP", 2, fn, deterministic=True), with
   fn(pattern, value) = value is not None and re.search(pattern, value) is not None. Without it any rule
   using |re crashes with "no such function: REGEXP".
4. Insert the events, run the query, collect the matched `_idx` values.
5. TP: every tp.jsonl event must match. TN: no tn.jsonl event may match. Baseline: no baseline event may match;
   only test baseline events whose `_logsource` equals the rule's logsource category (or its service when it
   has no category).
6. Print a Rich table: rule | TP x/y | TN fp | baseline fp | PASS/FAIL, then list each failing event.
   Exit 1 on any FAIL.
- Limitations to state in the README: synthetic fixtures, single-event logic only, SQLite does not test the
  Splunk/Elastic field mappings.

## Verified in a sandbox (2026-10-12)
pySigma 1.5.1, sqlite backend 2.0.0, splunk 2.1.0, elasticsearch 2.1.1, sysmon pipeline 2.0.0, windows pipeline 2.0.1.
- PowerShell rule using `CommandLine|windash|contains` with ' -e ', ' -ec ', ' -en ', ' -enc ' and every longer
  prefix of -EncodedCommand followed by a space: 3/3 TP, 0/4 near-miss TN (incl. `-Encoding UTF8`, `-ExecutionPolicy`).
  A bare ' -enco' substring would match `-Encoding`.
- The sqlite backend emits REGEXP for |re; plain sqlite3 has no REGEXP function until registered.
