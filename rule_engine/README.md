# Aegis Rule Engine v1

A deterministic, config-driven security rule engine that runs independently testable rules against PR/diff inputs and returns structured findings. No LLM calls, no network calls, no database required.

---

## What Was Built

A standalone Python package (`rule_engine/`) that implements:

- **Five security rules** loaded from `config/rules.yaml`
- **Structured findings** with per-finding confidence and redacted evidence
- **Engine isolation** — one rule crash never stops the others
- **Local CVE database** at `config/cve_db.yaml` for dependency scanning
- **79 tests** covering positive cases, false-positive guards, malformed input, and isolation

---

## How the Engine Works

```
rules.yaml
    │
    ▼
core/loader.py  ──importlib──▶  rules/*.py
    │
    ▼
core/engine.py
    │  for each rule:
    │    try: rule.run(context) → list[Finding]
    │    except: → RuleExecutionError (with duration_ms)
    ▼
EngineResult(findings, errors)
```

**AnalysisContext** is the input:
- `changed_files: list[ChangedFile]` — each has `diff`, `old_content`, `new_content`
- `dependency_changes: list[DependencyChange]` — each has `package_name`, `version`, `ecosystem`, `is_direct`
- `imports_by_file: dict[str, list[str]]` — maps file paths to imported package names

**Finding** is the output per detection:
- `rule_id`, `severity`, `confidence` (per-finding, not just per-rule)
- `file_path`, `line_number` (None for dependency findings)
- `evidence: dict[str, Any]` — structured; secrets are always redacted

---

## Deployment Note

The `NewCveDependencyRule` (SEC-003) loads the CVE database from disk once at instantiation time. The engine is designed to be **instantiated once and reused across many runs**, not re-created per request. In a web service or daemon, construct the `RuleEngine` at startup and call `.run(context)` for each PR — this keeps the disk-read and `importlib` overhead to a one-time cost.

```python
# At startup
engine = RuleEngine(load_rules(Path("config/rules.yaml")))

# Per PR
result = engine.run(context)
```

---

## How to Run Tests

```bash
cd rule_engine
pip install -r requirements.txt
pytest
```

With coverage:

```bash
pytest --cov=core --cov=rules --cov-report=term-missing
```

The `pythonpath = . tests` in `pytest.ini` adds both `rule_engine/` and `rule_engine/tests/` to sys.path, making all imports resolve correctly without any path manipulation in test files.

---

## How to Add a Rule

1. **Create the rule file** at `rules/my_rule.py`:

```python
from core.rule import Rule
from core.finding import Finding, RuleMetadata
from core.context import AnalysisContext

class MyRule(Rule):
    DEFAULT_METADATA = RuleMetadata(
        id="SEC-006", name="My Rule", version="1.0.0",
        severity="high", confidence=0.8,
        explanation_template="Found {issue} in {file_path} at line {line_number}.",
        enabled=True,
    )

    def __init__(self, metadata=None):
        self._meta = metadata or self.DEFAULT_METADATA

    @property
    def metadata(self):
        return self._meta

    def run(self, context: AnalysisContext) -> list[Finding]:
        findings = []
        # ... detection logic ...
        return findings
```

2. **Add an entry to `config/rules.yaml`**:

```yaml
- id: SEC-006
  name: My Rule
  version: "1.0.0"
  severity: high
  confidence: 0.8
  explanation_template: "Found {issue} in {file_path} at line {line_number}."
  enabled: true
  module: rules.my_rule
  class: MyRule
```

3. **Add tests** at `tests/rules/test_my_rule.py` with at minimum:
   - A positive case (fires on vulnerable input)
   - A false-positive guard (does not fire on safe input)
   - A malformed-input test (does not crash on empty/None)
   - An isolation test (instantiate and run directly)

---

## How to Disable a Rule

Set `enabled: false` in `config/rules.yaml`:

```yaml
- id: SEC-001
  name: Exposed Secret
  enabled: false   # ← disabled; will not run
  ...
```

Disabled rules are skipped at load time by `core/loader.py`.

---

## Rules

| ID | Name | Severity | Confidence | Description |
|----|------|----------|-----------|-------------|
| SEC-001 | Exposed Secret | critical | 0.75–0.95 | AWS keys, GitHub tokens, high-entropy secrets |
| SEC-002 | Hardcoded Credential | high | 0.80–0.90 | Literal strings assigned to password/token/key vars |
| SEC-003 | New CVE Dependency | high | 0.80 | Newly added direct dependency with known CVE |
| SEC-004 | Auth Bypass | critical | 0.85–0.90 | Deleted or commented-out auth checks |
| SEC-005 | Dangerous Sink Reachability | high | 0.70–0.90 | User input proximate to exec/eval/SQL |

---

## Known v1 Limitations

- **SEC-001**: Pure-hex strings and base64 blobs are skipped to reduce false positives; some short credentials may be missed.
- **SEC-003**: Exact version match only. Semver range matching is the first v1.1 task. Only fires when the package appears in `imports_by_file` — transitive dependencies that are not imported in changed files will not fire.
- **SEC-004**: Normalization covers whitespace and quote style; AST-level structural equivalence is deferred to v2. Only detects named decorator/function patterns — custom auth middleware names not in the pattern list are missed.
- **SEC-005**: Proximity-based taint detection only (5-line window + variable bridge). Interprocedural data-flow analysis is deferred to v2. Multi-hop data flows may be missed.
- No network calls — CVE database is a local YAML fixture. Update `config/cve_db.yaml` to add new vulnerabilities.
