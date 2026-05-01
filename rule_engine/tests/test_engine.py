from __future__ import annotations

from pathlib import Path

from conftest import make_context
from core.engine import RuleEngine
from core.finding import EngineResult, Finding, RuleExecutionError, RuleMetadata
from core.loader import _rules_from_config, load_rules
from core.rule import Rule

_CONFIG_PATH = Path(__file__).parent.parent / "config" / "rules.yaml"


# --- Helper rule classes ---

class _GoodRule(Rule):
    def __init__(self):
        self._meta = RuleMetadata(
            id="GOOD-001", name="Good Rule", version="1.0.0",
            severity="info", confidence=1.0, explanation_template="", enabled=True,
        )

    @property
    def metadata(self) -> RuleMetadata:
        return self._meta

    def run(self, context):
        return []


class _FindingRule(Rule):
    """Returns one dummy Finding."""
    def __init__(self):
        self._meta = RuleMetadata(
            id="FIND-001", name="Finding Rule", version="1.0.0",
            severity="high", confidence=0.9, explanation_template="", enabled=True,
        )

    @property
    def metadata(self) -> RuleMetadata:
        return self._meta

    def run(self, context):
        return [Finding(
            rule_id="FIND-001", rule_name="Finding Rule", version="1.0.0",
            severity="high", confidence=0.9, file_path="x.py", line_number=1,
            title="Test", explanation="Test", evidence={},
        )]


class _CrashingRule(Rule):
    def __init__(self):
        self._meta = RuleMetadata(
            id="CRASH-001", name="Crashing Rule", version="1.0.0",
            severity="info", confidence=1.0, explanation_template="", enabled=True,
        )

    @property
    def metadata(self) -> RuleMetadata:
        return self._meta

    def run(self, context):
        raise RuntimeError("intentional crash for testing")


class _BadOutputRule(Rule):
    """Returns junk instead of Finding objects."""
    def __init__(self):
        self._meta = RuleMetadata(
            id="BAD-001", name="Bad Output Rule", version="1.0.0",
            severity="info", confidence=1.0, explanation_template="", enabled=True,
        )

    @property
    def metadata(self) -> RuleMetadata:
        return self._meta

    def run(self, context):
        return [None, "bad string", 42]


# --- Engine tests ---

def test_loads_rules_from_config():
    rules = load_rules(_CONFIG_PATH)
    assert len(rules) == 5
    assert all(isinstance(r, Rule) for r in rules)


def test_skips_disabled_rules():
    config = {
        "rules": [
            {
                "id": "X-001", "name": "Disabled", "version": "1.0.0",
                "severity": "info", "confidence": 0.5, "explanation_template": "",
                "enabled": False, "module": "rules.exposed_secret", "class": "ExposedSecretRule",
            }
        ]
    }
    rules = list(_rules_from_config(config))
    assert rules == []


def test_continues_if_one_rule_throws():
    engine = RuleEngine([_CrashingRule(), _FindingRule()])
    result = engine.run(make_context())
    assert len(result.errors) == 1
    assert result.errors[0].rule_id == "CRASH-001"
    assert result.errors[0].error_type == "RuntimeError"
    assert len(result.findings) == 1


def test_returns_findings_and_errors_separately():
    engine = RuleEngine([_FindingRule(), _CrashingRule()])
    result = engine.run(make_context())
    assert isinstance(result, EngineResult)
    assert isinstance(result.findings, list)
    assert isinstance(result.errors, list)
    assert all(isinstance(f, Finding) for f in result.findings)
    assert all(isinstance(e, RuleExecutionError) for e in result.errors)


def test_handles_empty_context():
    rules = load_rules(_CONFIG_PATH)
    engine = RuleEngine(rules)
    result = engine.run(make_context())
    assert result.findings == []
    assert result.errors == []


def test_handles_malformed_context():
    # AnalysisContext with no files/deps — should not raise
    from core.context import AnalysisContext
    ctx = AnalysisContext(repo_path="")
    engine = RuleEngine([_GoodRule()])
    result = engine.run(ctx)
    assert result.findings == []
    assert result.errors == []


def test_error_includes_duration_ms():
    engine = RuleEngine([_CrashingRule()])
    result = engine.run(make_context())
    assert len(result.errors) == 1
    assert isinstance(result.errors[0].duration_ms, float)
    assert result.errors[0].duration_ms >= 0.0


def test_rejects_non_finding_rule_output():
    engine = RuleEngine([_BadOutputRule()])
    result = engine.run(make_context())
    # None/"bad string"/42 all rejected; no findings, no errors
    assert result.findings == []
    assert result.errors == []
