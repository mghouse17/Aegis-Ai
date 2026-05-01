"""
End-to-end integration tests.

These tests exercise the full pipeline: load rules from config → build a
realistic AnalysisContext → run the engine → verify findings. They are
intentionally coarse-grained; fine-grained rule behaviour is covered in
tests/rules/.
"""
from __future__ import annotations

from pathlib import Path

from conftest import make_added_diff, make_context, make_dep, make_removed_diff
from core.context import AnalysisContext, ChangedFile, DependencyChange
from core.engine import RuleEngine
from core.loader import load_rules

_CONFIG_PATH = Path(__file__).parent.parent / "config" / "rules.yaml"


def _engine() -> RuleEngine:
    return RuleEngine(load_rules(_CONFIG_PATH))


# ---------------------------------------------------------------------------
# Scenario 1: empty context → silence
# ---------------------------------------------------------------------------

def test_full_engine_on_empty_context():
    """All 5 rules run cleanly on an empty context with no findings or errors."""
    result = _engine().run(make_context())
    assert result.findings == []
    assert result.errors == []


# ---------------------------------------------------------------------------
# Scenario 2: synthetic PR with multiple findings from different rules
# ---------------------------------------------------------------------------

def test_full_engine_finds_issues_from_multiple_rules():
    """
    One AWS key, one hardcoded password, one vulnerable CVE dependency.
    Expect findings from at least SEC-001, SEC-002, and SEC-003.
    """
    aws_diff = make_added_diff(["AWS_SECRET = 'AKIAIOSFODNN7EXAMPLEABCD'"])
    pw_diff = make_added_diff(["password = 'myrealpassword99'"])

    ctx = make_context(
        files=[
            {
                "path": "config.py",
                "old_content": "",
                "new_content": aws_diff,
                "diff": aws_diff,
            },
            {
                "path": "auth.py",
                "old_content": "",
                "new_content": pw_diff,
                "diff": pw_diff,
            },
        ],
        deps=[make_dep("requests", "2.19.0", ecosystem="pip", is_direct=True)],
        imports={"requirements.txt": ["requests"]},
    )

    result = _engine().run(ctx)
    assert result.errors == [], f"Unexpected rule errors: {result.errors}"

    fired_ids = {f.rule_id for f in result.findings}
    assert "SEC-001" in fired_ids, "Expected SEC-001 (Exposed Secret) to fire"
    assert "SEC-002" in fired_ids, "Expected SEC-002 (Hardcoded Credential) to fire"
    assert "SEC-003" in fired_ids, "Expected SEC-003 (CVE Dependency) to fire"


# ---------------------------------------------------------------------------
# Scenario 3: safe code → no findings
# ---------------------------------------------------------------------------

def test_full_engine_safe_code_produces_no_findings():
    """
    Env-var lookups, placeholder passwords, and static exec strings should
    produce zero findings across all rules.
    """
    safe_diff = make_added_diff([
        "password = os.environ.get('DB_PASSWORD')",
        "api_key = config.get('api_key')",
        "token = settings.TOKEN",
        "exec('reload_config()')",
    ])

    ctx = make_context(
        files=[
            {
                "path": "app.py",
                "old_content": "",
                "new_content": safe_diff,
                "diff": safe_diff,
            }
        ]
    )

    result = _engine().run(ctx)
    assert result.errors == []
    assert result.findings == [], (
        f"Expected no findings on safe code, got: "
        f"{[(f.rule_id, f.title) for f in result.findings]}"
    )
