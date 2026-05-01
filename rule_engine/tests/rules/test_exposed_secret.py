from __future__ import annotations

from conftest import make_added_diff, make_context, make_file
from rules.exposed_secret import ExposedSecretRule

# A 40-char mixed-case string with Shannon entropy ≥ 4.5
_HIGH_ENTROPY_SECRET = "TSHf6pWkLUyifDLkDmWJ6UuVTAIjvFu7WICPhDeO"


def _rule() -> ExposedSecretRule:
    return ExposedSecretRule()


# --- Fires on known-vulnerable samples ---

def test_fires_on_aws_key():
    diff = make_added_diff(["AWS_KEY = 'AKIAIOSFODNN7EXAMPLEABCD'"])
    ctx = make_context(files=[{"path": "config.py", "language": "python",
                                "old_content": "", "new_content": diff, "diff": diff}])
    findings = _rule().run(ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-001"
    assert "AKIA" in findings[0].evidence["value"]
    assert findings[0].confidence == 0.95


def test_fires_on_github_token():
    # exactly 36 mixed-case alphanumeric chars after ghp_
    token = "ghp_" + "Xy3mPqR7nLwKsJ1dVbZcFo8uEhGtN2aQ9zAB"
    diff = make_added_diff([f"TOKEN = '{token}'"])
    ctx = make_context(files=[{"path": "app.py", "language": "python",
                                "old_content": "", "new_content": diff, "diff": diff}])
    findings = _rule().run(ctx)
    assert len(findings) == 1
    assert findings[0].confidence == 0.95
    assert findings[0].evidence["matched_pattern"] == "GITHUB_TOKEN"


def test_fires_on_high_entropy_assignment():
    diff = make_added_diff([f"secret = '{_HIGH_ENTROPY_SECRET}'"])
    ctx = make_context(files=[{"path": "app.py", "language": "python",
                                "old_content": "", "new_content": diff, "diff": diff}])
    findings = _rule().run(ctx)
    assert len(findings) == 1
    assert findings[0].confidence == 0.75
    assert findings[0].evidence["entropy"] >= 4.5


# --- Does not fire on safe equivalents ---

def test_does_not_fire_on_uuid():
    diff = make_added_diff(["api_key = '550e8400-e29b-41d4-a716-446655440000'"])
    ctx = make_context(files=[{"path": "app.py", "language": "python",
                                "old_content": "", "new_content": diff, "diff": diff}])
    assert _rule().run(ctx) == []


def test_does_not_fire_on_url():
    diff = make_added_diff(["endpoint = 'https://api.example.com/v1/auth'"])
    ctx = make_context(files=[{"path": "app.py", "language": "python",
                                "old_content": "", "new_content": diff, "diff": diff}])
    assert _rule().run(ctx) == []


def test_does_not_fire_on_base64_blob():
    # Base64-encoded string ending with '='
    diff = make_added_diff(["token = 'SGVsbG8gV29ybGQgdGhpcyBpcyBhIHRlc3Q='"])
    ctx = make_context(files=[{"path": "app.py", "language": "python",
                                "old_content": "", "new_content": diff, "diff": diff}])
    assert _rule().run(ctx) == []


def test_does_not_fire_on_hex_hash():
    diff = make_added_diff(["secret = 'a3f5e1b2c4d6e7f8a1b2c3d4e5f6a7b8'"])
    ctx = make_context(files=[{"path": "app.py", "language": "python",
                                "old_content": "", "new_content": diff, "diff": diff}])
    assert _rule().run(ctx) == []


def test_does_not_fire_on_placeholder():
    for placeholder in ["changeme", "your_secret_here", "xxx", "<YOUR_TOKEN>"]:
        diff = make_added_diff([f"secret = '{placeholder}'"])
        ctx = make_context(files=[{"path": "app.py", "language": "python",
                                    "old_content": "", "new_content": diff, "diff": diff}])
        result = _rule().run(ctx)
        assert result == [], f"Expected no finding for placeholder: {placeholder!r}"


def test_does_not_fire_on_env_var_reference():
    diff = make_added_diff(["token = os.environ.get('SECRET_TOKEN')"])
    ctx = make_context(files=[{"path": "app.py", "language": "python",
                                "old_content": "", "new_content": diff, "diff": diff}])
    assert _rule().run(ctx) == []


# --- Evidence redaction ---

def test_secret_is_redacted_in_evidence():
    diff = make_added_diff(["AWS_KEY = 'AKIAIOSFODNN7EXAMPLEABCD'"])
    ctx = make_context(files=[{"path": "config.py", "language": "python",
                                "old_content": "", "new_content": diff, "diff": diff}])
    findings = _rule().run(ctx)
    assert len(findings) == 1
    value = findings[0].evidence["value"]
    assert "AKIAIOSFODNN7EXAMPLEABCD" not in value
    assert "****" in value


# --- Malformed input ---

def test_handles_empty_diff():
    ctx = make_context(files=[{"path": "app.py", "language": "python",
                                "old_content": "", "new_content": "", "diff": ""}])
    assert _rule().run(ctx) == []


def test_handles_empty_context():
    assert _rule().run(make_context()) == []


def test_handles_none_diff():
    # diff=None — should not crash
    file = make_file(diff=None or "")
    from core.context import AnalysisContext
    ctx = AnalysisContext(repo_path="/r", changed_files=[file])
    assert _rule().run(ctx) == []


# --- Isolation ---

def test_runs_in_isolation():
    rule = ExposedSecretRule()
    assert rule.metadata.id == "SEC-001"
    assert rule.metadata.severity == "critical"
    diff = make_added_diff(["AWS_KEY = 'AKIAIOSFODNN7EXAMPLEABCD'"])
    file = make_file(diff=diff, new_content=diff)
    from core.context import AnalysisContext
    ctx = AnalysisContext(repo_path="/r", changed_files=[file])
    findings = rule.run(ctx)
    assert len(findings) == 1
