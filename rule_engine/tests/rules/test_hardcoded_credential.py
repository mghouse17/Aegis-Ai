from __future__ import annotations

import pytest

from conftest import make_added_diff, make_context, make_file
from rules.hardcoded_credential import HardcodedCredentialRule


def _rule() -> HardcodedCredentialRule:
    return HardcodedCredentialRule()


# --- Fires on known-vulnerable samples ---

def test_fires_on_password_literal():
    diff = make_added_diff(["password = 'supersecret123'"])
    ctx = make_context(files=[{"path": "auth.py", "language": "python",
                                "old_content": "", "new_content": diff, "diff": diff}])
    findings = _rule().run(ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-002"
    assert findings[0].evidence["credential_type"] == "password"
    assert "supersecret123" not in findings[0].evidence["value"]
    assert "****" in findings[0].evidence["value"]
    assert findings[0].confidence == 0.85


def test_fires_on_api_key_literal():
    diff = make_added_diff(["api_key = 'sk-prod-myRealApiKey9999'"])
    ctx = make_context(files=[{"path": "client.py", "language": "python",
                                "old_content": "", "new_content": diff, "diff": diff}])
    findings = _rule().run(ctx)
    assert len(findings) == 1
    assert findings[0].evidence["credential_type"] == "api_key"


def test_fires_on_token_literal():
    diff = make_added_diff(["token = 'bearer-abc123-realtoken-here'"])
    ctx = make_context(files=[{"path": "client.py", "language": "python",
                                "old_content": "", "new_content": diff, "diff": diff}])
    findings = _rule().run(ctx)
    assert len(findings) == 1
    assert findings[0].confidence == 0.80


def test_fires_on_private_key_literal():
    diff = make_added_diff(["private_key = 'rsa-private-key-value-here-12345'"])
    ctx = make_context(files=[{"path": "keys.py", "language": "python",
                                "old_content": "", "new_content": diff, "diff": diff}])
    findings = _rule().run(ctx)
    assert len(findings) == 1
    assert findings[0].confidence == 0.90


@pytest.mark.parametrize(
    ("credential_type", "secret"),
    [
        ("password", "supersecret123"),
        ("api_key", "sk-prod-myRealApiKey9999"),
        ("token", "bearer-abc123-realtoken-here"),
        ("private_key", "rsa-private-key-value-here-12345"),
    ],
)
def test_credential_value_is_fully_redacted(credential_type, secret):
    diff = make_added_diff([f"{credential_type} = '{secret}'"])
    ctx = make_context(files=[{
        "path": "app.py",
        "language": "python",
        "old_content": "",
        "new_content": diff,
        "diff": diff,
    }])

    findings = _rule().run(ctx)

    assert len(findings) == 1
    assert findings[0].evidence["value"] == "****"
    assert secret[:4] not in findings[0].evidence["value"]
    assert secret[-4:] not in findings[0].evidence["value"]


# --- Does not fire on safe equivalents ---

def test_does_not_fire_on_env_var_lookup():
    for line in [
        "password = os.environ.get('DB_PASSWORD')",
        "api_key = os.getenv('API_KEY')",
        "token = os.environ['TOKEN']",
    ]:
        diff = make_added_diff([line])
        ctx = make_context(files=[{"path": "app.py", "language": "python",
                                    "old_content": "", "new_content": diff, "diff": diff}])
        assert _rule().run(ctx) == [], f"Should not fire on: {line!r}"


def test_does_not_fire_on_config_get():
    for line in [
        "password = config.get('password')",
        "api_key = settings.API_KEY",
    ]:
        diff = make_added_diff([line])
        ctx = make_context(files=[{"path": "app.py", "language": "python",
                                    "old_content": "", "new_content": diff, "diff": diff}])
        assert _rule().run(ctx) == [], f"Should not fire on: {line!r}"


def test_does_not_fire_on_empty_string():
    diff = make_added_diff(["password = ''"])
    ctx = make_context(files=[{"path": "app.py", "language": "python",
                                "old_content": "", "new_content": diff, "diff": diff}])
    assert _rule().run(ctx) == []


def test_does_not_fire_on_placeholder_value():
    for placeholder in ["changeme", "example_password", "your_api_key", "xxx"]:
        diff = make_added_diff([f"password = '{placeholder}'"])
        ctx = make_context(files=[{"path": "app.py", "language": "python",
                                    "old_content": "", "new_content": diff, "diff": diff}])
        assert _rule().run(ctx) == [], f"Should not fire on placeholder: {placeholder!r}"


# --- Malformed input ---

def test_handles_empty_diff():
    ctx = make_context(files=[{"path": "app.py", "language": "python",
                                "old_content": "", "new_content": "", "diff": ""}])
    assert _rule().run(ctx) == []


def test_handles_empty_context():
    assert _rule().run(make_context()) == []


# --- Isolation ---

def test_runs_in_isolation():
    rule = HardcodedCredentialRule()
    assert rule.metadata.id == "SEC-002"
    assert rule.metadata.severity == "high"
    diff = make_added_diff(["password = 'myrealpassword'"])
    file = make_file(diff=diff, new_content=diff)
    from core.context import AnalysisContext
    ctx = AnalysisContext(repo_path="/r", changed_files=[file])
    findings = rule.run(ctx)
    assert len(findings) == 1
