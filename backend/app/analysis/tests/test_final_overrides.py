from __future__ import annotations

from app.analysis.models.classification_models import ChangeType, FileCategory
from app.analysis.models.diff_models import ChangedFileInput
from app.analysis.parser.diff_parser import parse_and_classify


def _classify(filename: str, patch: str):
    return parse_and_classify(ChangedFileInput(
        filename=filename,
        status="modified",
        patch=patch,
    ))


def test_test_file_with_github_token_fixture_is_audit_only():
    result = _classify(
        "backend/app/analysis/tests/test_security_signal_classifier.py",
        '@@ -1,1 +1,2 @@\n def test_token():\n+    API_KEY = "ghp_123456789SECRET"',
    )

    assert result.file_category == FileCategory.TEST
    assert result.is_test_only is True
    assert result.should_create_security_finding is False
    assert result.audit_log_only is True
    assert result.risk_score == 0
    assert "github_token" in result.security_signals


def test_test_file_with_auth_fixture_strings_does_not_leak_auth_logic_changed():
    result = _classify(
        "tests/test_login_session.py",
        '@@ -1,1 +1,3 @@\n def test_login():\n+    jwt = "fixture"\n+    session_token = "fake"',
    )

    assert result.file_category == FileCategory.TEST
    assert result.should_create_security_finding is False
    assert result.audit_log_only is True
    assert result.risk_score == 0
    assert ChangeType.AUTH_LOGIC_CHANGED not in result.change_types
    assert ChangeType.AUTH_LOGIC_CHANGED.value not in result.change_confidence


def test_test_file_with_fake_login_return_true_is_audit_only():
    result = _classify(
        "tests/test_auth.py",
        "@@ -1,1 +1,3 @@\n def test_login():\n+    def login(user):\n+        return True",
    )

    assert result.should_create_security_finding is False
    assert result.audit_log_only is True
    assert result.risk_score == 0
    assert "auth_bypass" in result.security_signals


def test_non_test_auth_file_keeps_meaningful_risk_and_auth_change_type():
    result = _classify(
        "backend/auth.py",
        "@@ -1,2 +1,3 @@\n def login(user):\n-    return verify(user)\n+    return True",
    )

    assert result.file_category == FileCategory.AUTH
    assert ChangeType.AUTH_LOGIC_CHANGED in result.change_types
    assert result.should_create_security_finding is True
    assert result.audit_log_only is False
    assert result.risk_score > 5


def test_docs_file_normalizes_to_audit_only_low_risk():
    result = _classify(
        "README.md",
        "@@ -1,1 +1,2 @@\n # Project\n+Updated usage notes",
    )

    assert result.should_create_security_finding is False
    assert result.audit_log_only is True
    assert result.risk_score <= 5


def test_safe_ci_cd_file_normalizes_to_audit_only_low_risk():
    result = _classify(
        ".github/workflows/ci.yml",
        "@@ -1,2 +1,3 @@\n name: CI\n+  run: npm test\n on: [push]",
    )

    assert result.should_create_security_finding is False
    assert result.audit_log_only is True
    assert result.risk_score <= 5


def test_dangerous_ci_cd_file_with_github_token_creates_finding():
    result = _classify(
        ".github/workflows/ci.yml",
        '@@ -1,2 +1,3 @@\n name: CI\n+  token: "ghp_123456789SECRET"\n on: [push]',
    )

    assert result.should_create_security_finding is True
    assert result.audit_log_only is False
    assert "github_token" in result.security_signals
