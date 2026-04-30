import pytest

from app.analysis.models.classification_models import ChangeType, FileCategory
from app.analysis.models.diff_models import ChangedFileInput
from app.analysis.parser.diff_parser import parse_and_classify, parse_diff


def test_none_patch_does_not_crash():
    inp = ChangedFileInput(filename="foo.py", status="modified", patch=None)
    result = parse_and_classify(inp)
    assert result.hunks == []
    assert result.added_lines == []
    assert result.removed_lines == []
    assert result.should_create_security_finding is False
    assert result.parsing_truncated is False


def test_empty_string_patch_does_not_crash():
    inp = ChangedFileInput(filename="foo.py", status="modified", patch="")
    result = parse_and_classify(inp)
    assert result.hunks == []
    assert result.should_create_security_finding is False


def test_binary_file_does_not_crash():
    inp = ChangedFileInput(
        filename="logo.png",
        status="modified",
        patch="Binary files a/logo.png and b/logo.png differ",
    )
    result = parse_and_classify(inp)
    assert result.hunks == []
    assert result.parsing_truncated is False
    assert result.should_create_security_finding is False


def test_large_diff_sets_truncation_flag():
    big_patch = "@@ -1,1 +1,1001 @@\n" + "\n".join(f"+line{i}" for i in range(1001))
    inp = ChangedFileInput(filename="foo.py", status="modified", patch=big_patch)
    parsed = parse_diff(inp, max_lines=100)
    assert parsed.parsing_truncated is True


def test_large_diff_returns_partial_results():
    big_patch = "@@ -1,1 +1,1001 @@\n" + "\n".join(f"+line{i}" for i in range(1001))
    inp = ChangedFileInput(filename="foo.py", status="modified", patch=big_patch)
    parsed = parse_diff(inp, max_lines=100)
    # Partial results should still have hunks and some added lines
    assert len(parsed.added_lines) > 0


def test_large_diff_1000_lines_via_parse_and_classify():
    big_patch = "@@ -1,1 +1,2001 @@\n" + "\n".join(f"+line{i}" for i in range(2001))
    inp = ChangedFileInput(filename="foo.py", status="modified", patch=big_patch)
    result = parse_and_classify(inp)
    # Should not crash and parsing_truncated should reflect the default limit
    assert isinstance(result.parsing_truncated, bool)


def test_file_with_no_signals_does_not_create_finding():
    patch = "@@ -1,1 +1,1 @@\n-x = 1\n+x = 2"
    inp = ChangedFileInput(filename="utils.py", status="modified", patch=patch)
    result = parse_and_classify(inp)
    assert result.should_create_security_finding is False


def test_test_file_with_security_signals_is_audit_only():
    patch = "@@ -1,1 +1,2 @@\n context\n+token = jwt.decode(x)"
    inp = ChangedFileInput(
        filename="tests/test_auth.py",
        status="modified",
        patch=patch,
    )
    result = parse_and_classify(inp)
    assert result.should_create_security_finding is False
    assert result.is_test_only is True
    assert result.audit_log_only is True
    assert result.risk_score == 0
    assert ChangeType.AUTH_LOGIC_CHANGED not in result.change_types


def test_test_file_is_still_included_in_output():
    patch = "@@ -1,1 +1,1 @@\n+assert True"
    inp = ChangedFileInput(filename="tests/test_something.py", status="added", patch=patch)
    result = parse_and_classify(inp)
    assert result.file_path == "tests/test_something.py"
    assert result.file_category == FileCategory.TEST


def test_auth_file_with_token_creates_finding():
    patch = "@@ -1,2 +1,3 @@\n context\n-old\n+const token = verifyToken(req)"
    inp = ChangedFileInput(
        filename="src/middleware/auth.ts",
        status="modified",
        patch=patch,
    )
    result = parse_and_classify(inp)
    assert result.should_create_security_finding is True
    assert result.file_category == FileCategory.AUTH
    assert "token" in result.security_signals


def test_unknown_file_classifies_safely():
    patch = "@@ -1,1 +1,1 @@\n-old line\n+new line"
    inp = ChangedFileInput(filename="some/random/file.xyz", status="modified", patch=patch)
    result = parse_and_classify(inp)
    assert result.file_category == FileCategory.UNKNOWN
    assert result.should_create_security_finding is False
    assert result.risk_score <= 5


def test_readme_change_is_docs_change_and_audit_only():
    patch = "@@ -1,1 +1,1 @@\n-old\n+new documentation"
    inp = ChangedFileInput(filename="README.md", status="modified", patch=patch)
    result = parse_and_classify(inp)
    assert result.file_category == FileCategory.DOCS
    assert ChangeType.DOCS_CHANGE in result.change_types
    assert result.should_create_security_finding is False
    assert result.audit_log_only is True
    assert result.risk_score <= 5


def test_auth_return_true_detects_auth_bypass():
    patch = "@@ -1,2 +1,2 @@\n def login(user):\n+    return True"
    inp = ChangedFileInput(filename="backend/auth.py", status="modified", patch=patch)
    result = parse_and_classify(inp)
    assert "auth_bypass" in result.security_signals


def test_test_only_file_is_audit_only_without_finding():
    patch = "@@ -1,1 +1,1 @@\n+API_KEY = \"ghp_123456789SECRET\""
    inp = ChangedFileInput(filename="tests/test_auth.py", status="modified", patch=patch)
    result = parse_and_classify(inp)
    assert result.audit_log_only is True
    assert result.should_create_security_finding is False
    assert result.risk_score == 0
    assert "github_token" in result.security_signals
    assert result.security_signals


def test_safe_test_only_file_remains_audit_only():
    patch = "@@ -1,1 +1,1 @@\n+assert result == expected"
    inp = ChangedFileInput(filename="tests/test_utils.py", status="modified", patch=patch)
    result = parse_and_classify(inp)
    assert result.audit_log_only is True
    assert result.should_create_security_finding is False
    assert result.risk_score == 0


def test_test_file_with_auth_fixture_strings_is_audit_only_without_auth_logic():
    patch = (
        "@@ -1,1 +1,4 @@\n"
        "+def test_login_session_jwt_fixture():\n"
        "+    token = jwt.decode(session_token)\n"
        "+    assert user.authenticated\n"
        "+    assert session_token"
    )
    inp = ChangedFileInput(filename="backend/app/analysis/tests/test_auth_examples.py", status="modified", patch=patch)
    result = parse_and_classify(inp)
    assert result.is_test_only is True
    assert result.should_create_security_finding is False
    assert result.audit_log_only is True
    assert result.risk_score == 0
    assert ChangeType.AUTH_LOGIC_CHANGED not in result.change_types


def test_test_file_with_fake_login_return_true_is_audit_only():
    patch = "@@ -1,1 +1,3 @@\n+def login(user):\n+    return True\n+assert login(user)"
    inp = ChangedFileInput(filename="tests/test_login.py", status="modified", patch=patch)
    result = parse_and_classify(inp)
    assert result.is_test_only is True
    assert result.should_create_security_finding is False
    assert result.audit_log_only is True
    assert result.risk_score == 0


def test_deleted_file_with_no_added_lines():
    patch = "@@ -1,3 +0,0 @@\n-line1\n-line2\n-line3"
    inp = ChangedFileInput(filename="old_file.py", status="deleted", patch=patch)
    result = parse_and_classify(inp)
    assert result.added_lines == []
    assert result.should_create_security_finding is False


def test_multiple_hunks_are_all_parsed():
    patch = (
        "@@ -1,2 +1,2 @@\n-old1\n+new1\n"
        "@@ -10,2 +10,2 @@\n-old2\n+new2"
    )
    inp = ChangedFileInput(filename="foo.py", status="modified", patch=patch)
    parsed = parse_diff(inp)
    assert len(parsed.hunks) == 2
    assert len(parsed.added_lines) == 2
    assert len(parsed.removed_lines) == 2


def test_secret_reference_derived_from_signals():
    # SECRET_REFERENCE is now derived in parse_and_classify from security_signals,
    # not directly from classify_changes. Verify end-to-end.
    from app.analysis.models.classification_models import ChangeType
    patch = "@@ -1,1 +1,2 @@\n context\n+const apiKey = process.env.MY_SECRET_KEY"
    inp = ChangedFileInput(filename="config.js", status="modified", patch=patch)
    result = parse_and_classify(inp)
    assert ChangeType.SECRET_REFERENCE in result.change_types
    assert result.should_create_security_finding is True


def test_docs_file_is_audit_log_only():
    patch = "@@ -1,1 +1,2 @@\n context\n+Added a new section."
    inp = ChangedFileInput(filename="README.md", status="modified", patch=patch)
    result = parse_and_classify(inp)
    assert result.file_category == FileCategory.DOCS
    assert result.should_create_security_finding is False
    assert result.audit_log_only is True


def test_docs_in_auth_dir_does_not_create_finding():
    patch = "@@ -1,1 +1,2 @@\n context\n+Updated auth flow description."
    inp = ChangedFileInput(filename="docs/auth/overview.md", status="modified", patch=patch)
    result = parse_and_classify(inp)
    assert result.file_category == FileCategory.DOCS
    assert result.should_create_security_finding is False
