import pytest

from app.analysis.classifier.change_classifier import classify_changes
from app.analysis.models.classification_models import ChangeType, FileCategory
from app.analysis.models.diff_models import ParsedFile


def _make_file(
    added: list[str] | None = None,
    removed: list[str] | None = None,
    file_path: str = "foo.py",
    status: str = "modified",
) -> ParsedFile:
    added_lines = [(i + 1, line) for i, line in enumerate(added or [])]
    removed_lines = [(i + 1, line) for i, line in enumerate(removed or [])]
    return ParsedFile(
        file_path=file_path,
        status=status,
        language=None,
        added_lines=added_lines,
        removed_lines=removed_lines,
    )


def test_new_function_python():
    pf = _make_file(added=["def handle_request(req):"])
    result = classify_changes(pf, FileCategory.API)
    assert ChangeType.NEW_FUNCTION in result


def test_new_function_js():
    pf = _make_file(added=["function processAuth(token) {"])
    result = classify_changes(pf, FileCategory.UNKNOWN)
    assert ChangeType.NEW_FUNCTION in result


def test_new_async_function():
    pf = _make_file(added=["async function fetchUser(id) {"])
    result = classify_changes(pf, FileCategory.API)
    assert ChangeType.NEW_FUNCTION in result


def test_modified_function():
    pf = _make_file(
        added=["def handle_request(req, res):"],
        removed=["def handle_request(req):"],
    )
    result = classify_changes(pf, FileCategory.API)
    assert ChangeType.MODIFIED_FUNCTION in result
    assert ChangeType.NEW_FUNCTION not in result


def test_auth_logic_changed_by_category():
    pf = _make_file(added=["  return true"])
    result = classify_changes(pf, FileCategory.AUTH)
    assert ChangeType.AUTH_LOGIC_CHANGED in result


def test_auth_logic_not_changed_by_keyword_in_non_auth_file():
    pf = _make_file(added=["  validateToken(req.headers.auth)"])
    result = classify_changes(pf, FileCategory.UNKNOWN)
    assert ChangeType.AUTH_LOGIC_CHANGED not in result


def test_auth_logic_not_changed_by_jwt_keyword_in_non_auth_file():
    pf = _make_file(added=["  const decoded = jwt.verify(token, secret)"])
    result = classify_changes(pf, FileCategory.UNKNOWN)
    assert ChangeType.AUTH_LOGIC_CHANGED not in result


def test_dependency_added():
    pf = _make_file(
        file_path="package.json",
        added=['  "express": "^4.18.0"'],
    )
    result = classify_changes(pf, FileCategory.DEPENDENCY)
    assert ChangeType.DEPENDENCY_ADDED in result


def test_dependency_removed():
    pf = _make_file(
        file_path="package.json",
        removed=['  "lodash": "^4.17.21"'],
    )
    result = classify_changes(pf, FileCategory.DEPENDENCY)
    assert ChangeType.DEPENDENCY_REMOVED in result


def test_config_change():
    pf = _make_file(file_path="app.yaml", added=["  debug: false"])
    result = classify_changes(pf, FileCategory.CONFIG)
    assert ChangeType.CONFIG_CHANGE in result


def test_test_only_change():
    pf = _make_file(
        file_path="tests/test_auth.py",
        added=["  assert result == True"],
    )
    result = classify_changes(pf, FileCategory.TEST)
    assert ChangeType.TEST_ONLY_CHANGE in result


def test_test_only_change_not_a_security_finding():
    # test_only_change should not combine with other non-test types
    pf = _make_file(
        file_path="tests/test_foo.py",
        added=["  expect(result).toBe(true)"],
    )
    result = classify_changes(pf, FileCategory.TEST)
    assert ChangeType.TEST_ONLY_CHANGE in result
    assert ChangeType.CONFIG_CHANGE not in result


def test_unknown_fallback():
    pf = _make_file(file_path="README.md", added=["Some text"])
    result = classify_changes(pf, FileCategory.UNKNOWN)
    assert ChangeType.UNKNOWN in result


def test_secret_reference_detected():
    pf = _make_file(added=["const apiKey = process.env.MY_SECRET_KEY"])
    result = classify_changes(pf, FileCategory.UNKNOWN)
    assert ChangeType.SECRET_REFERENCE in result


# ---------------------------------------------------------------------------
# Auth false-positive prevention (issues 6 + 7)
# ---------------------------------------------------------------------------


def test_whitespace_only_auth_change_does_not_trigger_auth_logic_changed():
    pf = _make_file(added=["   ", "  "], file_path="src/auth/login.py")
    result = classify_changes(pf, FileCategory.AUTH)
    assert ChangeType.AUTH_LOGIC_CHANGED not in result


def test_comment_only_auth_change_does_not_trigger_auth_logic_changed():
    pf = _make_file(
        added=["# fix typo in comment", "// another comment"],
        file_path="src/auth/login.py",
    )
    result = classify_changes(pf, FileCategory.AUTH)
    assert ChangeType.AUTH_LOGIC_CHANGED not in result


def test_meaningful_code_in_auth_file_triggers_auth_logic_changed():
    pf = _make_file(added=["    return True"], file_path="src/auth/login.py")
    result = classify_changes(pf, FileCategory.AUTH)
    assert ChangeType.AUTH_LOGIC_CHANGED in result


def test_empty_diff_in_auth_file_does_not_trigger():
    pf = _make_file(added=[], removed=[], file_path="src/auth/login.py")
    result = classify_changes(pf, FileCategory.AUTH)
    assert ChangeType.AUTH_LOGIC_CHANGED not in result
