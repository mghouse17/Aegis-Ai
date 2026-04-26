from __future__ import annotations

from app.analysis.models.classification_models import ChangeType, FileCategory
from app.analysis.models.diff_models import ParsedFile

_FUNCTION_PREFIXES = (
    "def ",
    "async def ",
    "function ",
    "async function ",
    "class ",
    "func ",
)

_FUNCTION_ARROW_KEYWORDS = ("= (", "=> {", "= async (", "=> (")

_AUTH_KEYWORDS = (
    "auth",
    "jwt",
    "token",
    "session",
    "password",
    "permission",
    "role",
    "admin",
    "oauth",
    "login",
    "logout",
    "bearer",
    "credential",
    "authorize",
    "authenticate",
)

_SECRET_KEYWORDS = (
    "secret",
    "api_key",
    "apikey",
    "apiKey",
    "password",
    "token",
    "private_key",
    "privatekey",
)


def classify_changes(
    parsed_file: ParsedFile,
    file_category: FileCategory,
) -> list[ChangeType]:
    result: list[ChangeType] = []

    added_has_func = _any_line_is_function(parsed_file.added_lines)
    removed_has_func = _any_line_is_function(parsed_file.removed_lines)

    if added_has_func and not removed_has_func:
        result.append(ChangeType.NEW_FUNCTION)
    elif added_has_func and removed_has_func:
        result.append(ChangeType.MODIFIED_FUNCTION)

    if _has_auth_signal(parsed_file, file_category):
        result.append(ChangeType.AUTH_LOGIC_CHANGED)

    if file_category == FileCategory.DEPENDENCY:
        if parsed_file.added_lines:
            result.append(ChangeType.DEPENDENCY_ADDED)
        if parsed_file.removed_lines:
            result.append(ChangeType.DEPENDENCY_REMOVED)

    if file_category == FileCategory.CONFIG:
        result.append(ChangeType.CONFIG_CHANGE)

    if _has_secret_reference(parsed_file.added_lines):
        result.append(ChangeType.SECRET_REFERENCE)

    # test_only_change: file is a test AND no other signal types were detected
    if file_category == FileCategory.TEST and not result:
        result.append(ChangeType.TEST_ONLY_CHANGE)

    if not result:
        result.append(ChangeType.UNKNOWN)

    return result


def _any_line_is_function(lines: list[tuple[int, str]]) -> bool:
    for _ln, content in lines:
        stripped = content.lstrip()
        for prefix in _FUNCTION_PREFIXES:
            if stripped.startswith(prefix):
                return True
        lower = content.lower()
        if any(kw in lower for kw in ("const ", "let ", "var ")):
            if any(arrow in content for arrow in _FUNCTION_ARROW_KEYWORDS):
                return True
    return False


def _has_auth_signal(parsed_file: ParsedFile, file_category: FileCategory) -> bool:
    if file_category == FileCategory.AUTH:
        return True
    all_lines = parsed_file.added_lines + parsed_file.removed_lines
    for _ln, content in all_lines:
        lower = content.lower()
        if any(kw in lower for kw in _AUTH_KEYWORDS):
            return True
    return False


def _has_secret_reference(added_lines: list[tuple[int, str]]) -> bool:
    for _ln, content in added_lines:
        lower = content.lower()
        if any(kw in lower for kw in _SECRET_KEYWORDS):
            # Require an assignment or function call context to reduce noise
            if "=" in content or "(" in content:
                return True
    return False
