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

# Prefixes that mark a line as a comment rather than a code change.
# A diff in an auth file with only comment/whitespace lines is not a security event.
_COMMENT_PREFIXES = ("#", "//", "/*", "*", "<!--")


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

    if file_category == FileCategory.CI_CD:
        result.append(ChangeType.CI_CD_CHANGE)

    if file_category == FileCategory.DOCS:
        result.append(ChangeType.DOCS_CHANGE)

    # NOTE: SECRET_REFERENCE is no longer set here.
    # It is derived in parse_and_classify from security_signals so that
    # there is a single source of truth for secret detection.

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
    all_lines = parsed_file.added_lines + parsed_file.removed_lines
    if not all_lines:
        return False

    # Any line in ANY category that contains an auth keyword is a signal.
    for _ln, content in all_lines:
        if any(kw in content.lower() for kw in _AUTH_KEYWORDS):
            return True

    # For AUTH-category files: also flag if there are meaningful (non-whitespace,
    # non-comment) code changes. Whitespace-only or comment-only diffs in auth
    # files are maintenance noise, not security events.
    if file_category == FileCategory.AUTH:
        for _ln, content in all_lines:
            stripped = content.strip()
            if stripped and not any(stripped.startswith(p) for p in _COMMENT_PREFIXES):
                return True

    return False
