from __future__ import annotations

from app.analysis.classifier.change_classifier import classify_changes
from app.analysis.classifier.risk_score import compute_risk_score
from app.analysis.classifier.security_signal_classifier import classify_security_signals
from app.analysis.models.classification_models import ChangeType, FileClassification
from app.analysis.models.diff_models import ChangedFileInput, ParsedFile
from app.analysis.parser.file_classifier import classify_file
from app.analysis.parser.hunk_parser import parse_hunk

_DEFAULT_MAX_LINES = 5000


def parse_diff(
    changed_file: ChangedFileInput,
    max_lines: int = _DEFAULT_MAX_LINES,
) -> ParsedFile:
    result = ParsedFile(
        file_path=changed_file.filename,
        status=changed_file.status,
        language=changed_file.language,
    )

    patch = changed_file.patch
    if not patch:
        return result

    if patch.startswith("Binary files"):
        return result

    lines = patch.splitlines()
    parsing_truncated = False
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        parsing_truncated = True

    # Split into hunk blocks: each block starts at a line beginning with @@
    hunk_blocks: list[list[str]] = []
    current: list[str] | None = None
    for line in lines:
        if line.startswith("@@"):
            if current is not None:
                hunk_blocks.append(current)
            current = [line]
        elif current is not None:
            current.append(line)

    if current is not None:
        hunk_blocks.append(current)

    for block in hunk_blocks:
        try:
            hunk = parse_hunk("\n".join(block))
            result.hunks.append(hunk)
        except Exception:
            # Truncated or malformed hunk — skip gracefully
            parsing_truncated = True

    # Flatten added/removed lines across all hunks
    result.added_lines = [line for h in result.hunks for line in h.added_lines]
    result.removed_lines = [line for h in result.hunks for line in h.removed_lines]
    result.parsing_truncated = parsing_truncated

    return result


def parse_and_classify(changed_file: ChangedFileInput) -> FileClassification:
    parsed_file = parse_diff(changed_file)
    file_category = classify_file(changed_file.filename)
    change_types = classify_changes(parsed_file, file_category)
    security_signals = classify_security_signals(parsed_file)
    risk = compute_risk_score(file_category, change_types, security_signals)

    is_test_only = (
        ChangeType.TEST_ONLY_CHANGE in change_types
        or file_category.value == "test"
    )

    should_create = not is_test_only and (
        len(security_signals) > 0
        or ChangeType.AUTH_LOGIC_CHANGED in change_types
        or ChangeType.SECRET_REFERENCE in change_types
    )

    return FileClassification(
        file_path=changed_file.filename,
        file_category=file_category,
        is_test_only=is_test_only,
        hunks=parsed_file.hunks,
        added_lines=parsed_file.added_lines,
        removed_lines=parsed_file.removed_lines,
        change_types=change_types,
        security_signals=security_signals,
        risk_score=risk,
        should_create_security_finding=should_create,
        audit_log_only=is_test_only,
        parsing_truncated=parsed_file.parsing_truncated,
    )
