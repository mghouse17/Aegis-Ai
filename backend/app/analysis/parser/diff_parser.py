from __future__ import annotations

import re
from pathlib import PurePosixPath

from app.analysis.classifier.change_classifier import classify_changes
from app.analysis.classifier.risk_score import compute_risk_score
from app.analysis.classifier.security_signal_classifier import classify_security_signals
from app.analysis.models.classification_models import ChangeType, FileClassification
from app.analysis.models.diff_models import ChangedFileInput, ParsedFile
from app.analysis.parser.file_classifier import classify_file
from app.analysis.parser.hunk_parser import parse_hunk

_DEFAULT_MAX_LINES = 5000

# Findings are created when risk_score reaches this value, even without an
# explicit named signal — covers high-scoring combinations that lack a single
# dominant keyword (e.g. config file + multiple minor signals).
_FINDING_RISK_THRESHOLD = 50

# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

_LANG_MAP: dict[str, str] = {
    ".py": "python",
    ".ts": "typescript", ".tsx": "typescript",
    ".js": "javascript", ".jsx": "javascript",
    ".go": "go",
    ".rb": "ruby",
    ".java": "java",
    ".rs": "rust",
    ".php": "php",
    ".cs": "csharp",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp",
    ".c": "c",
    ".sh": "shell", ".bash": "shell",
    ".yaml": "yaml", ".yml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".sql": "sql",
    ".tf": "terraform",
}


def _detect_language(filename: str) -> str | None:
    return _LANG_MAP.get(PurePosixPath(filename).suffix.lower())


# ---------------------------------------------------------------------------
# PR-level diff splitting — compiled once at import
# ---------------------------------------------------------------------------

# Split the raw diff into one segment per file.  Each segment starts with a
# `diff --git` line; the lookahead keeps that line inside the segment.
_DIFF_FILE_SPLIT_RE = re.compile(r"(?=^diff --git )", re.MULTILINE)

# Extracts `a/<path>` and `b/<path>` from the opening `diff --git` header.
# Greedy backtracking on group(1) means group(2) always captures the shortest
# trailing match — correct for both same-name and rename cases.
_FILE_HEADER_RE = re.compile(r"^diff --git a/(.+) b/(.+)$", re.MULTILINE)

_NEW_FILE_RE = re.compile(r"^new file mode", re.MULTILINE)
_DELETED_FILE_RE = re.compile(r"^deleted file mode", re.MULTILINE)
_RENAME_TO_RE = re.compile(r"^rename to (.+)$", re.MULTILINE)
_BINARY_RE = re.compile(r"^Binary files", re.MULTILINE)
_PATCH_START_RE = re.compile(r"^@@", re.MULTILINE)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_pr_diff(raw_diff: str) -> list[FileClassification]:
    """Parse a full unified GitHub PR diff into per-file classifications.

    Splits on ``diff --git`` boundaries, extracts filename / status / patch
    for each changed file, then delegates to :func:`parse_and_classify`.

    Known limitation: filenames containing the literal substring `` b/`` will
    not parse correctly — this covers ≥99 % of real-world filenames.
    """
    results: list[FileClassification] = []

    for segment in _DIFF_FILE_SPLIT_RE.split(raw_diff):
        segment = segment.strip()
        if not segment:
            continue

        m = _FILE_HEADER_RE.search(segment)
        if not m:
            continue

        # Use the b/ side as the canonical (post-merge) filename.
        # Strip surrounding quotes that Git adds for paths with special chars.
        filename = m.group(2).strip().strip('"')

        if _NEW_FILE_RE.search(segment):
            status = "added"
        elif _DELETED_FILE_RE.search(segment):
            status = "deleted"
        else:
            rename_m = _RENAME_TO_RE.search(segment)
            if rename_m:
                filename = rename_m.group(1).strip()
                status = "renamed"
            else:
                status = "modified"

        # Binary files have no @@ hunks; pass the sentinel so parse_diff can
        # detect and skip them cleanly.
        if _BINARY_RE.search(segment):
            patch: str | None = "Binary files"
        else:
            patch_m = _PATCH_START_RE.search(segment)
            patch = segment[patch_m.start():] if patch_m else None

        results.append(parse_and_classify(ChangedFileInput(
            filename=filename,
            status=status,
            patch=patch,
            language=_detect_language(filename),
        )))

    return results


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

    # A finding is created when ANY of the following is true (all deterministic,
    # no LLM involvement):
    #   1. risk_score reaches the threshold (high-scoring combination)
    #   2. A specific security signal was detected in added lines
    #   3. Auth logic was explicitly changed
    #   4. A secret reference was introduced
    #   5. A new dependency was added (supply-chain risk)
    #   6. A CI/CD pipeline file was modified (pipeline-injection risk)
    should_create = not is_test_only and (
        risk >= _FINDING_RISK_THRESHOLD
        or len(security_signals) > 0
        or ChangeType.AUTH_LOGIC_CHANGED in change_types
        or ChangeType.SECRET_REFERENCE in change_types
        or ChangeType.DEPENDENCY_ADDED in change_types
        or ChangeType.CI_CD_CHANGE in change_types
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


if __name__ == "__main__":
    import json
    import sys
    from pathlib import Path

    if len(sys.argv) < 2:
        print(
            "Usage: python -m app.analysis.parser.diff_parser <diff_file>",
            file=sys.stderr,
        )
        sys.exit(1)

    raw_diff = Path(sys.argv[1]).read_text(encoding="utf-8")
    results = parse_pr_diff(raw_diff)
    print(json.dumps([r.to_dict() for r in results], indent=2))
