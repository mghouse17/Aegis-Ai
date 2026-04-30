from __future__ import annotations

import re
from pathlib import PurePosixPath

from app.analysis.classifier.change_classifier import classify_changes
from app.analysis.classifier.risk_score import (
    _CI_CD_DANGEROUS_SIGNALS,
    _SECRET_SIGNALS,
    compute_risk_score,
    should_create_finding,
)
from app.analysis.classifier.security_signal_classifier import classify_security_signals
from app.analysis.models.classification_models import ChangeType, FileCategory, FileClassification
from app.analysis.models.diff_models import ChangedFileInput, ParsedFile
from app.analysis.parser.file_classifier import classify_file
from app.analysis.parser.hunk_parser import parse_hunk

_DEFAULT_MAX_LINES = 5000

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
# PR-level diff header detection — compiled once at import
# ---------------------------------------------------------------------------

# Matches a `diff --git a/<path> b/<path>` line EXACTLY (no re.MULTILINE).
# Used with re.match() against individual lines so that patch content which
# happens to contain "diff --git" text is never mistaken for a file header.
_FILE_HEADER_LINE_RE = re.compile(r"^diff --git a/(.+) b/(.+)$")

# Block-level metadata patterns (searched inside a collected block string).
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

    Uses a two-pass line-by-line scan instead of ``re.split`` so that:

    * All text before the first ``diff --git`` header is silently ignored.
    * Lines INSIDE a patch (added/removed/context) that happen to contain
      ``diff --git`` text are never mistaken for file boundaries — because
      those lines are prefixed with ``+``, ``-``, or `` `` and therefore
      cannot match the header pattern.
    * ``re.split`` zero-width-lookahead edge cases on Windows ``\\r\\n``
      line endings or BOMs are completely avoided.

    Known limitation: filenames containing the literal substring `` b/`` will
    not parse correctly — this covers ≥99 % of real-world filenames.
    """
    lines = raw_diff.splitlines()

    # Pass 1 — locate every valid ``diff --git a/… b/…`` header.
    # Strip trailing \r so Windows-style line endings never cause a miss.
    header_positions: list[tuple[int, re.Match]] = []
    for i, line in enumerate(lines):
        m = _FILE_HEADER_LINE_RE.match(line.rstrip("\r"))
        if m:
            header_positions.append((i, m))

    if not header_positions:
        return []

    results: list[FileClassification] = []

    # Pass 2 — each block runs from its header line up to (not including)
    # the next header line.  Joining with "\n" reconstructs a clean block
    # regardless of the original line-ending style.
    for block_idx, (hdr_line_no, hdr_match) in enumerate(header_positions):
        next_hdr_line_no = (
            header_positions[block_idx + 1][0]
            if block_idx + 1 < len(header_positions)
            else len(lines)
        )
        block = "\n".join(lines[hdr_line_no:next_hdr_line_no])

        # Use the b/ side as the canonical post-merge filename.
        # Strip surrounding quotes added by Git for paths with special chars.
        filename = hdr_match.group(2).strip().strip('"')
        if not filename:
            continue

        if _NEW_FILE_RE.search(block):
            status = "added"
        elif _DELETED_FILE_RE.search(block):
            status = "deleted"
        else:
            rename_m = _RENAME_TO_RE.search(block)
            if rename_m:
                filename = rename_m.group(1).strip()
                status = "renamed"
            else:
                status = "modified"

        if _BINARY_RE.search(block):
            patch: str | None = "Binary files"
        else:
            patch_m = _PATCH_START_RE.search(block)
            patch = block[patch_m.start():] if patch_m else None

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

    # Derive SECRET_REFERENCE from signals — single source of truth.
    if set(security_signals) & _SECRET_SIGNALS:
        if ChangeType.SECRET_REFERENCE not in change_types:
            change_types.append(ChangeType.SECRET_REFERENCE)

    is_test_only = (
        ChangeType.TEST_ONLY_CHANGE in change_types
        or file_category == FileCategory.TEST
    )
    is_docs = file_category == FileCategory.DOCS
    is_ci_cd = file_category == FileCategory.CI_CD
    ci_cd_dangerous = is_ci_cd and bool(set(security_signals) & _CI_CD_DANGEROUS_SIGNALS)

    should_create, audit_only = should_create_finding(
        file_category,
        change_types,
        security_signals,
        risk,
        is_test_only=is_test_only,
        is_docs=is_docs,
        is_ci_cd=is_ci_cd,
        ci_cd_dangerous=ci_cd_dangerous,
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
        audit_log_only=audit_only,
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
