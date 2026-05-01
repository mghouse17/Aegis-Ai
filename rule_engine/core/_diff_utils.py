from __future__ import annotations

import re

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def extract_added_lines(diff: str) -> list[tuple[int, str]]:
    """Return (new_line_number, content) for every added line in a unified diff."""
    if not diff:
        return []
    result: list[tuple[int, str]] = []
    new_line = 0
    for raw in diff.splitlines():
        m = _HUNK_RE.match(raw)
        if m:
            new_line = int(m.group(2))
            continue
        if raw.startswith("+++"):
            continue
        if raw.startswith("+"):
            result.append((new_line, raw[1:]))
            new_line += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            pass  # removed line — does not advance new_line
        elif raw.startswith("\\"):
            pass  # "\ No newline at end of file" marker
        else:
            new_line += 1  # context line advances both counters
    return result


def extract_removed_lines(diff: str) -> list[tuple[int, str]]:
    """Return (old_line_number, content) for every removed line in a unified diff."""
    if not diff:
        return []
    result: list[tuple[int, str]] = []
    old_line = 0
    for raw in diff.splitlines():
        m = _HUNK_RE.match(raw)
        if m:
            old_line = int(m.group(1))
            continue
        if raw.startswith("---"):
            continue
        if raw.startswith("-"):
            result.append((old_line, raw[1:]))
            old_line += 1
        elif raw.startswith("+") and not raw.startswith("+++"):
            pass  # added line — does not advance old_line
        elif raw.startswith("\\"):
            pass
        else:
            old_line += 1  # context line
    return result
