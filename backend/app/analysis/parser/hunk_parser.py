from __future__ import annotations

import re

from app.analysis.models.diff_models import Hunk

_HUNK_HEADER_RE = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)"
)


def parse_hunk(hunk_text: str) -> Hunk:
    lines = hunk_text.splitlines()
    if not lines:
        return Hunk(header="", old_start=0, old_count=0, new_start=0, new_count=0)

    m = _HUNK_HEADER_RE.match(lines[0])
    if not m:
        return Hunk(header=lines[0], old_start=0, old_count=0, new_start=0, new_count=0)

    old_start = int(m.group(1))
    old_count = int(m.group(2)) if m.group(2) is not None else 1
    new_start = int(m.group(3))
    new_count = int(m.group(4)) if m.group(4) is not None else 1
    header = lines[0]

    hunk = Hunk(
        header=header,
        old_start=old_start,
        old_count=old_count,
        new_start=new_start,
        new_count=new_count,
    )

    old_line = old_start
    new_line = new_start

    for raw in lines[1:]:
        if not raw:
            # blank context line
            hunk.context_lines.append((new_line, ""))
            old_line += 1
            new_line += 1
            continue

        prefix = raw[0]
        content = raw[1:]

        if prefix == "-":
            hunk.removed_lines.append((old_line, content))
            old_line += 1
        elif prefix == "+":
            hunk.added_lines.append((new_line, content))
            new_line += 1
        elif prefix == " ":
            hunk.context_lines.append((new_line, content))
            old_line += 1
            new_line += 1
        elif prefix == "\\":
            # "\ No newline at end of file" — skip, do not advance counters
            pass
        else:
            # Treat unexpected prefix as context to be safe
            hunk.context_lines.append((new_line, raw))
            old_line += 1
            new_line += 1

    return hunk
