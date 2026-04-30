"""Performance baseline test (Issue 16).

Uses wall-clock time to catch regressions, not benchmarking for its own sake.
Threshold is generous (2 s) so it won't flake on slow CI machines.
"""
from __future__ import annotations

import time

import pytest

from app.analysis.parser.diff_parser import parse_pr_diff


def _make_multi_file_diff(n_files: int = 10, lines_per_file: int = 500) -> str:
    parts: list[str] = []
    for i in range(n_files):
        filename = f"src/module_{i}/service.py"
        added = "\n".join(f"+line_{i}_{j} = {j}" for j in range(lines_per_file))
        parts.append(
            f"diff --git a/{filename} b/{filename}\n"
            f"index abc..def 100644\n"
            f"--- a/{filename}\n"
            f"+++ b/{filename}\n"
            f"@@ -1,1 +1,{lines_per_file} @@\n"
            f"{added}\n"
        )
    return "".join(parts)


def test_large_multi_file_diff_completes_within_budget():
    raw = _make_multi_file_diff(n_files=10, lines_per_file=500)
    t0 = time.perf_counter()
    results = parse_pr_diff(raw)
    elapsed = time.perf_counter() - t0

    assert len(results) == 10, "Expected one result per file"
    assert all(len(result.hunks) == 1 for result in results)
    assert all(len(result.added_lines) == 500 for result in results)
    assert all(not result.parsing_truncated for result in results)
    assert {result.file_path for result in results} == {
        f"src/module_{i}/service.py" for i in range(10)
    }
    assert elapsed < 2.0, (
        f"parse_pr_diff took {elapsed:.2f}s — performance regression detected"
    )


def test_large_diff_truncation_behavior_is_predictable():
    raw = _make_multi_file_diff(n_files=1, lines_per_file=5100)
    results = parse_pr_diff(raw)

    assert len(results) == 1
    assert results[0].parsing_truncated is True
    assert len(results[0].added_lines) > 0
    assert len(results[0].added_lines) < 5100
