from __future__ import annotations

from core._diff_utils import extract_added_lines, extract_removed_lines


def test_extract_added_lines_basic():
    diff = "@@ -1,1 +1,3 @@\n context\n+added_line_one\n+added_line_two\n"
    result = extract_added_lines(diff)
    assert result == [(2, "added_line_one"), (3, "added_line_two")]


def test_extract_removed_lines_basic():
    diff = "@@ -1,3 +1,1 @@\n context\n-removed_line_one\n-removed_line_two\n"
    result = extract_removed_lines(diff)
    assert result == [(2, "removed_line_one"), (3, "removed_line_two")]


def test_handles_multiple_hunks():
    diff = (
        "@@ -1,2 +1,2 @@\n"
        " context\n"
        "+first_added\n"
        "@@ -10,2 +10,2 @@\n"
        " context\n"
        "+second_added\n"
    )
    result = extract_added_lines(diff)
    assert (2, "first_added") in result
    assert (11, "second_added") in result
    assert len(result) == 2


def test_handles_context_lines_advance_counter():
    diff = "@@ -1,1 +1,4 @@\n context\n+a\n context\n+b\n"
    result = extract_added_lines(diff)
    # context starts at 1, '+a' is line 2, context advances to 3, '+b' is line 4
    assert result == [(2, "a"), (4, "b")]


def test_handles_empty_diff():
    assert extract_added_lines("") == []
    assert extract_removed_lines("") == []


def test_handles_none_like_diff():
    # Falsy inputs
    assert extract_added_lines(None) == []  # type: ignore[arg-type]
    assert extract_removed_lines(None) == []  # type: ignore[arg-type]


def test_skips_diff_header_lines():
    diff = "--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,2 @@\n+real_added\n"
    result = extract_added_lines(diff)
    assert result == [(1, "real_added")]
    # '--- a/app.py' should not appear in removed lines either
    removed = extract_removed_lines(diff)
    assert all("a/app.py" not in content for _, content in removed)


def test_line_numbers_start_at_header_new_start():
    diff = "@@ -1,0 +10,3 @@\n+line_a\n+line_b\n+line_c\n"
    result = extract_added_lines(diff)
    assert result[0][0] == 10
    assert result[1][0] == 11
    assert result[2][0] == 12


def test_removed_line_numbers_start_at_header_old_start():
    diff = "@@ -5,3 +1,0 @@\n-line_a\n-line_b\n-line_c\n"
    result = extract_removed_lines(diff)
    assert result[0][0] == 5
    assert result[1][0] == 6
    assert result[2][0] == 7


def test_added_does_not_count_removed_lines():
    diff = "@@ -1,2 +1,2 @@\n-removed\n+added\n"
    added = extract_added_lines(diff)
    assert len(added) == 1
    assert added[0] == (1, "added")


def test_removed_does_not_count_added_lines():
    diff = "@@ -1,2 +1,2 @@\n-removed\n+added\n"
    removed = extract_removed_lines(diff)
    assert len(removed) == 1
    assert removed[0] == (1, "removed")
