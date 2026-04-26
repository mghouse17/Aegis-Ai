import pytest

from app.analysis.parser.hunk_parser import parse_hunk


def test_standard_hunk_with_add_remove_context():
    patch = "@@ -10,7 +10,8 @@ function middleware(req, res)\n context\n-old line\n+new line\n context2"
    hunk = parse_hunk(patch)

    assert hunk.old_start == 10
    assert hunk.old_count == 7
    assert hunk.new_start == 10
    assert hunk.new_count == 8
    assert hunk.removed_lines == [(11, "old line")]
    assert hunk.added_lines == [(11, "new line")]
    assert (10, "context") in hunk.context_lines
    assert (12, "context2") in hunk.context_lines


def test_pure_add_block():
    patch = "@@ -0,0 +1,3 @@\n+line1\n+line2\n+line3"
    hunk = parse_hunk(patch)

    assert len(hunk.added_lines) == 3
    assert hunk.added_lines[0] == (1, "line1")
    assert hunk.added_lines[1] == (2, "line2")
    assert hunk.added_lines[2] == (3, "line3")
    assert hunk.removed_lines == []


def test_hunk_header_with_function_context():
    patch = "@@ -5,3 +5,4 @@ class AuthService"
    hunk = parse_hunk(patch)

    assert "class AuthService" in hunk.header
    assert hunk.old_start == 5
    assert hunk.new_start == 5


def test_line_numbers_are_accurate():
    # context_a is at new_line 20, removal at old_line 21, addition at new_line 21, context_b at new_line 22
    patch = "@@ -20,4 +20,4 @@\n context_a\n-old\n+new\n context_b"
    hunk = parse_hunk(patch)

    assert hunk.context_lines[0] == (20, "context_a")
    assert hunk.removed_lines[0] == (21, "old")
    assert hunk.added_lines[0] == (21, "new")
    assert hunk.context_lines[1] == (22, "context_b")


def test_hunk_count_omitted_defaults_to_one():
    # @@ -5 +5,3 @@ — old_count omitted, should default to 1
    patch = "@@ -5 +5,3 @@\n+a\n+b\n+c"
    hunk = parse_hunk(patch)

    assert hunk.old_count == 1
    assert hunk.new_count == 3


def test_no_newline_marker_is_skipped():
    patch = "@@ -1,1 +1,1 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file"
    hunk = parse_hunk(patch)

    assert hunk.removed_lines == [(1, "old")]
    assert hunk.added_lines == [(1, "new")]


def test_empty_hunk_text():
    hunk = parse_hunk("")
    assert hunk.header == ""
    assert hunk.added_lines == []
    assert hunk.removed_lines == []


def test_pure_removal_block():
    patch = "@@ -5,3 +5,0 @@\n-line1\n-line2\n-line3"
    hunk = parse_hunk(patch)

    assert len(hunk.removed_lines) == 3
    assert hunk.removed_lines[0] == (5, "line1")
    assert hunk.added_lines == []
