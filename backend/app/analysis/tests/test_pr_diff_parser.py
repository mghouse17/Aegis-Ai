"""Tests for parse_pr_diff() — the multi-file PR diff entry point."""
from __future__ import annotations

import pytest

from app.analysis.models.classification_models import ChangeType, FileCategory
from app.analysis.parser.diff_parser import parse_pr_diff

# ---------------------------------------------------------------------------
# Shared diff fixtures
# ---------------------------------------------------------------------------

_MULTI_FILE_DIFF = """\
diff --git a/src/auth/login.py b/src/auth/login.py
index abc1234..def5678 100644
--- a/src/auth/login.py
+++ b/src/auth/login.py
@@ -1,3 +1,4 @@
 import os
+import jwt
 def login(user, password):
     pass
diff --git a/requirements.txt b/requirements.txt
index 111aaaa..222bbbb 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,3 @@
 flask
+requests==2.31.0
 boto3
"""

_ADDED_FILE_DIFF = """\
diff --git a/new_module.py b/new_module.py
new file mode 100644
index 0000000..abc1234
--- /dev/null
+++ b/new_module.py
@@ -0,0 +1,4 @@
+import os
+
+def setup():
+    pass
"""

_DELETED_FILE_DIFF = """\
diff --git a/old_module.py b/old_module.py
deleted file mode 100644
index abc1234..0000000
--- a/old_module.py
+++ /dev/null
@@ -1,4 +0,0 @@
-import os
-
-def setup():
-    pass
"""

_RENAMED_FILE_DIFF = """\
diff --git a/old_name.py b/new_name.py
similarity index 95%
rename from old_name.py
rename to new_name.py
index abc..def 100644
--- a/old_name.py
+++ b/new_name.py
@@ -1,3 +1,3 @@
 import os
-old_function()
+new_function()
"""

_BINARY_FILE_DIFF = """\
diff --git a/assets/logo.png b/assets/logo.png
index abc1234..def5678 100644
Binary files a/assets/logo.png and b/assets/logo.png differ
"""

_CI_CD_DIFF = """\
diff --git a/.github/workflows/deploy.yml b/.github/workflows/deploy.yml
index abc..def 100644
--- a/.github/workflows/deploy.yml
+++ b/.github/workflows/deploy.yml
@@ -1,3 +1,4 @@
 name: Deploy
+  run: npm install --production
 on: [push]
"""

_DEPENDENCY_ADDED_DIFF = """\
diff --git a/requirements.txt b/requirements.txt
index 111aaaa..222bbbb 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,3 @@
 flask
+requests==2.31.0
 boto3
"""


# ---------------------------------------------------------------------------
# Multi-file parsing
# ---------------------------------------------------------------------------


def test_multi_file_diff_returns_one_result_per_file():
    results = parse_pr_diff(_MULTI_FILE_DIFF)
    assert len(results) == 2


def test_multi_file_diff_correct_filenames():
    results = parse_pr_diff(_MULTI_FILE_DIFF)
    paths = {r.file_path for r in results}
    assert "src/auth/login.py" in paths
    assert "requirements.txt" in paths


def test_multi_file_auth_file_classified_correctly():
    results = parse_pr_diff(_MULTI_FILE_DIFF)
    auth = next(r for r in results if r.file_path == "src/auth/login.py")
    assert auth.file_category == FileCategory.AUTH


def test_multi_file_dependency_file_classified_correctly():
    results = parse_pr_diff(_MULTI_FILE_DIFF)
    dep = next(r for r in results if r.file_path == "requirements.txt")
    assert dep.file_category == FileCategory.DEPENDENCY
    assert ChangeType.DEPENDENCY_ADDED in dep.change_types


def test_multi_file_dependency_creates_finding():
    results = parse_pr_diff(_MULTI_FILE_DIFF)
    dep = next(r for r in results if r.file_path == "requirements.txt")
    assert dep.should_create_security_finding is True


# ---------------------------------------------------------------------------
# Added file
# ---------------------------------------------------------------------------


def test_added_file_returns_one_result():
    results = parse_pr_diff(_ADDED_FILE_DIFF)
    assert len(results) == 1


def test_added_file_filename_extracted():
    results = parse_pr_diff(_ADDED_FILE_DIFF)
    assert results[0].file_path == "new_module.py"


def test_added_file_has_added_lines():
    results = parse_pr_diff(_ADDED_FILE_DIFF)
    assert len(results[0].added_lines) > 0


# ---------------------------------------------------------------------------
# Deleted file
# ---------------------------------------------------------------------------


def test_deleted_file_filename_extracted():
    results = parse_pr_diff(_DELETED_FILE_DIFF)
    assert results[0].file_path == "old_module.py"


def test_deleted_file_has_no_added_lines():
    results = parse_pr_diff(_DELETED_FILE_DIFF)
    assert results[0].added_lines == []


def test_deleted_file_does_not_create_finding():
    results = parse_pr_diff(_DELETED_FILE_DIFF)
    assert results[0].should_create_security_finding is False


# ---------------------------------------------------------------------------
# Renamed file
# ---------------------------------------------------------------------------


def test_renamed_file_uses_new_name():
    results = parse_pr_diff(_RENAMED_FILE_DIFF)
    assert len(results) == 1
    assert results[0].file_path == "new_name.py"


def test_renamed_file_has_added_and_removed_lines():
    results = parse_pr_diff(_RENAMED_FILE_DIFF)
    assert len(results[0].added_lines) > 0
    assert len(results[0].removed_lines) > 0


# ---------------------------------------------------------------------------
# Binary file
# ---------------------------------------------------------------------------


def test_binary_file_parses_safely():
    results = parse_pr_diff(_BINARY_FILE_DIFF)
    assert len(results) == 1


def test_binary_file_filename_extracted():
    results = parse_pr_diff(_BINARY_FILE_DIFF)
    assert results[0].file_path == "assets/logo.png"


def test_binary_file_has_no_added_lines():
    results = parse_pr_diff(_BINARY_FILE_DIFF)
    assert results[0].added_lines == []


def test_binary_file_does_not_create_finding():
    results = parse_pr_diff(_BINARY_FILE_DIFF)
    assert results[0].should_create_security_finding is False


# ---------------------------------------------------------------------------
# CI/CD file
# ---------------------------------------------------------------------------


def test_ci_cd_file_gets_ci_cd_category():
    results = parse_pr_diff(_CI_CD_DIFF)
    assert results[0].file_category == FileCategory.CI_CD


def test_ci_cd_file_gets_ci_cd_change_type():
    results = parse_pr_diff(_CI_CD_DIFF)
    assert ChangeType.CI_CD_CHANGE in results[0].change_types


def test_ci_cd_file_creates_finding():
    results = parse_pr_diff(_CI_CD_DIFF)
    assert results[0].should_create_security_finding is True


# ---------------------------------------------------------------------------
# Dependency addition
# ---------------------------------------------------------------------------


def test_dependency_added_creates_finding():
    results = parse_pr_diff(_DEPENDENCY_ADDED_DIFF)
    assert len(results) == 1
    assert results[0].should_create_security_finding is True


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_empty_raw_diff_returns_empty_list():
    assert parse_pr_diff("") == []


def test_whitespace_only_diff_returns_empty_list():
    assert parse_pr_diff("   \n\n  ") == []


def test_parse_pr_diff_does_not_crash_on_no_hunk():
    # Diff header present but no @@ lines (e.g. mode-only change)
    diff = (
        "diff --git a/script.sh b/script.sh\n"
        "old mode 100644\n"
        "new mode 100755\n"
    )
    results = parse_pr_diff(diff)
    assert len(results) == 1
    assert results[0].added_lines == []
    assert results[0].should_create_security_finding is False


# ---------------------------------------------------------------------------
# Checklist item 1 & 5: context lines preserved end-to-end through parse_pr_diff
# ---------------------------------------------------------------------------

_CONTEXT_LINE_DIFF = """\
diff --git a/src/utils.py b/src/utils.py
index aaa..bbb 100644
--- a/src/utils.py
+++ b/src/utils.py
@@ -10,5 +10,6 @@
 def helper():
-    return 1
+    return 2
+    # new comment
 x = helper()
 y = x + 1
"""


def test_context_lines_present_in_hunk():
    # Drives the full parse_pr_diff → parse_diff → parse_hunk chain and
    # asserts that added, removed, AND context lines are all captured.
    results = parse_pr_diff(_CONTEXT_LINE_DIFF)
    assert len(results) == 1
    hunk = results[0].hunks[0]

    # added lines (checklist: "added lines")
    added_contents = [content for _, content in hunk.added_lines]
    assert "    return 2" in added_contents
    assert "    # new comment" in added_contents

    # removed lines (checklist: "removed lines")
    removed_contents = [content for _, content in hunk.removed_lines]
    assert "    return 1" in removed_contents

    # context lines (checklist: "hunk context")
    context_contents = [content for _, content in hunk.context_lines]
    assert "def helper():" in context_contents
    assert "x = helper()" in context_contents
    assert "y = x + 1" in context_contents


def test_file_path_present_in_result():
    # Checklist: "file path" is captured from the diff --git header.
    results = parse_pr_diff(_CONTEXT_LINE_DIFF)
    assert results[0].file_path == "src/utils.py"


# ---------------------------------------------------------------------------
# Checklist item 4: large diff through parse_pr_diff does not crash
# ---------------------------------------------------------------------------

_LARGE_DIFF_HEADER = (
    "diff --git a/bigfile.py b/bigfile.py\n"
    "index aaa..bbb 100644\n"
    "--- a/bigfile.py\n"
    "+++ b/bigfile.py\n"
)


def test_large_diff_through_parse_pr_diff_does_not_crash():
    # 2000 added lines in a single file wrapped in a proper diff --git header.
    patch_lines = "\n".join(f"+line{i}" for i in range(2000))
    raw_diff = _LARGE_DIFF_HEADER + "@@ -1,1 +1,2000 @@\n" + patch_lines
    results = parse_pr_diff(raw_diff)
    assert len(results) == 1
    # Must not time out; parsing_truncated reflects whether the limit was hit
    assert isinstance(results[0].parsing_truncated, bool)


def test_large_diff_through_parse_pr_diff_sets_truncation_flag():
    # Force truncation by generating more lines than _DEFAULT_MAX_LINES (5000).
    patch_lines = "\n".join(f"+line{i}" for i in range(5100))
    raw_diff = _LARGE_DIFF_HEADER + "@@ -1,1 +1,5100 @@\n" + patch_lines
    results = parse_pr_diff(raw_diff)
    assert results[0].parsing_truncated is True


def test_large_diff_through_parse_pr_diff_returns_partial_lines():
    patch_lines = "\n".join(f"+line{i}" for i in range(5100))
    raw_diff = _LARGE_DIFF_HEADER + "@@ -1,1 +1,5100 @@\n" + patch_lines
    results = parse_pr_diff(raw_diff)
    # Partial results — some lines must have been captured before truncation
    assert len(results[0].added_lines) > 0
