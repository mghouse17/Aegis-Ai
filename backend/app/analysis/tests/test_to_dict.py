"""Tests for FileClassification.to_dict() serialization contract (Issue 10)."""
from __future__ import annotations

import json

import pytest

from app.analysis.models.diff_models import ChangedFileInput
from app.analysis.parser.diff_parser import parse_and_classify

_AUTH_PATCH = "@@ -1,2 +1,3 @@\n context\n-old\n+const token = verifyToken(req)"


def _result():
    return parse_and_classify(ChangedFileInput(
        filename="src/middleware/auth.ts",
        status="modified",
        patch=_AUTH_PATCH,
    ))


# ---------------------------------------------------------------------------
# Field presence
# ---------------------------------------------------------------------------

REQUIRED_KEYS = {
    "file_path", "file_category", "is_test_only",
    "hunks", "added_lines", "removed_lines",
    "change_types", "change_confidence", "security_signals",
    "dependency_changes", "risk_score",
    "should_create_security_finding", "audit_log_only", "parsing_truncated",
}


def test_to_dict_contains_all_required_keys():
    d = _result().to_dict()
    assert REQUIRED_KEYS.issubset(d.keys())


# ---------------------------------------------------------------------------
# Type correctness — enums must be serialized as strings
# ---------------------------------------------------------------------------


def test_file_category_is_string_not_enum():
    d = _result().to_dict()
    assert isinstance(d["file_category"], str)
    assert d["file_category"] == "auth"


def test_change_types_are_strings():
    d = _result().to_dict()
    assert isinstance(d["change_types"], list)
    assert all(isinstance(ct, str) for ct in d["change_types"])


def test_security_signals_are_strings():
    d = _result().to_dict()
    assert all(isinstance(s, str) for s in d["security_signals"])


def test_change_confidence_is_string_map():
    d = _result().to_dict()
    assert isinstance(d["change_confidence"], dict)
    assert all(isinstance(k, str) for k in d["change_confidence"].keys())
    assert all(isinstance(v, str) for v in d["change_confidence"].values())


def test_dependency_changes_are_dicts():
    result = parse_and_classify(ChangedFileInput(
        filename="requirements.txt",
        status="modified",
        patch="@@ -1,1 +1,2 @@\n flask\n+requests==2.31.0",
    ))
    d = result.to_dict()
    assert isinstance(d["dependency_changes"], list)
    assert d["dependency_changes"] == [{
        "package": "requests",
        "version": "2.31.0",
        "manager": "pip",
        "line": 2,
    }]


# ---------------------------------------------------------------------------
# Line-entry shape — must be {line: int, content: str}, NOT bare [int, str]
# ---------------------------------------------------------------------------


def test_added_lines_are_dicts_not_arrays():
    d = _result().to_dict()
    assert len(d["added_lines"]) > 0
    for entry in d["added_lines"]:
        assert isinstance(entry, dict), f"expected dict, got {type(entry)}"
        assert "line" in entry and "content" in entry
        assert isinstance(entry["line"], int)
        assert isinstance(entry["content"], str)


def test_removed_lines_are_dicts_not_arrays():
    d = _result().to_dict()
    assert len(d["removed_lines"]) > 0
    for entry in d["removed_lines"]:
        assert isinstance(entry, dict)
        assert "line" in entry and "content" in entry


def test_hunk_lines_are_dicts():
    d = _result().to_dict()
    assert len(d["hunks"]) > 0
    hunk = d["hunks"][0]
    for key in ("added_lines", "removed_lines", "context_lines"):
        for entry in hunk[key]:
            assert isinstance(entry, dict), f"hunk.{key} entry must be a dict"
            assert "line" in entry and "content" in entry


# ---------------------------------------------------------------------------
# JSON round-trip — full output must be json.dumps()-able
# ---------------------------------------------------------------------------


def test_to_dict_is_json_serializable():
    d = _result().to_dict()
    serialized = json.dumps(d)
    parsed = json.loads(serialized)
    assert parsed["file_path"] == "src/middleware/auth.ts"
    assert parsed["file_category"] == "auth"


def test_to_dict_with_empty_patch_is_json_serializable():
    result = parse_and_classify(ChangedFileInput(
        filename="foo.py", status="modified", patch=None
    ))
    serialized = json.dumps(result.to_dict())
    assert json.loads(serialized)["added_lines"] == []


# ---------------------------------------------------------------------------
# Scalar field types
# ---------------------------------------------------------------------------


def test_risk_score_is_int():
    assert isinstance(_result().to_dict()["risk_score"], int)


def test_is_test_only_is_bool():
    assert isinstance(_result().to_dict()["is_test_only"], bool)


def test_should_create_security_finding_is_bool():
    assert isinstance(_result().to_dict()["should_create_security_finding"], bool)


def test_audit_log_only_is_bool():
    assert isinstance(_result().to_dict()["audit_log_only"], bool)


def test_parsing_truncated_is_bool():
    assert isinstance(_result().to_dict()["parsing_truncated"], bool)
