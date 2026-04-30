"""Parameterized unit tests for should_create_finding() (Issue 11).

The function is a pure, LLM-free decision rule with no side effects.
Each test row represents one decision branch.
"""
from __future__ import annotations

import pytest

from app.analysis.classifier.risk_score import FINDING_RISK_THRESHOLD, should_create_finding
from app.analysis.models.classification_models import ChangeType, FileCategory

# Convenience aliases
_AUTH = FileCategory.AUTH
_DEP = FileCategory.DEPENDENCY
_CI_CD = FileCategory.CI_CD
_TEST = FileCategory.TEST
_DOCS = FileCategory.DOCS
_UNKNOWN = FileCategory.UNKNOWN

_ACL = ChangeType.AUTH_LOGIC_CHANGED
_DEP_ADD = ChangeType.DEPENDENCY_ADDED
_CI = ChangeType.CI_CD_CHANGE
_SEC = ChangeType.SECRET_REFERENCE


# ---------------------------------------------------------------------------
# Test-only and docs: always (False, True)
# ---------------------------------------------------------------------------


def test_test_only_never_creates_finding():
    create, audit = should_create_finding(_AUTH, [_ACL], ["token"], 80, is_test_only=True)
    assert create is False
    assert audit is True


def test_docs_never_creates_finding():
    create, audit = should_create_finding(_DOCS, [], [], 0, is_docs=True)
    assert create is False
    assert audit is True


def test_docs_with_high_risk_still_no_finding():
    create, audit = should_create_finding(_DOCS, [], ["jwt", "token"], 90, is_docs=True)
    assert create is False
    assert audit is True


# ---------------------------------------------------------------------------
# CI/CD: finding only when dangerous signals present
# ---------------------------------------------------------------------------


def test_ci_cd_safe_change_is_audit_only():
    create, audit = should_create_finding(
        _CI_CD, [_CI], [], 35, is_ci_cd=True, ci_cd_dangerous=False
    )
    assert create is False
    assert audit is True


def test_ci_cd_dangerous_change_creates_finding():
    create, audit = should_create_finding(
        _CI_CD, [_CI], ["hardcoded_secret"], 40, is_ci_cd=True, ci_cd_dangerous=True
    )
    assert create is True
    assert audit is False


# ---------------------------------------------------------------------------
# Normal files: various conditions
# ---------------------------------------------------------------------------


def test_no_signals_low_risk_no_finding():
    create, audit = should_create_finding(_UNKNOWN, [], [], 5)
    assert create is False
    assert audit is False


def test_any_security_signal_creates_finding():
    create, audit = should_create_finding(_UNKNOWN, [], ["jwt"], 10)
    assert create is True
    assert audit is False


def test_auth_logic_changed_creates_finding():
    create, audit = should_create_finding(_AUTH, [_ACL], [], 60)
    assert create is True
    assert audit is False


def test_secret_reference_creates_finding():
    create, audit = should_create_finding(_UNKNOWN, [_SEC], [], 35)
    assert create is True
    assert audit is False


def test_dependency_added_creates_finding():
    create, audit = should_create_finding(_DEP, [_DEP_ADD], [], 30)
    assert create is True
    assert audit is False


def test_risk_at_threshold_creates_finding():
    create, audit = should_create_finding(_UNKNOWN, [], [], FINDING_RISK_THRESHOLD)
    assert create is True
    assert audit is False


def test_risk_below_threshold_no_finding():
    create, audit = should_create_finding(_UNKNOWN, [], [], FINDING_RISK_THRESHOLD - 1)
    assert create is False
    assert audit is False


# ---------------------------------------------------------------------------
# Return type contract
# ---------------------------------------------------------------------------


def test_returns_tuple_of_two_bools():
    result = should_create_finding(_UNKNOWN, [], [], 0)
    assert isinstance(result, tuple)
    assert len(result) == 2
    assert all(isinstance(v, bool) for v in result)
