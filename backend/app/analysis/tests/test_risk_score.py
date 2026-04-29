"""Unit tests for compute_risk_score and the public threshold constants."""
from __future__ import annotations

import pytest

from app.analysis.classifier.risk_score import (
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    compute_risk_score,
)
from app.analysis.models.classification_models import ChangeType, FileCategory

# ---------------------------------------------------------------------------
# Base scores by category
# ---------------------------------------------------------------------------


def test_auth_base_score():
    assert compute_risk_score(FileCategory.AUTH, [], []) == 40


def test_database_base_score():
    assert compute_risk_score(FileCategory.DATABASE, [], []) == 35


def test_config_base_score():
    assert compute_risk_score(FileCategory.CONFIG, [], []) == 30


def test_api_base_score():
    assert compute_risk_score(FileCategory.API, [], []) == 25


def test_dependency_base_score():
    assert compute_risk_score(FileCategory.DEPENDENCY, [], []) == 20


def test_ci_cd_base_score():
    assert compute_risk_score(FileCategory.CI_CD, [], []) == 20


def test_frontend_base_score():
    assert compute_risk_score(FileCategory.FRONTEND, [], []) == 10


def test_unknown_base_score():
    assert compute_risk_score(FileCategory.UNKNOWN, [], []) == 5


def test_test_base_score_is_zero():
    assert compute_risk_score(FileCategory.TEST, [], []) == 0


# ---------------------------------------------------------------------------
# Change-type scores (additive on top of base)
# ---------------------------------------------------------------------------


def test_secret_reference_adds_30():
    score = compute_risk_score(FileCategory.UNKNOWN, [ChangeType.SECRET_REFERENCE], [])
    assert score == 5 + 30


def test_auth_logic_changed_adds_20():
    score = compute_risk_score(FileCategory.AUTH, [ChangeType.AUTH_LOGIC_CHANGED], [])
    assert score == 40 + 20


def test_ci_cd_change_adds_15():
    score = compute_risk_score(FileCategory.CI_CD, [ChangeType.CI_CD_CHANGE], [])
    assert score == 20 + 15


def test_config_change_adds_10():
    score = compute_risk_score(FileCategory.CONFIG, [ChangeType.CONFIG_CHANGE], [])
    assert score == 30 + 10


def test_dependency_added_adds_10():
    score = compute_risk_score(FileCategory.DEPENDENCY, [ChangeType.DEPENDENCY_ADDED], [])
    assert score == 20 + 10


def test_dependency_removed_adds_5():
    score = compute_risk_score(FileCategory.DEPENDENCY, [ChangeType.DEPENDENCY_REMOVED], [])
    assert score == 20 + 5


def test_new_function_adds_5():
    score = compute_risk_score(FileCategory.API, [ChangeType.NEW_FUNCTION], [])
    assert score == 25 + 5


def test_unknown_change_type_adds_zero():
    score = compute_risk_score(FileCategory.UNKNOWN, [ChangeType.UNKNOWN], [])
    assert score == 5  # only base


# ---------------------------------------------------------------------------
# Security signal score
# ---------------------------------------------------------------------------


def test_one_signal_adds_5():
    score = compute_risk_score(FileCategory.UNKNOWN, [], ["jwt"])
    assert score == 5 + 5


def test_three_unique_signals_add_15():
    score = compute_risk_score(FileCategory.UNKNOWN, [], ["jwt", "token", "secret"])
    assert score == 5 + 15


def test_duplicate_signals_deduped():
    score = compute_risk_score(FileCategory.UNKNOWN, [], ["jwt", "jwt", "jwt"])
    assert score == 5 + 5  # counted once


# ---------------------------------------------------------------------------
# Additive combinations and cap
# ---------------------------------------------------------------------------


def test_auth_plus_auth_change_plus_signal():
    # 40 + 20 + 5 = 65
    score = compute_risk_score(FileCategory.AUTH, [ChangeType.AUTH_LOGIC_CHANGED], ["token"])
    assert score == 65


def test_score_caps_at_100():
    # Auth(40) + secret(30) + auth_change(20) + 30 signals*5 = 240 → capped
    signals = [f"sig{i}" for i in range(30)]
    score = compute_risk_score(
        FileCategory.AUTH,
        [ChangeType.SECRET_REFERENCE, ChangeType.AUTH_LOGIC_CHANGED],
        signals,
    )
    assert score == 100


def test_score_never_exceeds_100_with_many_change_types():
    change_types = list(ChangeType)
    signals = [f"s{i}" for i in range(20)]
    score = compute_risk_score(FileCategory.AUTH, change_types, signals)
    assert score <= 100


# ---------------------------------------------------------------------------
# Threshold constants
# ---------------------------------------------------------------------------


def test_threshold_constants_are_ordered():
    assert RISK_LOW < RISK_MEDIUM < RISK_HIGH < RISK_CRITICAL


def test_threshold_constants_within_range():
    assert RISK_LOW >= 0
    assert RISK_CRITICAL <= 100


def test_finding_threshold_is_at_or_above_medium():
    from app.analysis.parser.diff_parser import _FINDING_RISK_THRESHOLD
    assert _FINDING_RISK_THRESHOLD >= RISK_MEDIUM


# ---------------------------------------------------------------------------
# Finding-threshold integration: parse_and_classify must create findings
# for high-risk files that lack an explicit named condition
# ---------------------------------------------------------------------------


def test_dependency_added_triggers_finding():
    from app.analysis.models.diff_models import ChangedFileInput
    from app.analysis.parser.diff_parser import parse_and_classify

    patch = "@@ -1,2 +1,3 @@\n flask\n+requests==2.31.0\n boto3"
    inp = ChangedFileInput(filename="requirements.txt", status="modified", patch=patch)
    result = parse_and_classify(inp)
    assert result.should_create_security_finding is True
    assert ChangeType.DEPENDENCY_ADDED in result.change_types


def test_ci_cd_change_triggers_finding():
    from app.analysis.models.diff_models import ChangedFileInput
    from app.analysis.parser.diff_parser import parse_and_classify

    patch = "@@ -1,2 +1,3 @@\n name: Deploy\n+  run: npm install\n on: [push]"
    inp = ChangedFileInput(
        filename=".github/workflows/deploy.yml",
        status="modified",
        patch=patch,
    )
    result = parse_and_classify(inp)
    assert result.should_create_security_finding is True
    assert ChangeType.CI_CD_CHANGE in result.change_types


def test_low_risk_unknown_file_does_not_trigger_finding():
    from app.analysis.models.diff_models import ChangedFileInput
    from app.analysis.parser.diff_parser import parse_and_classify

    patch = "@@ -1,1 +1,1 @@\n-x = 1\n+x = 2"
    inp = ChangedFileInput(filename="utils.py", status="modified", patch=patch)
    result = parse_and_classify(inp)
    assert result.should_create_security_finding is False
    assert result.risk_score < 50
