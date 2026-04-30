from __future__ import annotations

from app.analysis.classifier.taxonomy import CI_CD_DANGEROUS_SIGNALS
from app.analysis.models.classification_models import ChangeType, FileCategory, FileClassification

_BASE_SCORES: dict[FileCategory, int] = {
    FileCategory.AUTH: 40,
    FileCategory.DATABASE: 35,
    FileCategory.CONFIG: 30,
    FileCategory.DOCS: 0,
    FileCategory.API: 25,
    FileCategory.DEPENDENCY: 20,
    FileCategory.CI_CD: 20,
    FileCategory.FRONTEND: 10,
    FileCategory.UNKNOWN: 5,
    FileCategory.TEST: 0,
    FileCategory.DOCS: 0,
}

_CHANGE_TYPE_SCORES: dict[ChangeType, int] = {
    ChangeType.SECRET_REFERENCE: 30,
    ChangeType.AUTH_LOGIC_CHANGED: 20,
    ChangeType.CI_CD_CHANGE: 15,
    ChangeType.CONFIG_CHANGE: 10,
    ChangeType.DEPENDENCY_ADDED: 10,
    ChangeType.DEPENDENCY_REMOVED: 5,
    ChangeType.NEW_FUNCTION: 5,
}

_SIGNAL_SCORE = 5

# Public severity thresholds — consumers use these to bucket risk_score.
RISK_LOW = 20
RISK_MEDIUM = 40
RISK_HIGH = 60
RISK_CRITICAL = 80

# Finding decision constants — moved here so should_create_finding is testable
# independently of the parse pipeline.
FINDING_RISK_THRESHOLD = 50


def compute_risk_score(
    file_category: FileCategory,
    change_types: list[ChangeType],
    security_signals: list[str],
) -> int:
    score = _BASE_SCORES.get(file_category, 5)
    for ct in change_types:
        score += _CHANGE_TYPE_SCORES.get(ct, 0)
    score += len(set(security_signals)) * _SIGNAL_SCORE
    return min(score, 100)


def is_ci_cd_dangerous(security_signals: list[str]) -> bool:
    return bool(set(security_signals) & CI_CD_DANGEROUS_SIGNALS)


def should_create_finding(
    file_category: FileCategory,
    change_types: list[ChangeType],
    security_signals: list[str],
    risk_score: int,
    *,
    is_test_only: bool = False,
    is_docs: bool = False,
    is_ci_cd: bool = False,
    ci_cd_dangerous: bool = False,
) -> tuple[bool, bool]:
    """Return (should_create_security_finding, audit_log_only).

    All logic is deterministic — no LLM involvement.
    Rule priority (first match wins):
      1. Test-only or docs-only → never a finding, always audit-only.
      2. CI/CD → finding only if a dangerous signal is present; otherwise audit-only.
      3. Everything else → finding if risk threshold reached OR any named condition fires.
    """
    if is_test_only or is_docs:
        return False, True

    if is_ci_cd:
        dangerous = ci_cd_dangerous or is_ci_cd_dangerous(security_signals)
        return dangerous, not dangerous

    create = (
        risk_score >= FINDING_RISK_THRESHOLD
        or bool(set(security_signals))
        or ChangeType.AUTH_LOGIC_CHANGED in change_types
        or ChangeType.SECRET_REFERENCE in change_types
        or ChangeType.DEPENDENCY_ADDED in change_types
    )
    return create, False


def apply_final_overrides(result: FileClassification) -> FileClassification:
    """Apply product-level finding policy after all classifiers have run."""
    if result.is_test_only:
        result.should_create_security_finding = False
        result.audit_log_only = True
        result.risk_score = 0
        if result.file_category != FileCategory.AUTH:
            result.change_types = [
                change_type for change_type in result.change_types
                if change_type != ChangeType.AUTH_LOGIC_CHANGED
            ]
            result.change_confidence.pop(ChangeType.AUTH_LOGIC_CHANGED.value, None)
        return result

    if result.file_category == FileCategory.DOCS:
        result.should_create_security_finding = False
        result.audit_log_only = True

    if result.audit_log_only:
        result.risk_score = min(result.risk_score, 5)

    return result
