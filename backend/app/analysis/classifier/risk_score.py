from __future__ import annotations

from app.analysis.models.classification_models import ChangeType, FileCategory

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
