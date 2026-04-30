from __future__ import annotations

from app.analysis.models.classification_models import ChangeType, FileCategory

_BASE_SCORES: dict[FileCategory, int] = {
    FileCategory.AUTH: 40,
    FileCategory.DATABASE: 35,
    FileCategory.CONFIG: 30,
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

# Signals that indicate a secret value was introduced in the diff.
_SECRET_SIGNALS: frozenset[str] = frozenset({
    "secret", "api_key", "hardcoded_secret", "access_token", "refresh_token",
})

# CI/CD signals that represent pipeline-injection or credential-exposure risk.
_CI_CD_DANGEROUS_SIGNALS: frozenset[str] = frozenset({
    "hardcoded_secret",
    "github_token",
    "api_key",
    "curl_pipe_shell",
    "wget_pipe_shell",
    "chmod_777",
    "privileged_true",
    "permissions_write_all",
    "pull_request_target",
    "unpinned_action",
})


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
        return ci_cd_dangerous, not ci_cd_dangerous

    create = (
        risk_score >= FINDING_RISK_THRESHOLD
        or bool(set(security_signals))
        or ChangeType.AUTH_LOGIC_CHANGED in change_types
        or ChangeType.SECRET_REFERENCE in change_types
        or ChangeType.DEPENDENCY_ADDED in change_types
    )
    return create, False
