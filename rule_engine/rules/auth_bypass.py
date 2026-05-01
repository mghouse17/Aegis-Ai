from __future__ import annotations

import re
from collections import defaultdict

from core._diff_utils import extract_added_lines, extract_removed_lines
from core.context import AnalysisContext
from core.finding import Finding, RuleMetadata
from core.rule import Rule

# Auth check patterns to look for in removed lines (active auth being deleted)
_AUTH_PATTERNS = [
    "@requires_auth",
    "@login_required",
    "@permission_required",
    ".has_permission(",
    ".is_authenticated",
    "check_permission(",
    "require_role(",
    "verify_token(",
    "authMiddleware",
    "authenticate(",
    "is_authorized(",
]

# Commented-out auth checks in added lines
_COMMENTED_AUTH_RE = re.compile(
    r"#\s*(?:require_role|@requires_auth|@login_required|@permission_required|"
    r"check_permission|verify_token|is_authorized|has_permission)",
    re.IGNORECASE,
)

CONFIDENCE_MAP = {
    "deleted": 0.90,
    "commented_out": 0.85,
}


def _normalize(line: str) -> str:
    """Normalize line for moved-check comparison: collapse whitespace, unify quotes."""
    normalized = re.sub(r"\s+", " ", line.strip())
    return normalized.replace('"', "'")


class AuthBypassRule(Rule):
    DEFAULT_METADATA = RuleMetadata(
        id="SEC-004",
        name="Auth Bypass",
        version="1.0.0",
        severity="critical",
        confidence=0.9,
        explanation_template=(
            "An authentication or authorization check was {bypass_type} in {file_path} "
            "at line {line_number}. Evidence: {evidence}"
        ),
        enabled=True,
    )

    def __init__(self, metadata: RuleMetadata | None = None) -> None:
        self._meta = metadata or self.DEFAULT_METADATA

    @property
    def metadata(self) -> RuleMetadata:
        return self._meta

    def run(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for file in context.changed_files:
            findings.extend(self._scan_file(file))
        return findings

    def _scan_file(self, file) -> list[Finding]:
        findings: list[Finding] = []

        # Pass 1: removed lines — active auth checks deleted
        for line_num, content in extract_removed_lines(file.diff):
            if any(pattern in content for pattern in _AUTH_PATTERNS):
                if not self._exists_in_new_content(content, file.new_content):
                    evidence = {
                        "bypass_type": "deleted",
                        "removed_line": content.strip(),
                        "line_number": line_num,
                    }
                    findings.append(self._make_finding(file.path, line_num, "deleted", evidence))

        # Pass 2: added lines — auth checks commented out
        for line_num, content in extract_added_lines(file.diff):
            if _COMMENTED_AUTH_RE.search(content):
                evidence = {
                    "bypass_type": "commented_out",
                    "added_line": content.strip(),
                    "line_number": line_num,
                }
                findings.append(self._make_finding(file.path, line_num, "commented_out", evidence))

        return findings

    @staticmethod
    def _exists_in_new_content(removed_line: str, new_content: str) -> bool:
        """Return True if the auth check still exists in new_content (moved, not removed)."""
        norm_removed = _normalize(removed_line)
        if not norm_removed:
            return False
        for nc_line in new_content.splitlines():
            if _normalize(nc_line) == norm_removed:
                return True
        return False

    def _make_finding(
        self, file_path: str, line_num: int, bypass_type: str, evidence: dict
    ) -> Finding:
        confidence = CONFIDENCE_MAP.get(bypass_type, self._meta.confidence)
        explanation = self._meta.explanation_template.format_map(
            defaultdict(
                str,
                bypass_type=bypass_type,
                file_path=file_path,
                line_number=line_num,
                evidence=str(evidence),
            )
        )
        return Finding(
            rule_id=self._meta.id,
            rule_name=self._meta.name,
            version=self._meta.version,
            severity=self._meta.severity,
            confidence=confidence,
            file_path=file_path,
            line_number=line_num,
            title=f"Auth check {bypass_type} in {file_path}",
            explanation=explanation,
            evidence=evidence,
        )
