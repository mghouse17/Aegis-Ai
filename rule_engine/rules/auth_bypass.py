from __future__ import annotations

import re

from core.context import AnalysisContext, ChangedFile
from core.diff_utils import extract_added_lines, extract_removed_lines
from core.finding import Finding, RuleMetadata, build_finding
from core.rule import Rule

# Auth check patterns to detect in removed lines (active auth checks deleted)
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
    """Normalize a line for moved-check comparison: collapse whitespace, unify quotes."""
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

    def _scan_file(self, file: ChangedFile) -> list[Finding]:
        findings: list[Finding] = []

        # Pre-compute normalized new_content lines once per file (Issue 13 perf fix)
        norm_new_lines = {_normalize(l) for l in file.new_content.splitlines()}

        # Pass 1: removed lines — active auth checks deleted
        for line_num, content in extract_removed_lines(file.diff):
            if any(pattern in content for pattern in _AUTH_PATTERNS):
                norm_content = _normalize(content)
                if norm_content and norm_content not in norm_new_lines:
                    evidence = {
                        "bypass_type": "deleted",
                        "removed_line": content.strip(),
                        "line_number": line_num,
                    }
                    findings.append(
                        self._make_finding(file.path, line_num, "deleted", evidence)
                    )

        # Pass 2: added lines — auth checks commented out
        for line_num, content in extract_added_lines(file.diff):
            if _COMMENTED_AUTH_RE.search(content):
                evidence = {
                    "bypass_type": "commented_out",
                    "added_line": content.strip(),
                    "line_number": line_num,
                }
                findings.append(
                    self._make_finding(file.path, line_num, "commented_out", evidence)
                )

        return findings

    def _make_finding(
        self, file_path: str, line_num: int, bypass_type: str, evidence: dict
    ) -> Finding:
        return build_finding(
            meta=self._meta,
            confidence=CONFIDENCE_MAP.get(bypass_type, self._meta.confidence),
            file_path=file_path,
            line_number=line_num,
            title=f"Auth check {bypass_type} in {file_path}",
            evidence=evidence,
            template_vars={"bypass_type": bypass_type},
        )
