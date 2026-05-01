from __future__ import annotations

import re

from core.context import AnalysisContext, ChangedFile
from core.diff_utils import extract_added_lines, redact
from core.finding import Finding, RuleMetadata, build_finding
from core.rule import Rule

# --- Compiled patterns ---

_CRED_RE = re.compile(
    r"\b(password|passwd|api_key|apikey|secret|token|private_key)\s*=\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)

_SKIP_SOURCES = (
    "os.environ",
    "os.getenv",
    "config.get",
    "settings.",
    "getenv(",
    "env[",
)

_PLACEHOLDER_RE = re.compile(
    r"(?:changeme|example|dummy|your_|xxx|placeholder)",
    re.IGNORECASE,
)

CONFIDENCE_MAP = {
    "password": 0.85,
    "passwd": 0.85,
    "api_key": 0.85,
    "apikey": 0.85,
    "secret": 0.80,
    "token": 0.80,
    "private_key": 0.90,
}


def _is_placeholder(value: str) -> bool:
    return (
        not value
        or bool(_PLACEHOLDER_RE.search(value))
        or "<" in value
        or ">" in value
    )


class HardcodedCredentialRule(Rule):
    DEFAULT_METADATA = RuleMetadata(
        id="SEC-002",
        name="Hardcoded Credential",
        version="1.0.0",
        severity="high",
        confidence=0.85,
        explanation_template=(
            "A hardcoded {credential_type} literal was found in {file_path} at line {line_number}. "
            "Use environment variables or a secrets manager instead. Evidence: {evidence}"
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
        for line_num, content in extract_added_lines(file.diff):
            finding = self._check_line(file.path, line_num, content)
            if finding:
                findings.append(finding)
        return findings

    def _check_line(self, file_path: str, line_num: int, content: str) -> Finding | None:
        if any(skip in content for skip in _SKIP_SOURCES):
            return None

        m = _CRED_RE.search(content)
        if not m:
            return None

        var_name = m.group(1).lower()
        value = m.group(2)

        if _is_placeholder(value):
            return None

        confidence = CONFIDENCE_MAP.get(var_name, self._meta.confidence)
        evidence = {
            "credential_type": var_name,
            "value": redact(value),
            "source_line": line_num,
        }
        return build_finding(
            meta=self._meta,
            confidence=confidence,
            file_path=file_path,
            line_number=line_num,
            title=f"Hardcoded {var_name} in {file_path}",
            evidence=evidence,
            template_vars={"credential_type": var_name},
        )
