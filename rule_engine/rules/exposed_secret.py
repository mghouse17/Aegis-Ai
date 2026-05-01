from __future__ import annotations

import math
import re

from core.context import AnalysisContext, ChangedFile
from core.diff_utils import extract_added_lines, redact
from core.finding import Finding, RuleMetadata, build_finding
from core.rule import Rule

# --- Compiled patterns ---

_AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
_GH_TOKEN_RE = re.compile(r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}")

_SENSITIVE_VAR_RE = re.compile(
    r"\b(secret|api_key|apikey|token|credential|password|private_key)\s*=\s*[\"']([^\"']{20,})[\"']",
    re.IGNORECASE,
)

_URL_RE = re.compile(r"https?://")
_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)
_HEX_ONLY_RE = re.compile(r"^[0-9a-fA-F]+$")
_BASE64_CHARS_RE = re.compile(r"^[A-Za-z0-9+/]+=*$")

_PLACEHOLDER_RE = re.compile(
    r"(?:example|test|dummy|your_|xxx|changeme|placeholder)",
    re.IGNORECASE,
)

CONFIDENCE_MAP = {
    "aws_key": 0.95,
    "github_token": 0.95,
    "entropy": 0.75,
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum(count / length * math.log2(count / length) for count in freq.values())


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_RE.search(value)) or "<" in value or ">" in value


def _is_entropy_skip(value: str) -> bool:
    if _URL_RE.search(value):
        return True
    if _UUID_RE.search(value):
        return True
    if _HEX_ONLY_RE.match(value):
        return True
    if _BASE64_CHARS_RE.match(value) and value.endswith("="):
        return True
    return False


class ExposedSecretRule(Rule):
    DEFAULT_METADATA = RuleMetadata(
        id="SEC-001",
        name="Exposed Secret",
        version="1.0.0",
        severity="critical",
        confidence=0.9,
        explanation_template=(
            "A {secret_type} was detected in {file_path} at line {line_number}. "
            "This credential may be committed to source control. Evidence: {evidence}"
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
        # AWS access key
        m = _AWS_KEY_RE.search(content)
        if m:
            matched = m.group(0)
            evidence = {
                "matched_pattern": "AWS_ACCESS_KEY",
                "value": redact(matched),
                "source_line": line_num,
            }
            return self._make_finding(file_path, line_num, "aws_key", evidence)

        # GitHub token
        m = _GH_TOKEN_RE.search(content)
        if m:
            matched = m.group(0)
            evidence = {
                "matched_pattern": "GITHUB_TOKEN",
                "value": redact(matched),
                "source_line": line_num,
            }
            return self._make_finding(file_path, line_num, "github_token", evidence)

        # High-entropy assignment to sensitive variable
        m = _SENSITIVE_VAR_RE.search(content)
        if m:
            var_name = m.group(1)
            value = m.group(2)
            if not _is_placeholder(value) and not _is_entropy_skip(value):
                entropy = _shannon_entropy(value)
                if entropy >= 4.5:
                    evidence = {
                        "matched_pattern": "HIGH_ENTROPY_ASSIGNMENT",
                        "variable": var_name,
                        "value": redact(value),
                        "entropy": round(entropy, 2),
                        "source_line": line_num,
                    }
                    return self._make_finding(file_path, line_num, "entropy", evidence)

        return None

    def _make_finding(
        self,
        file_path: str,
        line_num: int,
        pattern_key: str,
        evidence: dict,
    ) -> Finding:
        confidence = CONFIDENCE_MAP.get(pattern_key, self._meta.confidence)
        secret_type = evidence.get("matched_pattern", pattern_key).replace("_", " ").title()
        return build_finding(
            meta=self._meta,
            confidence=confidence,
            file_path=file_path,
            line_number=line_num,
            title=f"Exposed {secret_type} in {file_path}",
            evidence=evidence,
            template_vars={"secret_type": secret_type},
        )
