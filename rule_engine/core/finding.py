from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RuleMetadata:
    id: str
    name: str
    version: str
    severity: str
    confidence: float
    explanation_template: str
    enabled: bool


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    version: str
    severity: str
    confidence: float
    file_path: str
    line_number: int | None
    title: str
    explanation: str
    evidence: dict[str, Any]


@dataclass
class RuleExecutionError:
    rule_id: str
    rule_name: str
    error_type: str
    error_message: str
    duration_ms: float


@dataclass
class EngineResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[RuleExecutionError] = field(default_factory=list)


def build_finding(
    meta: RuleMetadata,
    confidence: float,
    file_path: str,
    line_number: int | None,
    title: str,
    evidence: dict[str, Any],
    template_vars: dict[str, Any] | None = None,
) -> Finding:
    """Construct a Finding from rule metadata, rendering the explanation template."""
    line_number_str = str(line_number) if line_number is not None else "N/A"
    explanation = meta.explanation_template.format_map(
        defaultdict(
            str,
            file_path=file_path,
            line_number=line_number_str,
            evidence=str(evidence),
            **(template_vars or {}),
        )
    )
    return Finding(
        rule_id=meta.id,
        rule_name=meta.name,
        version=meta.version,
        severity=meta.severity,
        confidence=confidence,
        file_path=file_path,
        line_number=line_number,
        title=title,
        explanation=explanation,
        evidence=evidence,
    )
