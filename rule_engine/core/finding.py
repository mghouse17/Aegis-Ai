from __future__ import annotations

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
