from __future__ import annotations

import time

from core.context import AnalysisContext
from core.finding import EngineResult, Finding, RuleExecutionError
from core.rule import Rule


class RuleEngine:
    def __init__(self, rules: list[Rule]) -> None:
        self._rules = rules

    def run(self, context: AnalysisContext) -> EngineResult:
        findings: list[Finding] = []
        errors: list[RuleExecutionError] = []

        for rule in self._rules:
            start = time.time()
            try:
                for f in rule.run(context) or []:
                    if isinstance(f, Finding):
                        findings.append(f)
            except Exception as exc:
                meta = getattr(rule, "_meta", None)
                errors.append(
                    RuleExecutionError(
                        rule_id=getattr(meta, "id", "UNKNOWN"),
                        rule_name=getattr(meta, "name", type(rule).__name__),
                        error_type=type(exc).__name__,
                        error_message=str(exc),
                        duration_ms=round((time.time() - start) * 1000, 2),
                    )
                )

        return EngineResult(findings=findings, errors=errors)
