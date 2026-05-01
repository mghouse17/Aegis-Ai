from __future__ import annotations

import re
from collections import defaultdict

from core._diff_utils import extract_added_lines
from core.context import AnalysisContext
from core.finding import Finding, RuleMetadata
from core.rule import Rule

# Dangerous sinks — execution or data sinks that are risky with user input
_SINK_PATTERNS = [
    "exec(",
    "eval(",
    "os.system(",
    "subprocess.call(",
    "subprocess.run(",
    "subprocess.Popen(",
    "cursor.execute(",
    "db.execute(",
]

# User-controlled input sources
_SOURCE_PATTERNS = [
    "request.form",
    "request.args",
    "request.GET",
    "request.POST",
    "request.data",
    "request.json",
    "request.params",
    "query_params",
    "user_input",
    "sys.argv",
]

# Raw SQL with f-string or string concatenation — always dangerous
_RAW_SQL_FSTRING_RE = re.compile(
    r"(cursor|db)\.execute\s*\(\s*f[\"']",
    re.IGNORECASE,
)
_RAW_SQL_CONCAT_RE = re.compile(
    r"(cursor|db)\.execute\s*\(\s*[\"'][^\"']*[\"'].*\+",
    re.IGNORECASE,
)

# Variable assignment from a user input source
_SOURCE_ASSIGN_RE = re.compile(
    r"\s*(\w+)\s*=\s*(?:request\.[\w\.]+|query_params|user_input|sys\.argv)",
)

CONFIDENCE_MAP = {
    "same_line": 0.90,
    "within_3": 0.85,
    "within_5": 0.70,
    "raw_sql_fstring": 0.85,
}

_PROXIMITY_WINDOW = 5


def _extract_var_name(line: str) -> str | None:
    """Extract variable name from a user-input source assignment line."""
    m = _SOURCE_ASSIGN_RE.match(line)
    return m.group(1) if m else None


class DangerousSinkRule(Rule):
    DEFAULT_METADATA = RuleMetadata(
        id="SEC-005",
        name="Dangerous Sink Reachability",
        version="1.0.0",
        severity="high",
        confidence=0.85,
        explanation_template=(
            "User-controlled input appears to reach a dangerous sink ({sink}) in "
            "{file_path} at line {line_number}. Evidence: {evidence}"
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

    def _scan_file(self, file) -> list[Finding]:  # noqa: C901
        findings: list[Finding] = []
        added = extract_added_lines(file.diff)

        # Collect sink and source positions
        sink_lines: list[tuple[int, str, str]] = []   # (line_num, content, sink_name)
        source_lines: list[tuple[int, str, str | None]] = []  # (line_num, content, var_name)
        raw_sql_lines: list[tuple[int, str]] = []

        for line_num, content in added:
            # Check for raw SQL patterns first (always report)
            if _RAW_SQL_FSTRING_RE.search(content) or _RAW_SQL_CONCAT_RE.search(content):
                raw_sql_lines.append((line_num, content))

            # Collect sinks
            for sink in _SINK_PATTERNS:
                if sink in content:
                    sink_lines.append((line_num, content, sink))
                    break

            # Collect sources
            for source in _SOURCE_PATTERNS:
                if source in content:
                    var_name = _extract_var_name(content)
                    source_lines.append((line_num, content, var_name))
                    break

        # Report raw SQL findings
        for line_num, content in raw_sql_lines:
            evidence = {
                "sink": "cursor/db.execute",
                "pattern": "raw_sql_injection",
                "sink_line": line_num,
                "content": content.strip()[:120],
            }
            findings.append(
                self._make_finding(file.path, line_num, "raw_sql_fstring", evidence)
            )

        # Check proximity + variable bridge for source→sink
        seen: set[tuple[int, int]] = set()
        for src_num, src_content, var_name in source_lines:
            for sink_num, sink_content, sink_name in sink_lines:
                distance = abs(sink_num - src_num)
                if distance > _PROXIMITY_WINDOW:
                    continue

                # Require variable bridge OR same line
                if distance > 0 and var_name and var_name not in sink_content:
                    continue
                if distance > 0 and not var_name and src_num not in sink_content:
                    continue

                key = (src_num, sink_num)
                if key in seen:
                    continue
                seen.add(key)

                if distance == 0:
                    confidence_key = "same_line"
                elif distance <= 3:
                    confidence_key = "within_3"
                else:
                    confidence_key = "within_5"

                # Avoid double-reporting if also caught by raw_sql
                if any(sink_num == rln for rln, _ in raw_sql_lines):
                    continue

                evidence = {
                    "sink": sink_name,
                    "source": next(s for s in _SOURCE_PATTERNS if s in src_content),
                    "sink_line": sink_num,
                    "source_line": src_num,
                    "window": distance,
                }
                findings.append(
                    self._make_finding(file.path, sink_num, confidence_key, evidence)
                )

        return findings

    def _make_finding(
        self, file_path: str, line_num: int, confidence_key: str, evidence: dict
    ) -> Finding:
        confidence = CONFIDENCE_MAP.get(confidence_key, self._meta.confidence)
        sink = evidence.get("sink", "dangerous sink")
        explanation = self._meta.explanation_template.format_map(
            defaultdict(
                str,
                sink=sink,
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
            title=f"User input reaches {sink} in {file_path}",
            explanation=explanation,
            evidence=evidence,
        )
