from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from app.analysis.models.diff_models import Hunk


class FileCategory(str, Enum):
    AUTH = "auth"
    DEPENDENCY = "dependency"
    CONFIG = "config"
    TEST = "test"
    DOCS = "docs"
    API = "api"
    DATABASE = "database"
    CI_CD = "ci_cd"
    FRONTEND = "frontend"
    UNKNOWN = "unknown"


class ChangeType(str, Enum):
    NEW_FUNCTION = "new_function"
    MODIFIED_FUNCTION = "modified_function"
    AUTH_LOGIC_CHANGED = "auth_logic_changed"
    DEPENDENCY_ADDED = "dependency_added"
    DEPENDENCY_REMOVED = "dependency_removed"
    CONFIG_CHANGE = "config_change"
    CI_CD_CHANGE = "ci_cd_change"
    DOCS_CHANGE = "docs_change"
    SECRET_REFERENCE = "secret_reference"
    TEST_ONLY_CHANGE = "test_only_change"
    UNKNOWN = "unknown"


@dataclass
class FileClassification:
    file_path: str
    file_category: FileCategory
    is_test_only: bool
    hunks: list[Hunk] = field(default_factory=list)
    added_lines: list[tuple[int, str]] = field(default_factory=list)
    removed_lines: list[tuple[int, str]] = field(default_factory=list)
    change_types: list[ChangeType] = field(default_factory=list)
    change_confidence: dict[str, str] = field(default_factory=dict)
    security_signals: list[str] = field(default_factory=list)
    dependency_changes: list[dict] = field(default_factory=list)
    risk_score: int = 0
    should_create_security_finding: bool = False
    audit_log_only: bool = False
    parsing_truncated: bool = False

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "file_category": self.file_category.value,
            "is_test_only": self.is_test_only,
            "hunks": [
                {
                    "header": h.header,
                    "old_start": h.old_start,
                    "old_count": h.old_count,
                    "new_start": h.new_start,
                    "new_count": h.new_count,
                    "added_lines": h.added_lines,
                    "removed_lines": h.removed_lines,
                    "context_lines": h.context_lines,
                }
                for h in self.hunks
            ],
            "added_lines": self.added_lines,
            "removed_lines": self.removed_lines,
            "change_types": [ct.value for ct in self.change_types],
            "change_confidence": self.change_confidence,
            "security_signals": self.security_signals,
            "dependency_changes": self.dependency_changes,
            "risk_score": self.risk_score,
            "should_create_security_finding": self.should_create_security_finding,
            "audit_log_only": self.audit_log_only,
            "parsing_truncated": self.parsing_truncated,
        }
