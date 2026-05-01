from __future__ import annotations

from dataclasses import dataclass, field
from functools import cached_property


@dataclass
class ChangedFile:
    path: str
    old_content: str
    new_content: str
    diff: str
    # TODO(v2): used for language-aware rule filtering; no rule reads this in v1
    language: str = ""


@dataclass
class DependencyChange:
    package_name: str
    # None means this is a newly added dependency (no previous version)
    old_version: str | None
    new_version: str
    ecosystem: str
    is_direct: bool


@dataclass
class AnalysisContext:
    repo_path: str
    changed_files: list[ChangedFile] = field(default_factory=list)
    dependency_changes: list[DependencyChange] = field(default_factory=list)
    imports_by_file: dict[str, list[str]] = field(default_factory=dict)

    @cached_property
    def all_imports(self) -> frozenset[str]:
        """Flat set of all import names across every file in this context."""
        return frozenset(
            name
            for imports in self.imports_by_file.values()
            for name in imports
        )
