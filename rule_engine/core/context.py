from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ChangedFile:
    path: str
    language: str
    old_content: str
    new_content: str
    diff: str


@dataclass
class DependencyChange:
    package_name: str
    old_version: str
    new_version: str
    ecosystem: str
    is_direct: bool


@dataclass
class AnalysisContext:
    repo_path: str
    changed_files: list[ChangedFile] = field(default_factory=list)
    dependency_changes: list[DependencyChange] = field(default_factory=list)
    imports_by_file: dict[str, list[str]] = field(default_factory=dict)
