from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Hunk:
    header: str
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    added_lines: list[tuple[int, str]] = field(default_factory=list)
    removed_lines: list[tuple[int, str]] = field(default_factory=list)
    context_lines: list[tuple[int, str]] = field(default_factory=list)


@dataclass
class ParsedFile:
    file_path: str
    status: str
    language: str | None
    hunks: list[Hunk] = field(default_factory=list)
    added_lines: list[tuple[int, str]] = field(default_factory=list)
    removed_lines: list[tuple[int, str]] = field(default_factory=list)
    parsing_truncated: bool = False


@dataclass
class ChangedFileInput:
    filename: str
    status: str
    patch: str | None = None
    language: str | None = None
