from __future__ import annotations

import re
from pathlib import PurePosixPath

from app.analysis.models.diff_models import ParsedFile


def extract_dependency_changes(parsed_file: ParsedFile) -> list[dict]:
    filename = PurePosixPath(parsed_file.file_path).name.lower()
    if filename == "requirements.txt":
        return _extract_requirements_changes(parsed_file.added_lines)
    if filename == "package.json":
        return _extract_package_json_changes(parsed_file.added_lines)
    return []


def _extract_requirements_changes(added_lines: list[tuple[int, str]]) -> list[dict]:
    seen: dict[tuple[str, str], dict] = {}
    requirement_re = re.compile(r"^\s*([A-Za-z0-9_.-]+)==([^\s#]+)")
    for line_num, content in added_lines:
        match = requirement_re.match(content)
        if not match:
            continue
        package = match.group(1)
        version = match.group(2).rstrip(",")
        key = (package.lower(), version)
        if key not in seen:
            seen[key] = {
                "package": package,
                "version": version,
                "manager": "pip",
                "line": line_num,
            }
    return list(seen.values())


def _extract_package_json_changes(added_lines: list[tuple[int, str]]) -> list[dict]:
    seen: dict[tuple[str, str], dict] = {}
    package_re = re.compile(r'^\s*"([^"]+)"\s*:\s*"([^"]+)"\s*,?\s*$')
    ignored_keys = {
        "name",
        "version",
        "description",
        "main",
        "scripts",
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    }
    for line_num, content in added_lines:
        match = package_re.match(content)
        if not match:
            continue
        package, version = match.groups()
        if package in ignored_keys:
            continue
        key = (package.lower(), version)
        if key not in seen:
            seen[key] = {
                "package": package,
                "version": version,
                "manager": "npm",
                "line": line_num,
            }
    return list(seen.values())
