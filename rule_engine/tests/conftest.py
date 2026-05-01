from __future__ import annotations

from core.context import AnalysisContext, ChangedFile, DependencyChange


def make_added_diff(lines: list[str], start_line: int = 1) -> str:
    count = len(lines)
    header = f"@@ -1,1 +{start_line},{count} @@\n"
    return header + "\n".join(f"+{line}" for line in lines)


def make_removed_diff(lines: list[str], start_line: int = 1) -> str:
    count = len(lines)
    header = f"@@ -{start_line},{count} +1,1 @@\n"
    return header + "\n".join(f"-{line}" for line in lines)


def make_mixed_diff(removed: list[str], added: list[str], start_line: int = 1) -> str:
    r_count = len(removed)
    a_count = len(added)
    header = f"@@ -{start_line},{r_count} +{start_line},{a_count} @@\n"
    body = "\n".join(f"-{line}" for line in removed)
    if removed and added:
        body += "\n"
    body += "\n".join(f"+{line}" for line in added)
    return header + body


def make_file(
    path: str = "app.py",
    language: str = "python",
    diff: str = "",
    old_content: str = "",
    new_content: str = "",
) -> ChangedFile:
    return ChangedFile(
        path=path,
        language=language,
        old_content=old_content,
        new_content=new_content or diff,
        diff=diff,
    )


def make_context(
    files: list[dict] | None = None,
    deps: list[dict] | None = None,
    imports: dict | None = None,
) -> AnalysisContext:
    return AnalysisContext(
        repo_path="/fake/repo",
        changed_files=[ChangedFile(**f) for f in (files or [])],
        dependency_changes=[DependencyChange(**d) for d in (deps or [])],
        imports_by_file=imports or {},
    )


def make_dep(
    package: str,
    new_version: str,
    old_version: str = "",
    ecosystem: str = "pip",
    is_direct: bool = True,
) -> dict:
    return dict(
        package_name=package,
        new_version=new_version,
        old_version=old_version,
        ecosystem=ecosystem,
        is_direct=is_direct,
    )
