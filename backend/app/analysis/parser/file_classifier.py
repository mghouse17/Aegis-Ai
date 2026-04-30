from __future__ import annotations

from pathlib import PurePosixPath

from app.analysis.classifier.taxonomy import AUTH_KEYWORDS, DEPENDENCY_FILENAMES
from app.analysis.models.classification_models import FileCategory

_CI_CD_PATH_PREFIXES = (
    ".github/workflows/",
    ".gitlab-ci",
    ".circleci/",
)

_CI_CD_FILENAMES = {"dockerfile", "docker-compose.yml", "docker-compose.yaml", "jenkinsfile"}

_DATABASE_KEYWORDS = {"migrations", "migration", "schema", "repository", "orm"}
_DATABASE_PATH_KEYWORDS = {"db", "models"}

_API_PATH_KEYWORDS = {"routes", "controllers", "endpoints", "handlers", "api"}
_API_FILENAMES = {"views.py", "urls.py"}

_FRONTEND_SUFFIXES = {".jsx", ".tsx", ".vue", ".svelte"}
_FRONTEND_PATH_KEYWORDS = {"components", "pages"}

_DOC_FILENAMES = {"readme", "changelog", "contributing"}
_DOC_SUFFIXES = {".md", ".markdown", ".mdx", ".rst"}


def classify_file(file_path: str) -> FileCategory:
    p = PurePosixPath(file_path)
    lower_path = file_path.lower()
    lower_name = p.name.lower()
    lower_parts = {part.lower() for part in p.parts}
    lower_suffix = p.suffix.lower()

    if _is_test(lower_path, lower_name, lower_parts):
        return FileCategory.TEST

    if _is_docs(lower_path, lower_name, lower_parts, lower_suffix):
        return FileCategory.DOCS

    if lower_name in DEPENDENCY_FILENAMES:
        return FileCategory.DEPENDENCY

    if _is_ci_cd(lower_path, lower_name):
        return FileCategory.CI_CD

    if _is_auth(lower_path, lower_name, lower_parts):
        return FileCategory.AUTH

    if _is_config(lower_path, lower_name, lower_suffix):
        return FileCategory.CONFIG

    if _is_database(lower_path, lower_name, lower_parts, lower_suffix):
        return FileCategory.DATABASE

    if _is_api(lower_path, lower_name, lower_parts):
        return FileCategory.API

    if _is_frontend(lower_path, lower_suffix, lower_parts):
        return FileCategory.FRONTEND

    return FileCategory.UNKNOWN


def _is_test(lower_path: str, lower_name: str, lower_parts: set[str]) -> bool:
    test_parts = {"test", "tests", "__tests__", "spec"}
    if lower_parts & test_parts:
        return True
    for suffix in (
        ".test.ts", ".test.js", ".test.tsx", ".test.jsx", ".test.py",
        ".spec.ts", ".spec.js", ".spec.tsx", ".spec.jsx", ".spec.py",
    ):
        if lower_name.endswith(suffix):
            return True
    if lower_name.endswith("_test.go") or lower_name.endswith("_test.py"):
        return True
    if lower_name.startswith("test_") and lower_name.endswith(".py"):
        return True
    return False


def _is_docs(lower_path: str, lower_name: str, lower_parts: set[str], lower_suffix: str) -> bool:
    if lower_suffix in _DOC_SUFFIXES:
        return True
    if lower_parts & {"docs", "doc", "documentation"}:
        return True
    if PurePosixPath(lower_name).stem in _DOC_FILENAMES:
        return True
    return False


def _is_auth(lower_path: str, lower_name: str, lower_parts: set[str]) -> bool:
    for part in lower_parts:
        for keyword in AUTH_KEYWORDS:
            if keyword in part:
                return True
    return False


def _is_config(lower_path: str, lower_name: str, lower_suffix: str) -> bool:
    if lower_name == ".env" or lower_name.startswith(".env."):
        return True
    if lower_name in {"config.py", "settings.py"}:
        return True
    if lower_suffix in (".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"):
        return True
    if "config/" in lower_path or "/config/" in lower_path or lower_path.startswith("config/"):
        return True
    if "settings/" in lower_path or "/settings/" in lower_path or lower_path.startswith("settings/"):
        return True
    if lower_name.endswith(".config.js") or lower_name.endswith(".config.ts"):
        return True
    return False


def _is_ci_cd(lower_path: str, lower_name: str) -> bool:
    for prefix in _CI_CD_PATH_PREFIXES:
        if lower_path.startswith(prefix):
            return True
    if lower_name in _CI_CD_FILENAMES:
        return True
    return False


def _is_database(lower_path: str, lower_name: str, lower_parts: set[str], lower_suffix: str) -> bool:
    if lower_suffix == ".sql":
        return True
    for part in lower_parts:
        if part in _DATABASE_KEYWORDS:
            return True
        if part in _DATABASE_PATH_KEYWORDS:
            return True
    return False


def _is_api(lower_path: str, lower_name: str, lower_parts: set[str]) -> bool:
    if lower_name in _API_FILENAMES:
        return True
    for part in lower_parts:
        if part in _API_PATH_KEYWORDS:
            return True
    return False


def _is_frontend(lower_path: str, lower_suffix: str, lower_parts: set[str]) -> bool:
    if lower_suffix in _FRONTEND_SUFFIXES:
        return True
    for part in lower_parts:
        if part in _FRONTEND_PATH_KEYWORDS:
            return True
    if "src/ui/" in lower_path:
        return True
    return False
