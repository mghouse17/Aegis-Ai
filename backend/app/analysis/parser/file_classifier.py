from __future__ import annotations

from pathlib import PurePosixPath

from app.analysis.models.classification_models import FileCategory

_DEPENDENCY_FILENAMES = {
    "package.json",
    "requirements.txt",
    "pipfile",
    "pyproject.toml",
    "go.mod",
    "cargo.toml",
    "yarn.lock",
    "package-lock.json",
    "poetry.lock",
    "gemfile",
    "composer.json",
    "pom.xml",
    "build.gradle",
}

# "middleware" and "access" removed: too broad — CORS/rate-limit/logging middleware
# and access-log utilities were incorrectly classified as AUTH.
_AUTH_KEYWORDS = {
    "auth",
    "oauth",
    "jwt",
    "login",
    "logout",
    "session",
    "token",
    "password",
    "permission",
    "role",
    "guard",
    "credential",
    "authorize",
    "authenticate",
}

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

_DOC_SUFFIXES = {".md", ".markdown", ".mdx", ".rst"}
_DOC_FILENAMES = {"readme", "changelog", "license", "contributing", "authors", "notice"}
_DOC_DIRS = {"docs", "doc", "documentation"}


def classify_file(file_path: str) -> FileCategory:
    p = PurePosixPath(file_path)
    lower_path = file_path.lower()
    lower_name = p.name.lower()
    lower_parts = {part.lower() for part in p.parts}
    lower_suffix = p.suffix.lower()

    # 1. Test — must run before auth since test files may live in auth directories
    if _is_test(lower_path, lower_name, lower_parts):
        return FileCategory.TEST

    # 2. Docs — must run before auth so docs/auth/overview.md doesn't become AUTH
    if _is_docs(lower_name, lower_suffix, lower_parts):
        return FileCategory.DOCS

    # 3. Auth
    if _is_auth(lower_parts):
        return FileCategory.AUTH

    # 4. Dependency (exact filename match)
    if lower_name in _DEPENDENCY_FILENAMES:
        return FileCategory.DEPENDENCY

    # 5. CI/CD — must run before Config so .github/workflows/*.yml doesn't match yaml rule
    if _is_ci_cd(lower_path, lower_name):
        return FileCategory.CI_CD

    # 6. Config
    if _is_config(lower_path, lower_name, lower_suffix):
        return FileCategory.CONFIG

    # 7. Database
    if _is_database(lower_parts, lower_suffix):
        return FileCategory.DATABASE

    # 8. API
    if _is_api(lower_name, lower_parts):
        return FileCategory.API

    # 9. Frontend
    if _is_frontend(lower_path, lower_suffix, lower_parts):
        return FileCategory.FRONTEND

    return FileCategory.UNKNOWN


def _is_test(lower_path: str, lower_name: str, lower_parts: set[str]) -> bool:
    test_parts = {"test", "tests", "__tests__", "spec"}
    if lower_parts & test_parts:
        return True
    for suffix in (".test.ts", ".test.js", ".test.tsx", ".test.jsx", ".test.py",
                   ".spec.ts", ".spec.js", ".spec.tsx", ".spec.jsx"):
        if lower_name.endswith(suffix):
            return True
    if lower_name.endswith("_test.go"):
        return True
    if lower_name.startswith("test_") and lower_name.endswith(".py"):
        return True
    return False


def _is_docs(lower_name: str, lower_suffix: str, lower_parts: set[str]) -> bool:
    if lower_suffix in _DOC_SUFFIXES:
        return True
    if PurePosixPath(lower_name).stem in _DOC_FILENAMES:
        return True
    return bool(lower_parts & _DOC_DIRS)


def _is_auth(lower_parts: set[str]) -> bool:
    for part in lower_parts:
        for keyword in _AUTH_KEYWORDS:
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


def _is_database(lower_parts: set[str], lower_suffix: str) -> bool:
    if lower_suffix == ".sql":
        return True
    for part in lower_parts:
        if part in _DATABASE_KEYWORDS:
            return True
        if part in _DATABASE_PATH_KEYWORDS:
            return True
    return False


def _is_api(lower_name: str, lower_parts: set[str]) -> bool:
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
