import pytest

from app.analysis.models.classification_models import FileCategory
from app.analysis.parser.file_classifier import classify_file


def test_auth_middleware():
    assert classify_file("src/middleware/auth.ts") == FileCategory.AUTH


def test_auth_jwt_service():
    assert classify_file("src/services/JWTService.ts") == FileCategory.AUTH


def test_auth_login_handler():
    assert classify_file("handlers/loginHandler.go") == FileCategory.AUTH


def test_auth_session_util():
    assert classify_file("utils/sessionUtils.py") == FileCategory.AUTH


def test_dependency_package_json():
    assert classify_file("package.json") == FileCategory.DEPENDENCY


def test_dependency_requirements_txt():
    assert classify_file("requirements.txt") == FileCategory.DEPENDENCY


def test_dependency_pyproject():
    assert classify_file("pyproject.toml") == FileCategory.DEPENDENCY


def test_dependency_yarn_lock():
    assert classify_file("yarn.lock") == FileCategory.DEPENDENCY


def test_config_env():
    assert classify_file(".env") == FileCategory.CONFIG


def test_config_env_production():
    assert classify_file(".env.production") == FileCategory.CONFIG


def test_config_yaml():
    assert classify_file("config/settings.yaml") == FileCategory.CONFIG


def test_config_ini():
    assert classify_file("app.ini") == FileCategory.CONFIG


def test_test_jest():
    assert classify_file("src/__tests__/foo.test.ts") == FileCategory.TEST


def test_test_python():
    assert classify_file("tests/test_parser.py") == FileCategory.TEST


def test_test_spec_js():
    assert classify_file("src/components/Button.spec.js") == FileCategory.TEST


def test_test_go():
    assert classify_file("pkg/auth/auth_test.go") == FileCategory.TEST


def test_ci_cd_github_workflow():
    assert classify_file(".github/workflows/ci.yml") == FileCategory.CI_CD


def test_ci_cd_dockerfile():
    assert classify_file("Dockerfile") == FileCategory.CI_CD


def test_database_migration():
    assert classify_file("migrations/0001_initial.sql") == FileCategory.DATABASE


def test_database_sql_file():
    assert classify_file("scripts/seed.sql") == FileCategory.DATABASE


def test_api_routes():
    assert classify_file("src/routes/users.ts") == FileCategory.API


def test_api_views():
    assert classify_file("views.py") == FileCategory.API


def test_frontend_component():
    assert classify_file("src/components/Button.tsx") == FileCategory.FRONTEND


def test_frontend_vue():
    assert classify_file("src/views/Home.vue") == FileCategory.FRONTEND


def test_unknown_readme():
    assert classify_file("README.md") == FileCategory.UNKNOWN


def test_unknown_makefile():
    assert classify_file("Makefile") == FileCategory.UNKNOWN


def test_test_beats_auth_priority():
    # Test file inside auth directory — test must win
    assert classify_file("src/auth/__tests__/login.test.ts") == FileCategory.TEST


def test_case_insensitive_auth():
    assert classify_file("src/AUTH/middleware.py") == FileCategory.AUTH
