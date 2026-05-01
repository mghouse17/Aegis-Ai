from __future__ import annotations

from pathlib import Path

import pytest

from conftest import make_added_diff, make_context, make_dep, make_removed_diff
from core.context import AnalysisContext, ChangedFile, DependencyChange
from core.engine import RuleEngine
from core.finding import EngineResult
from core.loader import load_rules

_CONFIG_PATH = Path(__file__).parent.parent / "config" / "rules.yaml"


def _engine() -> RuleEngine:
    return RuleEngine(load_rules(_CONFIG_PATH))


@pytest.mark.parametrize(
    ("rule_id", "context"),
    [
        (
            "SEC-001",
            make_context(files=[{
                "path": "config.py",
                "language": "python",
                "old_content": "",
                "new_content": make_added_diff(["AWS_KEY = 'AKIAIOSFODNN7EXAMPLEABCD'"]),
                "diff": make_added_diff(["AWS_KEY = 'AKIAIOSFODNN7EXAMPLEABCD'"]),
            }]),
        ),
        (
            "SEC-002",
            make_context(files=[{
                "path": "auth.py",
                "language": "python",
                "old_content": "",
                "new_content": make_added_diff(["password = 'supersecret123'"]),
                "diff": make_added_diff(["password = 'supersecret123'"]),
            }]),
        ),
        (
            "SEC-003",
            make_context(
                deps=[make_dep("requests", "2.19.0", old_version=None, ecosystem="pip", is_direct=True)],
                imports={"requirements.txt": ["requests"]},
            ),
        ),
        (
            "SEC-004",
            make_context(files=[{
                "path": "views.py",
                "language": "python",
                "old_content": "@requires_auth\ndef profile(): pass",
                "new_content": "def profile(): pass",
                "diff": make_removed_diff(["@requires_auth"]),
            }]),
        ),
        (
            "SEC-005",
            make_context(files=[{
                "path": "app.py",
                "language": "python",
                "old_content": "",
                "new_content": make_added_diff(["result = eval(request.args.get('expr'))"]),
                "diff": make_added_diff(["result = eval(request.args.get('expr'))"]),
            }]),
        ),
    ],
)
def test_each_configured_rule_fires_on_known_vulnerable_sample(rule_id, context):
    result = _engine().run(context)

    assert result.errors == []
    assert rule_id in {finding.rule_id for finding in result.findings}


@pytest.mark.parametrize(
    ("rule_id", "context"),
    [
        (
            "SEC-001",
            make_context(files=[{
                "path": "config.py",
                "language": "python",
                "old_content": "",
                "new_content": make_added_diff(["api_key = '550e8400-e29b-41d4-a716-446655440000'"]),
                "diff": make_added_diff(["api_key = '550e8400-e29b-41d4-a716-446655440000'"]),
            }]),
        ),
        (
            "SEC-002",
            make_context(files=[{
                "path": "auth.py",
                "language": "python",
                "old_content": "",
                "new_content": make_added_diff(["password = os.environ.get('DB_PASSWORD')"]),
                "diff": make_added_diff(["password = os.environ.get('DB_PASSWORD')"]),
            }]),
        ),
        (
            "SEC-003",
            make_context(
                deps=[make_dep("requests", "2.28.0", old_version=None, ecosystem="pip", is_direct=True)],
                imports={"app.py": ["requests"]},
            ),
        ),
        (
            "SEC-004",
            make_context(files=[{
                "path": "views.py",
                "language": "python",
                "old_content": "@requires_auth\ndef profile(): pass",
                "new_content": "class Profile:\n    @requires_auth\n    def get(self): pass",
                "diff": make_removed_diff(["@requires_auth"]),
            }]),
        ),
        (
            "SEC-005",
            make_context(files=[{
                "path": "app.py",
                "language": "python",
                "old_content": "",
                "new_content": make_added_diff(["exec('print(\"hello\")')"]),
                "diff": make_added_diff(["exec('print(\"hello\")')"]),
            }]),
        ),
    ],
)
def test_each_configured_rule_does_not_fire_on_known_safe_equivalent(rule_id, context):
    result = _engine().run(context)

    assert result.errors == []
    assert rule_id not in {finding.rule_id for finding in result.findings}


def test_rule_engine_handles_malformed_input_without_crashing():
    malformed_context = AnalysisContext(
        repo_path="/fake/repo",
        changed_files=[
            ChangedFile(
                path="broken.py",
                old_content="",
                new_content="",
                diff=None,  # type: ignore[arg-type]
                language="python",
            )
        ],
        dependency_changes=[
            DependencyChange(
                package_name=None,  # type: ignore[arg-type]
                old_version=None,
                new_version=None,  # type: ignore[arg-type]
                ecosystem=None,  # type: ignore[arg-type]
                is_direct=True,
            )
        ],
        imports_by_file={"broken.py": ["requests"]},
    )

    result = _engine().run(malformed_context)

    assert isinstance(result, EngineResult)
    assert isinstance(result.findings, list)
    assert isinstance(result.errors, list)
