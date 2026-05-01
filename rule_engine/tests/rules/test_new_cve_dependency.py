from __future__ import annotations

from pathlib import Path

from conftest import make_context, make_dep
from rules.new_cve_dependency import NewCveDependencyRule

_CVE_DB = Path(__file__).parent.parent.parent / "config" / "cve_db.yaml"


def _rule() -> NewCveDependencyRule:
    return NewCveDependencyRule(cve_db_path=_CVE_DB)


# --- Fires on known-vulnerable samples ---

def test_fires_on_new_vulnerable_direct_dep():
    ctx = make_context(
        deps=[make_dep("requests", "2.19.0", old_version=None, ecosystem="pip", is_direct=True)],
        imports={"requirements.txt": ["requests"]},
    )
    findings = _rule().run(ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-003"
    assert findings[0].evidence["cve_id"] == "CVE-2023-32681"
    assert findings[0].evidence["package"] == "requests"
    assert findings[0].line_number is None
    assert findings[0].file_path == "dependencies"


def test_fires_on_version_change_to_vulnerable():
    ctx = make_context(
        deps=[make_dep("requests", "2.19.0", old_version="2.28.0", ecosystem="pip", is_direct=True)],
        imports={"app.py": ["requests"]},
    )
    findings = _rule().run(ctx)
    assert len(findings) == 1


def test_fires_on_npm_lodash():
    ctx = make_context(
        deps=[make_dep("lodash", "4.17.15", old_version=None, ecosystem="npm", is_direct=True)],
        imports={"index.js": ["lodash", "_"]},
    )
    findings = _rule().run(ctx)
    assert len(findings) == 1
    assert findings[0].evidence["cve_id"] == "CVE-2021-23337"


def test_fires_on_pyyaml_via_yaml_import():
    # pyyaml is imported as 'yaml' in Python — alias mapping must resolve this
    ctx = make_context(
        deps=[make_dep("pyyaml", "5.3.1", old_version=None, ecosystem="pip", is_direct=True)],
        imports={"app.py": ["yaml"]},
    )
    findings = _rule().run(ctx)
    assert len(findings) == 1
    assert findings[0].evidence["cve_id"] == "CVE-2020-1747"


# --- Does not fire on safe equivalents ---

def test_does_not_fire_on_transitive_dep():
    ctx = make_context(
        deps=[make_dep("requests", "2.19.0", old_version=None, ecosystem="pip", is_direct=False)],
        imports={"app.py": ["requests"]},
    )
    assert _rule().run(ctx) == []


def test_does_not_fire_if_not_imported():
    # Package is in deps but not imported in any changed file
    ctx = make_context(
        deps=[make_dep("requests", "2.19.0", old_version=None, ecosystem="pip", is_direct=True)],
        imports={},
    )
    assert _rule().run(ctx) == []


def test_does_not_fire_on_unaffected_version():
    ctx = make_context(
        deps=[make_dep("requests", "2.28.0", old_version=None, ecosystem="pip", is_direct=True)],
        imports={"app.py": ["requests"]},
    )
    assert _rule().run(ctx) == []


def test_does_not_fire_on_same_version_unchanged():
    # old_version == new_version and neither is empty → no change
    ctx = make_context(
        deps=[make_dep("requests", "2.19.0", old_version="2.19.0", ecosystem="pip", is_direct=True)],
        imports={"app.py": ["requests"]},
    )
    assert _rule().run(ctx) == []


def test_does_not_cross_ecosystem():
    # A "requests" package in npm is different from pip
    ctx = make_context(
        deps=[make_dep("requests", "2.19.0", old_version=None, ecosystem="npm", is_direct=True)],
        imports={"app.js": ["requests"]},
    )
    assert _rule().run(ctx) == []


# --- Schema correctness ---

def test_finding_has_none_line_number():
    ctx = make_context(
        deps=[make_dep("requests", "2.19.0", old_version=None, ecosystem="pip", is_direct=True)],
        imports={"app.py": ["requests"]},
    )
    findings = _rule().run(ctx)
    assert len(findings) == 1
    assert findings[0].line_number is None


def test_finding_file_path_is_dependencies():
    ctx = make_context(
        deps=[make_dep("requests", "2.19.0", old_version=None, ecosystem="pip", is_direct=True)],
        imports={"app.py": ["requests"]},
    )
    findings = _rule().run(ctx)
    assert len(findings) == 1
    assert findings[0].file_path == "dependencies"


# --- Malformed input ---

def test_handles_empty_context():
    assert _rule().run(make_context()) == []


# --- Isolation ---

def test_runs_in_isolation():
    rule = NewCveDependencyRule(cve_db_path=_CVE_DB)
    assert rule.metadata.id == "SEC-003"
    assert rule.metadata.severity == "high"
    ctx = make_context(
        deps=[make_dep("pyyaml", "5.3.1", old_version=None, ecosystem="pip", is_direct=True)],
        imports={"utils.py": ["yaml"]},
    )
    findings = rule.run(ctx)
    assert len(findings) == 1
