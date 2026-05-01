from __future__ import annotations

from conftest import make_added_diff, make_context, make_file, make_removed_diff, make_mixed_diff
from rules.auth_bypass import AuthBypassRule, _normalize


def _rule() -> AuthBypassRule:
    return AuthBypassRule()


# --- Fires on known-vulnerable samples ---

def test_fires_on_removed_decorator():
    diff = make_removed_diff(["@requires_auth"])
    ctx = make_context(files=[{
        "path": "views.py", "language": "python",
        "old_content": "@requires_auth\ndef view(): pass",
        "new_content": "def view(): pass",
        "diff": diff,
    }])
    findings = _rule().run(ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-004"
    assert findings[0].evidence["bypass_type"] == "deleted"
    assert findings[0].confidence == 0.90


def test_fires_on_removed_login_required():
    diff = make_removed_diff(["@login_required"])
    ctx = make_context(files=[{
        "path": "views.py", "language": "python",
        "old_content": "@login_required\ndef profile(): pass",
        "new_content": "def profile(): pass",
        "diff": diff,
    }])
    findings = _rule().run(ctx)
    assert len(findings) == 1


def test_fires_on_removed_permission_check():
    diff = make_removed_diff(["    if not user.has_permission(action): raise PermissionError"])
    ctx = make_context(files=[{
        "path": "api.py", "language": "python",
        "old_content": "if not user.has_permission(action): raise PermissionError",
        "new_content": "pass",
        "diff": diff,
    }])
    findings = _rule().run(ctx)
    assert len(findings) == 1


def test_fires_on_commented_out_role_check():
    # Auth check is added as a comment — this is a commented-out bypass
    diff = make_added_diff(['    # require_role("admin")'])
    ctx = make_context(files=[{
        "path": "views.py", "language": "python",
        "old_content": '    require_role("admin")',
        "new_content": '    # require_role("admin")',
        "diff": diff,
    }])
    findings = _rule().run(ctx)
    assert len(findings) == 1
    assert findings[0].evidence["bypass_type"] == "commented_out"
    assert findings[0].confidence == 0.85


def test_fires_on_commented_requires_auth():
    diff = make_added_diff(["    # @requires_auth"])
    ctx = make_context(files=[{
        "path": "views.py", "language": "python",
        "old_content": "    @requires_auth",
        "new_content": "    # @requires_auth",
        "diff": diff,
    }])
    findings = _rule().run(ctx)
    assert len(findings) == 1


# --- Does not fire on safe equivalents ---

def test_does_not_fire_on_moved_auth_check():
    # The decorator was removed from one place but exists elsewhere in new_content
    diff = make_removed_diff(["@requires_auth"])
    ctx = make_context(files=[{
        "path": "views.py", "language": "python",
        "old_content": "@requires_auth\ndef view(): pass",
        # still present in new content (moved, not removed)
        "new_content": "class View:\n    @requires_auth\n    def get(self): pass",
        "diff": diff,
    }])
    assert _rule().run(ctx) == []


def test_does_not_fire_on_reformatted_check():
    # Quote style changed: "admin" → 'admin' — normalized comparison handles this
    diff = make_removed_diff(['    require_role("admin")'])
    ctx = make_context(files=[{
        "path": "views.py", "language": "python",
        "old_content": '    require_role("admin")',
        # same check but with single quotes — should be treated as same check (moved)
        "new_content": "    require_role('admin')",
        "diff": diff,
    }])
    assert _rule().run(ctx) == []


def test_does_not_fire_on_unrelated_removal():
    diff = make_removed_diff(["    x = compute_value()"])
    ctx = make_context(files=[{
        "path": "views.py", "language": "python",
        "old_content": "x = compute_value()",
        "new_content": "",
        "diff": diff,
    }])
    assert _rule().run(ctx) == []


# --- Malformed input ---

def test_handles_empty_diff():
    ctx = make_context(files=[{
        "path": "app.py", "language": "python",
        "old_content": "", "new_content": "", "diff": "",
    }])
    assert _rule().run(ctx) == []


def test_handles_empty_context():
    assert _rule().run(make_context()) == []


# --- Direct utility tests for _normalize ---

def test_normalize_strips_leading_trailing_whitespace():
    assert _normalize("  @requires_auth  ") == "@requires_auth"


def test_normalize_collapses_internal_spaces():
    assert _normalize("require_role(  'admin'  )") == "require_role( 'admin' )"


def test_normalize_unifies_double_quotes_to_single():
    assert _normalize('require_role("admin")') == "require_role('admin')"


def test_normalize_empty_string():
    assert _normalize("") == ""


def test_normalize_whitespace_only():
    assert _normalize("   ") == ""


# --- Isolation ---

def test_runs_in_isolation():
    rule = AuthBypassRule()
    assert rule.metadata.id == "SEC-004"
    assert rule.metadata.severity == "critical"
    diff = make_removed_diff(["@requires_auth"])
    file = make_file(diff=diff, old_content="@requires_auth", new_content="")
    from core.context import AnalysisContext
    ctx = AnalysisContext(repo_path="/r", changed_files=[file])
    findings = rule.run(ctx)
    assert len(findings) == 1
