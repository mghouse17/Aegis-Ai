from __future__ import annotations

from conftest import make_added_diff, make_context, make_file
from rules.dangerous_sink import DangerousSinkRule


def _rule() -> DangerousSinkRule:
    return DangerousSinkRule()


def _ctx(lines: list[str], path: str = "app.py") -> object:
    diff = make_added_diff(lines)
    return make_context(files=[{
        "path": path, "language": "python",
        "old_content": "", "new_content": diff, "diff": diff,
    }])


# --- Fires on known-vulnerable samples ---

def test_fires_on_eval_with_input_same_line():
    ctx = _ctx(["result = eval(request.args.get('expr'))"])
    findings = _rule().run(ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-005"
    assert findings[0].confidence == 0.90  # same_line
    assert findings[0].evidence["sink"] == "eval("


def test_fires_on_exec_with_variable_bridge():
    # user_input assigned on line 1, exec uses it on line 2
    ctx = _ctx([
        "user_cmd = request.args.get('cmd')",
        "exec(user_cmd)",
    ])
    findings = _rule().run(ctx)
    assert len(findings) == 1
    assert findings[0].evidence["sink"] == "exec("
    assert findings[0].evidence["window"] == 1
    assert findings[0].confidence == 0.85  # within_3


def test_fires_on_os_system_with_bridge():
    ctx = _ctx([
        "cmd = request.form.get('command')",
        "import os",
        "os.system(cmd)",
    ])
    findings = _rule().run(ctx)
    assert len(findings) == 1
    assert findings[0].evidence["sink"] == "os.system("


def test_fires_on_raw_sql_fstring():
    ctx = _ctx(['cursor.execute(f"SELECT * FROM users WHERE id={user_id}")'])
    findings = _rule().run(ctx)
    assert len(findings) == 1
    assert findings[0].evidence["pattern"] == "raw_sql_injection"
    assert findings[0].confidence == 0.85


def test_fires_on_raw_sql_concatenation():
    ctx = _ctx(['cursor.execute("SELECT * FROM users WHERE id=" + user_id)'])
    findings = _rule().run(ctx)
    assert len(findings) == 1


# --- Does not fire on safe equivalents ---

def test_does_not_fire_when_sink_far_from_source():
    # Source at line 1, sink at line 8 — beyond the 5-line window
    lines = [
        "user_data = request.args.get('q')",
        "x = 1",
        "y = 2",
        "z = 3",
        "a = 4",
        "b = 5",
        "c = 6",
        "exec('safe_static_code')",
    ]
    ctx = _ctx(lines)
    findings = [f for f in _rule().run(ctx) if "sink" in f.evidence and f.evidence.get("sink") == "exec("]
    assert findings == []


def test_does_not_fire_without_variable_bridge():
    # request.args is on one line, exec() on another, but different variable
    ctx = _ctx([
        "safe_var = request.args.get('q')",
        "exec('print(\"hello\")')",
    ])
    # 'safe_var' does not appear in the exec line, no same-line match → no finding
    findings = [f for f in _rule().run(ctx)
                if f.evidence.get("sink") == "exec(" and f.evidence.get("source_line") is not None]
    assert findings == []


def test_does_not_fire_on_safe_exec():
    # exec with a static string — no user input source in file
    ctx = _ctx(["exec('import_setup_module()')"])
    findings = [f for f in _rule().run(ctx) if f.evidence.get("sink") == "exec("]
    assert findings == []


def test_does_not_fire_on_unassigned_source_near_sink():
    # Source appears without assignment — no variable bridge possible, different lines → no finding
    ctx = _ctx([
        "request.args.get('q')",  # source without assignment
        "exec('safe_string')",    # sink on next line, no bridge
    ])
    findings = [f for f in _rule().run(ctx) if f.evidence.get("sink") == "exec("]
    assert findings == []


def test_fires_on_unassigned_source_same_line_as_sink():
    # Source and sink on the same line — same-line rule fires regardless of variable bridge
    ctx = _ctx(["exec(request.args.get('cmd'))"])
    findings = _rule().run(ctx)
    assert len(findings) == 1
    assert findings[0].evidence["sink"] == "exec("
    assert findings[0].confidence == 0.90  # same_line


# --- Malformed input ---

def test_handles_empty_diff():
    ctx = make_context(files=[{
        "path": "app.py", "language": "python",
        "old_content": "", "new_content": "", "diff": "",
    }])
    assert _rule().run(ctx) == []


def test_handles_empty_context():
    assert _rule().run(make_context()) == []


# --- Isolation ---

def test_runs_in_isolation():
    rule = DangerousSinkRule()
    assert rule.metadata.id == "SEC-005"
    assert rule.metadata.severity == "high"
    diff = make_added_diff(["result = eval(request.args.get('expr'))"])
    file = make_file(diff=diff, new_content=diff)
    from core.context import AnalysisContext
    ctx = AnalysisContext(repo_path="/r", changed_files=[file])
    findings = rule.run(ctx)
    assert len(findings) == 1
