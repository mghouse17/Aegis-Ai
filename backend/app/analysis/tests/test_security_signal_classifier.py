import pytest

from app.analysis.classifier.security_signal_classifier import classify_security_signals
from app.analysis.models.diff_models import ParsedFile


def _make_file(added: list[str]) -> ParsedFile:
    return ParsedFile(
        file_path="foo.ts",
        status="modified",
        language=None,
        added_lines=[(i + 1, line) for i, line in enumerate(added)],
    )


def test_jwt_and_token_and_secret():
    pf = _make_file(["const token = jwt.sign(payload, secret)"])
    signals = classify_security_signals(pf)
    assert "jwt" in signals
    assert "token" in signals
    assert "secret" in signals


def test_eval_detection():
    pf = _make_file(["  eval(userInput)"])
    assert "eval" in classify_security_signals(pf)


def test_exec_detection():
    pf = _make_file(["  exec(cmd)"])
    assert "exec" in classify_security_signals(pf)


def test_process_env_detection():
    pf = _make_file(["const key = process.env.API_KEY"])
    signals = classify_security_signals(pf)
    assert "process.env" in signals


def test_os_environ_detection():
    pf = _make_file(["secret = os.environ.get('SECRET_KEY')"])
    assert "os.environ" in signals_for(pf)


def signals_for(pf: ParsedFile) -> list[str]:
    return classify_security_signals(pf)


def test_raw_sql_select():
    pf = _make_file(['query = "SELECT * FROM users WHERE id=" + userId'])
    assert "raw_sql" in classify_security_signals(pf)


def test_raw_sql_insert():
    pf = _make_file(['db.execute("INSERT INTO logs VALUES (" + data + ")")'])
    assert "raw_sql" in classify_security_signals(pf)


def test_inner_html():
    pf = _make_file(['element.innerHTML = userContent'])
    assert "innerHTML" in classify_security_signals(pf)


def test_dangerously_set_inner_html():
    pf = _make_file(['<div dangerouslySetInnerHTML={{ __html: content }} />'])
    assert "dangerouslySetInnerHTML" in classify_security_signals(pf)


def test_reject_unauthorized():
    pf = _make_file(['  rejectUnauthorized: false'])
    assert "rejectUnauthorized" in classify_security_signals(pf)


def test_verify_false():
    pf = _make_file(['requests.get(url, verify=False)'])
    assert "verify_false" in classify_security_signals(pf)


def test_subprocess_detection():
    pf = _make_file(['import subprocess'])
    assert "subprocess" in classify_security_signals(pf)


def test_shell_true():
    pf = _make_file(['subprocess.call(cmd, shell=True)'])
    assert "shell_true" in classify_security_signals(pf)


def test_admin_keyword():
    pf = _make_file(['if (user.role === "admin") {'])
    signals = classify_security_signals(pf)
    assert "admin" in signals
    assert "role" in signals


def test_permission_keyword():
    pf = _make_file(['  checkPermission(user, resource)'])
    assert "permission" in classify_security_signals(pf)


def test_no_false_positives_on_clean_code():
    pf = _make_file(["const x = 1 + 2", "function add(a, b) { return a + b; }"])
    assert classify_security_signals(pf) == []


def test_empty_added_lines_returns_empty():
    pf = ParsedFile(
        file_path="foo.py",
        status="modified",
        language=None,
        added_lines=[],
    )
    assert classify_security_signals(pf) == []


def test_results_are_deduplicated():
    pf = _make_file([
        "const token = jwt.sign(a, secret)",
        "const token = jwt.verify(b, secret)",
    ])
    signals = classify_security_signals(pf)
    assert signals.count("jwt") == 1
    assert signals.count("token") == 1
    assert signals.count("secret") == 1


def test_api_key_variants():
    pf = _make_file(["const apiKey = config.api_key"])
    signals = classify_security_signals(pf)
    assert "apiKey" in signals


def test_password_keyword():
    pf = _make_file(["  const hashed = bcrypt.hash(password, 10)"])
    assert "password" in classify_security_signals(pf)


# ---------------------------------------------------------------------------
# New signals added in Phase 1
# ---------------------------------------------------------------------------


def test_shell_true_with_spaces():
    # Spacing variant: `shell = True`
    pf = _make_file(["subprocess.call(cmd, shell = True)"])
    assert "shell_true" in classify_security_signals(pf)


def test_reject_unauthorized_no_space():
    # No-space variant: `rejectUnauthorized:false`
    pf = _make_file(["{ rejectUnauthorized:false }"])
    assert "rejectUnauthorized" in classify_security_signals(pf)


def test_reject_unauthorized_mixed_case():
    pf = _make_file(["rejectUnauthorized: False"])
    assert "rejectUnauthorized" in classify_security_signals(pf)


def test_weak_hash_md5_call():
    pf = _make_file(["digest = md5(data)"])
    assert "weak_hash" in classify_security_signals(pf)


def test_weak_hash_sha1_call():
    pf = _make_file(["checksum = sha1(content)"])
    assert "weak_hash" in classify_security_signals(pf)


def test_weak_hash_hashlib_md5():
    pf = _make_file(["h = hashlib.md5(data).hexdigest()"])
    assert "weak_hash" in classify_security_signals(pf)


def test_weak_hash_hashlib_sha1():
    pf = _make_file(["sig = hashlib.sha1(blob).digest()"])
    assert "weak_hash" in classify_security_signals(pf)


def test_cors_wildcard_origin_colon():
    pf = _make_file(["  origin: '*'"])
    assert "cors_wildcard" in classify_security_signals(pf)


def test_cors_wildcard_origin_equals():
    pf = _make_file(['  origin = "*"'])
    assert "cors_wildcard" in classify_security_signals(pf)


def test_cors_wildcard_allow_origins():
    pf = _make_file(['app.add_middleware(CORSMiddleware, allow_origins=["*"])'])
    assert "cors_wildcard" in classify_security_signals(pf)


def test_hardcoded_aws_key():
    pf = _make_file(["AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'"])
    assert "hardcoded_secret" in classify_security_signals(pf)


def test_hardcoded_github_pat():
    pf = _make_file(["token = 'ghp_" + "A" * 36 + "'"])
    assert "hardcoded_secret" in classify_security_signals(pf)


def test_hardcoded_private_key_header():
    pf = _make_file(["-----BEGIN PRIVATE KEY-----"])
    assert "hardcoded_secret" in classify_security_signals(pf)


def test_hardcoded_rsa_private_key_header():
    pf = _make_file(["-----BEGIN RSA PRIVATE KEY-----"])
    assert "hardcoded_secret" in classify_security_signals(pf)


def test_sha256_is_not_flagged_as_weak():
    # SHA-256 is acceptable; only md5/sha1 are weak
    pf = _make_file(["digest = hashlib.sha256(data).hexdigest()"])
    assert "weak_hash" not in classify_security_signals(pf)
