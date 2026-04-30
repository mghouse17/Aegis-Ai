from __future__ import annotations

import re

from app.analysis.models.diff_models import ParsedFile

# Compiled at module load for performance on large diffs.
# All signal names are canonical snake_case.
# Each entry: (signal_name, pattern_or_substring)
# str pattern → substring check; re.Pattern → regex search.
_SIGNALS: list[tuple[str, str | re.Pattern]] = [
    ("auth",                        re.compile(r"\bauth\b", re.IGNORECASE)),
    ("jwt",                         re.compile(r"\bjwt\b", re.IGNORECASE)),
    ("token",                       re.compile(r"\btoken\b", re.IGNORECASE)),
    ("session",                     re.compile(r"\bsession\b", re.IGNORECASE)),
    ("password",                    re.compile(r"\bpassword\b", re.IGNORECASE)),
    ("secret",                      re.compile(r"\bsecret\b", re.IGNORECASE)),
    # Canonical: api_key (covers apiKey and api_key in code)
    ("api_key",                     re.compile(r"\bapikey\b|\bapi_key\b", re.IGNORECASE)),
    ("access_token",                re.compile(r"\baccess_token\b", re.IGNORECASE)),
    ("refresh_token",               re.compile(r"\brefresh_token\b", re.IGNORECASE)),
    ("github_token",                re.compile(r"\bghp_[A-Za-z0-9_]+\b|\bgithub_pat_[A-Za-z0-9_]+\b")),
    ("permission",                  re.compile(r"permission", re.IGNORECASE)),
    ("role",                        re.compile(r"\brole\b", re.IGNORECASE)),
    ("admin",                       re.compile(r"\badmin\b", re.IGNORECASE)),
    ("eval",                        "eval("),
    ("exec",                        "exec("),
    # Canonical snake_case DOM sinks
    ("inner_html",                  "innerHTML"),
    ("dangerously_set_inner_html",  "dangerouslySetInnerHTML"),
    # Canonical snake_case env accessors
    ("process_env",                 "process.env"),
    ("os_environ",                  "os.environ"),
    ("raw_sql",                     re.compile(
        r"SELECT\s+.+\s+FROM|INSERT\s+INTO|DELETE\s+FROM|UPDATE\s+.+\s+SET",
        re.IGNORECASE,
    )),
    # Merged: all TLS/SSL verification bypass patterns under one canonical name
    ("tls_verification_disabled",   re.compile(
        r"rejectUnauthorized\s*:\s*false"
        r"|verify\s*=\s*False"
        r"|ssl_verify\s*=\s*False",
        re.IGNORECASE,
    )),
    ("subprocess",                  "subprocess"),
    ("shell_true",                  re.compile(r"shell\s*=\s*True")),
    ("weak_hash",                   re.compile(
        r"\bhashlib\.(md5|sha1)\b|\b(md5|sha1)\(",
        re.IGNORECASE,
    )),
    ("cors_wildcard",               re.compile(
        r"origin\s*[:=]\s*[\"']?\*[\"']?"
        r"|allow_origins\s*=\s*\[[\"']?\*[\"']?\]",
        re.IGNORECASE,
    )),
    ("curl_pipe_shell",             re.compile(r"\bcurl\b.+\|\s*(?:bash|sh)\b", re.IGNORECASE)),
    ("wget_pipe_shell",             re.compile(r"\bwget\b.+\|\s*(?:bash|sh)\b", re.IGNORECASE)),
    ("chmod_777",                   re.compile(r"\bchmod\s+777\b", re.IGNORECASE)),
    ("privileged_true",             re.compile(r"\bprivileged\s*:\s*true\b", re.IGNORECASE)),
    ("permissions_write_all",       re.compile(r"\bpermissions\s*:\s*write-all\b", re.IGNORECASE)),
    ("pull_request_target",         re.compile(r"\bpull_request_target\b", re.IGNORECASE)),
    ("privilege_escalation",        re.compile(r"\bis_admin\s*=\s*True\b", re.IGNORECASE)),
    # Hardcoded secrets: common token prefixes, AWS key, PEM header, named secret assignments
    ("hardcoded_secret",            re.compile(
        r"AKIA[A-Z0-9]{12,20}"
        r"|ghp_[A-Za-z0-9_]+"
        r"|github_pat_[A-Za-z0-9_]+"
        r"|sk-[A-Za-z0-9_-]+"
        r"|xoxb-[A-Za-z0-9-]+"
        r"|-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY"
        r"|\b(?:SECRET|PASSWORD|API_KEY|PRIVATE_KEY|access_token|refresh_token)\b\s*[:=]\s*[\"'][^\"']+[\"']",
        re.IGNORECASE,
    )),
]


def classify_security_signals(parsed_file: ParsedFile) -> list[str]:
    if not parsed_file.added_lines:
        return []

    found: set[str] = set()
    for _line_num, content in parsed_file.added_lines:
        for signal_name, pattern in _SIGNALS:
            if signal_name in found:
                continue
            if isinstance(pattern, str):
                if pattern in content:
                    found.add(signal_name)
            else:
                if pattern.search(content):
                    found.add(signal_name)
        if _is_unpinned_third_party_action(content):
            found.add("unpinned_action")
        if _is_auth_file(parsed_file.file_path) and _has_auth_bypass_pattern(content):
            found.add("auth_bypass")

    return sorted(found)


def _is_auth_file(file_path: str) -> bool:
    lower = file_path.lower()
    return any(part in lower for part in ("auth", "login", "middleware", "session"))


def _has_auth_bypass_pattern(content: str) -> bool:
    return bool(re.search(
        r"\breturn\s+True\b|\breturn\s+true\b|\bbypass\b|\bskip_auth\b|\ballow_all\b",
        content,
        re.IGNORECASE,
    ))


def _is_unpinned_third_party_action(content: str) -> bool:
    match = re.search(r"\buses\s*:\s*([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:@([^\s#]+))?", content)
    if not match:
        return False
    owner = match.group(1).lower()
    ref = match.group(3)
    if owner == "actions":
        return False
    if ref is None:
        return True
    if re.fullmatch(r"[0-9a-f]{40}", ref, re.IGNORECASE):
        return False
    return ref.lower() in {"main", "master", "latest", "dev", "develop", "head"}
