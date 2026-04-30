from __future__ import annotations

import re

from app.analysis.models.diff_models import ParsedFile

# All signal names are canonical snake_case.
# Compiled at module load for performance on large diffs.
# Each entry: (signal_name, pattern_or_substring)
# str pattern  → substring check (fast for exact literals)
# re.Pattern   → regex search
_SIGNALS: list[tuple[str, str | re.Pattern]] = [
    ("auth",                        re.compile(r"\bauth\b", re.IGNORECASE)),
    ("jwt",                         re.compile(r"\bjwt\b", re.IGNORECASE)),
    ("token",                       re.compile(r"\btoken\b", re.IGNORECASE)),
    ("session",                     re.compile(r"\bsession\b", re.IGNORECASE)),
    ("password",                    re.compile(r"\bpassword\b", re.IGNORECASE)),
    ("secret",                      re.compile(r"\bsecret\b", re.IGNORECASE)),
    # Normalized from camelCase "apiKey"
    ("api_key",                     re.compile(r"\bapikey\b|\bapi_key\b", re.IGNORECASE)),
    ("permission",                  re.compile(r"permission", re.IGNORECASE)),
    ("role",                        re.compile(r"\brole\b", re.IGNORECASE)),
    ("admin",                       re.compile(r"\badmin\b", re.IGNORECASE)),
    ("eval",                        "eval("),
    ("exec",                        "exec("),
    # Normalized from camelCase "innerHTML"
    ("inner_html",                  "innerHTML"),
    # Normalized from camelCase "dangerouslySetInnerHTML"
    ("dangerously_set_inner_html",  "dangerouslySetInnerHTML"),
    # Normalized from "process.env" (dot in signal name was a footgun)
    ("process_env",                 "process.env"),
    # Normalized from "os.environ"
    ("os_environ",                  "os.environ"),
    ("raw_sql",                     re.compile(
        r"SELECT\s+.+\s+FROM|INSERT\s+INTO|DELETE\s+FROM|UPDATE\s+.+\s+SET",
        re.IGNORECASE,
    )),
    # Merged: rejectUnauthorized + verify_false + ssl_verify_false → single signal.
    # Previously three overlapping signals; now one canonical name.
    ("tls_verification_disabled",   re.compile(
        r"rejectUnauthorized\s*:\s*false"
        r"|verify\s*=\s*False"
        r"|ssl_verify\s*=\s*False",
        re.IGNORECASE,
    )),
    ("subprocess",                  "subprocess"),
    # Space-tolerant: matches shell=True and shell = True
    ("shell_true",                  re.compile(r"shell\s*=\s*True")),
    # Weak hashing algorithms
    ("weak_hash",                   re.compile(
        r"\bhashlib\.(md5|sha1)\b|\b(md5|sha1)\(",
        re.IGNORECASE,
    )),
    # Broad CORS — origin: '*' or allow_origins=["*"]
    ("cors_wildcard",               re.compile(
        r"origin\s*[:=]\s*[\"']?\*[\"']?"
        r"|allow_origins\s*=\s*\[[\"']?\*[\"']?\]",
        re.IGNORECASE,
    )),
    # Hardcoded secrets: AWS access key, GitHub PAT, PEM private key header
    ("hardcoded_secret",            re.compile(
        r"AKIA[A-Z0-9]{16}"
        r"|ghp_[A-Za-z0-9]{36}"
        r"|-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY",
    )),
]

_TOTAL_SIGNALS = len(_SIGNALS)


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
        # Early exit: once every signal has fired there is nothing left to find.
        if len(found) == _TOTAL_SIGNALS:
            break

    return sorted(found)
