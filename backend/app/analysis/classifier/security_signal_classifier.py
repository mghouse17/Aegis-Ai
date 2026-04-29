from __future__ import annotations

import re

from app.analysis.models.diff_models import ParsedFile

# Compiled at module load for performance on large diffs.
# Each entry: (signal_name, pattern_or_substring)
# If pattern is a str → substring check; if re.Pattern → regex search.
_SIGNALS: list[tuple[str, str | re.Pattern]] = [
    ("auth",                    re.compile(r"\bauth\b", re.IGNORECASE)),
    ("jwt",                     re.compile(r"\bjwt\b", re.IGNORECASE)),
    ("token",                   re.compile(r"\btoken\b", re.IGNORECASE)),
    ("session",                 re.compile(r"\bsession\b", re.IGNORECASE)),
    ("password",                re.compile(r"\bpassword\b", re.IGNORECASE)),
    ("secret",                  re.compile(r"\bsecret\b", re.IGNORECASE)),
    ("apiKey",                  re.compile(r"\bapikey\b|\bapi_key\b", re.IGNORECASE)),
    ("permission",              re.compile(r"permission", re.IGNORECASE)),
    ("role",                    re.compile(r"\brole\b", re.IGNORECASE)),
    ("admin",                   re.compile(r"\badmin\b", re.IGNORECASE)),
    ("eval",                    "eval("),
    ("exec",                    "exec("),
    ("innerHTML",               "innerHTML"),
    ("dangerouslySetInnerHTML", "dangerouslySetInnerHTML"),
    ("process.env",             "process.env"),
    ("os.environ",              "os.environ"),
    ("raw_sql",                 re.compile(
        r"SELECT\s+.+\s+FROM|INSERT\s+INTO|DELETE\s+FROM|UPDATE\s+.+\s+SET",
        re.IGNORECASE,
    )),
    # Space-tolerant: matches `rejectUnauthorized: false` and `rejectUnauthorized:false`
    ("rejectUnauthorized",      re.compile(r"rejectUnauthorized\s*:\s*false", re.IGNORECASE)),
    ("verify_false",            re.compile(
        r"verify\s*=\s*False|ssl_verify\s*=\s*False",
        re.IGNORECASE,
    )),
    ("subprocess",              "subprocess"),
    # Space-tolerant: matches `shell=True` and `shell = True`
    ("shell_true",              re.compile(r"shell\s*=\s*True")),
    # Weak hashing algorithms
    ("weak_hash",               re.compile(
        r"\bhashlib\.(md5|sha1)\b|\b(md5|sha1)\(",
        re.IGNORECASE,
    )),
    # Broad CORS — origin: '*' or allow_origins = ["*"]
    ("cors_wildcard",           re.compile(
        r"origin\s*[:=]\s*[\"']?\*[\"']?"
        r"|allow_origins\s*=\s*\[[\"']?\*[\"']?\]",
        re.IGNORECASE,
    )),
    # Hardcoded secrets: AWS access key, GitHub PAT, PEM private key header
    ("hardcoded_secret",        re.compile(
        r"AKIA[A-Z0-9]{16}"
        r"|ghp_[A-Za-z0-9]{36}"
        r"|-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY",
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

    return sorted(found)
