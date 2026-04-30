from __future__ import annotations

DEPENDENCY_FILENAMES = {
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
    "pnpm-lock.yaml",
}

AUTH_KEYWORDS = {
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

AUTH_HIGH_CONFIDENCE_KEYWORDS = {
    "jwt",
    "token",
    "session",
    "permission",
    "role",
    "admin",
    "verify",
    "middleware",
}

AUTH_MEDIUM_PATH_KEYWORDS = {"auth", "login", "session", "middleware"}

SECRET_REFERENCE_KEYWORDS = {
    "secret",
    "api_key",
    "apikey",
    "apiKey",
    "password",
    "token",
    "private_key",
    "privatekey",
}

CI_CD_DANGEROUS_SIGNALS = frozenset({
    "hardcoded_secret",
    "github_token",
    "api_key",
    "curl_pipe_shell",
    "wget_pipe_shell",
    "chmod_777",
    "privileged_true",
    "permissions_write_all",
    "pull_request_target",
    "unpinned_action",
})
