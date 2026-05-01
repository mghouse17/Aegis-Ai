from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.integrations.github.webhook import verify_signature
from app.tests.conftest import make_signature

BODY = b'{"action": "opened"}'
SECRET = "my-test-secret"


@pytest.fixture(autouse=True)
def set_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", SECRET)


class TestVerifySignature:

    def test_valid_signature_passes(self) -> None:
        sig = make_signature(BODY, SECRET)
        verify_signature(BODY, sig)  # must not raise

    def test_missing_header_none_raises_401(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            verify_signature(BODY, None)
        assert exc_info.value.status_code == 401

    def test_missing_header_empty_string_raises_401(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            verify_signature(BODY, "")
        assert exc_info.value.status_code == 401

    def test_missing_header_whitespace_raises_401(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            verify_signature(BODY, "   ")
        assert exc_info.value.status_code == 401

    def test_wrong_prefix_raises_401(self) -> None:
        mac = make_signature(BODY, SECRET).removeprefix("sha256=")
        with pytest.raises(HTTPException) as exc_info:
            verify_signature(BODY, f"sha1={mac}")
        assert exc_info.value.status_code == 401

    def test_empty_value_after_prefix_raises_401(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            verify_signature(BODY, "sha256=")
        assert exc_info.value.status_code == 401

    def test_wrong_value_raises_401(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            verify_signature(BODY, "sha256=" + "a" * 64)
        assert exc_info.value.status_code == 401

    def test_tampered_body_raises_401(self) -> None:
        sig = make_signature(BODY, SECRET)
        with pytest.raises(HTTPException) as exc_info:
            verify_signature(BODY + b" tampered", sig)
        assert exc_info.value.status_code == 401

    def test_wrong_secret_raises_401(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sig = make_signature(BODY, "different-secret")
        with pytest.raises(HTTPException) as exc_info:
            verify_signature(BODY, sig)
        assert exc_info.value.status_code == 401

    def test_missing_env_var_raises_500(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GITHUB_WEBHOOK_SECRET")
        sig = make_signature(BODY, SECRET)
        with pytest.raises(HTTPException) as exc_info:
            verify_signature(BODY, sig)
        assert exc_info.value.status_code == 500
