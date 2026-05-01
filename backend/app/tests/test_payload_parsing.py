from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.integrations.github.types import PullRequestEvent
from app.tests.conftest import make_pr_payload


class TestPullRequestEventParsing:

    def test_full_payload_parses_correctly(self) -> None:
        data = make_pr_payload(action="opened", pr_number=7, installation_id=88888)
        event = PullRequestEvent.from_webhook(data, delivery_id=None)

        assert event.action == "opened"
        assert event.number == 7
        assert event.pull_request.number == 7
        assert event.pull_request.title == "Add feature X"
        assert event.repository.full_name == "org/my-repo"
        assert event.repository.private is True
        assert event.sender.login == "octocat"

    def test_installation_id_property(self) -> None:
        data = make_pr_payload(installation_id=77777)
        event = PullRequestEvent.from_webhook(data, delivery_id=None)
        assert event.installation_id == 77777

    def test_installation_id_none_when_absent(self) -> None:
        data = make_pr_payload(installation_id=None)
        event = PullRequestEvent.from_webhook(data, delivery_id=None)
        assert event.installation is None
        assert event.installation_id is None

    def test_delivery_id_attached_via_from_webhook(self) -> None:
        data = make_pr_payload()
        event = PullRequestEvent.from_webhook(data, delivery_id="uuid-delivery-123")
        assert event.delivery_id == "uuid-delivery-123"

    def test_delivery_id_none_when_not_provided(self) -> None:
        data = make_pr_payload()
        event = PullRequestEvent.from_webhook(data, delivery_id=None)
        assert event.delivery_id is None

    def test_missing_repository_raises_validation_error(self) -> None:
        data = make_pr_payload()
        del data["repository"]
        with pytest.raises(ValidationError):
            PullRequestEvent.from_webhook(data, delivery_id=None)

    def test_missing_sender_raises_validation_error(self) -> None:
        data = make_pr_payload()
        del data["sender"]
        with pytest.raises(ValidationError):
            PullRequestEvent.from_webhook(data, delivery_id=None)

    def test_missing_pull_request_raises_validation_error(self) -> None:
        data = make_pr_payload()
        del data["pull_request"]
        with pytest.raises(ValidationError):
            PullRequestEvent.from_webhook(data, delivery_id=None)

    def test_optional_pr_body_defaults_to_none(self) -> None:
        data = make_pr_payload()
        data["pull_request"].pop("body", None)
        event = PullRequestEvent.from_webhook(data, delivery_id=None)
        assert event.pull_request.body is None

    def test_ref_fields_parsed_correctly(self) -> None:
        data = make_pr_payload()
        event = PullRequestEvent.from_webhook(data, delivery_id=None)
        assert event.pull_request.head.sha == "abc123"
        assert event.pull_request.head.ref == "feature-x"
        assert event.pull_request.base.ref == "main"
