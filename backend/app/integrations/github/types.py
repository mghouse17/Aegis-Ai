from __future__ import annotations

from pydantic import BaseModel


class Ref(BaseModel):
    sha: str
    ref: str


class Installation(BaseModel):
    id: int


class Sender(BaseModel):
    id: int
    login: str


class Repository(BaseModel):
    id: int
    name: str
    full_name: str
    private: bool


class PullRequest(BaseModel):
    id: int
    number: int
    title: str
    state: str
    body: str | None = None
    head: Ref
    base: Ref


class PullRequestEvent(BaseModel):
    action: str
    number: int
    pull_request: PullRequest
    repository: Repository
    sender: Sender
    installation: Installation | None = None
    delivery_id: str | None = None  # set from X-GitHub-Delivery header, not body

    @property
    def installation_id(self) -> int | None:
        return self.installation.id if self.installation else None

    @classmethod
    def from_webhook(cls, payload: dict, delivery_id: str | None) -> "PullRequestEvent":
        """Parse from raw webhook dict and attach the delivery ID from the header.

        delivery_id is injected here so it flows through the model as a first-class
        field — callers never mutate validated models directly.
        """
        return cls.model_validate({**payload, "delivery_id": delivery_id})
