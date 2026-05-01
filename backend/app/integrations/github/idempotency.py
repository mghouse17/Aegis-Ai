from __future__ import annotations

from abc import ABC, abstractmethod


class DeliveryTracker(ABC):
    """Interface for tracking seen GitHub webhook delivery IDs.

    IMPORTANT: is_duplicate() + mark_seen() called separately is NOT atomic.
    Two concurrent requests with the same delivery_id can both pass the check
    before either marks it seen. Production implementations must use an atomic
    check-and-set primitive:
      - Redis:    SETNX delivery:<id> 1 EX <ttl>
      - Postgres: INSERT INTO seen_deliveries(id) ... ON CONFLICT DO NOTHING

    If the INSERT/SETNX returns "already existed", treat as duplicate.
    This collapses is_duplicate + mark_seen into a single atomic operation.
    """

    @abstractmethod
    def is_duplicate(self, delivery_id: str) -> bool:
        """Return True if this delivery ID has already been processed."""

    @abstractmethod
    def mark_seen(self, delivery_id: str) -> None:
        """Record that this delivery ID has been accepted.

        Called only after the event has been accepted for processing,
        never on ignored or rejected events.
        """


class NoOpDeliveryTracker(DeliveryTracker):
    """Default tracker that accepts all deliveries.

    Used in development and testing. Replace with a persistent implementation
    before production deployment to prevent duplicate processing on GitHub retries.
    """

    def is_duplicate(self, delivery_id: str) -> bool:
        return False

    def mark_seen(self, delivery_id: str) -> None:
        pass
