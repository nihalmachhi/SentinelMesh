"""Contracts for deterministic and optional model-backed investigators."""

from typing import Any, Protocol

from sentinelmesh.storage.sqlite import Store


class Investigator(Protocol):
    def build(self, store: Store, incident_id: str) -> dict[str, Any]: ...
