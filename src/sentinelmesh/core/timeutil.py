"""Shared ISO-8601 timestamp parsing and UTC conversion."""

from datetime import UTC, datetime


def parse_utc(timestamp: str) -> datetime:
    """Parse an offset-aware ISO-8601 value and return its UTC instant."""
    parsed = datetime.fromisoformat(timestamp)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a timezone offset")
    return parsed.astimezone(UTC)


def epoch_seconds(timestamp: str) -> float:
    return parse_utc(timestamp).timestamp()
