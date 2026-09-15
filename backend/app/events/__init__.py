"""Security events: typed vocabulary (:mod:`.types`) and the publish bus (:mod:`.bus`)."""

from app.events.types import EVENT_SEVERITIES, EventType

__all__ = ["EVENT_SEVERITIES", "EventType"]
