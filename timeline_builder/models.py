"""Core data models shared by every stage of the pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

UNKNOWN_USER = "unknown"


@dataclass
class Event:
    """One normalized log event, regardless of the log source it came from."""

    timestamp: datetime
    source: str  # windows_security | sysmon | wazuh
    host: str
    user: str
    event_id: str
    summary: str
    raw: dict[str, Any] = field(default_factory=dict, repr=False)
    technique: str | None = None  # MITRE ATT&CK id, e.g. T1110
    technique_name: str | None = None
    tactic: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "host": self.host,
            "user": self.user,
            "event_id": self.event_id,
            "summary": self.summary,
            "technique": self.technique,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
        }


@dataclass
class Incident:
    """A group of related events correlated by host/user inside a rolling window."""

    events: list[Event] = field(default_factory=list)
    incident_id: str = ""

    @property
    def start(self) -> datetime:
        return min(e.timestamp for e in self.events)

    @property
    def end(self) -> datetime:
        return max(e.timestamp for e in self.events)

    @property
    def duration(self) -> timedelta:
        return self.end - self.start

    @property
    def hosts(self) -> set[str]:
        return {e.host for e in self.events}

    @property
    def users(self) -> set[str]:
        return {e.user for e in self.events if e.user != UNKNOWN_USER}

    @property
    def techniques(self) -> list[str]:
        """Distinct technique ids in order of first appearance."""
        seen: list[str] = []
        for e in sorted(self.events, key=lambda x: x.timestamp):
            if e.technique and e.technique not in seen:
                seen.append(e.technique)
        return seen

    @property
    def tactics(self) -> list[str]:
        seen: list[str] = []
        for e in sorted(self.events, key=lambda x: x.timestamp):
            if e.tactic and e.tactic not in seen:
                seen.append(e.tactic)
        return seen

    @property
    def severity(self) -> str:
        """Heuristic: breadth of the kill chain observed."""
        n = len(self.tactics)
        if n >= 4:
            return "Critical"
        if n == 3:
            return "High"
        if n == 2:
            return "Medium"
        return "Low"

    def links(self, event: Event) -> bool:
        """True if the event shares a host or a known user with this incident."""
        if event.host in self.hosts:
            return True
        return event.user != UNKNOWN_USER and event.user in self.users

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "duration_seconds": int(self.duration.total_seconds()),
            "hosts": sorted(self.hosts),
            "users": sorted(self.users),
            "severity": self.severity,
            "techniques": self.techniques,
            "tactics": self.tactics,
            "event_count": len(self.events),
            "events": [e.to_dict() for e in sorted(self.events, key=lambda x: x.timestamp)],
        }
