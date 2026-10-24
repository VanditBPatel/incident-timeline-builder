"""Group related events into incidents by host/user inside a rolling time window."""

from __future__ import annotations

from datetime import timedelta

from .models import Event, Incident

DEFAULT_WINDOW = timedelta(minutes=30)


def correlate(events: list[Event], window: timedelta = DEFAULT_WINDOW) -> list[Incident]:
    """Correlate ATT&CK-tagged events.

    An event joins an open incident when it shares a host (or a known user) with
    it AND occurs within `window` of the incident's most recent event. If it
    links several incidents, those incidents are merged (e.g. a user moving
    from one host to another). Untagged events are treated as noise and skipped.
    """
    tagged = sorted((e for e in events if e.technique), key=lambda e: e.timestamp)
    incidents: list[Incident] = []

    for ev in tagged:
        matches = [i for i in incidents if ev.timestamp - i.end <= window and i.links(ev)]
        if not matches:
            incidents.append(Incident(events=[ev]))
            continue
        base = matches[0]
        for other in matches[1:]:
            base.events.extend(other.events)
            incidents.remove(other)
        base.events.append(ev)

    incidents.sort(key=lambda i: i.start)
    for n, inc in enumerate(incidents, start=1):
        inc.incident_id = f"INC-{n:03d}"
        inc.events.sort(key=lambda e: e.timestamp)
    return incidents
