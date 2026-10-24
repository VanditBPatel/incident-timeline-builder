"""Generate an analyst-readable narrative for each incident."""

from __future__ import annotations

from collections import Counter, OrderedDict

from .models import Event, Incident

_SOURCE_LABEL = {
    "windows_security": "Windows Security",
    "sysmon": "Sysmon",
    "wazuh": "Wazuh",
}


def _fmt_duration(seconds: int) -> str:
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def _stage_groups(incident: Incident) -> "OrderedDict[str, list[Event]]":
    groups: "OrderedDict[str, list[Event]]" = OrderedDict()
    for ev in incident.events:
        groups.setdefault(ev.technique or "?", []).append(ev)
    return groups


def build_narrative(incident: Incident) -> str:
    hosts = ", ".join(sorted(incident.hosts))
    users = ", ".join(sorted(incident.users)) or "no identifiable user"
    groups = _stage_groups(incident)
    sources = Counter(e.source for e in incident.events)
    src_text = ", ".join(f"{_SOURCE_LABEL.get(s, s)} ({n})" for s, n in sources.most_common())

    lines = [
        f"{incident.incident_id} [{incident.severity}] - "
        f"{incident.start:%Y-%m-%d %H:%M:%S} to {incident.end:%H:%M:%S} UTC "
        f"({_fmt_duration(int(incident.duration.total_seconds()))}).",
        "",
        f"Host(s): {hosts}. User(s): {users}. "
        f"{len(incident.events)} correlated events spanning {len(groups)} ATT&CK "
        f"technique(s) across {len(incident.tactics)} tactic(s). Sources: {src_text}.",
        "",
        "Kill-chain progression: " + " -> ".join(incident.tactics) + ".",
        "",
        "Sequence of activity:",
    ]
    for step, (tid, evs) in enumerate(groups.items(), start=1):
        first, last = evs[0], evs[-1]
        span = (
            f"{first.timestamp:%H:%M:%S}"
            if first.timestamp == last.timestamp
            else f"{first.timestamp:%H:%M:%S}-{last.timestamp:%H:%M:%S}"
        )
        srcs = sorted({_SOURCE_LABEL.get(e.source, e.source) for e in evs})
        lines.append(
            f"  {step}. {span} {tid} {first.technique_name} ({first.tactic}): "
            f"{len(evs)} event(s) seen by {', '.join(srcs)}. First: {first.summary}"
        )

    lines += [
        "",
        "Analyst notes: confirm the initial access vector, isolate the affected "
        "host(s), reset the credentials of the listed user(s), and review the "
        "external destinations and archive artefacts for data exposure.",
    ]
    return "\n".join(lines)
