"""Parsers that normalize Windows Security, Sysmon and Wazuh records into Events.

Each parser accepts JSON (a list) or NDJSON (one object per line), which is what
the common export paths produce (Get-WinEvent | ConvertTo-Json, Wazuh
alerts.json, Sysmon via Winlogbeat/nxlog).
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .models import UNKNOWN_USER, Event


# ---------------------------------------------------------------- helpers
def load_records(path: str | Path) -> list[dict[str, Any]]:
    """Load a JSON array or NDJSON file into a list of dicts."""
    text = Path(path).read_text(encoding="utf-8-sig").strip()
    if not text:
        return []
    if text.startswith("["):
        data = json.loads(text)
        return [r for r in data if isinstance(r, dict)]
    records = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_no}: invalid JSON ({exc})") from exc
        if isinstance(obj, dict):
            records.append(obj)
    return records


def parse_time(value: Any) -> datetime:
    """Parse the timestamp styles used by the three sources into aware UTC."""
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    s = str(value).strip()
    s = s.replace(" ", "T", 1) if re.match(r"\d{4}-\d{2}-\d{2} \d", s) else s
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", s)  # +0000 -> +00:00
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def normalize_host(name: Any) -> str:
    host = str(name or "unknown-host").strip().lower()
    return host.split(".")[0] or "unknown-host"


def normalize_user(name: Any) -> str:
    user = str(name or "").strip().lower()
    if "\\" in user:
        user = user.split("\\", 1)[1]
    if "@" in user:
        user = user.split("@", 1)[0]
    # Built-in service identities would wrongly link unrelated hosts, so they
    # are treated as "no user" for correlation purposes.
    if user in {"", "-", "n/a", "system", "local service", "network service"}:
        return UNKNOWN_USER
    return user


def _get(record: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Look a key up at top level, then inside EventData / data."""
    for container in (record, record.get("EventData") or {}, record.get("event_data") or {}):
        for key in keys:
            if key in container and container[key] not in (None, ""):
                return container[key]
    return default


# --------------------------------------------------------- Windows Security
_LOGON_TYPES = {
    "2": "interactive",
    "3": "network",
    "4": "batch",
    "5": "service",
    "7": "unlock",
    "10": "remote interactive (RDP)",
    "11": "cached interactive",
}


def parse_windows_security(path: str | Path) -> list[Event]:
    events: list[Event] = []
    for rec in load_records(path):
        event_id = str(_get(rec, "EventID", "event_id", default=""))
        ts = parse_time(_get(rec, "TimeCreated", "timestamp", "@timestamp"))
        host = normalize_host(_get(rec, "Computer", "computer", "host"))
        user = normalize_user(_get(rec, "TargetUserName", "SubjectUserName", "user"))
        ip = _get(rec, "IpAddress", "SourceNetworkAddress", default="-")
        logon_type = str(_get(rec, "LogonType", default=""))
        ltype = _LOGON_TYPES.get(logon_type, f"type {logon_type}" if logon_type else "unknown type")

        if event_id == "4625":
            summary = f"Failed logon for '{user}' from {ip} ({ltype})"
        elif event_id == "4624":
            summary = f"Successful logon for '{user}' from {ip} ({ltype})"
        elif event_id == "4720":
            summary = f"User account '{user}' created"
        elif event_id == "4697":
            summary = f"Service installed: {_get(rec, 'ServiceName', default='unknown')}"
        elif event_id == "1102":
            summary = "Security audit log cleared"
        else:
            summary = f"Windows Security event {event_id}"

        events.append(
            Event(ts, "windows_security", host, user, event_id, summary, raw=rec)
        )
    return events


# ------------------------------------------------------------------ Sysmon
def _truncate(text: str, limit: int = 140) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def parse_sysmon(path: str | Path) -> list[Event]:
    events: list[Event] = []
    for rec in load_records(path):
        event_id = str(_get(rec, "EventID", "event_id", default=""))
        ts = parse_time(_get(rec, "UtcTime", "TimeCreated", "timestamp"))
        host = normalize_host(_get(rec, "Computer", "computer", "host"))
        user = normalize_user(_get(rec, "User", "user"))
        image = str(_get(rec, "Image", default="unknown"))
        exe = image.replace("/", "\\").split("\\")[-1]

        if event_id == "1":
            cmd = str(_get(rec, "CommandLine", default=""))
            summary = f"Process created: {exe} :: {_truncate(cmd)}"
        elif event_id == "3":
            dst = _get(rec, "DestinationIp", default="?")
            port = _get(rec, "DestinationPort", default="?")
            summary = f"Network connection: {exe} -> {dst}:{port}"
        elif event_id == "10":
            target = str(_get(rec, "TargetImage", default="?")).split("\\")[-1]
            summary = f"Process access: {exe} -> {target}"
        else:
            summary = f"Sysmon event {event_id}: {exe}"

        events.append(Event(ts, "sysmon", host, user, event_id, summary, raw=rec))
    return events


# ------------------------------------------------------------------- Wazuh
def parse_wazuh(path: str | Path) -> list[Event]:
    events: list[Event] = []
    for rec in load_records(path):
        ts = parse_time(rec.get("timestamp") or rec.get("@timestamp"))
        agent = rec.get("agent") or {}
        host = normalize_host(agent.get("name") or rec.get("host"))
        rule = rec.get("rule") or {}
        data = rec.get("data") or {}
        win = (data.get("win") or {}).get("eventdata") or {}
        user = normalize_user(
            data.get("dstuser")
            or data.get("srcuser")
            or win.get("targetUserName")
            or win.get("user")
        )
        level = rule.get("level", "?")
        summary = f"Wazuh rule {rule.get('id', '?')} (level {level}): {rule.get('description', 'alert')}"
        events.append(
            Event(ts, "wazuh", host, user, str(rule.get("id", "")), summary, raw=rec)
        )
    return events


PARSERS = {
    "windows_security": parse_windows_security,
    "sysmon": parse_sysmon,
    "wazuh": parse_wazuh,
}


def parse_all(sources: dict[str, Iterable[str | Path]]) -> list[Event]:
    """sources maps a source name to the list of files holding that source."""
    events: list[Event] = []
    for name, paths in sources.items():
        parser = PARSERS[name]
        for path in paths:
            events.extend(parser(path))
    return events
