import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from timeline_builder.attack_map import map_events
from timeline_builder.correlate import correlate
from timeline_builder.models import Event
from timeline_builder.parsers import parse_all, parse_time

SAMPLE = Path(__file__).resolve().parent.parent / "sample_data"


def _load():
    events = parse_all(
        {
            "windows_security": [SAMPLE / "windows_security.json"],
            "sysmon": [SAMPLE / "sysmon.json"],
            "wazuh": [SAMPLE / "wazuh_alerts.json"],
        }
    )
    return map_events(events)


def test_sample_correlates_into_one_incident_with_five_techniques():
    events = _load()
    assert len(events) == 12
    incidents = correlate(events)
    assert len(incidents) == 1
    inc = incidents[0]
    assert len(inc.events) == 12
    assert inc.techniques == ["T1110", "T1078", "T1059.001", "T1071", "T1560"]
    assert inc.hosts == {"ws-fin-01"}
    assert inc.users == {"jdoe"}


def test_successful_logon_without_prior_failures_is_not_tagged():
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    ev = Event(ts, "windows_security", "h1", "alice", "4624", "ok",
               raw={"LogonType": 3})
    map_events([ev])
    assert ev.technique is None


def test_unrelated_hosts_stay_separate_incidents():
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    a = Event(ts, "wazuh", "h1", "unknown", "1", "a",
              raw={"rule": {"mitre": {"id": ["T1110"]}}})
    b = Event(ts + timedelta(minutes=1), "wazuh", "h2", "unknown", "1", "b",
              raw={"rule": {"mitre": {"id": ["T1110"]}}})
    map_events([a, b])
    assert len(correlate([a, b])) == 2


def test_window_splits_distant_events_on_same_host():
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    raw = {"rule": {"mitre": {"id": ["T1110"]}}}
    a = Event(ts, "wazuh", "h1", "unknown", "1", "a", raw=raw)
    b = Event(ts + timedelta(hours=3), "wazuh", "h1", "unknown", "1", "b", raw=raw)
    map_events([a, b])
    assert len(correlate([a, b], timedelta(minutes=30))) == 2


def test_user_moving_between_hosts_merges_incident():
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    raw = {"rule": {"mitre": {"id": ["T1110"]}}}
    a = Event(ts, "wazuh", "h1", "bob", "1", "a", raw=raw)
    b = Event(ts + timedelta(minutes=5), "wazuh", "h2", "bob", "1", "b", raw=raw)
    map_events([a, b])
    incidents = correlate([a, b])
    assert len(incidents) == 1
    assert incidents[0].hosts == {"h1", "h2"}


def test_parse_time_styles():
    assert parse_time("2026-10-20 09:15:20.311").hour == 9
    assert parse_time("2026-10-20T09:12:50.000+0000").minute == 12
    assert parse_time("2026-10-20T09:12:50Z").tzinfo is not None
