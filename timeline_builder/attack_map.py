"""Map normalized events to MITRE ATT&CK techniques.

Detection rules are deliberately explicit and readable so an analyst can audit
why an event was tagged. Wazuh alerts that already carry rule.mitre.id use it.
"""

from __future__ import annotations

import ipaddress
from datetime import timedelta

from .models import Event

# technique id -> (name, tactic)
TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1110": ("Brute Force", "Credential Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1560": ("Archive Collected Data", "Collection"),
    "T1136.001": ("Create Account: Local Account", "Persistence"),
    "T1543.003": ("Create or Modify System Process: Windows Service", "Persistence"),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", "Defense Evasion"),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", "Persistence"),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "Credential Access"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "Lateral Movement"),
}

_INTERNAL_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
]
_BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe"}
_ARCHIVERS = ("7z.exe", "7za.exe", "rar.exe", "winrar.exe", "zip.exe")
_REMOTE_LOGON_TYPES = {"3", "10"}

# Brute-force-then-success: this many failures within this window before a
# remote success is treated as use of a (now) valid account.
BRUTE_FORCE_FAILURES = 3
BRUTE_FORCE_LOOKBACK = timedelta(minutes=15)


def technique_info(tid: str, fallback_tactic: str | None = None) -> tuple[str, str]:
    if tid in TECHNIQUES:
        return TECHNIQUES[tid]
    return ("Unmapped technique", fallback_tactic or "Unknown")


def is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # hostnames / garbage: do not flag as external
    return any(addr in net for net in _INTERNAL_NETS)


def _tag(event: Event, tid: str, fallback_tactic: str | None = None) -> None:
    name, tactic = technique_info(tid, fallback_tactic)
    event.technique, event.technique_name, event.tactic = tid, name, tactic


def _map_security(event: Event) -> None:
    eid = event.event_id
    if eid == "4625":
        _tag(event, "T1110")
    elif eid == "4720":
        _tag(event, "T1136.001")
    elif eid == "4697":
        _tag(event, "T1543.003")
    elif eid == "1102":
        _tag(event, "T1070.001")
    # 4624 is resolved in map_events (needs prior-failure context)


def _map_sysmon(event: Event) -> None:
    raw = event.raw
    image = str(raw.get("Image") or (raw.get("EventData") or {}).get("Image") or "").lower()
    exe = image.replace("/", "\\").split("\\")[-1]
    cmd = str(raw.get("CommandLine") or (raw.get("EventData") or {}).get("CommandLine") or "").lower()

    if event.event_id == "1":
        if exe in _ARCHIVERS or "compress-archive" in cmd:
            _tag(event, "T1560")
        elif exe in {"powershell.exe", "pwsh.exe"}:
            _tag(event, "T1059.001")
        elif exe == "schtasks.exe" and "/create" in cmd:
            _tag(event, "T1053.005")
    elif event.event_id == "3":
        dst = str(raw.get("DestinationIp") or (raw.get("EventData") or {}).get("DestinationIp") or "")
        if dst and not is_internal(dst) and exe not in _BROWSERS:
            _tag(event, "T1071")
    elif event.event_id == "10":
        target = str(raw.get("TargetImage") or (raw.get("EventData") or {}).get("TargetImage") or "").lower()
        if target.endswith("lsass.exe"):
            _tag(event, "T1003.001")


_WAZUH_KEYWORDS = [
    (("logon failure", "authentication fail", "brute"), "T1110"),
    (("encoded command", "powershell"), "T1059.001"),
    (("archive", "compress"), "T1560"),
    (("external ip", "command and control", "c2", "outbound connection"), "T1071"),
]


def _map_wazuh(event: Event) -> None:
    rule = event.raw.get("rule") or {}
    mitre = rule.get("mitre") or {}
    ids = mitre.get("id") or []
    tactics = mitre.get("tactic") or []
    if isinstance(ids, str):
        ids = [ids]
    if ids:
        _tag(event, ids[0], tactics[0] if tactics else None)
        return
    desc = str(rule.get("description", "")).lower()
    for words, tid in _WAZUH_KEYWORDS:
        if any(w in desc for w in words):
            _tag(event, tid)
            return


def map_events(events: list[Event]) -> list[Event]:
    """Tag events in place with ATT&CK techniques and return them time-sorted."""
    ordered = sorted(events, key=lambda e: e.timestamp)
    for ev in ordered:
        if ev.source == "windows_security":
            _map_security(ev)
        elif ev.source == "sysmon":
            _map_sysmon(ev)
        elif ev.source == "wazuh":
            _map_wazuh(ev)

    # Context rule: remote success after repeated failures -> T1078
    for ev in ordered:
        if ev.source != "windows_security" or ev.event_id != "4624":
            continue
        ltype = str(
            ev.raw.get("LogonType") or (ev.raw.get("EventData") or {}).get("LogonType") or ""
        )
        if ltype not in _REMOTE_LOGON_TYPES:
            continue
        failures = [
            f
            for f in ordered
            if f.source == "windows_security"
            and f.event_id == "4625"
            and f.user == ev.user
            and f.host == ev.host
            and timedelta(0) <= ev.timestamp - f.timestamp <= BRUTE_FORCE_LOOKBACK
        ]
        if len(failures) >= BRUTE_FORCE_FAILURES:
            _tag(ev, "T1078")
    return ordered
