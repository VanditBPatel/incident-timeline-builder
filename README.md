# Incident Timeline Builder

**DFIR log correlation and forensic timeline tool** (Python, Matplotlib, MITRE ATT&CK)

Ingests Windows Security Event Log, Sysmon and Wazuh alert exports, normalizes them
into one unified timeline, correlates related events by host and user inside a
rolling time window, maps each event to a MITRE ATT&CK technique, and produces a
swimlane timeline plus an auto-written incident narrative.

## Quick start

```bash
pip install -r requirements.txt
python -m timeline_builder --demo              # run on bundled sample data
python -m pytest -q tests                      # run the tests
```

Run on your own exports (JSON array or NDJSON):

```bash
python -m timeline_builder \
  --security exports/security.json \
  --sysmon   exports/sysmon.json \
  --wazuh    exports/alerts.json \
  --window 30 --out output/
```

Outputs in `output/`: `INC-00N_timeline.png` (swimlane), `incidents.json`, `report.md`.

## Sample result

The bundled sample (12 raw events across the three sources) correlates into **one
incident** chain spanning **5 ATT&CK techniques**:
T1110 Brute Force -> T1078 Valid Accounts -> T1059.001 PowerShell ->
T1071 Application Layer Protocol -> T1560 Archive Collected Data.

## How it works

| Stage | Module | What it does |
| --- | --- | --- |
| Parse | `parsers.py` | Normalizes timestamps (UTC), hosts, users and summaries from each source |
| Map | `attack_map.py` | Rule-based ATT&CK tagging (Wazuh `rule.mitre.id` is used when present) |
| Correlate | `correlate.py` | Joins events sharing a host or user within a rolling window; merges incidents |
| Narrate | `narrative.py` | Kill-chain progression and step-by-step summary |
| Render | `render.py` | Swimlane chart, one lane per technique, shape/colour per source |
| Report | `report.py` | JSON and Markdown outputs |

### Mapping rules (readable on purpose)

- Security 4625 -> T1110; 4720 -> T1136.001; 4697 -> T1543.003; 1102 -> T1070.001
- Security 4624 (remote logon type 3/10) after 3+ failures for the same user/host within 15 min -> T1078
- Sysmon 1: archive tools or `Compress-Archive` -> T1560; PowerShell -> T1059.001; `schtasks /create` -> T1053.005
- Sysmon 3: external destination from a non-browser process -> T1071
- Sysmon 10: access to `lsass.exe` -> T1003.001

Events with no mapping are counted as noise and kept out of incidents. Extend the
rules in `attack_map.py`.

## Input fields used

- **Windows Security:** `TimeCreated`, `EventID`, `Computer`, `TargetUserName`, `IpAddress`, `LogonType` (also read from a nested `EventData`)
- **Sysmon:** `UtcTime`, `EventID`, `Computer`, `User`, `Image`, `CommandLine`, `DestinationIp`, `DestinationPort`, `TargetImage`
- **Wazuh:** `timestamp`, `agent.name`, `rule.id/level/description/mitre`, `data.dstuser`

## Limitations

- Severity is a simple heuristic (breadth of tactics), not a risk score.
- Technique mapping is rule-based and covers a small, extensible set of behaviours.
- The sample data is synthetic; IPs use the documentation range 203.0.113.0/24.
