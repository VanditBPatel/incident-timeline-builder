"""Write JSON and Markdown outputs for a set of incidents."""

from __future__ import annotations

import json
from pathlib import Path

from .models import Incident
from .narrative import build_narrative


def write_json(incidents: list[Incident], out_path: str | Path) -> Path:
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps([i.to_dict() for i in incidents], indent=2), encoding="utf-8"
    )
    return out


def write_markdown(
    incidents: list[Incident],
    out_path: str | Path,
    images: dict[str, str],
    total_events: int,
    unmapped: int,
) -> Path:
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    parts = [
        "# Incident Timeline Report",
        "",
        f"- Raw events ingested: {total_events}",
        f"- Events with no ATT&CK mapping (treated as noise): {unmapped}",
        f"- Incidents identified: {len(incidents)}",
        "",
    ]
    for inc in incidents:
        parts += [f"## {inc.incident_id}", "", "```text", build_narrative(inc), "```", ""]
        if inc.incident_id in images:
            parts += [f"![{inc.incident_id} timeline]({images[inc.incident_id]})", ""]
        parts += [
            "| Time (UTC) | Source | Host | User | ATT&CK | Summary |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for e in inc.events:
            summary = e.summary.replace("|", "\\|")
            parts.append(
                f"| {e.timestamp:%H:%M:%S} | {e.source} | {e.host} | {e.user} | "
                f"{e.technique} | {summary} |"
            )
        parts.append("")
    out.write_text("\n".join(parts), encoding="utf-8")
    return out
