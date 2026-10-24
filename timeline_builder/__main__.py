"""Command line entry point: python -m timeline_builder ..."""

from __future__ import annotations

import argparse
from datetime import timedelta
from pathlib import Path

from .attack_map import map_events
from .correlate import correlate
from .narrative import build_narrative
from .parsers import parse_all
from .render import render_swimlane
from .report import write_json, write_markdown

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_data"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="timeline_builder",
        description="Correlate Windows Security, Sysmon and Wazuh logs into "
        "ATT&CK-mapped incident timelines.",
    )
    p.add_argument("--security", nargs="*", default=[], help="Windows Security event log export(s) (JSON/NDJSON)")
    p.add_argument("--sysmon", nargs="*", default=[], help="Sysmon event export(s) (JSON/NDJSON)")
    p.add_argument("--wazuh", nargs="*", default=[], help="Wazuh alerts (JSON/NDJSON)")
    p.add_argument("--window", type=int, default=30, help="Rolling correlation window in minutes (default 30)")
    p.add_argument("--out", default="output", help="Output directory (default ./output)")
    p.add_argument("--demo", action="store_true", help="Run on the bundled sample data")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.demo:
        args.security = [str(SAMPLE_DIR / "windows_security.json")]
        args.sysmon = [str(SAMPLE_DIR / "sysmon.json")]
        args.wazuh = [str(SAMPLE_DIR / "wazuh_alerts.json")]

    if not (args.security or args.sysmon or args.wazuh):
        print("No input given. Use --security/--sysmon/--wazuh or --demo.")
        return 2

    events = parse_all(
        {"windows_security": args.security, "sysmon": args.sysmon, "wazuh": args.wazuh}
    )
    events = map_events(events)
    unmapped = sum(1 for e in events if not e.technique)
    incidents = correlate(events, timedelta(minutes=args.window))

    out = Path(args.out)
    images: dict[str, str] = {}
    for inc in incidents:
        png = render_swimlane(inc, out / f"{inc.incident_id}_timeline.png")
        images[inc.incident_id] = png.name
    write_json(incidents, out / "incidents.json")
    write_markdown(incidents, out / "report.md", images, len(events), unmapped)

    print(f"Ingested {len(events)} events -> {len(incidents)} incident(s)\n")
    for inc in incidents:
        print(build_narrative(inc))
        print()
    print(f"Outputs written to {out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
