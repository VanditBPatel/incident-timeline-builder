"""Render a swimlane forensic timeline (one lane per ATT&CK technique)."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.dates as mdates  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402

from .models import Incident  # noqa: E402

# Okabe-Ito colour-blind-safe palette; shape also differs per source.
_STYLE = {
    "windows_security": ("#0072B2", "o", "Windows Security"),
    "sysmon": ("#D55E00", "s", "Sysmon"),
    "wazuh": ("#009E73", "^", "Wazuh"),
}


def render_swimlane(incident: Incident, out_path: str | Path) -> Path:
    lanes: list[str] = incident.techniques  # first-seen order, top to bottom
    lane_index = {tid: i for i, tid in enumerate(lanes)}
    name_of = {e.technique: e.technique_name for e in incident.events}
    tactic_of = {e.technique: e.tactic for e in incident.events}

    fig_h = max(3.2, 0.95 * len(lanes) + 1.8)
    fig, ax = plt.subplots(figsize=(11, fig_h))

    # lane bands
    for tid, idx in lane_index.items():
        if idx % 2 == 0:
            ax.axhspan(idx - 0.5, idx + 0.5, color="#f3f3f3", zorder=0)

    # dashed progression line through the first event of each lane
    firsts = []
    for tid in lanes:
        ev = next(e for e in incident.events if e.technique == tid)
        firsts.append((ev.timestamp, lane_index[tid]))
    ax.plot(
        [t for t, _ in firsts],
        [y for _, y in firsts],
        linestyle="--",
        color="#888888",
        linewidth=1,
        zorder=1,
    )

    # small vertical offset per source so near-simultaneous events do not overlap
    offset = {"windows_security": -0.2, "sysmon": 0.0, "wazuh": 0.2}
    for ev in incident.events:
        color, marker, _ = _STYLE.get(ev.source, ("#555555", "D", ev.source))
        ax.scatter(
            ev.timestamp,
            lane_index[ev.technique] + offset.get(ev.source, 0.0),
            s=110,
            c=color,
            marker=marker,
            edgecolors="black",
            linewidths=0.6,
            zorder=3,
        )

    ax.set_yticks(range(len(lanes)))
    ax.set_yticklabels(
        [f"{tid}  {name_of[tid]}\n({tactic_of[tid]})" for tid in lanes], fontsize=9
    )
    ax.set_ylim(len(lanes) - 0.5, -0.5)  # first technique on top
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
    ax.xaxis.set_major_locator(mdates.AutoDateLocator(minticks=5, maxticks=10))
    ax.set_xlabel("Time (UTC)")
    ax.grid(axis="x", linestyle=":", alpha=0.5)
    ax.set_title(
        f"{incident.incident_id} forensic timeline - host {', '.join(sorted(incident.hosts))}, "
        f"user {', '.join(sorted(incident.users)) or 'n/a'} "
        f"[{incident.severity}]",
        fontsize=11,
        loc="left",
    )

    used = {e.source for e in incident.events}
    handles = [
        Line2D(
            [0], [0], marker=m, color="w", markerfacecolor=c, markeredgecolor="black",
            markersize=9, label=label,
        )
        for src, (c, m, label) in _STYLE.items()
        if src in used
    ]
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.16),
              ncol=len(handles), frameon=False)

    fig.tight_layout()
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out
