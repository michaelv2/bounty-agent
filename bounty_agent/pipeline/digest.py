"""Weekly digest (SPEC.md §4 stage G): a markdown file for the human, plus a short summary for Slack.

Everything here is read from the database. Hotspot text is untrusted model output,
so it is flattened to one line and length-capped before it goes into the markdown.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from bounty_agent.config import Config
from bounty_agent.ledger import Ledger


def _one_line(text: str, limit: int = 160) -> str:
    s = " ".join(str(text).split()).replace("|", "\\|")
    return s if len(s) <= limit else s[: limit - 1] + "…"


def week_label(now: datetime) -> str:
    y, w, _ = now.isocalendar()
    return f"{y}-W{w:02d}"


def build_digest(cfg: Config, conn: sqlite3.Connection, now: datetime | None = None) -> tuple[str, str]:
    """Returns (markdown, short_summary)."""
    now = now or datetime.now(timezone.utc)
    led = Ledger(conn, clock=lambda: now)
    b = cfg.budget
    week = week_label(now)
    lines = [f"# bounty-agent digest {week}", "", f"_Generated {now:%Y-%m-%d %H:%M} UTC_", ""]

    month, reserved = led.spent_month(), led.reserved_month()
    lines += ["## Budget", "",
              f"- Month: ${month:.2f} spent + ${reserved:.2f} reserved of ${b.monthly_usd:.2f}",
              f"- Today: ${led.spent_day():.2f} of ${b.daily_usd:.2f}",
              f"- Kill switch: {'**ENGAGED**' if cfg.kill_switch_path.exists() else 'off'}", ""]

    runs = conn.execute(
        "SELECT status, COUNT(*) AS n FROM runs WHERE started_at >= datetime('now', '-7 days') GROUP BY status"
    ).fetchall()
    last = conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 1").fetchone()
    lines += ["## Runs (last 7 days)", ""]
    lines += [f"- {r['status']}: {r['n']}" for r in runs] or ["- none"]
    if last:
        s = json.loads(last["summary_json"] or "{}")
        lines.append(f"- Last run #{last['id']} ({last['status']}, {last['started_at']}): "
                     f"{s.get('jobs_run', 0)} local jobs, {len(s.get('errors', []))} errors"
                     + (", ran out of time" if s.get("out_of_time") else ""))
    lines.append("")

    targets = conn.execute(
        "SELECT * FROM targets WHERE name IS NOT NULL ORDER BY id").fetchall()
    lines += ["## Targets", "", "| Target | Source | Stage | Note |", "|---|---|---|---|"]
    for t in targets:
        lines.append(f"| {t['name']} | {t['source']} | {t['stage']} | {_one_line(t['stage_error'] or '', 100)} |")
    if not targets:
        lines.append("| (none; add entries to config/targets.toml) | | | |")
    lines.append("")

    lines += ["## Top hotspots (local triage, unverified)", ""]
    any_hot = False
    for t in targets:
        hot = conn.execute(
            "SELECT * FROM hotspots WHERE target_id = ? ORDER BY rank LIMIT 5", (t["id"],)).fetchall()
        if not hot:
            continue
        any_hot = True
        lines += [f"**{t['name']}**", ""]
        lines += [f"{h['rank']}. `{_one_line(h['path'], 80)}` {_one_line(h['function'] or '', 60)} "
                  f"({h['confidence']}): {_one_line(h['rationale'] or '')}" for h in hot]
        lines.append("")
    if not any_hot:
        lines += ["No hotspots yet.", ""]

    pending_review = conn.execute(
        """SELECT COUNT(*) FROM findings f JOIN reviews r ON r.finding_id = f.id
           WHERE r.verdict IN ('submit', 'flag-for-human')""").fetchone()[0]
    lines += ["## Awaiting your review", "",
              f"{pending_review} finding(s)." if pending_review else
              "Nothing yet. Findings appear here once deep analysis (stage D) is built.", ""]

    counts = conn.execute("SELECT state, COUNT(*) AS n FROM jobs GROUP BY state").fetchall()
    failed = conn.execute(
        "SELECT kind, error FROM jobs WHERE state = 'failed' ORDER BY id DESC LIMIT 5").fetchall()
    lines += ["## Local queue", "", ", ".join(f"{r['state']}: {r['n']}" for r in counts) or "empty", ""]
    if failed:
        lines += ["Recent failures:", ""] + [f"- {r['kind']}: {_one_line(r['error'] or '', 200)}" for r in failed] + [""]

    stage_counts: dict[str, int] = {}
    for t in targets:
        stage_counts[t["stage"]] = stage_counts.get(t["stage"], 0) + 1
    short = (f"bounty-agent {week}: ${month:.2f}+${reserved:.2f} reserved of ${b.monthly_usd:.0f}/mo; "
             f"targets {', '.join(f'{k}={v}' for k, v in sorted(stage_counts.items())) or 'none'}; "
             f"{pending_review} awaiting review"
             + (f"; last run {last['status']}" if last else ""))
    return "\n".join(lines), short


def write_digest(cfg: Config, conn: sqlite3.Connection, now: datetime | None = None) -> tuple[Path, str]:
    now = now or datetime.now(timezone.utc)
    md, short = build_digest(cfg, conn, now)
    path = cfg.data_dir / "digests" / f"{week_label(now)}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(md + "\n", encoding="utf-8")
    return path, short
