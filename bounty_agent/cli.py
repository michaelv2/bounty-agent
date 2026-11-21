"""`bounty` command-line interface."""

from __future__ import annotations

from pathlib import Path

import typer

from bounty_agent import db
from bounty_agent.config import load_config
from bounty_agent.ledger import Ledger
from bounty_agent.queue import JobQueue
from bounty_agent.validate import has_blocking, lint_file

app = typer.Typer(help="bounty-agent: offline-first bug bounty pipeline. See SPEC.md.", no_args_is_help=True)


def _ctx():
    cfg = load_config()
    return cfg, db.connect(cfg.db_path)


@app.command()
def init() -> None:
    """Create the data directory and database."""
    cfg, _ = _ctx()
    typer.echo(f"Database ready at {cfg.db_path}")


@app.command()
def budget() -> None:
    """Show frontier-model spend against the caps."""
    cfg, conn = _ctx()
    led = Ledger(conn)
    b = cfg.budget
    typer.echo(f"Month: ${led.spent_month():.2f} spent + ${led.reserved_month():.2f} reserved / ${b.monthly_usd:.2f}")
    typer.echo(f"Today: ${led.spent_day():.2f} spent + ${led.reserved_day():.2f} reserved / ${b.daily_usd:.2f}")
    typer.echo(f"Kill switch: {'ENGAGED' if cfg.kill_switch_path.exists() else 'off'}")


@app.command()
def kill() -> None:
    """Engage the kill switch: refuse all frontier-model calls."""
    cfg, _ = _ctx()
    cfg.kill_switch_path.touch()
    typer.echo(f"Kill switch engaged ({cfg.kill_switch_path}). Run `bounty unkill` to resume.")


@app.command()
def unkill() -> None:
    """Release the kill switch."""
    cfg, _ = _ctx()
    cfg.kill_switch_path.unlink(missing_ok=True)
    typer.echo("Kill switch released.")


@app.command()
def queue() -> None:
    """Show local job-queue counts by state."""
    _, conn = _ctx()
    counts = JobQueue(conn).counts()
    if not counts:
        typer.echo("Queue is empty.")
    for state, n in sorted(counts.items()):
        typer.echo(f"{state:>8}: {n}")


@app.command()
def batches() -> None:
    """List Message Batches and their items' states."""
    _, conn = _ctx()
    rows = conn.execute(
        """SELECT b.id, b.api_id, b.stage, b.status, b.created_ts, COUNT(i.custom_id) AS n,
                  SUM(i.state = 'pending') AS pending, COALESCE(SUM(i.estimate_usd), 0) AS est
           FROM batches b LEFT JOIN batch_items i ON i.batch_id = b.id
           GROUP BY b.id ORDER BY b.created_ts DESC LIMIT 20"""
    ).fetchall()
    if not rows:
        typer.echo("No batches.")
    for r in rows:
        typer.echo(f"{r['id']} ({r['api_id'] or 'not created'})  {r['stage']:<15} {r['status']:<11} items={r['n']} pending={r['pending']} "
                   f"max=${r['est']:.2f}  created {r['created_ts']}")


@app.command("batch-collect")
def batch_collect() -> None:
    """Collect results for every finished batch (records costs, releases reservations)."""
    from bounty_agent.ledger import BudgetGuard
    from bounty_agent.router import BatchRunner, Router

    cfg, conn = _ctx()
    led = Ledger(conn)
    runner = BatchRunner(Router(cfg, led, BudgetGuard(led, cfg.budget, cfg.kill_switch_path)))
    for bid in runner.pending():
        done = runner.collect(bid)
        typer.echo(f"{bid}: {'still processing' if done is None else f'{len(done)} succeeded'}")


@app.command()
def fetch(
    url: str = typer.Argument(..., help="https://github.com/<owner>/<repo>"),
    ref: str = typer.Argument(..., help="tag, branch or full commit SHA (resolved and pinned)"),
    practice: bool = typer.Option(False, "--practice", help="confirm this is a practice target (no bounty program)"),
) -> None:
    """Fetch a repo + submodules with hardened git into an immutable snapshot.

    Real bounty targets are fetched by the pipeline after a scope check. This command is
    for practice targets (e.g. Damn Vulnerable DeFi) and needs --practice.
    """
    from bounty_agent.fetch import FetchError, fetch_snapshot

    if not practice:
        typer.echo("Refusing: real targets go through the pipeline's scope check. Use --practice for CTFs.")
        raise typer.Exit(2)
    cfg, conn = _ctx()
    try:
        snap = fetch_snapshot(url, ref, cfg.data_dir / "snapshots")
    except FetchError as exc:
        typer.echo(f"Fetch failed: {exc}")
        raise typer.Exit(1)
    conn.execute(
        "INSERT INTO targets (kind, locator, pinned_ref, snapshot_hash) VALUES ('repo', ?, ?, ?)",
        (snap.url, snap.commit, snap.content_hash),
    )
    typer.echo(f"{snap.path}\n  commit {snap.commit}\n  content hash {snap.content_hash}\n"
               f"  {len(snap.submodules)} submodules, {len(snap.skipped)} nested ones skipped")


@app.command()
def run(
    max_minutes: float = typer.Option(60, help="time budget for draining the local queue"),
    manifest: Path = typer.Option(Path("config/targets.toml"), help="target manifest"),
) -> None:
    """Run the pipeline once (meant for a nightly timer). Safe to re-run; resumes where it left off."""
    from bounty_agent.ledger import BudgetGuard
    from bounty_agent.pipeline import AlreadyRunning, Pipeline
    from bounty_agent.router import BatchRunner, Router

    cfg, conn = _ctx()
    led = Ledger(conn)
    router = Router(cfg, led, BudgetGuard(led, cfg.budget, cfg.kill_switch_path))
    pipeline = Pipeline(cfg, conn, router, manifest=manifest, batch_runner=BatchRunner(router))
    try:
        s = pipeline.run(max_minutes)
    except AlreadyRunning as exc:
        typer.echo(str(exc))
        raise typer.Exit(3)
    typer.echo(f"run #{s.run_id}: {s.jobs_run} local jobs, {s.batches_collected} batches collected"
               + (" (out of time; the next run continues)" if s.out_of_time else ""))
    for line in s.advanced:
        typer.echo(f"  {line}")
    for line in s.errors:
        typer.echo(f"  ERROR {line}")
    raise typer.Exit(1 if s.errors else 0)


@app.command()
def digest(short: bool = typer.Option(False, "--short", help="print only the one-line summary (for Slack)")) -> None:
    """Write this week's digest to data/digests/YYYY-Www.md and print the summary."""
    from bounty_agent.pipeline import write_digest

    cfg, conn = _ctx()
    path, summary = write_digest(cfg, conn)
    typer.echo(summary if short else f"{summary}\n{path}")


@app.command()
def targets() -> None:
    """List pipeline targets and their stages."""
    _, conn = _ctx()
    rows = conn.execute("SELECT * FROM targets WHERE name IS NOT NULL ORDER BY id").fetchall()
    if not rows:
        typer.echo("No targets. Add entries to config/targets.toml and run `bounty run`.")
    for t in rows:
        err = f"  ({t['stage_error']})" if t["stage_error"] else ""
        typer.echo(f"{t['name']:<24} {t['source']:<9} {t['stage']:<18} failures={t['failures']}{err}")


@app.command("target-reset")
def target_reset(name: str) -> None:
    """Clear a target's failures and unblock it (it resumes from the last completed stage)."""
    _, conn = _ctx()
    t = conn.execute("SELECT * FROM targets WHERE name = ?", (name,)).fetchone()
    if t is None:
        typer.echo(f"No target {name!r}.")
        raise typer.Exit(1)
    stage = t["stage"]
    if stage == "blocked":  # resume from the furthest stage whose output exists
        stage = "fetched" if t["snapshot_path"] else "new"
    conn.execute("UPDATE targets SET stage = ?, failures = 0, stage_error = NULL WHERE id = ?", (stage, t["id"]))
    typer.echo(f"{name}: reset to {stage}")


@app.command("lint-poc")
def lint_poc(paths: list[Path] = typer.Argument(..., exists=True, dir_okay=False)) -> None:
    """Flag Foundry cheatcode patterns that fake an exploit. Exits 1 if any unjustified high flag remains."""
    blocking = False
    for path in paths:
        flags = lint_file(path)
        for f in flags:
            extra = f"  [justified: {f.reason}]" if f.reason else ""
            typer.echo(f"{path}:{f.line}: {f.severity.upper():7} {f.rule}: {f.message}{extra}\n    {f.snippet}")
        blocking |= has_blocking(flags)
    if not blocking:
        typer.echo("No blocking flags.")
    raise typer.Exit(1 if blocking else 0)


@app.command("llm-ping")
def llm_ping() -> None:
    """Check the local LLM endpoint is reachable and every alias's model is available."""
    from bounty_agent.router import LocalProvider

    cfg = load_config()
    try:
        models = LocalProvider(cfg.local.base_url, timeout_s=10).list_models()
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"Cannot reach {cfg.local.base_url}: {type(exc).__name__}: {exc}")
        raise typer.Exit(1)
    typer.echo(f"{cfg.local.base_url} is up; {len(models)} model(s) available.")
    missing = {a: m for a, m in cfg.local.aliases.items() if m not in models}
    for alias, model in cfg.local.aliases.items():
        typer.echo(f"  {alias} -> {model}: {'MISSING' if alias in missing else 'ok'}")
    if missing:
        typer.echo("Models the server offers (copy the exact name into [local.aliases] in config/router.toml):")
        for m in sorted(models):
            typer.echo(f"  {m}")
    raise typer.Exit(1 if missing else 0)


if __name__ == "__main__":
    app()
