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
    typer.echo(f"Month: ${led.spent_month():.2f} / ${b.monthly_usd:.2f}")
    typer.echo(f"Today: ${led.spent_day():.2f} / ${b.daily_usd:.2f}")
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
