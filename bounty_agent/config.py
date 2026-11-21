"""Load configuration from config/router.toml (stdlib tomllib, no extra dependency)."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "router.toml"
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"


@dataclass(frozen=True)
class BudgetConfig:
    monthly_usd: float
    daily_usd: float
    per_target_usd: float


@dataclass(frozen=True)
class LocalConfig:
    base_url: str
    timeout_s: float = 600
    concurrency: int = 1
    aliases: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class SandboxConfig:
    image: str = "bounty-sandbox:latest"
    cpus: float = 2.0
    memory: str = "4g"
    pids_limit: int = 512
    timeout_s: float = 900


@dataclass(frozen=True)
class Config:
    budget: BudgetConfig
    local: LocalConfig
    routes: dict[str, str]
    data_dir: Path
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "bounty.db"

    @property
    def kill_switch_path(self) -> Path:
        """If this file exists, all frontier-model calls are refused."""
        return self.data_dir / "KILL"


def load_config(path: Path | None = None, data_dir: Path | None = None) -> Config:
    path = Path(path or os.environ.get("BOUNTY_CONFIG", DEFAULT_CONFIG))
    with path.open("rb") as f:
        raw = tomllib.load(f)

    local_raw = dict(raw["local"])
    aliases = local_raw.pop("aliases", {})
    return Config(
        budget=BudgetConfig(**raw["budget"]),
        local=LocalConfig(**local_raw, aliases=aliases),
        routes=dict(raw["routes"]),
        sandbox=SandboxConfig(**raw.get("sandbox", {})),
        data_dir=Path(data_dir or os.environ.get("BOUNTY_DATA_DIR", DEFAULT_DATA_DIR)),
    )
