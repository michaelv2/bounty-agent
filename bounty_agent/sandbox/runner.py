"""Run untrusted target code in a throwaway, network-less container (SPEC.md §4.1).

Rules this module enforces (each has a test):
  - Target code NEVER runs with network. The only networked container is the solc
    installer, which builds a project we generate ourselves; no target files are mounted.
  - Installed compilers are checked against soliditylang's published SHA-256 list and
    re-hashed before every run. The cache is mounted read-only whenever target code runs.
  - The target's foundry.toml is untrusted: a locked-down profile is appended and the
    config *as forge parses it* is checked before the PoC runs.
  - Pass/fail comes from `forge test --json`, never from the exit code (forge exits 0
    when zero tests match).
  - Host-side file operations on the scratch copy never follow symlinks.
  - Every docker argument is built here. Callers and LLMs supply file contents and a
    test-name filter, never flags or shell commands.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
import tomllib
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from bounty_agent.config import SandboxConfig

# Paths inside the container. HOME is on the /tmp tmpfs (noexec). forge keeps solc in
# $HOME/.svm and ignores SVM_HOME, so the compiler cache is bind-mounted exactly there.
HOME = "/tmp/home"
TARGET, SOLC_DIR = "/target", f"{HOME}/.svm"

MAX_OUTPUT_BYTES = 5 * 1024 * 1024    # per stream; the container is killed beyond this
MAX_FILE_BYTES = 1024 * 1024 * 1024   # RLIMIT_FSIZE inside the container
SOLC_LIST_URL = "https://binaries.soliditylang.org/linux-amd64/list.json"

_FILTER = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_*]{0,99}$")       # test-name filter
_DEST = re.compile(r"^test/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.t\.sol$")
_HOST_PATH = re.compile(r"^/[A-Za-z0-9_./-]+$")                     # safe for --mount
_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
_EXACT_PRAGMA = re.compile(r"pragma\s+solidity\s+=?\s*(\d+\.\d+\.\d+)\s*;")
_ANY_PRAGMA = re.compile(r"pragma\s+solidity\s+[^;]+;")

# Appended to the scratch copy's foundry.toml under a random name and selected with
# FOUNDRY_PROFILE. forge does NOT let the FOUNDRY_FFI env var override `ffi = true`
# in a target's config (tests/test_sandbox_forge.py). Fresh out/cache dirs mean
# prebuilt artifacts shipped with the target are never reused.
PROFILE_SETTINGS = (
    'ffi = false\n'
    'fs_permissions = []\n'
    'out = "bounty-out"\n'
    'cache_path = "bounty-cache"\n'
)

# Config keys a target could set to give the attacker powers the cheat lint can't see.
# They don't block the run; deviations from forge defaults go to the reviewer.
REVIEW_KEYS = ("sender", "tx_origin", "initial_balance", "block_timestamp", "block_number",
               "gas_limit", "block_coinbase", "chain_id", "evm_version")


class SandboxError(RuntimeError):
    pass


@dataclass(frozen=True)
class RunResult:
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_s: float
    truncated: bool = False

    @property
    def ok(self) -> bool:
        """Process-level success only. For PoCs, use PocResult.passed instead."""
        return self.exit_code == 0 and not self.timed_out and not self.truncated


@dataclass(frozen=True)
class PocResult:
    passed: bool
    reason: str
    tests: dict[str, str]                     # "Contract.test_name()" -> status
    config_notes: dict[str, object] = field(default_factory=dict)
    run: RunResult | None = None


# --------------------------------------------------------------------------- docker args

def _host_path(p: Path) -> str:
    s = str(p.resolve())
    if not _HOST_PATH.match(s):
        raise SandboxError(f"unsafe host path for a mount: {s!r}")
    return s


def base_args(cfg: SandboxConfig, *, name: str, target: Path, solc_dir: Path, network: bool,
              profile: str | None = None) -> list[str]:
    """The hardened `docker run` prefix. Network mode exists only for the solc installer."""
    if os.getuid() == 0 or os.getgid() == 0:
        raise SandboxError("refusing to run the sandbox as root")
    if not network and profile is None:
        raise SandboxError("offline runs must use an enforced sandbox profile")
    args = [
        "docker", "run", "--rm", "--name", name,
        "--label", "bounty.sandbox=1",
        "--pull", "never",
        "--init",
        "--network", "bridge" if network else "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", str(cfg.pids_limit),
        "--memory", cfg.memory, "--memory-swap", cfg.memory,
        "--cpus", str(cfg.cpus),
        "--ulimit", f"fsize={MAX_FILE_BYTES}",
        "--ulimit", "nofile=1024:1024",
        "--ulimit", "core=0",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=512m",
        "-e", f"HOME={HOME}",
        "--mount", f"type=bind,src={_host_path(target)},dst={TARGET}",
        "--mount", f"type=bind,src={_host_path(solc_dir)},dst={SOLC_DIR}" + ("" if network else ",readonly"),
        "-w", TARGET,
    ]
    if not network:
        args += ["-e", "FOUNDRY_OFFLINE=true"]
    if profile is not None:
        args += ["-e", f"FOUNDRY_PROFILE={profile}"]
    return args + [cfg.image]


def forge_test_command(test_file: str, match_test: str | None = None) -> list[str]:
    if not _DEST.match(test_file):
        raise SandboxError(f"invalid test file path: {test_file!r}")
    if match_test is not None and not _FILTER.match(match_test):
        raise SandboxError(f"invalid match_test: {match_test!r}")
    cmd = ["forge", "test", "--offline", "--force", "--json", "--match-path", test_file]
    if match_test:
        cmd += ["--match-test", match_test]
    return cmd


def _name(kind: str) -> str:
    return f"bounty-{kind}-{uuid.uuid4().hex[:12]}"


def _run(args: list[str], name: str, timeout_s: float) -> RunResult:
    """Run with a wall-clock timeout and capped output; kill the container on either limit."""
    start = time.monotonic()
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        p = subprocess.Popen(args, stdout=out, stderr=err)
        timed_out = truncated = False
        while p.poll() is None:
            if time.monotonic() - start > timeout_s:
                timed_out = True
            elif max(os.fstat(out.fileno()).st_size, os.fstat(err.fileno()).st_size) > MAX_OUTPUT_BYTES:
                truncated = True
            if timed_out or truncated:
                subprocess.run(["docker", "kill", name], capture_output=True)
                try:
                    p.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()
                break
            time.sleep(0.1)

        def read(f) -> str:
            f.seek(0)
            return f.read(MAX_OUTPUT_BYTES).decode("utf-8", "replace")

        return RunResult(None if (timed_out or truncated) else p.returncode,
                         read(out), read(err), timed_out, time.monotonic() - start, truncated)


# --------------------------------------------------------------------------- solc cache

class SolcCache:
    """Compiler cache: `svm/` is mounted into containers; `manifest.json` stays host-side."""

    def __init__(self, root: Path):
        self.root = root
        self.svm = root / "svm"
        self.manifest_path = root / "manifest.json"

    def manifest(self) -> dict[str, str]:
        return json.loads(self.manifest_path.read_text()) if self.manifest_path.exists() else {}

    def binary(self, version: str) -> Path:
        return self.svm / version / f"solc-{version}"

    def verify(self, versions: set[str]) -> None:
        """Re-hash each needed compiler against the manifest. Raises on any mismatch."""
        manifest = self.manifest()
        for v in sorted(versions):
            if v not in manifest:
                raise SandboxError(f"solc {v} is not installed; run install_solc first")
            b = self.binary(v)
            if b.is_symlink() or not b.is_file() or _sha256(b) != manifest[v]:
                raise SandboxError(f"solc {v} in the cache does not match its recorded checksum")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def official_solc_sha256(versions: set[str], list_json: dict | None = None) -> dict[str, str]:
    """SHA-256 per version from soliditylang's published list (fetched if not given)."""
    if list_json is None:
        import httpx2

        resp = httpx2.get(SOLC_LIST_URL, timeout=30)
        resp.raise_for_status()
        list_json = resp.json()
    by_version = {b["version"]: b["sha256"].removeprefix("0x") for b in list_json["builds"]
                  if "-nightly" not in b.get("path", "")}
    missing = versions - by_version.keys()
    if missing:
        raise SandboxError(f"solc version(s) not in the official list: {sorted(missing)}")
    return {v: by_version[v] for v in versions}


def install_solc(cfg: SandboxConfig, cache: SolcCache, versions: set[str], *,
                 list_json: dict | None = None) -> None:
    """Download compilers with network, using a project WE generate. No target code is involved."""
    for v in versions:
        if not _VERSION.match(v):
            raise SandboxError(f"invalid solc version: {v!r}")
    expected = official_solc_sha256(versions, list_json)
    cache.svm.mkdir(parents=True, exist_ok=True)
    manifest = cache.manifest()
    for v in sorted(versions - manifest.keys()):
        with tempfile.TemporaryDirectory(prefix="bounty-solc-") as tmp:
            proj = Path(tmp)
            (proj / "src").mkdir()
            (proj / "foundry.toml").write_text(f'[profile.default]\nsolc_version = "{v}"\n')
            (proj / "src" / "Empty.sol").write_text(f"// SPDX-License-Identifier: MIT\npragma solidity {v};\ncontract Empty {{}}\n")
            name = _name("solc")
            r = _run(base_args(cfg, name=name, target=proj, solc_dir=cache.svm, network=True)
                     + ["forge", "build"], name, cfg.timeout_s)
        if not r.ok:
            raise SandboxError(f"solc {v} install failed: {r.stderr[-500:]}")
        actual = _sha256(cache.binary(v))
        if actual != expected[v]:
            cache.binary(v).unlink(missing_ok=True)
            raise SandboxError(f"solc {v} checksum {actual} != official {expected[v]}")
        manifest[v] = actual
        cache.manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))


def required_solc_versions(snapshot: Path) -> set[str]:
    """Compiler versions a target needs, read host-side from its config and pragmas (no code runs)."""
    toml = snapshot / "foundry.toml"
    if toml.is_symlink():
        raise SandboxError("foundry.toml is a symlink")
    if toml.exists():
        try:
            default = tomllib.loads(toml.read_text(encoding="utf-8")).get("profile", {}).get("default", {})
        except tomllib.TOMLDecodeError as exc:
            raise SandboxError(f"target foundry.toml is not valid TOML: {exc}") from None
        configured = default.get("solc_version", default.get("solc"))
        if configured is not None:
            if not isinstance(configured, str) or not _VERSION.match(configured):
                # Rejects `solc = "./evil"`: a path would make forge execute a target-supplied binary.
                raise SandboxError(f"solc must be a plain version like 0.8.28, got {configured!r}")
            return {configured}
    versions, loose = set(), []
    for sol in snapshot.rglob("*.sol"):
        if sol.is_symlink() or "lib" in sol.relative_to(snapshot).parts[:1]:
            continue
        text = sol.read_text(encoding="utf-8", errors="replace")
        exact = _EXACT_PRAGMA.findall(text)
        versions.update(exact)
        if not exact and _ANY_PRAGMA.search(text):
            loose.append(str(sol.relative_to(snapshot)))
    if loose and not versions:
        raise SandboxError(f"can't pick a solc version from range pragmas (e.g. {loose[0]}); set solc_version")
    if not versions:
        raise SandboxError("no Solidity sources with a pragma found")
    return versions


# --------------------------------------------------------------------------- scratch copy

def _reject_special_files(root: Path) -> None:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for n in dirnames + filenames:
            mode = os.lstat(os.path.join(dirpath, n)).st_mode
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
                raise SandboxError(f"special file in snapshot: {os.path.join(dirpath, n)}")


def _strip_escaping_symlinks(work: Path) -> list[str]:
    """Remove symlinks that are absolute or point outside the scratch copy. Returns what was removed."""
    root = work.resolve()
    removed = []
    for dirpath, dirnames, filenames in os.walk(work, followlinks=False):
        for n in dirnames + filenames:
            p = Path(dirpath) / n
            if p.is_symlink():
                link = os.readlink(p)
                resolved = Path(os.path.realpath(p))
                if os.path.isabs(link) or not resolved.is_relative_to(root):
                    p.unlink()
                    removed.append(str(p.relative_to(work)))
    return removed


def _no_symlink_components(work: Path, rel: str) -> None:
    p = work
    for part in Path(rel).parts:
        p = p / part
        if p.is_symlink():
            raise SandboxError(f"path component is a symlink: {p.relative_to(work)}")


def _write_new_file(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def enforce_sandbox_profile(work: Path) -> str:
    """Append a randomly named, locked-down profile to the scratch copy's foundry.toml."""
    toml = work / "foundry.toml"
    if toml.is_symlink():
        raise SandboxError("foundry.toml is a symlink")
    text = toml.read_text(encoding="utf-8") if toml.exists() else ""
    try:
        profiles = tomllib.loads(text).get("profile", {})
    except tomllib.TOMLDecodeError as exc:
        raise SandboxError(f"target foundry.toml is not valid TOML: {exc}") from None
    name = f"bounty_sandbox_{uuid.uuid4().hex[:12]}"
    if name in profiles:
        raise SandboxError("profile name collision")
    fd = os.open(toml, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(f"\n\n[profile.{name}]\n{PROFILE_SETTINGS}")
    return name


def prepare_scratch(snapshot: Path, work: Path, poc_file: Path, dest: str) -> tuple[str, list[str]]:
    """Copy the snapshot, neutralize symlink tricks, add the PoC and the enforced profile."""
    if not _DEST.match(dest):
        raise SandboxError(f"PoC destination must look like test/Name.t.sol, got {dest!r}")
    _reject_special_files(snapshot)
    shutil.copytree(snapshot, work, symlinks=True)
    removed = _strip_escaping_symlinks(work)
    _no_symlink_components(work, dest)
    (work / dest).parent.mkdir(parents=True, exist_ok=True)
    _no_symlink_components(work, dest)
    try:
        _write_new_file(work / dest, poc_file.read_bytes())  # O_EXCL: never overwrite a target file
    except FileExistsError:
        raise SandboxError(f"{dest} already exists in the target; pick a new file name") from None
    return enforce_sandbox_profile(work), removed


# --------------------------------------------------------------------------- verdicts

def check_config(config: dict, defaults: dict | None = None) -> dict[str, object]:
    """Validate the config as forge parsed it. Raises on dangerous settings; returns review notes."""
    if config.get("ffi") is not False:
        raise SandboxError("ffi is not disabled in the effective config")
    if config.get("fs_permissions"):
        raise SandboxError("fs_permissions is not empty in the effective config")
    solc = config.get("solc")
    if solc is not None and not (isinstance(solc, str) and _VERSION.match(solc)):
        raise SandboxError(f"effective solc is not a plain version: {solc!r}")
    if config.get("eth_rpc_url"):
        raise SandboxError("eth_rpc_url is set in the effective config")
    for key in ("out", "cache_path"):
        if os.path.isabs(str(config.get(key, ""))) or ".." in Path(str(config.get(key, ""))).parts:
            raise SandboxError(f"{key} must be a relative path inside the target")
    defaults = defaults or {}
    return {k: config.get(k) for k in REVIEW_KEYS if k in defaults and config.get(k) != defaults.get(k)}


def judge(stdout: str, dest: str) -> tuple[bool, str, dict[str, str]]:
    """Pass only if forge's JSON shows >=1 test in the PoC file and every one succeeded."""
    line = next((ln for ln in reversed(stdout.strip().splitlines()) if ln.startswith("{")), None)
    if line is None:
        return False, "no JSON result from forge", {}
    try:
        suites = json.loads(line)
    except json.JSONDecodeError:
        return False, "unparseable JSON result from forge", {}
    tests: dict[str, str] = {}
    for suite, body in suites.items():
        path, _, contract = suite.rpartition(":")
        if path != dest:
            return False, f"unexpected test suite outside the PoC: {suite}", tests
        for test_name, res in (body.get("test_results") or {}).items():
            tests[f"{contract}.{test_name}"] = str(res.get("status"))
    if not tests:
        return False, "no tests ran (forge exits 0 in this case)", tests
    bad = {k: v for k, v in tests.items() if v != "Success"}
    if bad:
        return False, f"not all tests succeeded: {bad}", tests
    return True, f"{len(tests)} test(s) succeeded", tests


_DEFAULTS_CACHE: dict | None = None


def _default_config(cfg: SandboxConfig, cache: SolcCache) -> dict:
    """forge's defaults for REVIEW_KEYS, from an empty project we generate (computed once)."""
    global _DEFAULTS_CACHE
    if _DEFAULTS_CACHE is None:
        with tempfile.TemporaryDirectory(prefix="bounty-defaults-") as tmp:
            proj = Path(tmp)
            profile = enforce_sandbox_profile(proj)
            name = _name("cfg")
            r = _run(base_args(cfg, name=name, target=proj, solc_dir=cache.svm, network=False, profile=profile)
                     + ["forge", "config", "--json"], name, 120)
        _DEFAULTS_CACHE = json.loads(r.stdout) if r.ok else {}
    return _DEFAULTS_CACHE


def run_poc(cfg: SandboxConfig, snapshot: Path, cache: SolcCache, poc_file: Path, *,
            dest: str = "test/BountyPoC.t.sol", match_test: str | None = None) -> PocResult:
    """Validate one PoC against a snapshot: offline, in a scratch copy, judged from JSON."""
    versions = required_solc_versions(snapshot)
    cache.verify(versions)
    with tempfile.TemporaryDirectory(prefix="bounty-run-") as tmp:
        work = Path(tmp) / "target"
        profile, _removed = prepare_scratch(snapshot, work, poc_file, dest)

        name = _name("cfg")
        r = _run(base_args(cfg, name=name, target=work, solc_dir=cache.svm, network=False, profile=profile)
                 + ["forge", "config", "--json"], name, 120)
        if not r.ok:
            return PocResult(False, f"forge config failed: {r.stderr[-300:]}", {}, run=r)
        try:
            notes = check_config(json.loads(r.stdout), _default_config(cfg, cache))
        except (SandboxError, json.JSONDecodeError) as exc:
            return PocResult(False, f"config check failed: {exc}", {}, run=r)

        name = _name("test")
        r = _run(base_args(cfg, name=name, target=work, solc_dir=cache.svm, network=False, profile=profile)
                 + forge_test_command(dest, match_test), name, cfg.timeout_s)
        if r.timed_out or r.truncated:
            return PocResult(False, "timed out" if r.timed_out else "output limit exceeded", {}, notes, r)
        passed, reason, tests = judge(r.stdout, dest)
        return PocResult(passed, reason, tests, notes, r)
