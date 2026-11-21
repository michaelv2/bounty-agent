"""End-to-end with real Docker + forge (SPEC.md §4.1).

The solc installer downloads 0.8.28 once per session from binaries.soliditylang.org and
verifies it against the official checksum list. Everything else runs with --network none.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from bounty_agent.config import SandboxConfig
from bounty_agent.sandbox import SandboxError, SolcCache, install_solc, run_poc
from bounty_agent.sandbox.runner import base_args, enforce_sandbox_profile, forge_test_command
from bounty_agent.validate import has_blocking, lint_file
from tests.test_sandbox_egress import _docker_ready

FIXTURES = Path(__file__).parent / "fixtures"
POCS = FIXTURES / "pocs"
CFG = SandboxConfig()

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(not _docker_ready(), reason=f"docker or image {CFG.image} not available"),
]


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    root = tmp_path_factory.mktemp("forge")
    snapshot = root / "snapshot"
    shutil.copytree(FIXTURES / "foundry_min", snapshot)
    cache = SolcCache(root / "solc")
    install_solc(CFG, cache, {"0.8.28"})
    cache.verify({"0.8.28"})
    return snapshot, cache


def test_honest_exploit_poc_passes(env):
    snapshot, cache = env
    poc = POCS / "DoubleWithdraw.t.sol"
    assert not has_blocking(lint_file(poc))
    r = run_poc(CFG, snapshot, cache, poc)
    assert r.passed, (r.reason, r.run and r.run.stderr)
    assert r.tests == {"DoubleWithdrawPoC.test_exploit_double_withdraw()": "Success"}


@pytest.mark.parametrize("poc", ["Failing.t.sol", "Skip.t.sol", "NoTests.t.sol"])
def test_false_or_vacuous_pocs_fail(env, poc):
    snapshot, cache = env
    r = run_poc(CFG, snapshot, cache, POCS / poc)
    assert not r.passed, r.reason


def test_ffi_stays_disabled_even_if_target_enables_it(env):
    snapshot, cache = env
    assert "ffi = true" in (snapshot / "foundry.toml").read_text()  # the hostile setting is present
    poc = POCS / "Ffi.t.sol"
    assert has_blocking(lint_file(poc))
    r = run_poc(CFG, snapshot, cache, poc)
    assert not r.passed
    assert "PWN2" not in r.run.stdout + r.run.stderr  # the shell command never executed


def test_positive_control_ffi_runs_with_targets_own_profile(env, tmp_path):
    """Proves the ffi test can detect execution: under the target's hostile default profile, it runs."""
    snapshot, cache = env
    work = tmp_path / "w"
    shutil.copytree(snapshot, work)
    shutil.copyfile(POCS / "Ffi.t.sol", work / "test" / "Ffi.t.sol")
    a = base_args(CFG, name="bounty-ffi-control", target=work, solc_dir=cache.svm, network=False, profile="default")
    p = subprocess.run(a + forge_test_command("test/Ffi.t.sol"), capture_output=True, text=True, timeout=300)
    assert "PWN2" in p.stdout + p.stderr


def test_target_supplied_solc_binary_is_refused(env, tmp_path):
    snapshot, cache = env
    evil = tmp_path / "evil"
    shutil.copytree(snapshot, evil)
    (evil / "foundry.toml").write_text('[profile.default]\nsolc = "./evil.sh"\n')
    with pytest.raises(SandboxError, match="plain version"):
        run_poc(CFG, evil, cache, POCS / "DoubleWithdraw.t.sol")


def test_tampered_cache_blocks_runs(env, tmp_path):
    snapshot, cache = env
    copy = SolcCache(tmp_path / "solc")
    shutil.copytree(cache.root, copy.root)
    copy.binary("0.8.28").write_bytes(b"#!/bin/sh\necho backdoor\n")
    with pytest.raises(SandboxError, match="checksum"):
        run_poc(CFG, snapshot, copy, POCS / "DoubleWithdraw.t.sol")


def test_prebuilt_artifacts_in_target_are_ignored(env, tmp_path):
    """A target shipping its own out/ and cache/ can't make forge skip compiling the real source."""
    snapshot, cache = env
    rigged = tmp_path / "rigged"
    shutil.copytree(snapshot, rigged)
    (rigged / "out").mkdir()
    (rigged / "out" / "garbage.json").write_text("{}")
    (rigged / "cache").mkdir()
    (rigged / "cache" / "solidity-files-cache.json").write_text('{"_format": "rigged"}')
    r = run_poc(CFG, rigged, cache, POCS / "DoubleWithdraw.t.sol")
    assert r.passed, r.reason


def test_effective_config_is_checked_in_forge(env, tmp_path):
    """The appended profile wins under forge's own parser, not just Python's tomllib."""
    snapshot, cache = env
    work = tmp_path / "w"
    shutil.copytree(snapshot, work)
    profile = enforce_sandbox_profile(work)
    a = base_args(CFG, name="bounty-cfg-check", target=work, solc_dir=cache.svm, network=False, profile=profile)
    import json

    cfg = json.loads(subprocess.run(a + ["forge", "config", "--json"], capture_output=True, text=True,
                                    timeout=120).stdout)
    assert cfg["ffi"] is False and cfg["fs_permissions"] == [] and cfg["out"] == "bounty-out"
    assert cfg["solc"] == "0.8.28"  # inherited from the target's default profile
