"""Sandbox guardrails that don't need Docker: docker args, scratch-copy safety, config and verdict checks."""

import hashlib
import json
import os
from pathlib import Path

import pytest

from bounty_agent.config import SandboxConfig
from bounty_agent.sandbox import SandboxError, SolcCache, forge_test_command, required_solc_versions
from bounty_agent.sandbox.runner import (
    base_args,
    check_config,
    enforce_sandbox_profile,
    judge,
    official_solc_sha256,
    prepare_scratch,
)

CFG = SandboxConfig(image="bounty-sandbox:test")


def args(network: bool):
    return base_args(CFG, name="n", target=Path("/tmp/t"), solc_dir=Path("/tmp/c"), network=network,
                     profile=None if network else "bounty_sandbox_test")


def flag_value(a, flag):
    return a[a.index(flag) + 1]


def all_values(a, flag):
    return [a[i + 1] for i, x in enumerate(a) if x == flag]


# ------------------------------------------------------------------ docker args

def test_test_mode_has_no_network_and_full_hardening():
    a = args(network=False)
    assert flag_value(a, "--network") == "none"
    for required in ["--read-only", "--rm", "--init"]:
        assert required in a
    assert flag_value(a, "--pull") == "never"  # a missing image can't be replaced by a pulled one
    assert flag_value(a, "--cap-drop") == "ALL"
    assert flag_value(a, "--security-opt") == "no-new-privileges"
    assert "noexec" in flag_value(a, "--tmpfs")
    assert {"nofile=1024:1024", "core=0"} <= set(all_values(a, "--ulimit"))
    assert "FOUNDRY_OFFLINE=true" in a and "FOUNDRY_PROFILE=bounty_sandbox_test" in a
    assert "type=bind,src=/tmp/c,dst=/tmp/home/.svm,readonly" in all_values(a, "--mount")
    assert a[-1] == "bounty-sandbox:test"


def test_no_host_secrets_or_docker_socket_are_passed():
    for a in (args(network=False), args(network=True)):
        assert "docker.sock" not in " ".join(a)
        assert "--env-file" not in a and "--privileged" not in a and "-v" not in a
        assert not any(x.startswith("ANTHROPIC") for x in a)
        assert all(",src=/tmp/" in m for m in all_values(a, "--mount"))


def test_only_installer_mode_has_network_and_writable_cache():
    a = args(network=True)
    assert flag_value(a, "--network") == "bridge"
    assert "type=bind,src=/tmp/c,dst=/tmp/home/.svm" in all_values(a, "--mount")
    assert flag_value(a, "--cap-drop") == "ALL"


def test_offline_run_without_enforced_profile_is_refused():
    with pytest.raises(SandboxError, match="profile"):
        base_args(CFG, name="n", target=Path("/tmp/t"), solc_dir=Path("/tmp/c"), network=False)


def test_unsafe_mount_paths_refused(tmp_path):
    weird = tmp_path / "a,dst=etc"
    with pytest.raises(SandboxError, match="unsafe host path"):
        base_args(CFG, name="n", target=weird, solc_dir=tmp_path, network=False, profile="p")


def test_forge_test_command_is_offline_forced_json():
    cmd = forge_test_command("test/BountyPoC.t.sol", "test_exploit*")
    assert cmd[:6] == ["forge", "test", "--offline", "--force", "--json", "--match-path"]


@pytest.mark.parametrize("bad", ["--ffi", "-x", "../../etc/passwd", "src/Vault.sol", "test/x.sol",
                                 "test/../src/A.t.sol", "a b"])
def test_bad_test_paths_refused(bad):
    with pytest.raises(SandboxError):
        forge_test_command(bad)


@pytest.mark.parametrize("bad", ["--ffi", "a;b", "$(id)", "x" * 101])
def test_bad_test_filters_refused(bad):
    with pytest.raises(SandboxError):
        forge_test_command("test/A.t.sol", bad)


# ------------------------------------------------------------------ scratch copy (review H1, M1, L5)

@pytest.fixture
def snapshot(tmp_path):
    s = tmp_path / "snap"
    (s / "src").mkdir(parents=True)
    (s / "test").mkdir()
    (s / "src" / "Vault.sol").write_text("pragma solidity 0.8.28; contract Vault {}")
    (s / "foundry.toml").write_text('[profile.default]\nsolc_version = "0.8.28"\n')
    return s


@pytest.fixture
def poc(tmp_path):
    p = tmp_path / "Poc.t.sol"
    p.write_text("contract P { function test_x() public {} }")
    return p


@pytest.fixture
def victim(tmp_path):
    d = tmp_path / "victim"
    d.mkdir()
    (d / "precious").write_text("original")
    return d


def test_symlinked_test_dir_cannot_redirect_poc_write(tmp_path, snapshot, poc, victim):
    (snapshot / "test").rmdir()
    (snapshot / "test").symlink_to(victim)
    prepare_scratch(snapshot, tmp_path / "work", poc, "test/BountyPoC.t.sol")
    assert sorted(p.name for p in victim.iterdir()) == ["precious"]  # nothing written outside


def test_symlinked_poc_destination_cannot_overwrite_host_file(tmp_path, snapshot, poc, victim):
    (snapshot / "test" / "BountyPoC.t.sol").symlink_to(victim / "precious")
    prepare_scratch(snapshot, tmp_path / "work", poc, "test/BountyPoC.t.sol")
    assert (victim / "precious").read_text() == "original"


@pytest.mark.parametrize("dangling", [False, True])
def test_symlinked_foundry_toml_cannot_append_to_host_file(tmp_path, snapshot, poc, victim, dangling):
    (snapshot / "foundry.toml").unlink()
    (snapshot / "foundry.toml").symlink_to(victim / ("missing.toml" if dangling else "precious"))
    prepare_scratch(snapshot, tmp_path / "work", poc, "test/BountyPoC.t.sol")
    assert (victim / "precious").read_text() == "original"
    assert not (victim / "missing.toml").exists()


def test_internal_relative_symlinks_are_kept(tmp_path, snapshot, poc):
    (snapshot / "src" / "Alias.sol").symlink_to("Vault.sol")
    prepare_scratch(snapshot, tmp_path / "work", poc, "test/BountyPoC.t.sol")
    assert (tmp_path / "work" / "src" / "Alias.sol").is_symlink()


def test_poc_cannot_overwrite_an_existing_target_file(tmp_path, snapshot, poc):
    (snapshot / "test" / "Existing.t.sol").write_text("original test")
    with pytest.raises(SandboxError, match="already exists"):
        prepare_scratch(snapshot, tmp_path / "work", poc, "test/Existing.t.sol")


def test_poc_cannot_replace_contract_sources(tmp_path, snapshot, poc):
    with pytest.raises(SandboxError, match="destination"):
        prepare_scratch(snapshot, tmp_path / "work", poc, "src/Vault.sol")


def test_special_files_rejected(tmp_path, snapshot, poc):
    os.mkfifo(snapshot / "src" / "pipe")
    with pytest.raises(SandboxError, match="special file"):
        prepare_scratch(snapshot, tmp_path / "work", poc, "test/BountyPoC.t.sol")


def test_snapshot_is_untouched(tmp_path, snapshot, poc):
    def state():
        return sorted((str(p.relative_to(snapshot)), p.read_bytes() if p.is_file() else b"")
                      for p in snapshot.rglob("*"))
    before = state()
    prepare_scratch(snapshot, tmp_path / "work", poc, "test/BountyPoC.t.sol")
    assert state() == before


# ------------------------------------------------------------------ profile + effective config (M3)

def test_enforced_profile_is_appended(tmp_path):
    import tomllib

    (tmp_path / "foundry.toml").write_text('[profile.default]\nffi = true\nsolc_version = "0.8.28"\n')
    name = enforce_sandbox_profile(tmp_path)
    cfg = tomllib.loads((tmp_path / "foundry.toml").read_text())
    assert cfg["profile"][name]["ffi"] is False and cfg["profile"][name]["fs_permissions"] == []
    assert cfg["profile"][name]["out"] == "bounty-out"  # fresh artifacts, never the target's
    assert cfg["profile"]["default"]["solc_version"] == "0.8.28"


def test_invalid_target_config_is_refused(tmp_path):
    (tmp_path / "foundry.toml").write_text("this is [not toml")
    with pytest.raises(SandboxError, match="not valid TOML"):
        enforce_sandbox_profile(tmp_path)


SAFE = {"ffi": False, "fs_permissions": [], "solc": "0.8.28", "eth_rpc_url": None, "out": "bounty-out",
        "cache_path": "bounty-cache", "sender": "0xdefault"}


@pytest.mark.parametrize("override", [
    {"ffi": True}, {"fs_permissions": [{"access": "read", "path": "/"}]}, {"solc": "./evil"},
    {"solc": "/usr/bin/solc"}, {"eth_rpc_url": "https://x"}, {"out": "/out"}, {"cache_path": "../../x"},
])
def test_effective_config_check_rejects_dangerous_settings(override):
    with pytest.raises(SandboxError):
        check_config({**SAFE, **override})


def test_attacker_favorable_settings_become_review_notes():
    assert check_config({**SAFE, "sender": "0xowner"}, defaults={"sender": "0xdefault"}) == {"sender": "0xowner"}
    assert check_config(SAFE, defaults={"sender": "0xdefault"}) == {}


# ------------------------------------------------------------------ solc versions + cache (H2)

def test_solc_path_in_target_config_refused(snapshot):
    (snapshot / "foundry.toml").write_text('[profile.default]\nsolc = "./evil"\n')
    with pytest.raises(SandboxError, match="plain version"):
        required_solc_versions(snapshot)


def test_solc_version_from_config_or_exact_pragmas(snapshot):
    assert required_solc_versions(snapshot) == {"0.8.28"}
    (snapshot / "foundry.toml").unlink()
    (snapshot / "src" / "B.sol").write_text("pragma solidity =0.8.25; contract B {}")
    assert required_solc_versions(snapshot) == {"0.8.28", "0.8.25"}


def test_range_pragmas_without_config_refused(snapshot):
    (snapshot / "foundry.toml").unlink()
    (snapshot / "src" / "Vault.sol").write_text("pragma solidity ^0.8.0; contract Vault {}")
    with pytest.raises(SandboxError, match="range pragmas"):
        required_solc_versions(snapshot)


def test_official_checksums_from_list():
    listing = {"builds": [{"version": "0.8.28", "sha256": "0xabc", "path": "solc-linux-amd64-v0.8.28+commit"}]}
    assert official_solc_sha256({"0.8.28"}, listing) == {"0.8.28": "abc"}
    with pytest.raises(SandboxError, match="not in the official list"):
        official_solc_sha256({"0.8.99"}, listing)


def test_tampered_compiler_detected(tmp_path):
    cache = SolcCache(tmp_path)
    b = cache.binary("0.8.28")
    b.parent.mkdir(parents=True)
    b.write_bytes(b"real solc")
    cache.manifest_path.write_text(json.dumps({"0.8.28": hashlib.sha256(b"real solc").hexdigest()}))
    cache.verify({"0.8.28"})
    b.write_bytes(b"backdoored solc")
    with pytest.raises(SandboxError, match="checksum"):
        cache.verify({"0.8.28"})
    with pytest.raises(SandboxError, match="not installed"):
        cache.verify({"0.8.20"})


# ------------------------------------------------------------------ verdicts (M2)

DEST = "test/BountyPoC.t.sol"


def suite(status="Success", path=DEST, name="test_exploit()"):
    return {f"{path}:PoC": {"test_results": {name: {"status": status}}}}


def test_judge_passes_only_real_successes():
    assert judge(json.dumps(suite()), DEST)[0] is True


@pytest.mark.parametrize("stdout, why", [
    ("{}", "no tests ran"),
    (json.dumps(suite("Skipped")), "not all"),
    (json.dumps(suite("Failure")), "not all"),
    (json.dumps(suite(path="test/Other.t.sol")), "outside the PoC"),
    ("[PASS] test_exploit() (gas: 1)", "no JSON"),
    ("{not json", "unparseable"),
])
def test_judge_rejects_vacuous_or_forged_results(stdout, why):
    passed, reason, _ = judge(stdout, DEST)
    assert not passed and why in reason


# ---- bug hunt 2026-11-21 ----

def test_failed_defaults_run_is_an_error_and_not_cached(monkeypatch, tmp_path):
    from bounty_agent.sandbox import runner

    monkeypatch.setattr(runner, "_DEFAULTS_CACHE", None)
    monkeypatch.setattr(runner, "_run", lambda *a, **k: runner.RunResult(None, "", "timeout", True, 120.0))
    with pytest.raises(SandboxError, match="default config"):
        runner._default_config(CFG, SolcCache(tmp_path))
    assert runner._DEFAULTS_CACHE is None  # the next run tries again instead of using {}


def test_force_remove_waits_for_late_containers(monkeypatch):
    from bounty_agent.sandbox import runner

    calls = []
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: calls.append(a[0]))
    monkeypatch.setattr(runner.time, "sleep", lambda s: None)
    # gone, then the container shows up late (create was in flight), then gone for good
    seq = iter([False, True, False, False])
    monkeypatch.setattr(runner, "_container_exists", lambda name: next(seq))
    runner._force_remove("bounty-test-x")
    assert sum(1 for c in calls if c[:3] == ["docker", "rm", "-f"]) == 4

    monkeypatch.setattr(runner, "_container_exists", lambda name: True)
    with pytest.raises(SandboxError, match="could not remove"):
        runner._force_remove("bounty-test-y", attempts=3)
