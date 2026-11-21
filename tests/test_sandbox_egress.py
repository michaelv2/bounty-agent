"""Real egress test: PoC containers must not reach DNS, the internet, or the LAN (SPEC.md §4.1).

Needs Docker and the bounty-sandbox image (`docker build -t bounty-sandbox sandbox/foundry`).
Skipped otherwise. Each probe has a positive control in fetch mode, which has network,
so a broken probe can't pass the test by accident.
"""

import shutil
import socket
import subprocess
from pathlib import Path

import pytest

from bounty_agent.config import SandboxConfig
from bounty_agent.sandbox.runner import base_args

CFG = SandboxConfig()


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    r = subprocess.run(["docker", "image", "inspect", CFG.image], capture_output=True)
    return r.returncode == 0


pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(not _docker_ready(), reason=f"docker or image {CFG.image} not available"),
]


def _llm_server():
    try:
        return socket.gethostbyname("llm-server"), 11434
    except OSError:
        return None


def probe(tmp_path: Path, network: bool, script: str) -> int:
    target, cache = tmp_path / "t", tmp_path / "c"
    target.mkdir(exist_ok=True)
    cache.mkdir(exist_ok=True)
    a = base_args(CFG, name=f"bounty-probe-{tmp_path.name[-8:]}", target=target, solc_dir=cache, network=network,
                  profile=None if network else "probe")
    return subprocess.run(a + ["bash", "-c", script], capture_output=True, timeout=60).returncode


DNS = "getent hosts github.com"


def _https_probe() -> str:
    # Resolve on the host, so the probe tests raw TCP egress rather than DNS.
    # (Some networks refuse well-known anycast IPs, so don't hardcode one.)
    try:
        ip = socket.gethostbyname("github.com")
    except OSError:
        pytest.skip("host cannot resolve github.com")
    return f"timeout 5 bash -c 'exec 3<>/dev/tcp/{ip}/443'"


@pytest.mark.parametrize("kind", ["dns", "https"])
def test_internet_blocked_in_test_mode(tmp_path, kind):
    script = DNS if kind == "dns" else _https_probe()
    assert probe(tmp_path, network=True, script=script) == 0, "positive control failed: probe is broken"
    assert probe(tmp_path, network=False, script=script) != 0


def test_lan_llm_server_blocked_in_test_mode(tmp_path):
    host = _llm_server()
    if host is None:
        pytest.skip("llm-server does not resolve on this host")
    ip, port = host
    script = f"timeout 5 bash -c 'exec 3<>/dev/tcp/{ip}/{port}'"
    assert probe(tmp_path, network=True, script=script) == 0, "positive control failed: probe is broken"
    assert probe(tmp_path, network=False, script=script) != 0


def test_root_filesystem_is_read_only(tmp_path):
    assert probe(tmp_path, network=False, script="touch /usr/pwned") != 0
    assert probe(tmp_path, network=False, script="touch /target/ok") == 0  # the working copy is writable


def test_runs_as_non_root(tmp_path):
    assert probe(tmp_path, network=False, script='test "$(id -u)" != 0') == 0
