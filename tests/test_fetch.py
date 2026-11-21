"""Hardened git fetch guardrails (SPEC.md §4.1, stage B). No network needed."""

import subprocess

import pytest

from bounty_agent.fetch import FetchError, HardenedGit, content_hash, validate_url
from bounty_agent.fetch.git import (
    HARDENING,
    _strip_git_dirs,
    filter_proxy_git_params,
    parse_gitmodules,
    resolve_submodule_url,
    validate_submodule_path,
)


@pytest.mark.parametrize("url, expected", [
    ("https://github.com/theredguild/damn-vulnerable-defi", "https://github.com/theredguild/damn-vulnerable-defi"),
    ("https://GitHub.com/a/b.git/", "https://github.com/a/b"),
])
def test_good_urls_normalized(url, expected):
    assert validate_url(url) == expected


@pytest.mark.parametrize("url", [
    "http://github.com/a/b",                 # not https
    "git@github.com:a/b.git",                # ssh
    "ssh://git@github.com/a/b",
    "git://github.com/a/b",
    "file:///home/maqo/projects/oracle",     # local repos on this machine
    "ext::sh -c touch% /tmp/pwned",          # git's command-running transport
    "https://evil.example/a/b",              # host not allowlisted
    "https://user:token@github.com/a/b",     # embedded credentials
    "https://github.com:8443/a/b",           # port
    "https://github.com/a",                  # not owner/repo
    "https://github.com/a/b/c",
    "https://github.com/a/b?x=1",
])
def test_bad_urls_refused(url):
    with pytest.raises(FetchError):
        validate_url(url)


def test_relative_submodule_urls():
    parent = "https://github.com/theredguild/damn-vulnerable-defi"
    assert resolve_submodule_url(parent, "../forge-std.git") == "https://github.com/theredguild/forge-std"
    with pytest.raises(FetchError):  # climbing out of the host lands on another host
        resolve_submodule_url(parent, "../../../evil.example/a/b")


@pytest.mark.parametrize("path", ["/etc", "../outside", "lib/../../x", "-c", "", "lib/.git/hooks", ".git"])
def test_unsafe_submodule_paths(path):
    with pytest.raises(FetchError):
        validate_submodule_path(path)


def test_gitmodules_parsing():
    text = '[submodule "lib/forge-std"]\n\tpath = lib/forge-std\n\turl = https://github.com/foundry-rs/forge-std\n'
    assert parse_gitmodules(text) == [("lib/forge-std", "lib/forge-std", "https://github.com/foundry-rs/forge-std")]
    with pytest.raises(FetchError, match="missing"):
        parse_gitmodules('[submodule "x"]\n\tpath = x\n')


def test_hardening_flags_and_isolated_config():
    g = HardenedGit()
    try:
        assert g.env["GIT_CONFIG_GLOBAL"] == "/dev/null" and g.env["GIT_CONFIG_NOSYSTEM"] == "1"
        assert g.env["GIT_ALLOW_PROTOCOL"] == "https" and g.env["GIT_TERMINAL_PROMPT"] == "0"
        assert "protocol.allow=never" in HARDENING and "core.hooksPath=/dev/null" in HARDENING
        assert "core.fsmonitor=false" in HARDENING and "filter.lfs.process=" in HARDENING
    finally:
        g.close()


def test_git_itself_blocks_file_transport(tmp_path):
    """Defense in depth: even if URL validation were bypassed, git refuses file://."""
    repo = tmp_path / "local"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    g = HardenedGit(timeout_s=30)
    try:
        with pytest.raises(FetchError, match="not allowed|unsupported"):
            g.run("ls-remote", f"file://{repo}")
    finally:
        g.close()


def test_git_itself_blocks_ext_transport(tmp_path):
    marker = tmp_path / "pwned"
    g = HardenedGit(timeout_s=30)
    try:
        with pytest.raises(FetchError):
            g.run("ls-remote", f"ext::sh -c touch% {marker}")
    finally:
        g.close()
    assert not marker.exists()


def test_proxy_plumbing_forwarded_everything_else_dropped():
    env = {
        "HTTPS_PROXY": "http://127.0.0.1:3128",
        "GIT_CONFIG_PARAMETERS": " ".join([
            "'http.proxyAuthMethod=basic'",
            "'credential.http://127.0.0.1:3128.helper=!proxy-helper'",
            "'credential.https://github.com.helper=!steal'",      # helper for another URL
            "'url.https://evil.example/.insteadOf=https://github.com/'",
            "'core.hooksPath=/tmp/hooks'",
        ]),
    }
    kept = filter_proxy_git_params(env)
    assert "proxyAuthMethod" in kept and "127.0.0.1:3128.helper" in kept
    assert "steal" not in kept and "insteadOf" not in kept and "hooksPath" not in kept
    assert filter_proxy_git_params({}) == ""


def test_git_dirs_stripped_and_content_hash(tmp_path):
    root = tmp_path / "snap"
    (root / "lib" / "dep").mkdir(parents=True)
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text("[core]")
    (root / "lib" / "dep" / ".git").write_text("gitdir: ../../.git/modules/dep")
    (root / "A.sol").write_text("contract A {}")
    _strip_git_dirs(root)
    assert not (root / ".git").exists() and not (root / "lib" / "dep" / ".git").exists()
    h1 = content_hash(root)
    assert h1 == content_hash(root)  # stable
    (root / "A.sol").write_text("contract A { }")
    assert content_hash(root) != h1  # sensitive to content
