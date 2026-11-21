"""Hardened git fetch of target repos into immutable snapshots (SPEC.md §4 stage B, §4.1).

Target repos are hostile. Git itself is the attack surface here, so:
  - The user's global and system git config are ignored (no credential helpers, no URL
    rewrites, no includes). HOME points at an empty temp dir.
  - Only https to allowlisted hosts. file://, ext::, ssh, git:// are blocked at the git level.
  - No hooks, no fsmonitor, no LFS or other filters, no terminal prompts.
  - Commits are pinned by full SHA and fetched shallowly by SHA. Tags are resolved once.
  - Submodules are NOT handled by `git submodule`. We read .gitmodules ourselves, validate
    each URL and path, and fetch the exact commit the parent's gitlink pins, with limits on
    recursion depth and count.
  - Every .git directory is removed from the finished snapshot. The snapshot is content-hashed
    and made read-only.
"""

from __future__ import annotations

import configparser
import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

ALLOWED_HOSTS = frozenset({"github.com"})
# Libraries vendor their own test deps as nested submodules (OZ -> forge-std -> ds-test ...),
# which builds rarely need. Deeper than this, submodules are skipped and recorded, not fetched;
# a missing one shows up as a compile error. The count limit is a hard stop against blowup.
MAX_SUBMODULE_DEPTH = 2
MAX_SUBMODULES = 80
GIT_TIMEOUT_S = 300

_SHA = re.compile(r"^[0-9a-f]{40}$")
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")
_REPO_PATH = re.compile(r"^/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?(?:\.git)?/?$")

HARDENING = [
    "-c", "protocol.allow=never",
    "-c", "protocol.https.allow=always",
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "core.symlinks=true",
    # No credential.helper reset here: GIT_CONFIG_NOSYSTEM + GIT_CONFIG_GLOBAL=/dev/null already
    # drop every user/system helper, and a reset would also drop a proxy's own auth helper.
    "-c", "submodule.recurse=false",
    "-c", "fetch.recurseSubmodules=false",
    "-c", "filter.lfs.smudge=",
    "-c", "filter.lfs.process=",
    "-c", "filter.lfs.required=false",
    "-c", "http.followRedirects=false",
    "-c", "advice.detachedHead=false",
    "-c", "init.defaultBranch=main",
]


class FetchError(RuntimeError):
    pass


@dataclass
class Snapshot:
    path: Path
    url: str
    commit: str
    content_hash: str
    submodules: list[dict] = field(default_factory=list)  # [{"path", "url", "commit"}]
    skipped: list[str] = field(default_factory=list)      # nested submodule paths beyond the depth limit


def validate_url(url: str) -> str:
    """Return a normalized https URL, or raise. Only allowlisted hosts, no credentials, no ports."""
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise FetchError(f"only https URLs are allowed: {url!r}")
    if parts.username or parts.password or parts.port or parts.query or parts.fragment:
        raise FetchError(f"URL must not contain credentials, port, query or fragment: {url!r}")
    if (parts.hostname or "").lower() not in ALLOWED_HOSTS:
        raise FetchError(f"host not allowed: {parts.hostname!r}")
    if not _REPO_PATH.match(parts.path):
        raise FetchError(f"URL must look like https://github.com/<owner>/<repo>: {url!r}")
    path = parts.path.rstrip("/").removesuffix(".git")
    return f"https://{parts.hostname.lower()}{path}"


def resolve_submodule_url(parent_url: str, url: str) -> str:
    """Resolve a .gitmodules URL (absolute, or relative like ../repo.git) and validate it."""
    if url.startswith(("../", "./")):
        base = parent_url.rstrip("/").split("/")
        for seg in url.split("/"):
            if seg == "..":
                base.pop()
            elif seg not in ("", "."):
                base.append(seg)
        url = "/".join(base)
    return validate_url(url)


def validate_submodule_path(path: str) -> str:
    p = Path(path)
    if p.is_absolute() or ".." in p.parts or path.startswith("-") or not path.strip() or ".git" in p.parts:
        raise FetchError(f"unsafe submodule path: {path!r}")
    return path


def parse_gitmodules(text: str) -> list[tuple[str, str, str]]:
    """[(name, path, url)] from .gitmodules text. Parsed by us, never by `git submodule`."""
    cp = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        cp.read_string(text)
    except configparser.Error as exc:
        raise FetchError(f"malformed .gitmodules: {exc}") from None
    out = []
    for section in cp.sections():
        m = re.match(r'^submodule\s+"(.+)"$', section)
        if not m:
            continue
        sec = cp[section]
        if "path" not in sec or "url" not in sec:
            raise FetchError(f"submodule {m.group(1)!r} is missing path or url")
        out.append((m.group(1), sec["path"].strip(), sec["url"].strip()))
    return out


def _sq(s: str) -> str:
    """git's own single-quote format for GIT_CONFIG_PARAMETERS entries."""
    return "'" + s.replace("'", "'\\''") + "'"


def filter_proxy_git_params(environ) -> str:
    """Keep only proxy plumbing from an inherited GIT_CONFIG_PARAMETERS.

    Some environments (like Claude Code's sandbox) route traffic through an authenticating
    proxy and inject `http.proxy*` settings plus a credential helper scoped to the proxy's
    URL. Those are forwarded. Anything else (helpers for other URLs, hooks, url rewrites,
    filters) is dropped.
    """
    import shlex

    raw = environ.get("GIT_CONFIG_PARAMETERS", "")
    proxy = environ.get("HTTPS_PROXY") or environ.get("https_proxy") or ""
    p = urlsplit(proxy) if proxy else None
    proxy_base = f"{p.scheme}://{p.hostname}:{p.port}" if p and p.hostname and p.port else None
    kept = []
    try:
        tokens = shlex.split(raw)
    except ValueError:
        return ""
    for tok in tokens:
        key, _, value = tok.partition("=")
        k = key.lower()
        if k in ("http.proxy", "http.proxyauthmethod"):
            kept.append(_sq(f"{key}={value}"))
        elif proxy_base and k == f"credential.{proxy_base}.helper".lower():
            kept.append(_sq(f"{key}={value}"))
    return " ".join(kept)


class HardenedGit:
    def __init__(self, timeout_s: float = GIT_TIMEOUT_S):
        self.timeout_s = timeout_s
        self._home = tempfile.mkdtemp(prefix="bounty-githome-")
        self.env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": self._home,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "/bin/false",
            "SSH_ASKPASS": "/bin/false",
            "GIT_ALLOW_PROTOCOL": "https",
            "GIT_LFS_SKIP_SMUDGE": "1",
            "LANG": "C",
        }
        # Network plumbing only (proxies, CA bundles). Nothing that changes git's behavior.
        for var in ("http_proxy", "https_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
                    "ALL_PROXY", "all_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR", "GIT_SSL_CAINFO"):
            if var in os.environ:
                self.env[var] = os.environ[var]
        proxy_params = filter_proxy_git_params(os.environ)
        if proxy_params:
            self.env["GIT_CONFIG_PARAMETERS"] = proxy_params

    def close(self) -> None:
        shutil.rmtree(self._home, ignore_errors=True)

    def run(self, *args: str, cwd: Path | None = None) -> str:
        cmd = ["git", *HARDENING, *args]
        try:
            p = subprocess.run(cmd, cwd=cwd, env=self.env, capture_output=True, text=True,
                               timeout=self.timeout_s)
        except subprocess.TimeoutExpired:
            raise FetchError(f"git timed out: {' '.join(args[:2])}") from None
        if p.returncode != 0:
            raise FetchError(f"git {' '.join(args[:2])} failed: {p.stderr.strip()[-400:]}")
        return p.stdout

    def resolve_ref(self, url: str, ref: str) -> str:
        """Full commit SHA for a tag/branch (dereferencing annotated tags), or the SHA itself."""
        url = validate_url(url)
        if _SHA.match(ref):
            return ref
        if not _REF.match(ref) or ".." in ref:
            raise FetchError(f"invalid ref: {ref!r}")
        out = self.run("ls-remote", "--", url, f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}", f"refs/heads/{ref}")
        refs = dict(reversed(line.split("\t")) for line in out.splitlines() if "\t" in line)
        sha = refs.get(f"refs/tags/{ref}^{{}}") or refs.get(f"refs/tags/{ref}") or refs.get(f"refs/heads/{ref}")
        if not sha or not _SHA.match(sha):
            raise FetchError(f"ref {ref!r} not found at {url}")
        return sha

    def checkout(self, url: str, commit: str, dest: Path) -> None:
        """Shallow-fetch exactly `commit` into a fresh directory `dest`."""
        url = validate_url(url)
        if not _SHA.match(commit):
            raise FetchError(f"commit must be a full 40-char SHA: {commit!r}")
        dest.mkdir(parents=True, exist_ok=False)
        self.run("init", "-q", str(dest))
        self.run("fetch", "-q", "--depth", "1", "--no-tags", "--", url, commit, cwd=dest)
        self.run("checkout", "-q", "--detach", "FETCH_HEAD", cwd=dest)
        head = self.run("rev-parse", "HEAD", cwd=dest).strip()
        if head != commit:
            raise FetchError(f"fetched {head}, expected {commit}")

    def gitlink(self, repo: Path, path: str) -> str:
        """Commit SHA the parent repo pins for submodule `path`."""
        out = self.run("ls-tree", "HEAD", "--", path, cwd=repo).strip()
        parts = out.split()
        if len(parts) < 3 or parts[0] != "160000" or parts[1] != "commit" or not _SHA.match(parts[2]):
            raise FetchError(f"no pinned submodule commit for {path!r}")
        return parts[2]


def _fetch_tree(git: HardenedGit, url: str, commit: str, dest: Path, depth: int, seen: list[dict],
                skipped: list[str]) -> None:
    git.checkout(url, commit, dest)
    gm = dest / ".gitmodules"
    if not gm.exists() or gm.is_symlink():
        return
    for _name, path, sub_url in parse_gitmodules(gm.read_text(encoding="utf-8", errors="replace")):
        path = validate_submodule_path(path)
        if depth >= MAX_SUBMODULE_DEPTH:
            skipped.append(str(dest / path))
            continue
        sub_url = resolve_submodule_url(url, sub_url)
        sub_commit = git.gitlink(dest, path)
        if len(seen) >= MAX_SUBMODULES:
            raise FetchError(f"more than {MAX_SUBMODULES} submodules")
        target = dest / path
        # The gitlink leaves an empty directory; it must be a real dir inside dest (not a symlink).
        if target.is_symlink() or (target.exists() and any(target.iterdir())):
            raise FetchError(f"submodule path {path!r} is occupied or a symlink")
        if not target.resolve().is_relative_to(dest.resolve()):
            raise FetchError(f"submodule path {path!r} escapes the repo")
        if target.exists():
            target.rmdir()
        seen.append({"path": str(target), "url": sub_url, "commit": sub_commit})
        _fetch_tree(git, sub_url, sub_commit, target, depth + 1, seen, skipped)


def _strip_git_dirs(root: Path) -> None:
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        for name in list(dirnames):
            if name == ".git":
                shutil.rmtree(Path(dirpath) / name)
                dirnames.remove(name)
        for name in filenames:
            if name == ".git":  # submodule-style gitfile
                (Path(dirpath) / name).unlink()


def content_hash(root: Path) -> str:
    """SHA-256 over sorted (relative path, type, content or link target). Stable across machines."""
    h = hashlib.sha256()
    for p in sorted(root.rglob("*"), key=lambda x: x.relative_to(root).as_posix()):
        rel = p.relative_to(root).as_posix()
        if p.is_symlink():
            h.update(b"L" + rel.encode() + b"\0" + os.readlink(p).encode() + b"\0")
        elif p.is_file():
            h.update(b"F" + rel.encode() + b"\0" + hashlib.sha256(p.read_bytes()).digest())
        elif p.is_dir():
            h.update(b"D" + rel.encode() + b"\0")
    return h.hexdigest()


def _make_read_only(root: Path) -> None:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            p = Path(dirpath) / name
            if not p.is_symlink():
                p.chmod(p.stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def fetch_snapshot(url: str, ref: str, snapshots_dir: Path, *, git: HardenedGit | None = None) -> Snapshot:
    """Fetch `url` at `ref` (tag, branch or SHA) with submodules into snapshots_dir/<repo>-<sha12>."""
    url = validate_url(url)
    own = git is None
    git = git or HardenedGit()
    try:
        commit = git.resolve_ref(url, ref)
        name = f"{url.rsplit('/', 1)[-1]}-{commit[:12]}"
        final = snapshots_dir / name
        if final.exists():
            raise FetchError(f"snapshot already exists: {final}")
        snapshots_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="bounty-fetch-", dir=snapshots_dir) as tmp:
            work = Path(tmp) / name
            seen: list[dict] = []
            skipped: list[str] = []
            _fetch_tree(git, url, commit, work, 0, seen, skipped)
            _strip_git_dirs(work)
            subs = [{**s, "path": str(Path(s["path"]).relative_to(work))} for s in seen]
            skipped = [str(Path(p).relative_to(work)) for p in skipped]
            digest = content_hash(work)
            work.rename(final)
        _make_read_only(final)
        return Snapshot(final, url, commit, digest, subs, skipped)
    finally:
        if own:
            git.close()
