"""Filesystem helpers for hostile directory trees (target snapshots and sandbox scratch copies)."""

from __future__ import annotations

import os
import stat
from pathlib import Path


class UnsafeTree(RuntimeError):
    pass


def reject_special_files(root: Path) -> None:
    """Refuse FIFOs, sockets and device files (copying or reading them can hang or misbehave)."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for n in dirnames + filenames:
            mode = os.lstat(os.path.join(dirpath, n)).st_mode
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
                raise UnsafeTree(f"special file in tree: {os.path.join(dirpath, n)}")


def strip_escaping_symlinks(root: Path) -> list[str]:
    """Remove symlinks that are absolute or resolve outside `root`. Returns the removed paths.

    Relative links that stay inside the tree (e.g. src/Alias.sol -> Vault.sol) are kept.
    Without this, host-side code reading `root/some/file` could be redirected to any host
    file (an SSH key, a webhook secret) and send it to an LLM.
    """
    real_root = root.resolve()
    removed = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for n in dirnames + filenames:
            p = Path(dirpath) / n
            if p.is_symlink():
                link = os.readlink(p)
                if os.path.isabs(link) or not Path(os.path.realpath(p)).is_relative_to(real_root):
                    p.unlink()
                    removed.append(p.relative_to(root).as_posix())
    return removed
