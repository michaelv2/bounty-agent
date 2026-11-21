"""PoC-cheat lint for Foundry tests (SPEC.md §4, stage E).

LLM-written exploit PoCs often "pass" only because they use Foundry cheatcodes
to grant themselves powers a real attacker wouldn't have: acting as the owner,
writing protocol storage directly, mocking an oracle, minting unlimited funds.
This lint flags those patterns, so the skeptic review and the human see them.

It is a heuristic text scan, not a Solidity parser. It errs toward flagging.
A flagged line can be accepted with a justification comment on the same or
previous line, which is shown to reviewers instead of being hidden:

    // cheatlint-allow: privileged-prank owner is the attacker after the bug in step 2
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

HIGH, INFO, ALLOWED = "high", "info", "allowed"

PRIVILEGED_NAMES = re.compile(
    r"\b(owner|admin|gov\w*|guardian|operator|keeper|multisig|timelock|deployer|dao|"
    r"manager|minter|controller|authority|pauser|upgrader)\b",
    re.IGNORECASE,
)
PRANK = re.compile(r"\bvm\.(?:prank|startPrank)\s*\(([^;]*)\)\s*;")
DEAL = re.compile(r"\b(?:vm\.)?deal\s*\(([^;]*)\)\s*;")
UNBOUNDED = re.compile(r"type\s*\(\s*u?int\d*\s*\)\s*\.max")
SIMPLE_RULES = [
    ("storage-write", re.compile(r"\bvm\.store\s*\("), "writes protocol storage directly"),
    ("mock-call", re.compile(r"\bvm\.mockCall(?:Revert)?\s*\("), "mocks a call (e.g. an oracle) instead of using real state"),
    ("code-etch", re.compile(r"\bvm\.etch\s*\("), "replaces deployed contract code"),
]
ALLOW = re.compile(r"//\s*cheatlint-allow:\s*([a-z-]+)\s+(\S.*)$")


@dataclass(frozen=True)
class Flag:
    rule: str
    severity: str  # high | info | allowed
    line: int
    snippet: str
    message: str
    reason: str = ""  # justification when severity == "allowed"


def _strip_block_comments(text: str) -> str:
    # Blank out /* ... */ but keep newlines so line numbers stay correct.
    return re.sub(r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text, flags=re.DOTALL)


def _raw_flags(code: str) -> list[tuple[str, str, str]]:
    """(rule, severity, message) for one line of code with comments removed."""
    found = []
    for m in PRANK.finditer(code):
        if PRIVILEGED_NAMES.search(m.group(1)):
            found.append(("privileged-prank", HIGH, "acts as a privileged account; attacker can't do this"))
    for m in DEAL.finditer(code):
        if UNBOUNDED.search(m.group(1)):
            found.append(("unbounded-deal", HIGH, "gives the attacker unbounded funds"))
        else:
            found.append(("deal", INFO, "mints funds to an account; justify attacker capital (e.g. flash loan)"))
    for rule, pattern, message in SIMPLE_RULES:
        if pattern.search(code):
            found.append((rule, HIGH, message))
    return found


def lint_source(text: str) -> list[Flag]:
    lines = _strip_block_comments(text).splitlines()
    flags: list[Flag] = []
    for i, line in enumerate(lines):
        code = line.split("//", 1)[0]
        raw = _raw_flags(code)
        if not raw:
            continue
        # Justification may sit on this line or the one before it.
        allows = {}
        for candidate in (line, lines[i - 1] if i > 0 else ""):
            m = ALLOW.search(candidate)
            if m:
                allows[m.group(1)] = m.group(2).strip()
        for rule, severity, message in raw:
            if rule in allows:
                flags.append(Flag(rule, ALLOWED, i + 1, line.strip(), message, allows[rule]))
            else:
                flags.append(Flag(rule, severity, i + 1, line.strip(), message))
    return flags


def lint_file(path: Path | str) -> list[Flag]:
    return lint_source(Path(path).read_text(encoding="utf-8"))


def has_blocking(flags: list[Flag]) -> bool:
    """True if any unjustified high-severity flag remains. Such a PoC can't reach the human gate."""
    return any(f.severity == HIGH for f in flags)
