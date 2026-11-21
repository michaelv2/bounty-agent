"""PoC-cheat lint for Foundry tests (SPEC.md §4, stage E).

LLM-written exploit PoCs often "pass" only because they use Foundry cheatcodes
to grant themselves powers a real attacker wouldn't have: acting as the owner,
writing protocol storage directly, mocking an oracle, minting unlimited funds,
or skipping the test. This lint flags those patterns for the skeptic review and the human.

It is a heuristic, not a parser, and it is NOT the security boundary. The sandbox
(no network, ffi disabled in the effective config, JSON verdicts) is. The lint's job
is to surface unrealistic attacker powers to reviewers.

How it scans: comments are removed with string awareness, then the code is split into
statements (on ; { }), so a call spread over several lines is still one statement.

A flag can be accepted with a justification comment on the same line as the statement
or the line before it. The justification is shown to reviewers, not hidden:

    // cheatlint-allow: privileged-prank owner is the attacker after the bug in step 2

Some rules (ffi) can never be justified.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

HIGH, INFO, ALLOWED = "high", "info", "allowed"

# Never acceptable in a PoC, even with a justification.
NON_SUPPRESSIBLE = frozenset({"ffi"})

# Common names for the cheatcode handle: forge-std's `vm`, older `hevm`, `cheats`.
CHEAT = r"\b(?:vm|hevm|cheats?|_vm)\s*\.\s*"

PRIVILEGED_NAMES = re.compile(
    r"\b(owner|admin|gov\w*|guardian|operator|keeper|multisig|timelock|deployer|dao|"
    r"manager|minter|controller|authority|pauser|upgrader|treasury)\b",
    re.IGNORECASE,
)
UNBOUNDED = re.compile(r"type\s*\(\s*u?int\d*\s*\)\s*\.\s*max")
ALLOW = re.compile(r"//\s*cheatlint-allow:\s*([a-z-]+)\s+(\S.*)$")

# (rule, severity, pattern, message). Patterns run on a single statement.
RULES: list[tuple[str, str, re.Pattern, str]] = [
    ("ffi", HIGH, re.compile(CHEAT + r"(?:ffi|tryFfi)\s*\("),
     "runs shell commands; disabled in the sandbox and never legitimate in a PoC"),
    ("vacuous-pass", HIGH, re.compile(CHEAT + r"(?:skip|assume|assumeNoRevert)\s*\("),
     "can make the test pass or skip without the exploit happening"),
    ("storage-write", HIGH, re.compile(CHEAT + r"store\s*\(|\bstdstore\b[\s\S]*\.\s*checked_write\s*\("),
     "writes protocol storage directly"),
    ("mock-call", HIGH, re.compile(CHEAT + r"(?:mockCall|mockCallRevert|mockCalls|mockFunction)\s*\("),
     "mocks a call (e.g. an oracle) instead of using real state"),
    ("code-etch", HIGH, re.compile(CHEAT + r"etch\s*\(|\bdeployCodeTo\s*\("),
     "replaces deployed contract code"),
    ("environment", HIGH, re.compile(
        CHEAT + r"(?:setEnv|createFork|createSelectFork|selectFork|rpcUrl|rpc|writeFile|writeLine|"
        r"readFile|startBroadcast|broadcast|allowCheatcodes|setNonce|setNonceUnsafe|resetNonce)\s*\("),
     "manipulates the test environment, files or forks"),
    ("raw-cheatcode", HIGH, re.compile(
        r"hevm\s+cheat\s+code|0x7109709ecfa91a80626ff3989d68f67f5b1dd12d", re.IGNORECASE),
     "builds its own handle to the cheatcode address (can hide any cheatcode)"),
    ("time-travel", INFO, re.compile(CHEAT + r"(?:warp|roll)\s*\(|\b(?:skip|rewind)\s*\(\s*\d"),
     "moves time or block number; check it's realistic for the attack"),
    ("storage-read", INFO, re.compile(CHEAT + r"load\s*\("), "reads storage directly"),
]

PRANK = re.compile(r"(?:" + CHEAT + r"(?:prank|startPrank|changePrank)|\b(?:hoax|startHoax|changePrank))\s*\(([\s\S]*)\)")
DEAL = re.compile(r"(?:" + CHEAT + r"deal|\bdeal|\bhoax|\bstartHoax)\s*\(([\s\S]*)\)")


@dataclass(frozen=True)
class Flag:
    rule: str
    severity: str  # high | info | allowed
    line: int
    snippet: str
    message: str
    reason: str = ""  # justification when severity == "allowed"


def strip_comments(text: str) -> str:
    """Blank out // and /* */ comments, respecting string literals. Keeps newlines and offsets."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            i = j + 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j == -1 else j
            out[i:j] = " " * (j - i)
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out[i:j] = [ch if ch == "\n" else " " for ch in text[i:j]]
            i = j
        else:
            i += 1
    return "".join(out)


def _statements(code: str):
    """Yield (start_line, end_line, statement_text) split on ; { } outside string literals."""
    start, line, start_line, quote = 0, 1, 1, None
    for i, c in enumerate(code):
        if quote:
            if c == quote and code[i - 1] != "\\":
                quote = None
        elif c in "\"'":
            quote = c
        elif c in ";{}":
            stmt = code[start:i + 1]
            if stmt.strip():
                first = start_line + code[start:i + 1][: len(stmt) - len(stmt.lstrip())].count("\n")
                yield first, line, stmt.strip()
            start, start_line = i + 1, line
        if c == "\n":
            line += 1
    if code[start:].strip():
        yield start_line, line, code[start:].strip()


def _raw_flags(stmt: str) -> list[tuple[str, str, str]]:
    found = []
    m = PRANK.search(stmt)
    if m and PRIVILEGED_NAMES.search(m.group(1)):
        found.append(("privileged-prank", HIGH, "acts as a privileged account; attacker can't do this"))
    m = DEAL.search(stmt)
    if m:
        if UNBOUNDED.search(m.group(1)):
            found.append(("unbounded-deal", HIGH, "gives the attacker unbounded funds"))
        else:
            found.append(("deal", INFO, "mints funds to an account; justify attacker capital (e.g. flash loan)"))
    for rule, severity, pattern, message in RULES:
        if pattern.search(stmt):
            found.append((rule, severity, message))
    return found


def lint_source(text: str) -> list[Flag]:
    lines = text.splitlines()
    code = strip_comments(text)
    flags: list[Flag] = []
    for first, last, stmt in _statements(code):
        raw = _raw_flags(stmt)
        if not raw:
            continue
        allows: dict[str, str] = {}
        for ln in {first - 1, first, last}:
            if 1 <= ln <= len(lines):
                m = ALLOW.search(lines[ln - 1])
                if m:
                    allows[m.group(1)] = m.group(2).strip()
        snippet = " ".join(stmt.split())[:160]
        for rule, severity, message in raw:
            if rule in allows and rule not in NON_SUPPRESSIBLE:
                flags.append(Flag(rule, ALLOWED, first, snippet, message, allows[rule]))
            else:
                flags.append(Flag(rule, severity, first, snippet, message))
    return flags


def lint_file(path: Path | str) -> list[Flag]:
    return lint_source(Path(path).read_text(encoding="utf-8"))


def has_blocking(flags: list[Flag]) -> bool:
    """True if any unjustified high-severity flag remains. Such a PoC can't reach the human gate."""
    return any(f.severity == HIGH for f in flags)
