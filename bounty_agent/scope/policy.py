"""Scope-as-code: deny-by-default checks before any action on a target (SPEC.md §3).

Every stage that touches a target calls `check(policy, action, asset)` first.
Something is allowed only if *all* of these hold:
  1. a human has confirmed the parsed policy,
  2. the program's AI/automation rules are known and allow us,
  3. the action is one the policy lists,
  4. the asset is explicitly in scope and not explicitly out of scope,
  5. the action is not one the pipeline never does automatically (live traffic, submission).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from fnmatch import fnmatchcase


class Action(str, Enum):
    CLONE_SOURCE = "clone_source"      # git clone / download verified source
    LOCAL_ANALYSIS = "local_analysis"  # static analysis and LLM review of a local copy
    LOCAL_BUILD = "local_build"        # compile and run tests in the sandbox
    LOCAL_FORK = "local_fork"          # run PoCs on a local chain fork (RPC reads only)
    LIVE_REQUEST = "live_request"      # send traffic to the target's real systems
    SUBMIT = "submit"                  # file a report on a bounty platform


# Never allowed automatically, whatever a policy says. Live traffic is out of scope
# until Phase 4 (SPEC.md §2). Submission is always done by a human.
FORBIDDEN_ACTIONS = frozenset({Action.LIVE_REQUEST, Action.SUBMIT})


class ScopeViolation(PermissionError):
    pass


@dataclass
class Policy:
    program: str
    human_confirmed: bool = False
    ai_allowed: bool | None = None  # None = unknown, which is treated as "no"
    in_scope: list[str] = field(default_factory=list)       # exact locators or fnmatch globs
    out_of_scope: list[str] = field(default_factory=list)   # takes precedence over in_scope
    allowed_actions: list[Action] = field(default_factory=list)
    notes: str = ""

    def to_json(self) -> str:
        d = asdict(self)
        d["allowed_actions"] = [a.value for a in self.allowed_actions]
        return json.dumps(d, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> Policy:
        d = json.loads(text)
        d["allowed_actions"] = [Action(a) for a in d.get("allowed_actions", [])]
        return cls(**d)


def _norm(locator: str) -> str:
    # Case-insensitive (EVM addresses, hostnames) and ignore trailing slashes / .git on repo URLs.
    s = locator.strip().lower().rstrip("/")
    return s.removesuffix(".git")


def _matches(asset: str, patterns: list[str]) -> bool:
    a = _norm(asset)
    return any(fnmatchcase(a, _norm(p)) for p in patterns)


def check(policy: Policy, action: Action, asset: str) -> None:
    """Raise ScopeViolation unless `action` on `asset` is explicitly allowed."""
    action = Action(action)
    if action in FORBIDDEN_ACTIONS:
        raise ScopeViolation(f"{action.value} is never performed automatically by the pipeline")
    if not policy.human_confirmed:
        raise ScopeViolation(f"policy for {policy.program!r} has not been confirmed by a human")
    if policy.ai_allowed is not True:
        raise ScopeViolation(f"{policy.program!r}: AI/automation use is not known to be allowed")
    if action not in policy.allowed_actions:
        raise ScopeViolation(f"{policy.program!r}: action {action.value} is not in the policy's allowed actions")
    if _matches(asset, policy.out_of_scope):
        raise ScopeViolation(f"{asset!r} is explicitly out of scope for {policy.program!r}")
    if not _matches(asset, policy.in_scope):
        raise ScopeViolation(f"{asset!r} is not in scope for {policy.program!r}")


def is_allowed(policy: Policy, action: Action, asset: str) -> bool:
    try:
        check(policy, action, asset)
    except ScopeViolation:
        return False
    return True
