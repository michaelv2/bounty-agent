"""bounty-agent: offline-first agentic pipeline for source-available bug bounty targets.

See SPEC.md for the design. The guardrails live in:
  - bounty_agent.scope     deny-by-default scope and policy checks
  - bounty_agent.ledger    cost tracking and hard budget caps
  - bounty_agent.validate  deterministic PoC validation, including the PoC-cheat lint
"""

__version__ = "0.0.1"
