# bounty-agent

A personal pipeline that uses agents to find, validate and write up vulnerabilities in **source-available** bug bounty targets: smart contracts and audit contests first, open-source projects next. It combines a local LLM (on `llm-server`) with Claude models.

> **Status:** Phase 0, spec and skeleton. See [SPEC.md](SPEC.md) for the full design, roadmap and rules of engagement.

## Ground rules (non-negotiable)
- **Nothing touches live systems.** Analysis runs in sandboxes with no network egress, against local copies and forks.
- **No proof, no report.** A finding is only written up after a deterministic proof-of-concept passes.
- **A human submits.** The pipeline never submits anything to a bounty platform. The account holder reviews and submits manually.
- **Scope is code.** If a program's policy doesn't explicitly allow something, the pipeline doesn't do it.

## Layout (planned)
```
bounty_agent/   pipeline stages (intel, fetch, triage, analysis, validate, dedup, review, report, ledger, router, queue)
benchmarks/     practice targets + historical contests + scoring harness
sandbox/        Dockerfiles per target type
docs/           architecture, how-tos, learning path
```
