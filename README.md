# bounty-agent

A personal pipeline that uses agents to find, validate and write up vulnerabilities in **source-available** bug bounty targets: smart contracts and audit contests first, open-source projects next. It combines a local LLM (on `llm-server`) with Claude models.

> **Status:** Phase 0, spec and skeleton. See [SPEC.md](SPEC.md) for the full design, roadmap and rules of engagement.

## Ground rules (non-negotiable)
- **Nothing touches live systems.** Analysis runs in sandboxes with no network egress, against local copies and forks.
- **No proof, no report.** A finding is only written up after a deterministic proof-of-concept passes.
- **A human submits.** The pipeline never submits anything to a bounty platform. The account holder reviews and submits manually.
- **Scope is code.** If a program's policy doesn't explicitly allow something, the pipeline doesn't do it.

## Quickstart
```bash
uv sync                      # install locked dependencies into .venv
uv run pytest                # run the guardrail tests (Docker tests skip unless the image exists)
docker build -t bounty-sandbox:latest sandbox/foundry   # build the PoC sandbox image
uv run bounty init           # create data/bounty.db
uv run bounty budget         # frontier spend vs caps (config/router.toml)
uv run bounty llm-ping       # check llm-server is reachable and its models are present
uv run bounty fetch https://github.com/theredguild/damn-vulnerable-defi v4.1.0 --practice  # hardened fetch
uv run python -m benchmarks.dvd.smoke             # end-to-end smoke test (Docker + llm-server)
uv run bounty lint-poc path/to/Exploit.t.sol   # flag PoCs that cheat with Foundry cheatcodes
uv run bounty batches        # Message Batches (50% off) and their state
uv run bounty batch-collect  # collect finished batches, record costs, release reservations
uv run bounty kill           # emergency stop for all Claude API calls (`unkill` to resume)
```
Claude calls need `ANTHROPIC_API_KEY` in the environment. Local-only commands don't.

## Layout (planned)
```
bounty_agent/   pipeline stages (intel, fetch, triage, analysis, validate, dedup, review, report, ledger, router, queue)
benchmarks/     practice targets + historical contests + scoring harness
sandbox/        Dockerfiles per target type
docs/           architecture, how-tos, learning path
```
