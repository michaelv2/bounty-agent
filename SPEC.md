# SPEC v0.2: Agentic Bug Bounty Pipeline ("bounty-agent")

## Context
The goal is side income from public bug bounty programs, using an agent pipeline that mixes local and frontier models to find, validate and write up vulnerabilities that pay out. This is a personal tool for now. It is also meant to be **handed off to a teenage tinkerer**, so it has to be safe by default, modular and well documented, and built around real problems.

**Changelog**
- v0.6: stage F2 (skeptic review) built. Opus 5.5 at effort `high` tries to refute each stage-D finding (impact, intent, preconditions, PoC realism, scope and severity) and returns `submit` / `reject` / `flag-for-human`. Fail-safe rules sit in code, not in the prompt: an unparseable or declined reply becomes `flag-for-human`; `submit` is downgraded to `flag-for-human` when the PoC has cheat-lint warnings or a program target has no human-confirmed scope. Batch mode by default (the next run collects it and applies results idempotently from `batch_items`); `bounty review <id>` runs one synchronously. Gated by `[review] enabled = false`. Findings now keep the full stage-D hypothesis (`findings.details_json`). The digest lists findings that passed the skeptic, with its concerns. **First live F2 run (2026-11-21):** finding #1 (the DVD false positive) was rejected at confidence 0.95 for the right reasons (only a view call is asserted; the zero-fee grace period is intended; the target's own monitor requires `fee == 0`), at $0.03 synchronous. One D+F2 pass on a hotspot cost about $0.034 in total.
- **First live stage-D run (2026-11-21, DVD Unstoppable, DeepSeek via Mistral, $0.0042):** produced a **false positive**. The model wrote a PoC asserting `flashFee == 0` during the grace period — true, but *intended* behavior, not the challenge's bug (a donation that breaks the share/asset invariant). The PoC passed the sandbox because it asserts a real fact; it shows no attacker gain or broken invariant. Lessons: (1) "a Foundry test passes" is NOT "a vulnerability with impact" — the judge only checks the named test ran and succeeded; (2) the cheat lint correctly stayed silent (no cheatcodes — a weak claim, not cheating); (3) this is concrete justification for the F2 skeptic (Opus) and the human gate, and for the backtest's ground-truth comparison. **Build F2 before trusting any finding.** Possible stage-D hardening: push the prompt/judge toward asserting a before/after impact delta, and for practice/backtest targets check the challenge's own success condition (DVD `_isSolved`) rather than the model's self-asserted impact.
- **Stage-D prompt follow-up (2026-11-21):** the hypothesis now carries an explicit `exploitable: yes|no`. A "no" records a dropped hypothesis with the model's reason and runs nothing. Before this, the prompt asked for a "test asserting the safe behavior" on a no, and that passing test would have been recorded as a finding (a latent false-positive path, caught by a regression test). Also restored prompt guidance lost when it was compressed to avoid safety-classifier interruptions: the attacker is an unprivileged actor in the threat model, impact must be concrete, relative imports start from `test/`, flash-loan amounts must be justified, and intended behavior is not a bug.
- v0.5: stage D (deep analysis) with a pluggable provider: any OpenAI-compatible API via `[providers]` and `provider:model` routes, budgeted like Claude. Default first pass is DeepSeek V4.1-Flash-1017 hosted on Mistral's API (~15x cheaper than Opus). Gated by `[analysis] enabled` (off until opted in); `bounty analyze <name> [--dry-run]` for manual runs.
- v0.4: `bounty run` controller (§4.2), local triage stage C, hotspot ranking, weekly digest, nightly script.
- v0.3.3: bug hunt (code review, 10 findings fixed, each with a regression test that fails on the old code): batch reservations now survive day/month rollover and are written before the paid API call; snapshots never keep links to host files; cheat-lint alias bypass closed; config-review defaults no longer cached on failure; crashed jobs stop retrying; stale .gitmodules entries skipped; timed-out containers verifiably removed; non-ASCII token estimates; relative submodule URLs bounded.
- v0.3.2: hardened git fetch (stage B), DVD smoke test passing, local reasoning-model handling (`reasoning_effort`, truncation detection).
- v0.3.1: sandbox hardened after a security review: no networked builds of target code, verified solc cache, JSON verdicts, effective-config check, symlink-safe scratch copies, rewritten cheat lint. Added the Batch API (§5) and orchestration (§4.2).
- v0.3: execution sandbox design (§4.1): a dedicated `--network none` container rather than AgentSafe.
- v0.2.2: the son takes over `llm-server` administration behind an interface contract (§12).
- v0.2.1: recorded the `llm-server` host, the digest going to both markdown and Slack, the private repo, and account creation as a Phase 0 task.
- v0.2: added the operator constraints (§0), Opus as the primary reviewer (stage F2), a budget-driven model routing and cost model, the handoff/learning plan (§12), and revised kill criteria.
- v0.1: initial draft.

---

## 0. Operator Constraints
| Constraint | Value | Design consequence |
|---|---|---|
| Local compute | Dual RTX 3090 (48 GB VRAM) on host **`llm-server`**. `qwen3.8:27b` on Ollama (assumed `http://llm-server:11434`), serving one request at a time. | The local lane is a **serial job queue** that runs overnight or in idle time. Work there must be batchable and resumable. |
| Frontier budget | **$50–100/month** | Hard monthly cap in the ledger. Opus only for deep reasoning. Batch API and prompt caching everywhere possible. |
| Human review time | **~1 hr/week** | Opus is the primary reviewer, and the human only reviews what reaches the final gate. **≤3 review packets/week**, each readable in under 10 minutes. |
| Target class | Smart contracts and OSS are both fine | Start with smart contracts, because there is better backtest data and PoCs are deterministic. OSS comes second. |
| Ownership | Personal, possible product later | Single user, SQLite, no multi-tenancy. Keep stage interfaces clean so it can become a product later. |

**Local-lane throughput options** (configurable via `router.yaml`):
1. Default: Ollama with concurrency=1 and a persistent queue.
2. Worth checking: Ollama's `OLLAMA_NUM_PARALLEL` setting may allow concurrent requests on your version, at a VRAM cost.
3. Upgrade path: vLLM with `--tensor-parallel-size 2` across both 3090s, which batches requests continuously and gives much higher throughput.
4. Overflow lane: when the local queue backs up, Claude Haiku 5.5 is cheap enough to use for bulk work ($0.10/$0.50 per MTok, half that via batch).

---

## 1. Opinion (summary; unchanged from v0.1)
- **The idea is sound. "Automate all public bounties" is not.** Broad web scanning is crowded (XBOW, platform-native agents like Bugcrowd's Savant Pathseeker).
- **Platforms penalize unvalidated AI reports.** HackerOne changed its policy in Feb 2026 and Bugcrowd its enforcement in Mar 2026. HackerOne paused the Internet Bug Bounty in Mar 2026.
- **Duplicates pay $0**, and bad reports damage your reputation.
- **Where a solo operator has an edge:**
  1. Source-available targets that can be reproduced offline (smart contracts, audit contests, OSS).
  2. Depth over breadth.
  3. Deterministic PoC validation as the moat.
  4. **Backtesting** on past contests with published findings before spending on live targets.
- **Expectations:** a skill-building side project that might pay occasionally. Budget 3–6 months before the first meaningful payout.

## 2. Scope & Strategy
| Phase | Target class | Live-system contact |
|---|---|---|
| 0 | Practice targets (Damn Vulnerable DeFi, Ethernaut) + policy research | None |
| 1 | Backtest on past Code4rena/Sherlock contests | None |
| 2 | Live audit contests + Immunefi smart-contract programs | None (local mainnet fork) |
| 3 | OSS programs with source in scope | None (local build) |
| 4 (optional) | Web/API programs that explicitly allow automation | Yes, behind human approval gates |

The pipeline never covers: social engineering, DoS, out-of-scope assets, or auto-submission.

## 3. Non-negotiable Rules of Engagement (enforced in code)
1. **Scope as code.** Every action checks a parsed, human-confirmed policy record. Deny by default.
2. **No live network access by default.** Sandboxes have no egress except an allowlist (package mirrors, RPC endpoints for fork *reads*).
3. **Two-tier review.** Opus does the full adversarial review (stage F2). The human still makes the final call and submits manually, because submissions go out under the human's account and platforms hold the researcher responsible. That final read is short because Opus has done the heavy lifting.
4. **Program AI policy.** Store each program's AI/automation rules. Skip programs that ban them. Disclose AI assistance where required.
5. **PoC or it didn't happen.** A deterministic validator must pass before anything is drafted.
6. **No sensitive data.** If a PoC would expose real user data, stop and escalate.
7. **Cost caps.** Per-target, per-day and monthly hard caps, plus a kill switch. Default monthly cap: $75.

## 4. Architecture
```
[A Intel] → [B Fetch] → [C Triage: local queue] → [D Deep Analysis: Opus] → [E Validate: deterministic]
                                                                                   ↓
 [H Ledger/EV] ← [G Report + Human Gate] ← [F2 Opus Skeptic Review] ← [F Dedup/Novelty]
```
- **A. Program Intel:** pull data from:
  - `arkadiyt/bounty-targets-data`
  - Immunefi listings
  - Code4rena, Sherlock and Cantina feeds

  The local model parses each policy into a structured record, which a human confirms once per program. Each program gets an EV score:

  `EV = max_payout × tooling_fit × freshness ÷ competition`
- **B. Fetch:** pinned commit or block. Snapshots are immutable.
- **C. Triage (local queue, overnight):**
  - Run Slither, Aderyn, Semgrep and CodeQL.
  - The local model writes per-file summaries, a value-flow and trust-boundary map, and a hotspot ranking.
  - Output: the top-K hotspots.
- **D. Deep Analysis (built 2026-11-21; first pass DeepSeek V4.1-Flash-1017 via Mistral; Opus escalation planned, not built yet):**
  - The codebase and triage map are sent as a **cached prefix**.
  - Opus generates exploit hypotheses per hotspot and writes Foundry or other PoCs.
  - It iterates on PoC failures within a per-target turn and $ cap.
- **E. Validation (deterministic):**
  - The PoC must pass in the sandbox: a fork test showing loss or invariant break, or an ASan crash.
  - **PoC-cheat lint:** flag Foundry cheatcodes that fake the exploit, such as `vm.prank` as owner/admin, `vm.deal`/`deal` beyond realistic attacker capital, `vm.store` on protocol state, or mocked oracles not in the threat model. LLM-written PoCs often cheat this way. `vm.ffi` (shell execution) is flagged and also disabled in the sandbox.
  - All target code runs in the **execution sandbox** (§4.1).
- **F. Dedup/Novelty:** check against known-issues lists, prior audits, public disclosures, GitHub issues, CVE/GHSA, and (for backtests) the contest's own findings.
- **F2. Opus Skeptic Review:** a separate Opus call (Batch API) that tries to *refute* the finding. It checks:
  - scope
  - attacker preconditions and privileges
  - whether the PoC is realistic
  - severity under the program's own rubric
  - known-issue overlap

  It outputs a verdict (`submit` / `reject` / `flag-for-human`), a confidence score and specific concerns. Rejections are logged, not deleted, so the skeptic's accuracy can be audited later.
- **G. Report + Human Gate:** a **one-page review packet**:
  - TL;DR and severity
  - why it is novel
  - the skeptic's concerns
  - a one-command PoC rerun (`make verify FINDING=…`)
  - the draft report

  It is delivered in a weekly digest, both as a markdown file (`digests/YYYY-WW.md`) and as a short Slack summary via `notify-on-complete`.
- **H. Ledger:** $ per stage, per target and per month. Outcomes. Skeptic accuracy (verdict vs. platform outcome). The data feeds EV scoring and model routing.

### 4.1 Execution Sandbox (decided 2026-11-21)
Untrusted target code runs at validation time: build scripts, test code, and Foundry's `vm.ffi`, which can run shell commands. So it runs in a dedicated throwaway container, **not** in AgentSafe. AgentSafe allows HTTPS egress and holds credentials by design. It suits an agent's dev environment, not a detonation chamber for hostile code. The sandbox reuses AgentSafe's hardening patterns:
- non-root user, `cap_drop ALL`, `no-new-privileges`
- pinned versions, bumped only after an audit
- binary-only installs, read-only mounts

```
host (WSL)                                   no Docker socket inside any container
├── bounty pipeline  → Claude API, llm-server
│     ├── solc installer: network, but builds a project WE generate. No target files mounted.
│     │                   Compiler SHA-256 checked against soliditylang's list.json and recorded
│     │                   in a host-side manifest. Re-hashed before every run.
│     └── PoC run:        docker run --network none --read-only --cap-drop ALL --init --pull never
│                           --security-opt no-new-privileges, pids/memory/cpu limits, ulimits
│                           (fsize, nofile, core), tmpfs /tmp noexec, timeout + output cap,
│                           scratch copy of the snapshot, solc cache read-only
│                         1. `forge config --json` → the effective config is checked
│                         2. `forge test --offline --force --json` → JSON verdict
└── (Phase 2) anvil fork container: egress to the RPC provider only, joined to the run
      container via an internal-only Docker network (the run container still has no internet)
```
- **Target code never runs with network.** There is no networked build of target code. Compiler versions are read host-side from `foundry.toml` or exact pragmas, and a path-valued `solc` is refused.
- **The command is fixed in code** (`bounty_agent/sandbox/runner.py`). An LLM supplies file contents (the PoC) and an optional test-name filter, never docker arguments or shell commands.
- **Pass/fail comes from `forge test --json`.** A PoC passes only if at least one test in *its own file* ran and every test reports `Success`. forge exits 0 when zero tests match, so the exit code alone means nothing. Skipped tests fail validation.
- **The scratch copy is hostile.** Absolute or escaping symlinks are removed, special files are rejected, and host-side writes use `O_NOFOLLOW` and `O_EXCL`. The PoC must be a *new* file under `test/`, so it can't overwrite the contract under test.
- **Foundry config is untrusted.** forge ignores `FOUNDRY_FFI=false` when the target's `foundry.toml` sets `ffi = true` (found by test, 2026-11-21). The runner appends a randomly named profile with `ffi = false`, `fs_permissions = []` and fresh `out`/`cache_path`, selects it with `FOUNDRY_PROFILE`, and then checks **forge's own parse** of the config. Attacker-favorable settings such as `sender`, `initial_balance` and `block_*` that differ from forge defaults are passed to reviewers as notes.
- **Tests** (`tests/test_sandbox_*.py`): DNS, HTTPS and LAN egress probes with positive controls; ffi blocked, with a positive control showing it otherwise runs; vacuous, skipped and failing PoCs rejected; target-supplied solc refused; tampered compiler detected; rigged prebuilt artifacts ignored; symlink attacks on host files.
- **Image** `bounty-sandbox`: Debian slim pinned by digest, plus the pinned Foundry release (checksum-verified, `forge` only). No apt in the final stage. Defined in `sandbox/foundry/Dockerfile`.
- **Still open:**
  - **Telemetry:** check whether forge phones home in installer mode.
  - **Cheat lint:** move to an allowlist built on a real Solidity AST.
- **Stage B fetch (built 2026-11-21, `bounty_agent/fetch/git.py`):** host git with the user's global and system config ignored. Only https to github.com is allowed (`file://`, `ext::`, ssh and git:// are blocked by git itself, as tested). No hooks, fsmonitor or LFS filters. Commits are pinned by SHA and fetched shallowly. Submodules are parsed and validated by our code and fetched at their gitlinked commits: depth 2, then skipped and recorded; hard cap of 80. `.git` is stripped, the snapshot is content-hashed and made read-only. The only inherited git settings are proxy plumbing (an authenticating proxy's `http.proxy*` and its URL-scoped credential helper).
- **Smoke test (`benchmarks/dvd/smoke.py`):** DVD v4.1.0 fetch (28 submodules, 82 MB, ~13 s), solc 0.8.25 verified, local triage on `llm-server`, the known Unstoppable solution passes on DVD's own success check, and an empty solution fails. **Passed 2026-11-21.** Known limit: DVD challenges that read JSON fixtures need read-only `fs_permissions`, which the enforced profile currently clears.
- **Later:** if the controller moves into AgentSafe (no Docker socket), a small host-side runner takes validation jobs from the queue and runs this same fixed command.

### 4.2 Orchestration (who runs the daily process)
- **The controller is deterministic Python code, not an LLM.** `bounty run` is a resumable state machine over the SQLite tables, started headless by a systemd timer or cron on the WSL host. Each run picks targets by EV, enqueues local jobs, drains the local queue (overnight), submits and collects batches, runs PoCs in the sandbox, and writes the digest.
- **Why not an LLM supervisor:** budget caps, scope checks and sandbox arguments must not be open to negotiation. Prompt injection in target code must not be able to reroute the pipeline. A deterministic controller is also testable, reproducible, and spends no tokens on "managing".
- **LLMs are workers inside stages,** chosen per stage by the router: local Qwen for bulk work, Opus for deep analysis (D) and the skeptic filter (F2) in front of the human.
- **Claude Code is the dev and review environment,** not part of the automated loop. The weekly human review can be a Claude Code session ("walk me through this week's digest"). The pipeline calls the Anthropic API directly so every token goes through the ledger.
- **Built 2026-11-21 (`bounty_agent/pipeline/`):** `bounty run` with a run lock and a `runs` history. Each run requeues stale jobs, collects finished batches, syncs `config/targets.toml`, advances targets through `new → fetched → compiler_ready → triage_queued → triaged → ranked → awaiting_analysis`, and drains the local queue within a time budget. A failing step records the error. After 3 failures the target is `blocked` until `bounty target-reset`. `program` targets are refused until a confirmed policy exists. `bounty digest` writes the weekly markdown and a one-line summary. `scripts/bounty-nightly.sh` wraps both and is **installed in cron at 01:30** (log: `data/nightly.log`). It posts the one-line summary to Slack via `SLACK_WEBHOOK_URL`, loaded from `~/.bashrc_env` at runtime like the machine's other cron jobs. A failed post never fails the run. First real run: DVD Unstoppable went `new → awaiting_analysis` in 3.4 min. The real bug ranked #4 of 5 in local triage; deep analysis has to recover it from the top-K.
- **Ops reviewer: Mistral Large 4 (decided 2026-11-21).** Once a week it reads the ledger, backtest metrics, queue and batch state, and recent outcomes. It writes a short progress note with *proposed* config changes (routes, caps, EV weights), which a human approves. It is advisory only: no write access to config, no control-path role. It goes through the router and ledger like every other model (provider + price-table entry + caps). Its input is pipeline metrics, never raw target code. Not yet built. It needs Mistral's current API and pricing checked first.

## 5. Model Routing & Cost Model
Prices are from Anthropic's pricing docs as of 2026-11-21, per MTok:
- **Opus 5.5:** $4 input / $20 output; batch $2 / $10; cache hit $0.20
- **Sonnet 5.5:** $2 / $10; batch $1 / $5
- **Haiku 5.5:** $0.10 / $0.50

The 4.7+ tokenizer produces about 30% more tokens than older models, so the estimates assume that.

| Stage | Default | Fallback / experiment |
|---|---|---|
| A policy parsing, C summaries/hotspots, F similarity | Local Qwen (free, serial) | Haiku 5.5 overflow |
| D hypotheses + PoC writing | Opus 5.5, cached prefix | Sonnet 5.5 (A/B in backtest) |
| F2 skeptic review | Opus 5.5 via Batch API | n/a |
| G report draft | Sonnet 5.5 via Batch API | Local |

**Estimated cost per mid-size contest** (~200k-token codebase):
| Item | Cost |
|---|---|
| Cache write | ~$1–2 |
| ~20 hypothesis turns on cache | ~$1 input + ~$2 output |
| PoC iteration | ~$3–4 |
| Skeptic and report | <$1 |
| **Total** | **~$8–10 per contest on Opus**, roughly half on Sonnet |

So **$75/month covers ~7–9 deep runs**. The EV ranking has to be selective. These numbers are estimates, and the Phase 1 ledger replaces them with real ones.

Note: frontier models may refuse some exploit-development prompts. Local-fork PoCs for authorized contests are usually fine. If refusals become a problem, look into Anthropic's Cyber Verification Program (access for verified security research).

## 6. Data Model (SQLite)
- `programs`
- `scope_assets`
- `policies` (parsed + `human_confirmed`)
- `targets` (snapshot hash)
- `hotspots`
- `hypotheses`
- `pocs` (status, logs, `cheat_flags`)
- `findings`
- `reviews` (skeptic verdict, confidence, concerns)
- `submissions` (platform, status, payout)
- `costs` (stage, model, tokens, $)
- `jobs` (local queue: state, retries)

## 7. Tech Stack
- Python 3.11+, uv (locked, with an `exclude-newer` cooling-off cutoff), Typer CLI, SQLite, Docker sandboxes
- Foundry, Slither, Aderyn, Semgrep, CodeQL
- Anthropic SDK, plus `httpx2` (the SDK's own HTTP library) for the OpenAI-compatible local endpoint
- Every dependency goes through the **security-auditor** gate before install

Layout:
```
bounty_agent/{intel,fetch,triage,analysis,validate,dedup,review,report,ledger,router,queue}/
benchmarks/   # practice targets + historical contests + scoring harness
sandbox/      # Dockerfiles per target type
docs/         # architecture, how-tos, learning path (§12)
```

## 8. Roadmap
- **Phase 0 (1–2 wks): research, practice, skeleton**
  - *Status 2026-11-21:* skeleton done, with 41 tests:
    - config, schema
    - ledger with monthly/daily/per-target caps and a kill switch
    - router with local aliases, Haiku overflow and a pre-call budget check
    - serial job queue
    - deny-by-default scope guard
    - PoC-cheat lint
    - CLI

    Done since: Batch API, execution sandbox (security-reviewed), hardened git fetch, and the DVD smoke test (passed). `bounty run` controller and weekly digest done too, then stage D (deep analysis, pluggable provider) and F2 (skeptic review). Next: a live F2 check on the DVD false positive, then the backtest harness.
  - Verify current AI/automation policies, **age requirements** and KYC/tax rules on Immunefi, Code4rena, Sherlock and Cantina.
  - **Create accounts (human task):** Code4rena and Sherlock first, since they're needed for live contests in Phase 2. Immunefi and Cantina next. Backtesting doesn't need accounts, because past contest repos and findings are public.
  - Confirm the `llm-server` Ollama endpoint is reachable from the dev machine, and benchmark tokens/sec for `qwen3.8:27b`.
  - Repo skeleton, ledger with cost caps, router, local job queue.
  - End-to-end smoke test on **Damn Vulnerable DeFi** challenges. Known bugs and small codebases make for cheap, deterministic fixtures at <$1 each.
- **Phase 1 (4–6 wks, ~$50–80 total): backtest MVP**
  - Stages B–F2 on 8–10 past Code4rena/Sherlock contests.
  - Metrics: recall on known High/Medium findings, post-validation false-positive rate, skeptic accuracy, $ per contest.
  - A/B test Opus vs. Sonnet for stage D on a subset.
- **Phase 2:** live, one contest or Immunefi program at a time, chosen by EV.
- **Phase 3:** OSS programs, adding fuzz-harness generation.
- **Phase 4:** web targets, only after the earlier phases show a positive ROI.

## 9. Economics & Kill Criteria
- **Go to Phase 2** if all of these hold:
  - the backtest finds ≥15% of known High/Medium findings
  - fewer than 1 false positive per contest reaches the human gate
  - average cost is ≤$10 per contest
- **Kill or pivot** after 3 months live if any of these hold:
  - cumulative payouts are below 2× spend
  - the duplicate rate is above 60%
  - the human gate regularly takes more than 1 hr/week

## 10. Key Risks
| Risk | Mitigation |
|---|---|
| Reputation damage | PoC-only, PoC-cheat lint, Opus skeptic, human final gate |
| Legal / out-of-scope activity | No live contact through Phase 3, scope-as-code, deny by default |
| Budget overrun | Hard monthly cap, local-first, batch + cache, EV-selective deep runs |
| Prompt injection from target code | No egress, no secrets in sandbox, read-only tools. Target content is untrusted. |
| Policy changes | Re-parse on each run. A changed policy forces human re-confirmation. |
| Minor operating accounts | Submissions and payouts stay under the adult account holder unless a platform's terms explicitly allow minors |

## 11. Decisions & Open Questions
**Decided (2026-11-21)**
- Local LLM runs on host `llm-server`.
- No platform accounts yet, so creating them is a Phase 0 human task.
- The digest goes out as both a markdown file and Slack.
- The code lives in a private GitHub repo.

**Open**
1. Confirm the Ollama port on `llm-server` (default 11434), and whether it's reachable from WSL.
2. Should the son get his own GitHub account as a collaborator now? Recommended: yes, with branch protection on `main` so changes arrive as PRs.
3. Does `llm-server` serve anything besides this project? If so, list those uses in the `infra/` runbook so his optimizations don't break them.

## 12. Handoff & Learning Plan
The project is designed so a teenage tinkerer can work on it safely and learn real skills:
- **Safe by default:** sandbox egress is off, scope-as-code applies, and only the adult account holder can submit. No configuration flag lets the pipeline hit a live target before Phase 4, and even then it needs explicit approval.
- **Learning path:** each step teaches a skill, and each finished step turns into a test fixture:
  1. Ethernaut and Damn Vulnerable DeFi by hand
  2. Write a Slither detector
  3. Improve a pipeline stage
  4. Run a backtest and read the metrics
- **Good first issues:**
  - new static-analysis adapter
  - PoC-cheat lint rules
  - dashboard for ledger metrics
  - EV-score tuning from backtest data
  - local-lane throughput (vLLM migration)
- **Docs:** `CLAUDE.md` with project conventions, `docs/architecture.md`, and a `docs/learning-path.md`.
- **He owns `llm-server`.** The son administers the local LLM host. Ground rules:
  - **Interface contract:** the pipeline depends only on an OpenAI-compatible endpoint at a fixed URL plus model *aliases* (`local-triage`, `local-summarize`). He can swap Ollama for vLLM, change quantization or switch models without touching pipeline code, as long as the contract holds and a benchmark doesn't regress.
  - **Config as code:** the host setup (service files, model list, env vars) lives in `infra/llm-server/` with a README runbook. Changes go through PRs.
  - **Own credentials:** he uses his own user account and SSH key on the host, with sudo scoped as needed. Nobody shares the parent's keys.
  - **Network:** Ollama/vLLM have no auth, so they listen on the LAN or Tailscale only and are never port-forwarded to the internet.
  - **Benchmark before and after:** `benchmarks/llm_server.py` measures tokens/sec, concurrency and triage quality on a fixed fixture set. That gives him an objective scoreboard for his optimizations.
- **Metrics are the teacher.** The backtest harness gives objective feedback (recall, false positives, $), so changes can be judged by numbers, not vibes.

## Verification (of the MVP)
- Unit tests per stage. An end-to-end run on 1 Damn Vulnerable DeFi challenge and 1 archived contest produces validated PoCs, a skeptic review, a review packet and ledger rows.
- Backtest report table: recall, precision, skeptic accuracy and $ per contest, compared with published findings.
- Guardrail tests:
  - the sandbox blocks egress
  - out-of-scope targets are refused
  - the monthly cap halts frontier calls
  - the PoC-cheat lint catches seeded cheating PoCs
