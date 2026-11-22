# TODO

Work that is planned but not built. [SPEC.md](SPEC.md) has the design and the reasons behind it.

## Code checks instead of model judgment

Right now some decisions rest on Opus's judgment in the skeptic stage (F2). Each item below turns one of them into a visible step in code, with a test. Code can't be argued with, costs nothing to run, and gives the same answer every time. The skeptic stays as a second opinion.

Background: on its first live run, stage D produced a PoC that passed but proved nothing (it asserted `flashFee == 0` during an intended grace period). The skeptic caught it. Items 1 and 2 would have caught it before any Opus call.

- [ ] **1. Ground truth on practice targets.** Every Damn Vulnerable DeFi challenge has an `_isSolved()` check. For `practice` targets, run it after the PoC and fail the PoC if it returns false, whatever the models claim.
  - Done when: the DVD false positive (finding #1) fails this check in a test, and a real Unstoppable solution passes it.
  - Bonus: practice runs score themselves (solved / not solved) in the digest.

- [ ] **2. An impact check on every PoC, by bug class.** Each PoC must assert a concrete before/after effect, and *which* effect depends on the class of bug (see item 6):
  - theft: the attacker's balance goes up, or the protocol's goes down;
  - denial of service: a call that succeeded before the exploit now reverts (this is Unstoppable's real bug, so "balances changed" alone would wrongly fail it);
  - frozen funds: a withdrawal that worked before can no longer succeed;
  - privilege: the owner or a role changes to the attacker.
  A PoC that only reads view functions fails.
  - Where: the stage D prompt and harness (`pipeline/analysis.py`), plus a parse/lint check that the class's required assertions exist.
  - Done when: a "reads a fee, asserts zero" PoC is rejected before the sandbox verdict counts as a pass, and a correct Unstoppable DoS PoC is accepted.

- [ ] **3. Known-issue check (stage F, not built).** Before the skeptic, compare each finding with the program's known-issues list, published audits and, for backtests, the contest's own findings. Show matches in the digest.
  - Done when: a backtest finding that duplicates a published issue is marked as a duplicate, with a link to it.

- [ ] **4. Each program's own severity scale.** Store the program's severity rules next to its scope policy. Code checks the skeptic's severity against them, and disagreement becomes `flag-for-human`.
  - Done when: a finding the skeptic rates `high` that the program's rules cap at `medium` is flagged in the digest.

- [ ] **5. Measure the skeptic.** Log its verdicts against what actually happened (backtest answers now, platform outcomes later) and report its accuracy in the digest.
  - Done when: the digest shows the skeptic's accuracy and false-reject rate over the last N findings.

### From the vulnerability-research discussion (2026-11-21)

Ideas from a Le Chat conversation about how security flaws are found, translated to smart contracts. Its news claims weren't verified, and none of these ideas depend on them.

- [ ] **6. One weakness class at a time.** Make the bug class an explicit field from triage onward (reentrancy, access control, accounting/invariant breaks such as donation attacks, rounding, oracle manipulation, DoS, ...). Each class gets a short checklist in the triage prompt and a PoC assertion template (item 2). Runs can then target one class, and the backtest can score recall per class.
  - Done when: `hotspots` and `findings` have a `class` column, the digest groups by it, and a class outside the list is rejected.

- [ ] **7. Entry-point inventory and coverage.** Untrusted input enters a contract through its external/public state-changing functions. List them with code (Slither or the solc AST, not a model), then report which ones triage looked at, which became hotspots and which got a PoC.
  - Done when: the digest shows "N of M entry points examined" per target, and unexamined ones are listed.

- [ ] **8. Fix check (differential test).** A real bug has a fix that makes the PoC fail. Stage D also proposes a minimal patch; the sandbox applies it to a scratch copy and re-runs the PoC, which must now **fail**. If the PoC still passes on the patched code, it isn't testing the bug.
  - Done when: the DVD false positive fails this check (no sensible patch changes "fee is zero during the grace period"), and a real Unstoppable PoC fails against the patched vault as expected.
  - Bonus: the patch goes into the report as the suggested fix.

- [ ] **9. Deterministic tools as triage inputs.** Run Slither detectors and Foundry fuzz/invariant tests alongside the local model, and merge their hits into the hotspot ranking. (Adding Slither is a new dependency: run the security-auditor review first, per CLAUDE.md.)
  - Done when: a hotspot shows its source (model, Slither, fuzz), and the backtest compares the sources' hit rates.

- [ ] **10. The funnel in every digest.** Files → hotspots → PoCs written → PoCs passed → skeptic verdicts, with $ at each step. "There's a lot of noise" stops being a feeling and becomes a number showing which stage makes it.
  - Done when: the digest has a funnel table for the week and for each target.

- [ ] **11. A submission checklist at the human gate.** Disclosure judgment stays with a human, but the steps are written down and ticked in the review packet: scope re-checked against the program page, not a known issue or duplicate, the program's disclosure terms read, the PoC re-run from a clean checkout, the report goes through the platform's private channel only, and nothing is published.
  - Done when: the review packet (stage G) includes the checklist, and the packet can't be marked "submitted" with an unticked box.

- [x] Review the Le Chat conversation for more ideas (done; see items 6–11).

## Other open items

- [ ] Backtest harness (Phase 1): run past Code4rena/Sherlock contests and score recall, false positives and $ per contest. Compare models on the same harness too (DeepSeek, GLM, Opus): the workflow may matter more than the model.
- [ ] Turn on stages D and F2 in the nightly run (`[analysis] enabled` and `[review] enabled` in `config/router.toml`), together, once items 1, 2 and 8 are done.
- [ ] Opus escalation for high-confidence misses (`[analysis] escalate`, which isn't built yet).
- [ ] Stage A: pull program scope and rules from platforms, with a human confirming each policy.
- [ ] Stage G: one-page review packets with a one-command PoC re-run.
- [ ] Human task: check each platform's age, identity (KYC) and tax rules, and its policy on AI-assisted reports.
