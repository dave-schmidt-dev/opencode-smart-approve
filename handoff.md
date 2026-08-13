# Handoff: opencode-smart-approve
- **Active Plan:** `~/Documents/Projects/.plans/opencode-smart-approve/classifier-qualification-recovery-2026-08-10-tasks.md`
- **Current Task:** `TASK-013 / Phase 3 Task 3.3 — resolve fresh release-corpus branch`
- **Critical Files:** `scripts/qualification/custody.ts`, `scripts/qualification/release-corpus.ts`, `tests/eval/qualification-custody.test.ts`, `tests/eval/release-corpus.test.ts`, `SPEC.md`

## Strategic Momentum
The attended release boundary was hardened with input-stage progress heartbeats, observer-failure isolation, and a rubric digest bound to actual file bytes. The source-current candidate `d419a4f7…` passed 475/475 development invocations and all automated gates, but release remains disabled because the fresh corpus, independent adjudicator, custodian, and release decision are human-only gates. The immediate next move is to name those roles and run the attended fresh-corpus workflow without exposing private corpus bytes to automation.

## Active Subagents

None.
