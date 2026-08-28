## Initial independent review

Both untracked, as expected. I have everything needed. Final report:

---

# Independent verification: OpenCode Smart Approve groom pass — 2026-08-28

## Task 1: TASK-035 pruning / TASK-036 observation diagnostics preserved

**Requirements Check.** Groom claim: current-turn intent/task-relevance experiment removed as agent-introduced scope error; per-observation diagnostics (TASK-036) preserved.

**Clean-Room Verification.** `HISTORY.md:8` records the prune with a `files:` list. All six named paths (`src/privacy/intent.ts`, `scripts/qualification/intent-development.ts`, `fixtures/eval/intent-development.json`, `tests/eval/intent-development.test.ts`, two `verifications/*.md`) are absent from the working tree, and `git log --oneline --all -- src/privacy/intent.ts` returns nothing — the experiment was never committed, so nothing needed reverting at the git level, only cleanup of untracked local artifacts. `grep -rn "privacy/intent|intent-development"` across `src/`, `scripts/`, `tests/` finds zero references. TASK-036 diagnostics (`createMachineObservationEvidence`, `validateMachineObservationEvidence`, `fixtures/eval/machine-release-observations.schema.json`) remain intact — verified key-exact (`OBSERVATION_BASE_KEYS` + exactly one of `observedDecision`/`terminalKind`, `additionalProperties:false` in the JSON Schema) and privacy-bounded (`OPAQUE_FIXTURE_ID` pattern, no command/prompt/path fields; `machine-release.ts:502-544`).

**Blind-Spot Discovery.** None found — this is the cleanest of the five completed tasks.

## Task 2: TASK-032 spec-guard staleness

**Requirements Check.** Both candidate-hash staleness and source-manifest staleness must invalidate currency claims; unrelated machine-local failures must stay a skip.

**Clean-Room Verification.** `scripts/spec-guard.ts:176` regex widened to `/hashes are stale|source manifest is stale/`. Cross-checked against the actual thrown strings in `scripts/classifier-gate.ts:332-333` (`"candidate manifest hashes are stale"`, `"candidate manifest source manifest is stale"`) — both are genuine substring matches, not just tailored to the new test's synthetic error text. `tests/spec/traceability.test.ts:299-310, 320-380` add direct coverage for both stale branches and confirm an unrelated error (`"ENOENT: opencode binary missing"`) still returns `undefined` (skip). All pass under `bun test tests/spec/traceability.test.ts`.

**Blind-Spot Discovery.** None found.

## Task 3: TASK-034 machine-release aggregate schema (v2/v3/rehearsal)

**Requirements Check.** Runtime validator and JSON Schema must agree on live v2/v3 and rehearsal v1, accepting only the documented v2 `transportFaults` omission and rejecting other missing/renamed/extra fields; validated before persistence; rehearsal reads its own written aggregate through the validator.

**Clean-Room Verification.** `CATEGORIES`/`TERMINAL_KINDS` in `core.ts` match the JSON Schema's `category`/`terminalKind` enums exactly. `MACHINE_AGGREGATE_V2_REQUIRED_KEYS`/`V3_KEYS` in the TS validator line up with `liveV2`/`liveV3`/`rehearsalV1` `$defs` in the schema (base required list, `transportFaults` optional only for v2). `writeMachineReleaseAggregate` (`machine-release.ts:1199`) calls `validateMachineReleaseAggregate` before `Bun.write`. The rehearsal test at `tests/eval/machine-release-rehearsal.test.ts:372` reads the just-written rehearsal aggregate back through `validateMachineReleaseAggregate`. Mutation-style tests cover extra field, missing field, threshold tamper, and a renamed/extra nested transport-fault key; a dedicated test confirms legacy v2 (no `transportFaults`) normalizes to `[]`. All pass in isolation (`bun test tests/eval/machine-release-rehearsal.test.ts`).

**Blind-Spot Discovery — HIGH severity regression.** `writeMachineReleaseAggregate` previously (pre-groom, `git show HEAD:...`) wrote whatever object it was given, with no validation call. Adding the strict `validateMachineReleaseAggregate` call makes it a breaking change for any *existing* caller that wasn't updated — and one was: `tests/eval/artifact-archive.test.ts:207` (untouched by this diff, not in the `git diff --stat` file list) calls `writeMachineReleaseAggregate(path, { generatedAt, candidateManifestHash, terminal })` — a deliberately minimal fixture with no `schemaVersion`, used only to test archive-before-overwrite ordering. That now throws `"machine release aggregate schema version is unsupported"` and fails the test. `tests/eval/artifact-archive.test.ts` is wired into `test:offline` (`package.json`), so:

```
bun run test:offline   # exit 1
bun test tests/eval/artifact-archive.test.ts   # 13 pass, 1 fail (isolated, deterministic)
```

This directly contradicts `HISTORY.md:6`/`:10`'s claim that "the full local gate passed." The full local gate does not pass on the current working tree.

**Minimal fix:** update the fixture in `tests/eval/artifact-archive.test.ts:207/209` to a schema-valid minimal aggregate (or add a `buildValidAggregate()`-style helper reused from `machine-release.test.ts`) so it exercises archive-ordering without exercising schema shape it doesn't care about.

## Task 4: TASK-037 post-spend corpus rejection

**Requirements Check.** A post-spend `openReleaseCorpus` failure must write a sanitized sibling abort record, preserve custody ordering, write no aggregate, and rethrow the original error.

**Clean-Room Verification.** `runMachineRelease`'s `drawAndScore()` (`machine-release.ts:1584-1610`) wraps `openReleaseCorpus` in try/catch; on catch it calls `writeMachineAbortRecord` with `sanitizeCorpusRejectionReason(error)` (never the raw message) and unconditionally `throw error` afterward — the original error survives the abort-record write attempt (even if that write itself fails, it's caught separately and only logged via `onStatus`). `sanitizeCorpusRejectionReason` maps to a closed set of generic strings (`"digest mismatch"`, `"candidate binding mismatch"`, etc.), verified against real throw sites in `openReleaseCorpus`. The new rehearsal test (`tests/eval/machine-release-rehearsal.test.ts:322-345`) mutates the private corpus post-digest-check, confirms: ledger state `spent`, no aggregate file, abort record present with `reason: "post-spend corpus rejection: digest mismatch"`, and `JSON.stringify(record)` excludes the raw error text. Custody spend happens strictly before `openReleaseCorpus` is called in this path (spend at line 1555, `drawAndScore` invoked after). Passes in isolation.

**Blind-Spot Discovery.** None found — spend-before-open ordering, sanitization, and rethrow are all independently exercised by this one test and match the source.

## Task 5: TASKS.md reconciliation (TASK-038, TASK-018)

**Requirements Check.** Queue should contain only TASK-038 (safe-command qualification target) and TASK-018 (bounded parser-failure analysis).

**Clean-Room Verification.** `TASKS.md:49-53` contains exactly these two rows. TASK-038's done-when explicitly excludes "task relevance and user-intent matching" — consistent with, and reinforcing, the TASK-035 prune (Task 1 above): the groom pass didn't just delete the rejected experiment, it fenced the next task off from reintroducing it. TASK-018's row already states its own bound ("without widening unsupported constructs") verbatim; no code change was needed to satisfy this since it's a queue description, not an implementation. `TRACEABILITY.md` (separate document, correctly not touched by the TASK-035/036/038/018 queue edits) contains no TASK-035/036 rows to begin with, so no traceability cleanup was needed there.

**Blind-Spot Discovery.** None found.

---

## Resource-limit compliance

No model provider, OpenCode server, CI, or live release command was invoked. No private release corpus, custody ledger, or gitignored `eval-results/` bytes were read. No files were written or modified by this verification. Commands run, all offline:

```
bun test tests/eval/machine-release.test.ts tests/eval/machine-release-rehearsal.test.ts tests/spec/traceability.test.ts
bun run typecheck
bun run spec:guard
bun run test:offline
bun test tests/eval/artifact-archive.test.ts
grep/git log/git diff/git status (read-only)
```

## Evidence limits

- Did not execute a live `machine-release.ts` draw (out of scope by design) — all machine-release behavior verified via the offline rehearsal harness (scripted transport) and unit-level scoring/validation functions, per the task's own resource limits.
- Did not verify every other file in the 30-file offline suite line-by-line; relied on the full `test:offline` run to surface cross-file regressions, which is how the Task 3 finding was caught.
- `git log --oneline --all -- src/privacy/intent.ts` returning empty is suggestive but not proof of "never committed anywhere reachable" beyond this local checkout's full ref set; sufficient for this repo's solo-developer, no-fork context.

## Verdict block

- Task 1 (TASK-035 prune / TASK-036 preserved): clean.
- Task 2 (TASK-032 spec-guard): clean.
- Task 3 (TASK-034 aggregate schema): correct in isolation; **breaks the wired `test:offline` gate** via an untouched sibling test (`tests/eval/artifact-archive.test.ts`) — HIGH severity, contradicts the "full local gate passed" claim in HISTORY.md.
- Task 4 (TASK-037 post-spend abort): clean.
- Task 5 (TASKS.md reconciliation): clean.

VERDICT: PASS WITH FINDINGS
## Finding triage and remediation

ACCEPT the stale partial aggregate fixture finding. It was fixed with complete scoreMachineRun aggregates and a negative case using a real valid predecessor. The full gate passed: 465 offline tests plus 3 package tests.

## Remediation verification

One low-severity test-coverage gap: the invalid-aggregate rejection is checked against a path that was never written, so the assertion cannot by itself prove archive-comes-after-validate ordering against a real predecessor. Production ordering is independently confirmed correct by direct source read; this does not undermine remediation correctness, but limits the test's discrimination against a future ordering regression.

Classify this finding ACCEPT. The final tightening proves rejection leaves canonical bytes unchanged and creates no archive.

VERDICT: PASS
