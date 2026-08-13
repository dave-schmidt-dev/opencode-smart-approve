# Verification — Custody Progress Heartbeats, Observer Isolation, Rubric-Byte Binding

- Date: 2026-08-13
- Verifier: independent verification pass (clean-room reading)
- Scope: post-fix qualification custody + rubric-binding changes.
- Artefacts read in full: `scripts/qualification/custody.ts`,
  `scripts/qualification/release-corpus.ts`,
  `tests/eval/qualification-custody.test.ts`.
- Context read: `tests/eval/release-corpus.test.ts`, `INVARIANTS.md`,
  `SPEC.md` (§REQ-008, §REQ-011), `README.md` (attended release workflow),
  `fixtures/eval/authoring-rubric.md`, prior verification
  `2026-08-13-external-adjudicator-binding-verification.md`.
- Caller/test broadening (within resource limits): `scripts/qualification/release-operator.ts`
  (the production attended caller of `runAttendedRelease`) and
  `tests/eval/release-operator.test.ts`, read to confirm the heartbeat fix is
  actually reached and to check whether the *real* private-input read can tick.

## Original clean-room execution limitation

I could **not execute any command** this session. Every `bash` call — from the
main shell *and* from a dispatched `validation-runner` subagent — failed at the
harness sandbox layer while creating its temporary session environment. So
`bun test tests/eval/qualification-custody.test.ts`,
`bun test tests/eval/release-corpus.test.ts`, `bun run typecheck`, and
`git diff HEAD` **were not run**, and the working-tree diff was not obtained.

Consequently, in the original clean-room pass: (a) suite pass/fail was
**unverified by execution**; (b) I could
not diff against `HEAD`, so "no unrelated behavior changed" rests on reading the
current full sources against the four stated tasks, not on a diff. The prior
verification's "27/27 passed" refers to a *pre-change* tree and does not cover
these uncommitted edits. Verdicts below are **by reading**. This gap should be
closed by running the three commands in an unsandboxed session before relying on
the change.

Concrete named risk identified at that point: the heartbeat-count assertions
(`toBe(4)`, `toBe(3)` in qualification-custody.test.ts:199, :229, :303) depend on
bun's `jest.useFakeTimers()` actually driving `setInterval`. My by-hand
microtask/timer trace shows the counts are correct **conditional on fake timers
working as jest's do**; if this bun version's fake-timer/`setInterval` interaction
differs, those specific assertions are the most likely failures. Run them.

---

## Task 1 — Input-stage heartbeats while `readPrivateInput()` is pending; teardown on resolve/reject

**Requirements check — VERIFIED (by reading).**
`runAttendedRelease` (custody.ts:529) spends custody first
(`spendBeforePrivateInput`, :538), emits `spent` (:539), then
`opening_private_input` (:540), emits the `private_input_open` durability event
(:541), and only then starts the input heartbeat (:542). So repeated opaque
progress fires **after** the ledger is spent, satisfying the spot-check. The
heartbeat interval is created only when `onStatus` is defined
(`startHeartbeat`, :536) and is cleared in a `finally` around the `await`
(:544-548), so it is torn down on **both** resolve and reject of
`readPrivateInput`. The status values are the fixed enum
(`opening_private_input`, `qualifying`, …) — no private bytes.

Qualification heartbeat (:549-556) mirrors this: started after
`notifyStatus("qualifying")`, cleared in a `finally` around
`await options.qualify(...)`, so it clears on success and on rejection. Because
the `finally` precedes `sanitizePublicAggregate` (:558), a throwing sanitize
cannot leak the interval.

Heartbeat interval is validated as an integer in [1, 60000] (:531); production
default is 10_000ms (:530), meeting REQ-008's "refreshes at least every 10s."

Test coverage present and logically consistent (I traced the fake-timer
microtask ordering by hand): input heartbeat count = 4 after 15ms @ 5ms
(release-corpus… custody test:209-237, immediate emit + 3 fires), qualify count
= 4 (:179-207), qualify heartbeat cleared on rejection with ledger left spent
(:282-313), and post-spend read failure leaves ledger spent (:164-177). All
consistent; none executed.

**Caller wiring — VERIFIED.** The production caller
`runAttendedFileRelease` (release-operator.ts:73) threads `onStatus`
(:50 option, passed at :85) into `runAttendedRelease`, and its `onStatus` union
(:50) is character-for-character the same 5-literal union as custody.ts:161, so
that surface typechecks by reading. The operator test supplies `onStatus`
(release-operator.test.ts:171) and asserts `spent` precedes
`opening_private_input` (:194). The fix is therefore **reached**, not inert, and
the genuinely perceptible wait — `options.qualify` (the 475-invocation provider
run) — flows through the truly-async `await options.qualify(...)` (custody.ts:553),
so the **qualifying** heartbeat can fire during it.

**Finding F1 (scoped, low severity — not a security/correctness defect).** In the
file-backed operator, `readPrivateInput` is `readPrivateCorpusAfterSpend`
(release-operator.ts:66-70) = a **synchronous `readFileSync`** wrapped in an
`async` arrow (:86). Because the body blocks the event loop and never yields, the
input-stage `setInterval` created at custody.ts:542 **cannot fire during the real
read** — only the single immediate `notifyStatus("opening_private_input")`
(custody.ts:540) surfaces. This does **not** violate Task 1's contract today: the
private corpus is a small local JSON (95 + 6 fixtures), so its read is not a
*perceptible* wait, and the async stdin variant (`readStdinAfterSpend`,
custody.ts:566-570, used by `runAttendedStdinRelease`) *does* yield and would tick
the input heartbeat during a human/pipe wait. Latent risk to record: if a future
change points the operator's private input at a slow/large or network-backed
source without converting the read to an async, yielding form, the input heartbeat
will silently not tick and the wait will appear hung. The fake-timer unit tests
pass only because their `readPrivateInput` returns an *unresolved promise* — they
do not exercise a synchronous read.

**Finding F2 (test-coverage, low severity).** No test asserts *repeated*
input-stage or qualifying heartbeats **through the operator**: the operator test's
`qualify`/read both resolve immediately (release-operator.test.ts:172-176), so it
only proves the single ordered `opening_private_input`. Repeated-heartbeat
behavior is proven solely by the custody-level fake-timer unit tests
(qualification-custody.test.ts:179-237, :282-313). Adequate for the mechanism;
there is no integration-level proof the operator surfaces repeated progress during
a genuinely pending `qualify`.

**Blind spot (design note, not a defect):** the immediate emit at :540 and the
interval both send the identical `opening_private_input` string, so a consumer
cannot distinguish "phase entered" from "still waiting." Progress is still
visibly repeated, so the requirement holds; only worth noting if the TUI needs a
monotonic tick.

## Task 2 — Synchronous and asynchronous `onStatus` observer failures isolated from custody

**Requirements check — VERIFIED (by reading).**
`notifyStatus` (:533-535) is
`try { void Promise.resolve(options.onStatus?.(status)).catch(() => undefined); } catch {}`.
- **Sync throw:** `onStatus?.(status)` throws during argument evaluation, before
  `Promise.resolve` runs → caught by the outer `try/catch`. Custody is untouched.
- **Async throw / rejected promise:** `Promise.resolve(P)` returns the rejected
  promise and `.catch()` is attached in the **same tick**, so there is no window
  for an `unhandledRejection`.
`onStatus` is referenced only inside `notifyStatus` and `startHeartbeat` (which
calls `notifyStatus`), so every observer call — including every heartbeat fire —
is wrapped; a throwing interval callback cannot surface an uncaught timer error.

Durability observer isolation preserved: `emit` (:241-243) wraps
`onEvent` in `try {} catch {}` at every call site (reserve, spend, fsyncs, lock,
`private_input_open`). Custody file writes in `spendBeforePrivateInput` /
`writeDurable` are independent of both observers, so neither can weaken the
`spent` outcome.

Tests present: sync-throw leaves ledger spent (test:239-256), async-throw
asserts `unhandledRejection == []` and ledger spent (:258-280), recovery emits
`spent` through a pushing observer (:143-162). Not executed.

## Task 3 — `rubricHash` computed from rubric file bytes, not its pathname; stable project root

**Requirements check — VERIFIED (by reading).**
`releaseRubricDigest` (release-corpus.ts:169-171) is
`digestPrivateBytes(readFileSync(resolve(PROJECT_ROOT, RELEASE_RUBRIC_BINDING)))`
— it hashes the **bytes** of `fixtures/eval/authoring-rubric.md`
(`digestPrivateBytes` = SHA-256 over the buffer, custody.ts:204-206), not the
path string. `toPublicReleaseManifest` sets `rubricHash: releaseRubricDigest()`
(:545). `PROJECT_ROOT` (:167) =
`resolve(dirname(fileURLToPath(import.meta.url)), "../..")`, i.e. anchored to the
module's own location (`scripts/qualification/…` → repo root), so it is
**independent of `process.cwd()`** and stable.

Path-vs-content regression present: release-corpus.test.ts:163-164 asserts
`rubricHash === digestPrivateBytes(readFileSync(<rubric>))` **and**
`!== digestPrivateBytes("fixtures/eval/authoring-rubric.md")` — exactly the
path-vs-content distinction. (Note: the test resolves the rubric via
`process.cwd()`, which is correct only when the runner is invoked from repo root;
the production code path via `import.meta.url` is the robust one.)

The rubric is a committed, non-private authoring-rules fixture, so publishing its
byte digest leaks no private corpus data.

**Blind spot:** the hash is over raw bytes with no newline/EOL normalization, so
a benign whitespace/line-ending change to the rubric file changes `rubricHash`.
That is the intended semantics (bind to *actual* authoring content) and desirable
for staleness detection — flagged only so a future editor is not surprised.

**Design note (not a defect).** The private corpus binds the rubric by **path**
(`bindings.rubric`, release-corpus.ts:341, transitively covered by the signed
`subjectDigest`), while the public manifest binds the **current file's bytes**
(:545). Nothing ties the two together, so `rubricHash` records whatever the rubric
file contains **at manifest-generation time**, not provably the revision the
author signed over. If the rubric is edited between authoring/adjudication and
public-manifest generation, the published hash reflects the later bytes silently.
The task asked only for byte-binding, which is met; binding the manifest to the
*authored* rubric revision (e.g. signing its byte-hash into the adjudication
payload) would be a stronger contract, out of scope here.

## Task 4 — Aggregate-only output and external adjudicator binding preserved

**Requirements check — VERIFIED (by reading).**
- **Aggregate-only:** `runAttendedRelease` still calls
  `sanitizePublicAggregate(publicArtifact)` before returning (:558);
  `sanitizePublicAggregate` (:411) rejects arrays anywhere, enforces the exact
  key allowlist (`assertPublicAggregateKeys`, :393), rejects forbidden key names
  (`FORBIDDEN_PUBLIC_KEYS`, :181) and forbidden private substrings
  (`scanForbiddenStrings`). Unchanged from the prior verified state.
- **Adjudicator binding:** `verifyHumanAdjudicationAttestation`
  (release-corpus.ts:255) still pins `attestation.adjudicatorID` **and**
  `attestation.publicKey` to the custodian-supplied `authorizedAdjudicator`
  (:261) before the ed25519 verify (:265); `parseShape` (:382) and
  `validateParsedCorpus` (:422) both re-run it, and `toPublicReleaseManifest`
  reaches it via `parseReleaseCorpus` (:537). A corpus cannot self-authorize. The
  new `rubricHash` field passes `assertPublicReleaseManifest`'s key/value scan
  (:518-533): `rubricHash` matches no forbidden-key pattern, and a SHA-256 hex
  digest contains no fixture identifier substring.
- **Model approval disabled / no unrelated change:** `main` (custody.ts:572-581)
  still refuses unattended release and returns 1; no enablement path was added.
  Nothing in the two changed files touches `MODEL_APPROVAL_QUALIFIED` (confirmed
  disabled in the prior pass). No new import, export-surface change, or corpus
  read appeared in either file relative to their documented purpose. (Caveat: this
  is a read-based judgment; the `HEAD` diff could not be produced — see the
  execution limitation.)

## Verdict

- **VERIFIED (by reading):** Tasks 1–4. The heartbeat fix is **reached** by the
  production caller (`runAttendedFileRelease` threads `onStatus`); the perceptible
  qualify wait flows through a truly-async await so its heartbeat can fire;
  heartbeats are post-spend, opaque, and torn down on both resolve and reject;
  sync and async `onStatus` failures and durability-observer failures cannot alter
  the `spent` custody outcome or raise an unhandled rejection; `rubricHash` binds
  the rubric file **bytes** via a `cwd`-independent project root with a real
  path-vs-content regression; aggregate-only sanitisation and the
  external-adjudicator binding are intact; model-backed approval stays disabled.
- **Scoped findings (low severity, non-blocking):**
  - **F1** — the file-backed operator's private-input read is a synchronous
    `readFileSync`, so the *input-stage* heartbeat interval cannot tick during it;
    only the immediate status shows. Not a violation today (small local corpus is
    not a perceptible wait; the async stdin path does tick), but a latent hang-look
    risk if that input source ever becomes slow/large without yielding.
  - **F2** — no integration test proves the operator surfaces *repeated* progress
    during a genuinely pending read/qualify; repeated-heartbeat behavior is covered
    only by custody-level fake-timer unit tests.
- **Original pass incomplete, main-session execution follow-up complete:** The
  clean-room verifier could not run commands, but the main checkout later ran the
  focused, full offline, evaluation, spec, harvest, typecheck, and exact-runtime
  gates recorded below. The fake-timer heartbeat assertions passed.
- **No material security or correctness defects.** Blind/design notes: duplicate
  heartbeat status string; byte-exact rubric hash sensitive to whitespace; public
  `rubricHash` binds publication-time bytes rather than the authored revision.

## Main-session execution follow-up

The main checkout independently ran the focused custody/release-corpus tests
and typecheck successfully. `bun run check` passed 205 tests with 1,408
expectations plus package smoke 3/3; `bun run test:eval:unit` passed 66 tests
with 430 expectations; `bun run spec:guard` and harvest passed; and
`bun run test:e2e` passed 11/11 integration tests plus 14 pass, 1 intentional
skip, and 0 failures. The frozen candidate
`d419a4f7215d4cea1d284580f46eaf5c4ff8cc46235d1f57174330c6ddb0c8c5` then
completed 475/475 development invocations with zero invalid runs and
2.799-second p95 latency. Release remains disabled pending the human-only
fresh corpus, independent adjudicator, custodian, and release decision.
