# Verification — External Adjudicator Trust Binding (attended release)

- Date: 2026-08-13
- Verifier: independent adjudication pass (clean-room reading)
- Scope: fresh-corpus qualification recovery — custodian-supplied external adjudicator
  identity/public-key binding for attended human release, without enabling model-backed
  approval.
- Artefacts read in full: `scripts/qualification/release-corpus.ts`,
  `scripts/qualification/release-operator.ts`, `tests/eval/release-operator.test.ts`.
- Context read: `tests/eval/release-corpus.test.ts`, `scripts/qualification/custody.ts`,
  `scripts/qualification/generate-release-draft.ts`, `scripts/qualification/core.ts`,
  `src/plugin.ts`, `INVARIANTS.md`, `ledger.yaml`, `fixtures/eval/release-corpus.schema.json`.

## Original clean-room execution limitation

I could **not execute any command** in this session. Every `bash` call was either denied
by the permission gate (`bun --version`, `bun test …` → "requires approval") or failed at
the harness sandbox layer (`ls …` → `EPERM … mkdir '/Users/.../session-env/...'`). A
`validation-runner` subagent dispatched to run
`bun test tests/eval/release-operator.test.ts tests/eval/release-corpus.test.ts`
and to grep for callers hit the same approval gate and could not run either.

At the time of this clean-room review, the task instruction "run your own focused tests;
do not trust the existing test claims" could not be satisfied. The verdicts in the
original review section below were therefore by reading of source + tests, not by
execution. The limitation was later resolved; the follow-up execution section records
the actual repository validation. It does not describe the current test status.

---

## Task 1 — Human adjudication signatures bound to subject, candidate, roles, timestamps

**Requirements check — VERIFIED (by reading).**
`createHumanAdjudicationAttestation` (release-corpus.ts:218) signs
`humanAdjudicationPayload` (:198) over `{schemaVersion, algorithm, subjectDigest,
candidateManifestHash, authorID, adjudicatorID, custodianID, authoredAt, adjudicatedAt,
custodyAt}`. `subjectDigest = humanReleaseSubjectDigest` (:213) is
`digestPrivateBytes(canonical(corpus \ adjudication))`, so the signature transitively
covers **all** corpus content (bindings, minimums, generatedAt, corpusVersion, every
release + generalization fixture) — not just the roles/timestamps enumerated in the
payload. `canonical` (core.ts:241) sorts object keys recursively, so the digest is
input-order-independent and deterministic.

`verifyHumanAdjudicationAttestation` (:247) fails closed and requires, in order:
schema/algorithm match; `subjectDigest` == recomputed and `candidateManifestHash` ==
`corpus.bindings.candidateManifestHash` (:250); all three role IDs == corpus roles (:251);
all three timestamps == corpus timestamps (:252); the external binding (Task 2); payload
hash; and finally the ed25519 signature verifies. Any single mismatch → `false` →
`parseShape` throws (:374). Tamper resistance confirmed: altering any fixture changes
`subjectDigest` (breaks :250 *and* the signature); altering a role/timestamp breaks both
its equality check and `subjectDigest`.

## Task 2 — Out-of-band AuthorizedAdjudicator binding threaded through every path

**Requirements check — VERIFIED (by reading).** The binding is the security core and it is
correct: the signature is verified against `attestation.publicKey`
(release-corpus.ts:256-257), and `attestation.publicKey` is pinned to the custodian's
out-of-band key at :253 (`attestation.publicKey !== authorizedAdjudicator.publicKey →
false`), with `attestation.adjudicatorID` also pinned to
`authorizedAdjudicator.adjudicatorID`. A corpus therefore **cannot authorize itself**: a
self-supplied keypair fails the pin; a matching ID with a non-matching key fails the pin;
and forging a signature under the custodian's key is infeasible without the private key.
Replay to a different corpus fails because the payload binds `subjectDigest`.

Threading in the attended wrapper (release-operator.ts):
- :74 hard-requires `options.authorizedAdjudicator` (truthiness guard).
- :90 `parseReleaseCorpus(JSON.parse(bytes), { authorizedAdjudicator })` — parse verifies.
- :93 `toPrivateAuthoringManifest(parsed, …, { authorizedAdjudicator })` — re-parses, re-verifies.
- :103 and :109 `releaseCorpusIdentifiers(parsed, { authorizedAdjudicator })` — re-parses, re-verifies.
Every private-corpus parse/projection/identifier call carries the binding; defense in
depth (each call re-runs full verification via `parseReleaseCorpus`).

The public projection `toPublicReleaseManifest` (:528) and `toReleaseAuthoringManifest`
(:472) both go through `parseReleaseCorpus(value, options)`; called on a human envelope
without the binding they throw "not authorized". So no projection path yields eligibility
without the custodian key.

## Task 3 — A/B regression coverage (no binding / mismatch / match)

**Requirements check — VERIFIED (by reading of the tests; NOT executed).**
- No binding: release-corpus.test.ts:90 `parseReleaseCorpus(human)` → throws /not authorized/;
  release-operator.test.ts:298 asserts custody is spent, `calls === 0`, no public file.
- Mismatched key: release-corpus.test.ts:93; release-operator.test.ts:315 (matching ID,
  fresh key) → /not authorized/ before qualification.
- Matching: release-corpus.test.ts:91; release-operator.test.ts:181 full happy path.

**Blind-spot (test-coverage / operational, not a security defect).** The "matching" case
is proven only for **already-normalized** input. `humanReleaseSubjectDigest` digests the
*parser-reconstructed* subject, and `parseFixture` normalizes (release-corpus.ts:311 drops
`errorPath:false`; bindings/minimums/rubric are rebuilt from constants at :340-345). Both
test helpers build the signing subject from `generateAutomatedDraft`, which is itself
parser output, so the signed digest trivially equals the re-parsed digest. A
human-*authored* envelope that contains a field the parser drops/normalizes (e.g. an
explicit `errorPath: false`, or a differently-ordered/whitespaced serialization signed as
raw bytes) would verify only if the custodian signs the **canonicalized** subject. This
fails closed (mismatch → rejected), so it is not a vulnerability, but the real custodian
workflow must sign `humanReleaseSubjectDigest`'s canonical subject, not authored bytes, and
there is no test covering an authored-but-non-normalized envelope.

## Task 4 — Aggregate-only output, raw digest/custody binding, no-overwrite, custody order

**Requirements check — VERIFIED (by reading).**
- Spend-before-input: `runAttendedRelease` (custody.ts:527) spends (`spendBeforePrivateInput`,
  :530) before `readPrivateInput` (:534) and before `qualify` (:536). Wrapper reads the file
  only inside `readPrivateInput` (release-operator.ts:86).
- Never qualifies an invalid human envelope: model `qualify` runs at :98, strictly after the
  digest/commitment check (:89), `parseReleaseCorpus` (:90, verifies binding), candidate
  binding (:91), eligibility (:92), and lint (:94). Any failure throws before :98. Custody is
  still spent (one-shot semantics) — matches tests at :204, :235, :298.
- Public output bound to signed raw digest + custody number: `corpusDigest =
  digestPrivateBytes(bytes)` over the raw file (:88), checked == `commitment.corpusDigest`
  and the commitment signature verified (:89); sanitized aggregate must satisfy
  `corpusDigest === corpusDigest` and `custodyNumber === spentLedger.consumptionNumber`
  (:104). Test :285 covers rejection of an unbound aggregate.
- No overwrite: pre-check `existsSync(publicArtifactPath)` before spend (:78, test :270), and
  the real race guard `durablePublicWrite` uses `linkSync` which fails EEXIST rather than
  `renameSync` replace (custody.ts:433-435).
- Aggregate-only / strict allowlist: `sanitizePublicAggregate` (custody.ts:409) rejects
  arrays anywhere (`scanPublicFields`, per-invocation output forbidden), enforces an **exact**
  key allowlist (`assertPublicAggregateKeys`, :391 — so `providerOutput`/`response`/
  per-invocation keys are rejected as "unknown or missing fields"), rejects forbidden key
  names, and `scanForbiddenStrings` rejects any private identifier substring
  (`releaseCorpusIdentifiers`: ids, commands, structuralKeys, all canaries incl. secret).
- Custody ordering preserved: `spendBeforePrivateInput` enforces monotonic
  `consumptionNumber` and reserved-commitment match (custody.ts:309-331); unchanged by this work.

**Model-backed approval remains disabled — VERIFIED.** `MODEL_APPROVAL_QUALIFIED = false as
const` (plugin.ts:23) is ANDed into the coordinator's `modelEnabled` at plugin.ts:141 and
again at :199, so no config can enable model approval. `ledger.yaml` only records gate-test
coverage and is not evidence of the flag; the flag itself was read in `src/plugin.ts`.
Automated drafts stay non-eligible and require no binding: `generateAutomatedDraft`
(generate-release-draft.ts:53) sets `releaseEligible: false` and `parseReleaseCorpus(draft)`
(no `authorizedAdjudicator`) succeeds because the human-verification branch
(release-corpus.ts:373-374, 413-414) is gated on `HUMAN_RELEASE_SCHEMA`; the wrapper rejects
a draft at release-operator.ts:92 (test :204).

---

## Observations (no exploit path; not ranked findings)

- `assertPublicReleaseManifest`'s `forbiddenKeys` regex (release-corpus.ts:511) is
  full-anchored, so a key literally named `providerOutput` would not match. No exploit path:
  the public *manifest* is code-constructed from a fixed field set, and the *written*
  artifact is the public aggregate, which passes the exact-allowlist `assertPublicAggregateKeys`.
- Timestamp ordering (authoredAt ≤ adjudicatedAt ≤ custodyAt) is bound but not enforced. Not
  a stated requirement, and eligibility never derives from timestamps alone (signature +
  external key required).

## Verdict

- **VERIFIED (by reading):** Tasks 1, 2, 4 and the "model-backed approval disabled" floor
  check. The external-adjudicator binding is correctly enforced on every human-envelope
  parse/projection/identifier path examined; a human corpus cannot become release-eligible
  from roles, timestamps, or a self-supplied key alone. Custody-spend ordering, raw
  digest/custody binding, strict aggregate allowlisting, and no-overwrite writes hold.
- **VERIFIED with a test-coverage gap:** Task 3's cases are present and correct, but the
  "matching" case only exercises pre-normalized input; no test covers a human-authored
  envelope containing a parser-dropped field (operational note; fails closed).
- **INCOMPLETE (environment-limited):** The test suite was **not executed** (bash gated), so
  suite pass/fail is unverified. A repo-wide `rg` for callers could not be run; instead I
  enumerated callers by reading module imports. Across the qualification source modules only
  three touch release-corpus parsing: `release-corpus.ts` (definitions),
  `generate-release-draft.ts` (drafts only — correctly needs no binding, human branch is
  gated on `HUMAN_RELEASE_SCHEMA`), and `release-operator.ts` (threads the binding on all
  five sites). `scripts/classifier-gate.ts`, `scripts/qualification/verify-terminal.ts`, and
  `scripts/qualification/custody.ts` import only from `core`/`classifier-gate` and never
  parse a release corpus. No unbound human-envelope caller found — but this rests on
  import-reading, not an executed grep, so residual risk of an unread module remains.
- **No material security findings.**

## Follow-up execution

After workspace access was restored, the focused release-corpus/custody/operator
tests passed 27/27; the full offline/package gate passed 202/0 with 1,400
expectations, the evaluation/A-B gate passed 63/0 with 422 expectations, and
the OpenCode 1.18.10 E2E gates passed 11/11 plus 14 pass, 1 intentional skip,
0 fail. The final source-current development draw passed all 475 invocations
with zero invalid runs. The execution limitation above applies only to the
original clean-room review session.
