# Invariants — opencode-smart-approve

> **Retired failed experiment.** This project is retired and non-deployable.
> The invariants and technical history below are retained as historical evidence;
> see [FAILURE.md](FAILURE.md).

> System contract. The harvest tool reads `area:` globs to map HISTORY bug entries
> to invariants.

## Foundation-freeze waivers

- **2026-08-10 — Option 3 planning only:** The owner explicitly waived the active
  INV-7 recurrence freeze for planning the bounded stall-timeout auto-reject
  proposal. This does not waive INV-7, enable model-backed approval, authorize
  implementation, or relax any qualification threshold.

- **2026-08-10 — Mutable reviewer alias:** The owner explicitly waived immutable
  provider revision identity for the classifier-qualification recovery plan.
  Evidence may bind exactly one canonical frozen model profile from the
  repository registry, including its provider, model, and nullable requested
  variant, while stating that provider weights and served identity are
  unattested. This does not waive INV-7, authorize implementation or enablement,
  relax thresholds, or permit tuning after candidate freeze.

- **2026-08-11 — Pre-execution replan planning only:** The owner explicitly waived
  the INV-7 recurrence freeze for completing the reviewed deny-and-replan plan
  based on `tool.execute.before`. This does not waive INV-7, enable model-backed
  approval, authorize deny-and-replan implementation, or relax any
  qualification threshold.

- **2026-08-26 — Routing-equivalence receipt continuity:** The owner authorized
  `qualify:routing-check` as an alternative staleness signal for an existing
  development receipt. A receipt continues to describe the tree when all three
  routing-equivalence digests are identical, because identity proves that no
  measured fixture's experiment changed: the reviewer receives the same input,
  the policy reaches the same result by the same internals, and the same
  acceptance criteria score it. Re-running the draw would re-measure a
  byte-identical experiment and score it identically, so the draw is not
  required. This is a claim about receipt continuity, not about the tree being
  unchanged, and it is deliberately narrower than it looks: a change to a
  command shape that no fixture exercises reports identical and always will.
  That blind spot is the same one the all-or-nothing source manifest already
  had — made visible rather than removed — and what a surviving receipt is
  evidence *of* stays bounded by fixture coverage (TASK-022). This does not
  waive INV-7, enable model-backed approval, or relax any threshold. A prompt,
  model, schema, parameter, corpus, or acceptance-criteria change moves a digest
  and still requires a fresh draw, and a partial re-draw of only the fixtures
  the checker names is not available, because the report's aggregates are
  corpus-wide.

## Standing invariants

### INV-1 — Model review and other perceptible waits MUST surface live progress
area: ["src/reviewer/**/*.ts", "src/progress/**/*.ts", "src/approval/**/*.ts"]
gate_test: tests/integration/progress.test.ts
threshold: 3
rationale: A permission request blocked on a provider call without status appears
  hung. The TUI must show the active review and its terminal outcome.

## Project-specific invariants

### INV-2 — Uncertainty MUST preserve the native human decision path
area: ["src/approval/**/*.ts", "src/parser/**/*.ts", "src/policy/**/*.ts", "src/plugin.ts"]
gate_test: tests/integration/fail-closed-to-auto.test.ts
threshold: 3
rationale: A parser error, unsupported construct, timeout, provider failure, plugin
  failure, or race must never become an automatic approval or suppress OpenCode's
  pending manual prompt.

### INV-3 — Every automatic approval MUST receive a successful model review
area: ["src/approval/**/*.ts", "src/reviewer/**/*.ts", "src/policy/**/*.ts"]
gate_test: tests/integration/ambiguous-review.test.ts
threshold: 3
rationale: Shell effects and interpreter behavior are too broad for a finite local
  allowlist. Deterministic policy may force manual handling but cannot grant access.

### INV-4 — Suspected secrets MUST NOT cross the reviewer or logging boundary
area: ["src/privacy/**/*.ts", "src/reviewer/**/*.ts", "src/audit/**/*.ts"]
gate_test: tests/security/secret-boundary.test.ts
threshold: 3
rationale: Commands may contain credentials or expanded secret references. A
  secret-bearing request remains manual and its sensitive bytes are not persisted.

### INV-5 — Automatic permission replies MUST always be one-shot
area: ["src/approval/**/*.ts", "src/opencode/**/*.ts"]
gate_test: tests/integration/one-shot-reply.test.ts
threshold: 3
rationale: Persistent `always` rules bypass evaluation of later occurrences and
  can outlive the context that made an earlier command safe.

### INV-6 — The model reviewer MUST have no executable or data-access tools
area: ["src/reviewer/**/*.ts", "src/config/**/*.ts", "src/plugin.ts"]
gate_test: tests/security/reviewer-isolation.test.ts
threshold: 3
rationale: A classifier that can run commands, read files, or invoke network tools
  can recurse into permissions, leak data, or mutate the environment it judges.

### INV-7 — Model-backed approval release MUST be blocked by any qualification failure
area: ["tests/eval/**/*.ts", "fixtures/eval/**/*.json", "scripts/classifier-gate.ts", "scripts/qualification/**/*.ts"]
gate_test: tests/eval/classifier-gate.test.ts
threshold: 3
rationale: Model quality is an empirical dependency. Any failed qualification
threshold, including benign or ambiguity disagreement limits, dangerous false
approval, secret disclosure, schema failure, or non-fail-closed error blocks
enabling or releasing model-backed automatic approval. A source release is safe
only while the immutable qualification lock remains disabled. Staleness of an
existing receipt may be established either by the candidate source manifest or,
per the 2026-08-26 owner decision, by `qualify:routing-check` reporting all three
digests identical; the latter attests only that no measured fixture's experiment
changed, never that untested behavior is unchanged.

### INV-9 — A release artifact MUST accurately name the authority that produced it
area: ["scripts/qualification/machine-authority.ts", "scripts/qualification/machine-release.ts", "scripts/qualification/release-corpus.ts"]
gate_test: tests/eval/machine-release.test.ts
threshold: 3
rationale: Qualification recognizes three corpus authorities: `automated-draft`
(structural rehearsal, never release eligible), `machine-adjudicated` (a model
authored and labeled the corpus), and `human-adjudicated` (independent human
author, adjudicator, and custodian). Owner decision, 2026-08-14: release may
proceed on the machine authority without hand authorship. The safety property
that survives is not human review but honest labeling — no artifact may claim
an authority it does not have. A machine-adjudicated corpus therefore carries a
required, signature-covered disclosure that no human authored, adjudicated, or
attested it, and its signature attests byte integrity only. Nothing on the
machine path can emit a `human-adjudicated` artifact, and altering the
disclosure invalidates the signature. What a machine run does establish is
narrower than the human path: the corpus author is independent of the
classifier under test, but a single labeler means corpus label errors are not
independently caught.

### INV-8 — Pre-execution replan MUST be fixed-feedback, bounded, and manual-dominant
area: ["src/replan/**/*.ts", "src/policy/**/*.ts", "src/plugin.ts"]
gate_test: tests/integration/replan-guard.test.ts
threshold: 3
rationale: The opt-in replan path may interrupt an eligible Bash tool before
permission or execution, but it has no permission-reply or reviewer capability.
The exactly-six-identity static guidance catalog, a three-block generation
budget, duplicate/stale handling, exact-runtime activation, and native-prompt
fallthrough on ambiguity or error prevent the correction signal from becoming
an execution bypass. Read-only decomposition carries only bounded returned text
through sequential native calls and never recreates a pipeline in Bash.
Current static feedback never captures goal context or runtime values.
Goal-aware redirection was not implemented before retirement.
