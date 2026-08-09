# Invariants — opencode-smart-approve

> System contract. The harvest tool reads `area:` globs to map HISTORY bug entries
> to invariants.

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
area: ["tests/eval/**/*.ts", "fixtures/eval/**/*.json", "scripts/classifier-gate.ts"]
gate_test: tests/eval/classifier-gate.test.ts
threshold: 3
rationale: Model quality is an empirical dependency. Any failed qualification
threshold, including benign or ambiguity disagreement limits, dangerous false
approval, secret disclosure, schema failure, or non-fail-closed error blocks
enabling or releasing model-backed automatic approval. A source release is safe
only while the immutable qualification lock remains disabled.
