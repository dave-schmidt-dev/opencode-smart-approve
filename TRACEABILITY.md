# Requirement traceability

This release map is separate from the local-only task queue and history.

| Task | Requirements | Tests |
| --- | --- | --- |
| TASK-001 | REQ-001, REQ-007 | tests/unit/permission-event.test.ts; tests/integration/one-shot-reply.test.ts; tests/integration/approval-flow.test.ts; tests/e2e/opencode-contract-canary.test.ts |
| TASK-002 | REQ-002, REQ-003 | tests/unit/shell-policy.test.ts; tests/integration/fail-closed-to-auto.test.ts; tests/spec/traceability.test.ts |
| TASK-003 | REQ-004, REQ-005 | tests/integration/ambiguous-review.test.ts; tests/security/reviewer-isolation.test.ts; tests/e2e/opencode-contract-canary.test.ts |
| TASK-004 | REQ-006 | tests/security/secret-boundary.test.ts |
| TASK-005 | REQ-008 | tests/integration/progress.test.ts; tests/e2e/opencode-contract-canary.test.ts |
| TASK-006 | REQ-009 | tests/unit/config.test.ts; tests/unit/shell-policy.test.ts |
| TASK-007 | REQ-010 | tests/security/audit-redaction.test.ts |
| TASK-008 | REQ-011 | tests/eval/classifier-gate.test.ts; tests/eval/qualification-custody.test.ts; tests/eval/qualification-terminal.test.ts; tests/eval/release-corpus.test.ts; tests/eval/release-operator.test.ts; tests/eval/reviewer-contract-parity.test.ts; tests/integration/progress.test.ts; tests/spec/traceability.test.ts |
| TASK-009 | REQ-012 | tests/package/package.test.ts; tests/spec/traceability.test.ts; tests/e2e/opencode-1.18.10.test.ts |
| TASK-010 | REQ-013 | tests/spec/traceability.test.ts |
| TASK-011 | REQ-014 | tests/unit/config.test.ts; tests/unit/shell-policy.test.ts; tests/unit/replan-guidance.test.ts; tests/integration/replan-guard.test.ts; tests/integration/fail-closed-to-auto.test.ts; tests/integration/progress.test.ts; tests/security/audit-redaction.test.ts; tests/e2e/opencode-contract-canary.test.ts; tests/e2e/opencode-1.18.10.test.ts |

## REQ-011 selector evidence

- Observed safety-routing selector (100% manual): `tests/eval/classifier-gate.test.ts` :: `observed safety-routing error fixtures stay manual with integer REQ-011 accounting`
- Mandatory mechanical-fault selector: `tests/eval/classifier-gate.test.ts` :: `fault injection has mandatory invalid-run accounting and no shared latency identifiers`

The locked sample gate remains 40 benign, 15 dangerous, 10 ambiguous, 10
injection, 10 secret, and 10 obfuscated/syntax fixtures; five repeats at
temperature zero; 30-second timeout; 10-second p95; 2% other-repeat limit.
Requested alias drift remains an accepted residual risk because the manifest is
staleness-only and explicitly does not attest immutable model revision or served
variant.

The fixed-candidate selector is `tests/eval/classifier-gate.test.ts` :: `freezes one source-current candidate with no provider or held-out attestation`; it covers the singular candidate, current hashes, unavailable provider/served-variant status, and empty spent-heldout arrays.

## Current qualification recovery evidence

The source-current development terminal report is validated by
`scripts/classifier-gate.ts` and bound to
`eval-results/frozen-candidate-manifest.json`. Its aggregate-only contract and
invalid-run/no-retry behavior are covered by
`tests/eval/classifier-gate.test.ts`. The failure-only no-corpus terminal branch
is covered by `tests/eval/qualification-terminal.test.ts` and implemented in
`scripts/qualification/verify-terminal.ts`; it remains available for failed
development draws, while the current source-current draw is `development-pass`.
Fresh draft generation, cryptographic human-envelope and
out-of-band adjudicator-key validation, and attended custody ordering
are covered by `tests/eval/release-corpus.test.ts` and
`tests/eval/release-operator.test.ts`. The exact-runtime candidate lock canary
and production/evaluation parity are covered by
`tests/eval/reviewer-contract-parity.test.ts`.
The release checkpoint is recorded in
`eval-results/qualification-release-gate.md`; it is `release-disabled` pending
fresh private corpus authorship, independent adjudication, and human custody.

## INV-7 runner evidence

`INVARIANTS.md` contains exactly one INV-7 gate mapping to
`tests/eval/classifier-gate.test.ts`; `package.json` contains exactly one
`test:offline` runner entry for that selector. Custody, source-manifest, and
fault evidence remain subordinate to that release lock.

## INV-8 evidence map

`REQ-014` and `INV-8` are jointly evidenced by policy classification in
`tests/unit/shell-policy.test.ts`, the exactly-six static guidance catalog in
`tests/unit/replan-guidance.test.ts`, pre-execution guard and native-fallthrough
coverage in `tests/integration/replan-guard.test.ts`, privacy-safe audit coverage
in `tests/security/audit-redaction.test.ts`, bounded progress coverage in
`tests/integration/progress.test.ts`, and pinned-runtime proof in
`tests/e2e/opencode-contract-canary.test.ts` and
`tests/e2e/opencode-1.18.10.test.ts`. No replan evidence may map to a permission
reply path.

The evidence map covers the implemented static catalog only. Owner-authorized
goal-aware redirection is future work, not implemented by this release; any
future extension must preserve pre-execution operation and must not execute or
rewrite commands, reply to permission requests, or approve them.
