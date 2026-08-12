# Requirement traceability

This release map is separate from the local-only task queue and history.

| Task | Requirements | Tests |
| --- | --- | --- |
| TASK-001 | REQ-001, REQ-007 | tests/unit/permission-event.test.ts; tests/integration/one-shot-reply.test.ts; tests/integration/approval-flow.test.ts; tests/e2e/opencode-contract-canary.test.ts |
| TASK-002 | REQ-002, REQ-003 | tests/unit/shell-policy.test.ts; tests/integration/fail-closed-to-auto.test.ts |
| TASK-003 | REQ-004, REQ-005 | tests/integration/ambiguous-review.test.ts; tests/security/reviewer-isolation.test.ts; tests/e2e/opencode-contract-canary.test.ts |
| TASK-004 | REQ-006 | tests/security/secret-boundary.test.ts |
| TASK-005 | REQ-008 | tests/integration/progress.test.ts; tests/e2e/opencode-contract-canary.test.ts |
| TASK-006 | REQ-009 | tests/unit/config.test.ts; tests/unit/shell-policy.test.ts |
| TASK-007 | REQ-010 | tests/security/audit-redaction.test.ts |
| TASK-008 | REQ-011 | tests/eval/classifier-gate.test.ts |
| TASK-009 | REQ-012 | tests/package/package.test.ts; tests/spec/traceability.test.ts; tests/e2e/opencode-1.18.10.test.ts |
| TASK-010 | REQ-013 | tests/spec/traceability.test.ts |
| TASK-011 | REQ-014 | tests/unit/config.test.ts; tests/unit/shell-policy.test.ts; tests/unit/replan-guidance.test.ts; tests/integration/replan-guard.test.ts; tests/integration/fail-closed-to-auto.test.ts; tests/integration/progress.test.ts; tests/security/audit-redaction.test.ts; tests/e2e/opencode-contract-canary.test.ts; tests/e2e/opencode-1.18.10.test.ts |

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
