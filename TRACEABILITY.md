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
