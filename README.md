# OpenCode Smart Approve

OpenCode Smart Approve is a TypeScript plugin that automatically answers
OpenCode shell permission requests only when a command is demonstrably safe. It
keeps OpenCode's native `bash: ask` posture, replies with `once`, and leaves the
ordinary human prompt in place whenever parsing, policy, model review, or plugin
execution is uncertain.

## MVP

- Target OpenCode 1.18.10 first.
- Handle shell (`bash`) permission requests only.
- Parse commands before classification; never classify from regexes alone.
- Use deterministic parsing and policy only to force manual handling or prepare a
  bounded reviewer input; deterministic logic never grants permission in the MVP.
- Require DeepSeek V4 Flash review for every automatic approval.
- Never transmit suspected secrets to the reviewer.
- Display review progress and use a configurable 30-second timeout.
- Reply `once` only; every future occurrence is evaluated again.

The plugin is an application-level policy layer, not an operating-system sandbox.
OpenCode, its configured provider, and other loaded plugins remain trusted.

## Authoritative documents

- `SPEC.md` defines requirements and locked MVP decisions.
- `TASKS.md` maps implementation work to requirements and concrete tests.
- `INVARIANTS.md` defines contracts every future change must preserve.
- `ledger.yaml` records invariant gate coverage.

Implementation is complete. `HISTORY.md` records the verified MVP delivery; the
local planning record remains outside the repository.

## Installation and removal

Install from a package reference or symlink in your global OpenCode plugin loader;
keep native `bash: ask` enabled. Set `model.enabled=false` and restart OpenCode to
disable automatic approvals. Remove the loader entry to restore stock OpenCode;
no session-data edit is required. Support is qualified for OpenCode 1.18.10 only.
The DeepSeek reviewer remains a mandatory, empirically qualified model gate.

## Verified OpenCode boundary

OpenCode 1.18.10 publishes `permission.asked` events and accepts
`client.permission.reply({ requestID, reply: "once" })`. The separately declared
`permission.ask` plugin hook is not invoked by the 1.18.10 permission path, so the
MVP uses the event hook. The runtime event is newer than the generated plugin SDK
event union and must be validated at runtime.

Primary references:

- [OpenCode plugin documentation](https://opencode.ai/docs/plugins/)
- [OpenCode 1.18.10 permission schema](https://github.com/anomalyco/opencode/blob/v1.18.10/packages/schema/src/v1/permission.ts)
- [OpenCode 1.18.10 permission service](https://github.com/anomalyco/opencode/blob/v1.18.10/packages/opencode/src/permission/index.ts)
- [OpenCode 1.18.10 shell tool](https://github.com/anomalyco/opencode/blob/v1.18.10/packages/opencode/src/tool/shell.ts)
- [OpenCode 1.18.10 plugin runtime](https://github.com/anomalyco/opencode/blob/v1.18.10/packages/opencode/src/plugin/index.ts)
