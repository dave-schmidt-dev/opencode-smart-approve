# OpenCode Smart Approve

OpenCode Smart Approve is a TypeScript plugin that automatically answers
OpenCode shell permission requests only when a command is demonstrably safe. It
keeps OpenCode's native `bash: ask` posture, replies with `once`, and leaves the
ordinary human prompt in place whenever parsing, policy, model review, or plugin
execution is uncertain.

## MVP implementation status

- Target OpenCode 1.18.10 first.
- Handle shell (`bash`) permission requests only.
- Parse commands before classification; never classify from regexes alone.
- Use deterministic parsing and policy only to force manual handling or prepare a
  bounded reviewer input; deterministic logic never grants permission in the MVP.
- Require a qualified DeepSeek V4 Flash review for every automatic approval.
- Never transmit suspected secrets to the reviewer.
- Display review progress and use a configurable 30-second timeout.
- Reply `once` only; every future occurrence is evaluated again.

The plugin is an application-level policy layer, not an operating-system sandbox.
OpenCode, its configured provider, and other loaded plugins remain trusted.

## Authoritative documents

- `SPEC.md` defines requirements and locked MVP decisions.
- `TRACEABILITY.md` maps requirements to implementation tasks and concrete tests.
- `INVARIANTS.md` defines contracts every future change must preserve.
- `ledger.yaml` records invariant gate coverage.

The MVP implementation is present, but the model qualification gate failed. The
plugin remains fail-closed with model-backed automatic approval disabled by an
immutable release gate. The failed report is retained locally under the
gitignored `eval-results/` directory; it is not qualification evidence.

## Installation and removal

This repository is not published to npm. A local checkout may be linked from the
global OpenCode plugin loader for evaluation; keep native `bash: ask` enabled.
`model.enabled=true` cannot enable automatic approvals in this release. Remove the
loader entry to restore stock OpenCode; no session-data edit is required. OpenCode
1.18.10 is the tested compatibility target, not a model qualification. DeepSeek V4
Flash remains a candidate reviewer until every qualification threshold passes.

## Development verification

The disposable OpenCode checks use the pinned local `opencode-ai@1.18.10` binary
by default. They isolate config, data, state, and cache under a temporary root and
fail closed when an explicit `OPENCODE_BIN` reports any other version. Run the
offline checks with `bun run check`; run the attended exact-runtime checks with
`bun run test:e2e`. The separate attended `bun run qualify:live` command produces
qualification evidence but cannot enable approval unless every locked gate passes.
These checks do not install the plugin globally or enable model-backed approval.

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
