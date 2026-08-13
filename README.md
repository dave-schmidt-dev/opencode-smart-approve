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

The MVP implementation is present. The latest source-current development draw
completed all 475 invocations as `development-pass`: 225 valid provider calls,
475 classifier observations, and zero invalid runs. The private release branch
has not been created because no fresh human-authored corpus,
independently bound adjudicator, or human custodian is present. The plugin
remains fail-closed with model-backed automatic approval disabled by an
immutable release gate.

The six identity-specific replan micro-plans are static, disabled-default
guidance for blocked shell attempts; their presence is not qualification
evidence. The 42-scenario usefulness result is
directional only; it is not qualification evidence and does not enable
model-backed approval or auto-approval.

Replan requires an explicit `replan.enabled: true` owner opt-in; installation
does not set it. It can block only `awk`, `xargs`, `find`, `env`, `command`, or
`cmp`, and only three distinct blocked calls per user-message generation. It
then falls through to OpenCode's native Bash permission prompt. Replan never
executes or rewrites a command, replies to a permission request, or guarantees
task completion.

Static prompt tuning is stopped. The current enriched catalog is retained;
the compact-catalog candidate remains test-only and was not promoted. Goal-aware
or goal-specific redirection is owner-authorized future work, not implemented in
this build. Any future extension must remain pre-execution and preserve the
boundaries above: it must not execute or rewrite commands, reply to permission
requests, or approve them.

## Installation and removal

This repository is not published to npm. A local checkout may be linked from the
global OpenCode plugin loader for evaluation; keep native `bash: ask` enabled.
`model.enabled=true` cannot enable automatic approvals in this release. Remove the
loader entry to restore stock OpenCode; no session-data edit is required. OpenCode
1.18.10 is the tested compatibility target, not a model qualification. DeepSeek V4
Flash remains a candidate reviewer until the attended private release branch and
human custody attestation pass.

## Development verification

The disposable OpenCode checks use the pinned local `opencode-ai@1.18.10` binary
by default. They isolate config, data, state, and cache under a temporary root and
fail closed when an explicit `OPENCODE_BIN` reports any other version. Run the
offline checks with `bun run check`; run the attended exact-runtime checks with
`bun run test:e2e`. The separate attended `bun run qualify:development` command
produces the source-current aggregate development report but cannot enable
approval. Private release evaluation requires the separate human-custodian
workflow and is not run by the development command.
These checks do not install the plugin globally or enable model-backed approval.
The attended command requires `OPENCODE_AUTH_PATH` to point to the existing
OpenCode auth file; pass the path only, never credential contents.

The active evaluator reads only `fixtures/eval/development.json`; the historical
combined corpus is diagnostic-only. v3 artifacts bind source, configuration,
threshold, runtime, requested alias/variant, rubric, and custody-schema hashes as
staleness checks. They explicitly do not attest immutable model revision or served
variant. Private release evaluation is a human-custodian, one-use in-memory stream
operation and public verification is not independently recomputable.

After the offline evidence phase, the native candidate boundary is explicit:
`bun run scripts/classifier-gate.ts --freeze-candidate eval-results/frozen-candidate-manifest.json`
creates the sole source-current candidate, and `--validate-candidate` checks it.
Neither command reads the private release stream or enables model approval.

The automated fresh-corpus rehearsal is deliberately non-authoritative:
`bun run scripts/qualification/generate-release-draft.ts <candidate-manifest-hash>`
writes a mode-600 95-fixture draft plus six generalization fixtures marked
`releaseEligible: false`. `scripts/qualification/release-operator.ts` is the
attended wrapper for a later human-adjudicated corpus: it requires a signed
human attestation bound to the corpus, roles, timestamps, and candidate; checks
the source-current development report; pins the adjudicator ID and public key
to a custodian-supplied out-of-band binding; verifies the signed exact-byte
digest; spends custody before opening private input; emits a qualifying
heartbeat; rejects drafts; and writes only a strict aggregate. It requires an
in-process qualification callback and never manufactures human roles or a
release attestation.

The coordinator-backed parity harness is an offline contract check:
`bun test tests/eval/reviewer-contract-parity.test.ts`. It compares the
production registration and reviewer payload with the evaluation contract,
exercises negative controls, and compiles a disposable one-lock candidate
without changing this checkout. It is contract evidence only; it does not
qualify or enable model-backed approval.

The current release checkpoint is recorded in
`eval-results/qualification-release-gate.md`. The development result is an
aggregate `development-pass` receipt; release remains disabled because the
fresh human corpus, independent labels, custodian receipt, and countersignature
are absent.

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
