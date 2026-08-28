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
- Require a qualified model-profile review for every automatic approval.
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

The MVP implementation is present. The plugin remains fail-closed, with
model-backed automatic approval disabled by an immutable release gate.

No source-current `development-pass` receipt exists. This document quotes no
candidate hash. `eval-results/` is not committed, so a hash written into
committed prose cannot be checked by a reader or by a gate; read current state
from the tools instead. `bun run scripts/classifier-gate.ts --validate-candidate
eval-results/frozen-candidate-manifest.json` prints the current freeze and exits
non-zero once it no longer matches source, and `--validate-development-report
<report> --candidate <manifest>` reports whether a receipt is still bound to it.

No development draw has been run against the freeze on disk. Whether that
freeze still matches source is not recorded here: it goes stale the moment any
file in its source manifest changes, so a verdict written into this document is
true only until the next commit. Run `--validate-candidate` for the answer. The development report beside it is a
failed MiMo V2.5 A/B comparison (`stop-disabled` / `invalid_run`, 164 of 475
runs invalid) bound to an earlier candidate. Earlier development receipts are
not recoverable: `qualify:development` and `qualify:live` both write the single
fixed path `eval-results/development-candidate-report.json`, and
`--freeze-candidate` likewise overwrites one fixed manifest path, so each new
draw or freeze destroys its predecessor. `eval-results/` is gitignored, so there
is no second copy. Re-running the development draw against the current freeze is
the next qualification step.

Release is blocked on classifier evidence, not on authorship. An owner decision
of 2026-08-14 (INV-9) accepts a `machine-adjudicated` corpus for release so long
as the artifact honestly names the authority that produced it, so a
human-authored corpus, an independently bound human adjudicator, and a human
custodian are no longer preconditions. Two machine-adjudicated release draws
have been spent, and the most recent returned `machine-release-fail`.

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
1.18.10 is the tested compatibility target, not a model qualification. DeepSeek
V4 Flash remains the disabled production default. `src/reviewer/model-profile.ts`
is the single registry for production and qualification identities; MiMo V2.5 is
available as an A/B candidate and omits `variant` because OpenCode Go exposes no
selectable variant for it.

## Development verification

The disposable OpenCode checks use the pinned local `opencode-ai@1.18.10` binary
by default. They isolate config, data, state, and cache under a temporary root and
fail closed when an explicit `OPENCODE_BIN` reports any other version. Run the
offline checks with `bun run check` (typecheck, the offline suite, and the
package check); run the attended exact-runtime checks with `bun run test:e2e`.
`bun run spec:guard` verifies that `SPEC.md`, `TRACEABILITY.md`, and
`INVARIANTS.md` still agree on requirements, tasks, and invariants.
The separate attended `bun run qualify:development` command
produces the source-current aggregate development report but cannot enable
approval. Private release evaluation requires the separate human-custodian
workflow and is not run by the development command.
These checks do not install the plugin globally or enable model-backed approval.
The attended command requires `OPENCODE_AUTH_PATH` to point to the existing
OpenCode auth file; pass the path only, never credential contents.

The active evaluator reads only `fixtures/eval/development.json`; the historical
combined corpus is diagnostic-only. Current v4 qualification artifacts bind source, configuration,
threshold, runtime, selected model profile, rubric, and custody-schema hashes as
staleness checks. They explicitly do not attest immutable model revision or served
variant. Private release evaluation is a human-custodian, one-use in-memory stream
operation and public verification is not independently recomputable.

After the offline evidence phase, the native candidate boundary is explicit:
`bun run scripts/classifier-gate.ts --freeze-candidate eval-results/frozen-candidate-manifest.json`
creates the sole source-current candidate, and `--validate-candidate` checks it.
Add `--model-profile mimo-v2.5` to the freeze command for the MiMo A/B candidate;
later validation and live qualification infer that frozen profile automatically.
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

The machine-adjudicated path is the one INV-9 permits for release, and it is
separate from the human wrapper above. `scripts/qualification/harvest-usage.ts`
sources the benign stratum from real local agent session history rather than
model invention, keeping only commands the reviewer prompt's own allow paragraph
instructs the model to allow. `scripts/qualification/author-machine-corpus.ts`
authors the remaining strata against a named candidate manifest and writes the
corpus bound to it. `scripts/qualification/machine-release.ts` draws it once,
taking optional `--candidate <manifest>` and `--development-report <report>`
paths (both default to the canonical artifacts); it validates the source-current
candidate and requires a bound `development-pass` before custody work. It spends
custody before opening private input, so an interrupted run cannot be re-drawn
for a better result. Authoring writes `${outputPath}.digest.json` automatically;
the public companion records only the candidate binding and SHA-256 identity of
the exact corpus bytes. Release validates that companion before custody, then
checks the private bytes against it after spending. `scripts/qualification/machine-authority.ts`
holds the authority labels and the signed provenance, including `commandSource`,
which records per-stratum whether a command was authored or harvested.
`scripts/qualification/measure-routing.ts` reports what share of real executions
reach the reviewer at all. None of these enables model approval; a passing draw
is a precondition for flipping the gate, not the flip itself.

The machine path is rehearsed offline before it is ever run for real.
`tests/eval/machine-release-rehearsal.test.ts` drives `runMachineRelease`
itself -- runtime preflight, the pre-spend provider probe, custody, corpus
validation, the digest companion, observed-route checking, blinding, the
concurrent draw loop, the real reviewer agent and its schema parsing, the abort
guards, transport-fault capture, scoring against the shipped thresholds and the
artifact write -- against a scripted session client from
`scripts/qualification/rehearsal.ts`. The single stubbed seam is `DrawTransport`,
the boundary a live model call sits behind, so a rehearsal exercises the harness
and says nothing whatever about the classifier. This exists because three
consumptions of a one-use release corpus were spent discovering harness defects,
which is the most expensive possible place to find them. A rehearsal artifact is
marked three independent ways -- a `machine-release-rehearsal/v1` schema, an
`executionMode: "rehearsal"` field, and a filename prefix the writer enforces --
and `bun run spec:guard` rejects any committed document that cites one.

Both release paths require a source-current `development-pass` report bound to
the same candidate and reject `stop-disabled` or stale reports. The machine path
performs this validation before ledger initialization/spend and before reading
the private corpus; its separate binding check proves that the corpus and frozen
manifest name the same candidate.

The coordinator-backed parity harness is an offline contract check:
`bun test tests/eval/reviewer-contract-parity.test.ts`. It compares the
production registration and reviewer payload with the evaluation contract,
exercises negative controls, and compiles a disposable one-lock candidate
without changing this checkout. It is contract evidence only; it does not
qualify or enable model-backed approval.

The current release checkpoint is recorded in
`eval-results/qualification-release-gate.md`. `eval-results/` is not committed,
so a fresh clone carries the commands that produce these artifacts but none of
the artifacts themselves. The development report currently on disk is a failed
A/B comparison, not a `development-pass` receipt; release remains disabled
because no release draw has returned `machine-release-pass` and no source-current
development pass is bound to the current freeze.

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
