# SPEC: OpenCode Smart Approve

Status: implemented MVP
PlanningTier: impulse
Target: OpenCode 1.18.10 on macOS and Linux
License: MIT

## 1. Purpose

OpenCode Smart Approve reduces repetitive shell approval prompts without weakening
OpenCode's native permission boundary. It automatically replies to a pending shell
permission only when a mandatory constrained model review supports approval.
Deterministic parsing and policy may force manual handling but never grant permission
in the MVP. Every uncertain outcome remains an ordinary human choice.

## 2. MVP audience and outcome

The MVP is for a developer running OpenCode interactively who wants Codex- or
Claude-like safe-command automation. Success means routine low-risk commands proceed
without user action, every candidate command is reviewed by DeepSeek V4 Flash, and no
error path can turn into an automatic approval.

## 3. Scope

### In scope

- OpenCode `permission.asked` events whose `permission` is `bash`.
- Bash-compatible syntax parsing and conservative effect classification.
- Deterministic parser/privacy hard blocks with no local auto-allow tier.
- Mandatory model review for every command eligible for auto-approval.
- One-shot permission replies, progress display, bounded audit records, and tests.
- Personal global installation first, packaged so public npm publication remains
  possible after release approval.

### Out of scope

- File-edit, MCP, browser, network, task, or external-directory permissions.
- Automatic persistent (`always`) approvals.
- Automatic rejection of commands; unsafe or uncertain means the user decides.
- Operating-system sandboxing or containment of OpenCode itself.
- Learning rules from approval history.
- Ralph-loop or other unattended implementation automation.
- Windows/PowerShell support in the MVP.

## 4. End-to-end flow

1. OpenCode emits `permission.asked` and keeps its native prompt pending.
2. The plugin validates the runtime payload and ignores non-`bash` permissions.
3. The command is scanned for secrets before any provider-bound operation.
4. A Bash parser produces an AST and a bounded feature summary.
5. Deterministic policy returns `model_review` or `manual`; it cannot approve.
6. `manual` sends no reply, leaving the native prompt available.
7. `model_review` displays progress and asks a tool-free reviewer session to return
   a strict structured verdict within the configured timeout.
8. Only a valid model `allow` replies `once`; every other result remains manual.
9. A later occurrence is evaluated again. The user is not asked to act when that
    new evaluation succeeds.

## 5. Decision state machine

`RECEIVED -> IGNORED | PRIVACY_BLOCKED | PARSE_FAILED | POLICY_MANUAL |
REVIEWING`

- `REVIEWING -> REVIEW_ALLOWED -> REPLY_ONCE -> COMPLETE`
- `REVIEWING -> REVIEW_MANUAL | REVIEW_TIMEOUT | REVIEW_ERROR -> COMPLETE`
- `PRIVACY_BLOCKED | PARSE_FAILED | POLICY_MANUAL -> COMPLETE`
- Any duplicate, late, or losing reply attempt -> `STALE -> COMPLETE`

`COMPLETE` means the plugin has stopped processing. It does not imply that the
shell command executed; manual states leave that decision with OpenCode and the user.

## 6. Functional requirements

### REQ-001: Runtime permission integration

- Type: Functional
- Priority: P0
- Description: Consume the actual OpenCode 1.18.10 permission event and preserve
  the native prompt until a one-shot approval succeeds.
- Acceptance criteria:
  - [ ] Runtime validation accepts the documented `permission.asked` request shape.
  - [ ] Only requests with `permission === "bash"` enter classification.
  - [ ] The command is read only from `metadata.command` when it is a string.
  - [ ] A tagged-source contract test proves that the same command value passed to
    the permission ask is passed to the shell process without rewrite or truncation.
  - [ ] The plugin never configures global `bash: allow`.
  - [ ] No implementation path depends on the unwired `permission.ask` hook.

### REQ-002: Parsed deterministic hard blocks

- Type: Security
- Priority: P0
- Description: Parse complete command text and classify from explicit syntax and
  policy facts rather than regex matching alone; this layer cannot approve.
- Acceptance criteria:
  - [ ] `web-tree-sitter` with the Bash grammar parses the entire command.
  - [ ] Parse errors, missing nodes, control characters, unsupported nodes, and
    exceeded size/depth/segment limits return `manual`.
  - [ ] Command substitutions, process substitutions, backticks, `eval`, `exec`,
    `source`, functions, loops, heredocs, redirects, and unresolved expansions do
    return `manual` or `model_review`, never approval.
  - [ ] Command-prefix environment assignments and configuration-driven execution
    features are included in the risk summary or return `manual`.
  - [ ] Non-Bash interpreter detection, unknown shell semantics, symlinks, `..`
    traversal, and unresolved path identity return `manual`.

### REQ-003: No deterministic permission grant

- Type: Functional
- Priority: P1
- Description: Preserve useful hard-block analysis without claiming a finite local
  allowlist can safely authorize shell execution.
- Acceptance criteria:
  - [ ] No parser, policy, executable, subcommand, flag, operand, or path predicate
    can directly call the OpenCode approval adapter.
  - [ ] Sensitive path patterns (`.env*`, credentials, keychains, SSH/GPG material,
    auth databases, and configured additions) return `manual`.
  - [ ] Commands not blocked by privacy, parser, interpreter, or ownership checks
    return `model_review` regardless of executable name.
  - [ ] Native OpenCode pattern rules are documented as an optional user-managed
    optimization but are not created or modified by the plugin.
  - [ ] The architecture record explains that native prefix/source patterns cannot
    supply complete syntax features, secret redaction, mandatory model judgment,
    or progress; an allow pattern would bypass INV-3, while an ask pattern leaves
    the plugin's structured review work necessary.

### REQ-004: Mandatory automatic-approval review

- Type: Security
- Priority: P0
- Description: Every command eligible for auto-approval must receive a successful
  model review.
- Acceptance criteria:
  - [ ] Default reviewer is `opencode-go/deepseek-v4-flash`, variant `max`.
  - [ ] Reviewer model, provider, variant, and timeout are configurable.
  - [ ] Reviewer receives only the redacted command representation, parser feature
    summary, policy facts, and project/external path classes.
  - [ ] Reviewer returns schema-validated JSON with decision `allow` or `manual`
    and enumerated reason codes.
  - [ ] Empty, malformed, truncated, uncertain, inconsistent, or provider-error
    output returns `manual`.
  - [ ] Every automatic approval has one matching valid model `allow` result.
  - [ ] No model response can override a deterministic `manual` result.

### REQ-005: Reviewer isolation and lifecycle

- Type: Security
- Priority: P0
- Description: Model classification runs outside the blocked parent session with
  no tools or environmental access.
- Acceptance criteria:
  - [ ] A dedicated child session uses an internal agent whose permission default
    is deny and whose executable, filesystem, MCP, web, and task tools are disabled.
  - [ ] The permission event handler starts classification asynchronously and does
    not block OpenCode's event bridge.
  - [ ] Reviewer session creation, prompt, result extraction, abort, and deletion
    are bound to the exact request ID and session IDs created by the plugin.
  - [ ] Timeout aborts and deletes the reviewer session before returning `manual`.
  - [ ] Recursive permission events from reviewer-owned sessions are immediately
    replied to with `reject`; their parent command remains manual.
  - [ ] The detached event callback catches every synchronous and asynchronous
    exception, records a bounded reason code, and sends no approval reply.

### REQ-006: Secret boundary

- Type: Security
- Priority: P0
- Description: Commands suspected of containing secrets remain manual without a
  provider call.
- Acceptance criteria:
  - [ ] Detection covers credential-like variable names, common token/key formats,
    secret-bearing CLI flags, sensitive files, and configured patterns.
  - [ ] A canary secret test proves zero matching bytes in model requests, progress
    messages, audit records, errors, and snapshots.
  - [ ] Environment values and file contents are never read for classification.
  - [ ] Secret detection failure returns `manual`.

### REQ-007: One-shot concurrency semantics

- Type: Correctness
- Priority: P0
- Description: Automatic approval is idempotent, request-scoped, and race-safe.
- Acceptance criteria:
  - [ ] The only automatic reply is `{ reply: "once" }` for the exact request ID.
  - [ ] `always` is unreachable from plugin decision code; `reject` is used only
    to terminate permission requests owned by the isolated reviewer session.
  - [ ] In-flight work is deduplicated by request ID.
  - [ ] If the user answers first, the plugin treats OpenCode's not-found response
    as a stale race and performs no retry.
  - [ ] Late model results cannot approve a completed or different request.

### REQ-008: Visible bounded progress

- Type: Usability
- Priority: P0
- Description: A user can see when and why automatic review is waiting.
- Acceptance criteria:
  - [ ] Model review immediately shows an informational TUI status containing a
    redacted command summary and `Reviewing command`.
  - [ ] Approval shows a short success status; timeout, model error, or manual
    outcome shows that the native prompt remains available.
  - [ ] Status remains visible for the full review and refreshes at least every
    10 seconds while the request is pending.
  - [ ] Default timeout is 30 seconds and configuration accepts 10–60 seconds only
    after the OpenCode pending-request lifetime canary passes at both bounds.
  - [ ] Progress delivery failure does not alter the approval decision.

### REQ-009: Configuration and policy

- Type: Functional
- Priority: P1
- Description: Configuration is explicit, validated, and incapable of silently
  widening hard safety boundaries.
- Acceptance criteria:
  - [ ] Only global configuration is supported in the MVP; project configuration
    is never loaded.
  - [ ] Unknown keys, invalid enum values, and out-of-range limits fail startup
    validation and leave OpenCode's native permissions unchanged.
  - [ ] User rules can request `model_review` or `manual` but cannot grant approval.
  - [ ] `model.enabled=false` is valid and routes every request to manual handling
    after OpenCode restarts.
  - [ ] Configuration changes require restart in the MVP.

### REQ-010: Privacy-preserving audit trail

- Type: Quality
- Priority: P1
- Description: Decisions are diagnosable without retaining raw commands or secrets.
- Acceptance criteria:
  - [ ] JSONL audit records contain timestamp, request hash, command-shape hash,
    policy/prompt/model identifiers, decision, reason codes, latency, and race state.
  - [ ] Raw command text, model prompt text, model output prose, environment values,
    and credentials are never persisted.
  - [ ] Audit logging defaults off; when enabled it uses a size-bounded rotating
    file beneath the project or explicitly configured directory.

### REQ-011: Classifier qualification gate

- Type: Quality
- Priority: P0
- Description: DeepSeek V4 Flash becomes the default only after a versioned,
  repeatable safety evaluation.
- Acceptance criteria:
  - [ ] A versioned development corpus and a disjoint held-out release corpus each
    cover benign, dangerous, ambiguous, prompt-injection, secret-bearing, and
    obfuscated/syntax categories; held-out labels are unavailable to prompt tuning.
  - [ ] Each set contains at least 40 benign, 15 dangerous, 10 ambiguous, 10 prompt-
    injection, 10 secret-bearing, and 10 obfuscated/syntax fixtures.
  - [ ] Every fixture runs five times at temperature zero; seed is used only if the
    provider supports it.
  - [ ] Development and held-out results each have zero dangerous, secret-bearing,
    injection, or critical false automatic approvals.
  - [ ] Error-path fixtures are 100% manual and leak zero canary-secret bytes.
  - [ ] Per set, benign false-manual observations are at most
    `floor(0.05 * benign_fixture_count * 5)`; the report records numerator and
    denominator as integers.
  - [ ] Critical and ambiguous fixtures have zero decision disagreements. Across
    all other repeat comparisons, disagreements are at most
    `floor(0.005 * fixture_count * 4)` per set, with integer counts reported.
  - [ ] Review latency p95 is at most 10 seconds under the 30-second hard timeout;
    latency failure blocks default-model qualification but never weakens safety.
  - [ ] Reports identify thresholds as empirical sample gates, not proof of a
    universal false-approval probability.

### REQ-012: Compatibility and packaging

- Type: Quality
- Priority: P1
- Description: Ship a reproducible plugin with an explicit OpenCode compatibility
  boundary and a recoverable installation path.
- Acceptance criteria:
  - [ ] Dependencies are pinned; `main`, `exports`, and `files` define the runtime
    entry and exclude tests, logs, fixtures, local configuration, and credentials.
  - [ ] `bun run check` is offline-only; live evaluation and OpenCode E2E each have
    separate attended scripts.
  - [ ] The bundled Bash grammar records its upstream version, source, license,
    checksum, and reproducible update procedure.
  - [ ] End-to-end tests run against the installed OpenCode 1.18.10 binary and a
    disposable isolated configuration/data directory.
  - [ ] Plugin load failure leaves `bash: ask` unchanged.
  - [ ] Installation uses a symlink or package reference that can be removed to
    restore stock OpenCode without editing session data.
  - [ ] Support for later OpenCode versions requires the same E2E gate before the
    compatibility range is widened.

### REQ-013: Spec-task-test traceability

- Type: Quality
- Priority: P0
- Description: Requirements, tasks, tests, and invariants remain aligned.
- Acceptance criteria:
  - [ ] Every `REQ-###` maps to at least one `TASK-###` in `TASKS.md`.
  - [ ] Every requirement maps to at least one concrete test selector.
  - [ ] Every invariant's gate test exists before release.
  - [ ] The final check fails when a requirement, task, test, or invariant mapping
    is missing.

## 7. Non-functional requirements

- The event callback must yield control within 50 ms before asynchronous review.
- Parser input limit: 128 KiB; nested shell depth: 8; command-segment limit: 128.
- At most one reviewer is active per permission request and four per OpenCode
  instance; excess requests remain manual.
- All network/provider calls have explicit cancellation and the configured timeout.
- Session metrics expose review count, cumulative review latency, timeout count,
  and manual-fallback count without recording command text.
- Path identity checks use metadata-only `lstat`/`realpath` operations; they never
  read file contents, and any unavailable, symlinked, or escaping path is manual.
- Logs use hashes and reason codes, never raw command content.
- Public APIs and non-obvious safety logic have docstrings/comments explaining
  the prevented failure, not restating code.

## 8. Architecture defaults

- Runtime: Bun with strict TypeScript.
- OpenCode API: `@opencode-ai/plugin` and `@opencode-ai/sdk` pinned to 1.18.10.
- Parser: `web-tree-sitter` with a bundled, checksum-verified Bash grammar WASM.
- Validation: Zod schemas at every external/runtime boundary.
- Tests: Bun unit/integration tests plus disposable OpenCode process E2E tests.
- Persistence: optional rotating JSONL audit only; no database.
- Retry policy: no automatic model retry for a permission decision. A retry could
  produce a different safety answer; the current request remains manual instead.
- Release control: only the user authorizes global installation, npm publication,
  or widening the OpenCode/model compatibility declaration.

## 9. Threat model

Protected assets are command-execution authority, workspace/user files, secrets,
and the integrity of the approval decision. Adversaries include malicious command
text, prompt injection inside arguments/comments, parser differentials, encoded or
dynamic shell syntax, compromised model output, concurrent
user/plugin replies, and another plugin in the same process.

The MVP trusts the OpenCode process, its SDK transport, the selected provider, and
the loaded parser binary. It does not claim protection from a compromised OpenCode
runtime or malicious co-plugin. Model output is untrusted data and never has direct
permission authority without schema, state, and deterministic hard-block checks.

## 10. Recovery and rollback

- A single request recovers by leaving the native prompt pending.
- A bad configuration recovers by refusing plugin activation.
- A bad model qualification recovers by disabling model-backed auto-approval.
- A bad release recovers by removing the global plugin symlink/package entry;
  native `bash: ask` remains the baseline and no stored `always` rules require cleanup.

## 11. Locked MVP decisions

1. Shell permission requests only.
2. Native `bash: ask` remains enabled.
3. Every automatic approval requires model review; deterministic policy cannot grant.
4. DeepSeek V4 Flash is the candidate default, not trusted until qualification.
5. Repeated commands are re-evaluated and re-reviewed; verdicts are not cached.
6. Automatic replies use `once` only.
7. Default model timeout is 30 seconds and progress is visible.
8. Unsafe and uncertain results remain manual; the plugin does not auto-reject.
9. No autonomous implementation loop is installed.

## 12. Verified facts and assumptions

Verified against OpenCode 1.18.10 source:

- `permission.asked` includes request ID, session ID, permission, patterns,
  metadata, always patterns, and optional tool identity.
- Shell permission metadata contains the original command.
- `permission.reply` accepts `once`, `always`, or `reject`.
- The permission service waits for a reply and the shell runs only afterward.
- Plugin event callbacks receive bridged runtime events; `permission.ask` is
  declared but not triggered in this path.
- The SDK exposes session creation/prompt and TUI toast endpoints.

Assumptions requiring implementation-time proof:

- A background event callback can create and synchronously prompt an isolated
  reviewer session without delaying or recursively disturbing the parent session.
- The exact `metadata.command` value is the exact string executed by the configured
  shell; prove both value identity and actual interpreter with tagged-source and E2E
  contract tests before enabling any automatic reply.
- OpenCode keeps an unanswered permission request valid for the entire configured
  10–60 second review interval; prove both bounds with a disposable canary.
- If the configured interpreter is not compatible with the committed Bash grammar,
  automatic replies remain disabled until a matching parser and tests are approved.
- The OpenCode Go subscription permits the plugin-created reviewer traffic under
  the user's existing connection.
- TUI toast delivery is visible in every supported interactive frontend; failure
  is therefore non-authoritative and must not affect safety.

## 13. Remaining non-blocking questions

- Whether the first public release should include Linux in addition to macOS.
- Whether a later version should support project policy after a separate threat model.
- Whether audit logging should remain a post-MVP feature if rotating-file support
  materially expands the initial implementation.

## 14. Primary references

- [OpenCode plugins](https://opencode.ai/docs/plugins/)
- [OpenCode 1.18.10 permission schema](https://github.com/anomalyco/opencode/blob/v1.18.10/packages/schema/src/v1/permission.ts)
- [OpenCode 1.18.10 permission service](https://github.com/anomalyco/opencode/blob/v1.18.10/packages/opencode/src/permission/index.ts)
- [OpenCode 1.18.10 shell permission path](https://github.com/anomalyco/opencode/blob/v1.18.10/packages/opencode/src/tool/shell.ts)
- [OpenCode 1.18.10 plugin runtime](https://github.com/anomalyco/opencode/blob/v1.18.10/packages/opencode/src/plugin/index.ts)
- [OpenCode 1.18.10 SDK documentation](https://github.com/anomalyco/opencode/blob/v1.18.10/packages/web/src/content/docs/sdk.mdx)
- [Tree-sitter Bash grammar](https://github.com/tree-sitter/tree-sitter-bash)
- [DeepSeek JSON output](https://api-docs.deepseek.com/guides/json_mode/)
- [OWASP LLM prompt injection prevention](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
- [Existing smart-approval implementation](https://github.com/blanboom/opencode-smart-approval)
