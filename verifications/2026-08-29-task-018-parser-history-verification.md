# TASK-018 Parser-History Repair — Independent Verification

Scope: `scripts/qualification/harvest-usage.ts`, `scripts/qualification/analyze-parser-history.ts`,
`tests/eval/harvest-usage.test.ts`, `tests/eval/analyze-parser-history.test.ts`,
`tests/eval/measure-routing.test.ts`, `package.json`, `README.md`.

## Task 1: Decode supported Codex `/bin/{ba,z}sh -lc` wrapper arguments without shell execution

**Requirements check.** `decodeCodexWrapper` (`scripts/qualification/harvest-usage.ts:79-124`) must
decode single- and double-quoted wrapper arguments, including both `'\''` and `'"'"'` single-quote
splice forms, without executing harvested content, and leave ambiguous/unsupported shapes
byte-identical.

**Clean-room verification.**
- Regex `^\/bin\/(?:ba|z)?sh\s+-l?c\s+([\s\S]+)$` at `harvest-usage.ts:80` matches the same
  `/bin/{ba,z,''}sh -l?c` head the prior implementation matched; no shell metachar interpretation.
- Single-quote branch (`harvest-usage.ts:88-93`): replaces both splice sequences with a sentinel,
  then bails to the original string if any unspliced `'` remains — this correctly rejects
  quote-boundary-crossing shapes such as `'foo'$(cmd)'bar'` (traced by hand: inner retains two
  unmatched `'`, `normalized.includes("'")` is true, falls through to `return command`).
- Double-quote branch (`harvest-usage.ts:96-119`): walks char-by-char, only unescapes `\"`, `\\`,
  `\$`, `` \` ``, and line-continuation `\<LF>`; any unescaped `"`, backtick, or `$` followed by an
  expansion-starting character (`[a-zA-Z_0-9{(*@#?$!-]`, `'`, `"`) aborts to `return command`
  unchanged. No substitution is ever evaluated — only string slicing and a fixed regex class test.
- `checkBashSyntaxWithBashN` (`analyze-parser-history.ts:57-68`) supplies the command only via
  `stdio: ["pipe", "ignore", "ignore"]` stdin to `/bin/bash -n` — syntax check only, stdout/stderr
  suppressed, no execution.
- Ran the project's full offline suite (`bun run check`, allowlisted): typecheck, spec-guard, and
  `test:offline` (now including `tests/eval/analyze-parser-history.test.ts`) — **481 pass, 0 fail**,
  plus `test:package` 3/3. This included both quote-splice test cases in
  `tests/eval/harvest-usage.test.ts:250-273` and the malformed/unsupported-shape byte-identity test
  at `tests/eval/harvest-usage.test.ts:275-291`.
- `collectLocalCommands` (`harvest-usage.ts:323-326`) calls `collectLocalExecutions`, so the decode
  fix applies uniformly to both the new diagnostic and the existing benign-candidate harvest path
  used only by future corpus authoring (`harvestBenignCommands`, `harvest-usage.ts:388-399`) — not
  by any live qualification, release, or scoring path.

**Blind-spot discovery.** The single-quote sentinel is `"\u0000"`. If harvested text ever contained
a literal NUL byte, the sentinel could theoretically collide and mis-decode. In practice this is not
reachable: a raw NUL cannot appear in a real process argv (it is the C string terminator), and if one
somehow appeared in captured JSON/sqlite text, `parseBash`'s `hasControlByte` check
(`src/parser/bash-parser.ts:47,75`) would independently route the command to the fail-closed
`control_byte` manual path regardless of how the decoder handled it. No corrective action needed;
noted for completeness, not a defect.

## Task 2: Aggregate-only fixed-cutoff parser-history analyzer and CLI command

**Requirements check.** `analyzeParserHistory` must apply an inclusive upper cutoff
(`recordedAt <= cutoff`), exclude missing/invalid timestamps, classify by `BashParseFailure.reason`,
split Bash-invalid syntax from Bash-valid/tree-sitter divergence, split limit violations by
AST-depth vs. segments, identify which limit failures are already manual under built-in rules,
preserve unsupported constructs as a separate negative-control category, emit no raw command/cwd/
path/hash/prompt/response/secret, and surface bounded progress on stderr while keeping stdout to the
final JSON report.

**Clean-room verification.**
- Cutoff: `analyze-parser-history.ts:100-107` — entries without `recordedAt`, or with an unparsable
  timestamp (`isNaN(entryDate.getTime())`), are skipped; otherwise `entryDate.getTime() <= cutoffMs`
  is the inclusion test. This is exactly `recordedAt <= cutoff`, inclusive, as required.
- Reason ordering matches the real parser's priority exactly: `src/parser/bash-parser.ts:63-67`
  checks `missing_node` → `parse_error` (`root.hasError`) → `limit_exceeded` → `unsupported_construct`
  in that order, and the analyzer's `failuresByReason` keying off `parseResult.reason`
  (`analyze-parser-history.ts:139-140`) inherits that priority unmodified rather than
  re-implementing it.
- Limit split reuses `parseResult.limits` entries keyed by `"ast_depth"` / `"segments"`
  (`analyze-parser-history.ts:144-148`), which come straight from `src/parser/limits.ts` and
  `bash-parser.ts:61-62` — no re-derivation of the limit thresholds.
- "Already manual under built-in rules" calls the real `evaluateBuiltinRules` from
  `src/policy/builtin-rules.ts` (`analyze-parser-history.ts:149`) rather than a re-implemented
  heuristic, so this figure cannot drift from actual routing behavior.
- Unsupported-construct labels (`analyze-parser-history.ts:157-159`) are drawn from
  `parseResult.features.unsupported`, which is populated only from a fixed grammar-node-type
  vocabulary in `src/parser/features.ts:44-56,77-92` (e.g. `case_statement`, `test_command`) — never
  from command text — so the "no raw command" privacy property holds even in the per-construct
  breakdown.
- Privacy test at `tests/eval/analyze-parser-history.test.ts:104-127` asserts the serialized report
  excludes injected secret-shaped and path-shaped strings, and progress is via a caller-supplied
  callback carrying only `(processed, total)` counters (`analyze-parser-history.ts:169-174`); default
  stderr writes are fixed-format count strings only (`analyze-parser-history.ts:129,172`).
- `targetFailures` deliberately excludes `unsupported_construct`
  (`analyze-parser-history.ts:182-184`, matching the doc comment at line 34), consistent with the
  requirement that unsupported constructs remain a separate negative control rather than folding into
  the repaired-history headline count.
- Ran `bun run qualify:routing-check` (allowlisted, read-only comparison): **all three digests
  identical** (`routing-equivalence: identical`), independently confirming the README/HISTORY claim
  that the existing v4 development receipt stands under the 2026-08-26 INV-7 waiver despite this
  diff's changes making the candidate source manifest stale.
- Confirmed via `git status --short` that no file outside the seven listed (plus the two new files)
  is modified, and by inspection that none of `src/parser/**`, `src/policy/**`, `src/reviewer/**`,
  `scripts/classifier-gate.ts`, `scripts/qualification/machine-release.ts`, or any CI/workflow file
  changed. `eval-results/` (gitignored) has no artifacts newer than `TASKS.md`, consistent with the
  HISTORY claim that no qualification or release ran during this work.

**Blind-spot discovery.** None found beyond the note above. The design choice to call the real
`evaluateBuiltinRules` and inherit `parseBash`'s reason priority (rather than re-deriving either)
is the strongest structural guarantee here — it makes the diagnostic's classification impossible to
silently diverge from actual routing behavior.

## Task 3: Tests, local task/history/readme records

**Requirements check.** Add decoder, cutoff, privacy, progress, failure-cause, grammar-gap, and
unchanged-routing tests; update TASKS.md/HISTORY.md/README.md; wire the new test file into the
offline runner.

**Clean-room verification.**
- `tests/eval/analyze-parser-history.test.ts` covers: stable two-run aggregate equality over a
  synthetic mixed Claude+Codex home with an explicit cutoff (lines 27-101); privacy/redaction plus
  observable progress (104-127); failure-reason/limit/unsupported classification using
  hand-verifiable fixtures — `echo (`, `echo |`, a 4-level nested substitution, and 129 semicolon-
  joined `true` commands (129-183); an injected-parser divergence case (185-253); and three
  synthetic Bash-valid/tree-sitter-failing grammar gaps, each independently confirmed
  Bash-valid via a direct `checkBashSyntaxWithBashN` call inside the test itself before being run
  through the analyzer (255-276). I hand-traced the 129-`true` and 4-level-substitution fixtures
  against `src/policy/builtin-rules.ts`'s `dynamicSyntax`/`unknownBinary` logic and both reconcile
  with the test's expected `alreadyManualUnderBuiltinRules`/`notManualUnderBuiltinRules` split.
- `tests/eval/measure-routing.test.ts` gained one test asserting unsupported constructs and parser
  failures stay at `routed === 0` (lines 118-137). Confirmed this is a real exercise of
  `evaluateDeterministicPolicy` (not a vacuous pass): `PROJECT_ROOT` is the real repo root
  (`tests/eval/measure-routing.test.ts:15`), which exists on disk, so `summarizeRouting` does not
  short-circuit on the `cwdExists` filter.
- `package.json`: `analyze:parser-history` script added; `tests/eval/analyze-parser-history.test.ts`
  appended to both `test:offline` and `test:eval:unit` runner strings. No other script line changed
  (`qualify:development`, `qualify:live`, `qualify:routing-baseline`, `qualify:routing-check`,
  `qualify:verify-terminal` are untouched).
- `README.md` documents the new command, the inclusive cutoff/exclusion rule, and the privacy
  property; text matches the verified code behavior.
- `TASKS.md` shows "No open tasks" and `HISTORY.md` carries the TASK-018 entry with concrete
  numbers, both consistent with the doc-scribe convention of porting a verified `done` row out of the
  live queue.
- Independently reconciled the HISTORY numeric claims: `1,608 = 1,575 (astDepth) + 27 (parse_error) +
  6 (missing_node)`; `18 + 15 = 33 = 27 + 6`; `1,379 + 196 = 1,575`. All internally consistent with
  the `targetFailures`/`limitViolations`/divergence formulas in `analyze-parser-history.ts`.

**Blind-spot discovery.** The external plan-tracking file
`/Users/dave/Documents/Projects/.plans/opencode-smart-approve/parser-history-repair-2026-08-29-tasks.md`
still lists Task 018.1 as `**Status:** pending`, even though the work is complete, tested, and
already recorded in `HISTORY.md`. This file lives outside the repo and is out of scope for me to
edit, but the status field is stale and could mislead a future reader of the plan record. Low
severity, doc-only, no code or safety impact.

## Verdict

**PASS.**

All three completed tasks hold up under clean-room re-derivation: the wrapper decoder is provably
fail-safe (bails to byte-identical output on any shape it does not fully understand, verified both
by code trace and by the full passing test suite), the analyzer's cutoff/privacy/classification
logic was independently traced against the real parser and policy modules rather than taking the
implementation's word for it, and `bun run check` (481/481 + 3/3) plus `bun run qualify:routing-check`
(all three digests identical) were run live as part of this review and both confirm the claims made
in `README.md` and `HISTORY.md`. No parser, grammar, limit, policy, reviewer, candidate,
qualification, release, or enablement file changed; no qualification or release artifacts were
produced. One low-severity, out-of-repo documentation staleness note (external plan file status
field) is the only finding.
