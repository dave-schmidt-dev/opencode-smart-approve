import type { ReplanExecutableIdentity } from "../policy/executable-identity";

/** Harness-neutral decomposition rule for bounded read-only recovery. */
export const REPLAN_DECOMPOSITION_GUIDANCE =
  "For read-only work, decompose the operation into sequential native tool calls and carry only bounded text returned by each call into the next. Never recreate the pipeline as separate Bash commands, wrappers, substitutions, or loops. If a native tool cannot cover a step, stop this attempt; after the bounded replan budget is exhausted, the next attempt falls through to the native permission prompt for a human decision." as const;

/** Fixed safety instructions retained for the generic no-identity fallback. */
export const REPLAN_GUIDANCE_PREAMBLE =
  `Blocked before permission or execution. Do not retry the blocked executable through a wrapper, alias, command substitution, pipeline, shell loop, or alternate spelling. Use the named native tool or bounded alternative. ${REPLAN_DECOMPOSITION_GUIDANCE} If it cannot complete the operation, stop this attempt and explain the blocker. After the bounded replan budget is exhausted, the next attempt falls through to the native Bash permission prompt; work waits there until a human approves or declines. Do not guess, inspect the environment, or keep retrying.` as const;

export interface ReplanGuidanceEntry {
  readonly unsafeProperty: string;
  readonly nativeAlternative: string;
  readonly shellFallbackProhibition: string;
  readonly nativePromptStopInstruction: string;
  readonly feedback: string;
}

/**
 * Finite compile-time guidance for the only identities eligible for replan.
 * Every message is literal: no command, goal, provider, environment, or secret
 * value can be copied into feedback.
 */
export const REPLAN_GUIDANCE_CATALOG: Readonly<Record<ReplanExecutableIdentity, ReplanGuidanceEntry>> = Object.freeze({
  awk: Object.freeze({
    unsafeProperty: "awk interprets program text over input and can perform unbounded file or process access.",
    nativeAlternative: "Use the native read tool for bounded inspection, grep for a bounded literal search, or glob to enumerate known project paths.",
    shellFallbackProhibition: "Do not replace awk with another shell interpreter, sh -c, a wrapper, command substitution, or a script file.",
    nativePromptStopInstruction: "If those native tools do not cover the operation, stop and explain the blocker; after the bounded replan budget is exhausted, the next attempt falls through to the native permission prompt and work waits for a human decision.",
    feedback: "SMART_APPROVE_REPLAN_MICROPLAN: awk was blocked. Your next action MUST be a native tool call, not prose: call glob for known project paths, then read or grep bounded returned files. Do not use Bash, a wrapper, pipeline, loop, substitution, alias, interpreter, or script. If native tools cannot complete this step, stop and explain; after bounded replans are exhausted, the native Bash permission prompt waits for a human decision. awk interprets program text over input and can perform unbounded file or process access. Use the native read tool for bounded inspection, grep for a bounded literal search, or glob to enumerate known project paths. Do not replace awk with another shell interpreter, sh -c, a wrapper, command substitution, or a script file. If those native tools do not cover the operation, stop and explain the blocker; after the bounded replan budget is exhausted, the next attempt falls through to the native permission prompt and work waits for a human decision.",
  }),
  xargs: Object.freeze({
    unsafeProperty: "xargs turns generated input into additional command invocations, creating fan-out and argument expansion.",
    nativeAlternative: "Use glob for a bounded project list, then one native read or grep operation per known item.",
    shellFallbackProhibition: "Do not replace xargs with a shell loop, sh -c, nested command substitution, or another fan-out wrapper.",
    nativePromptStopInstruction: "If no bounded native operation covers the items, stop and explain the blocker; after the bounded replan budget is exhausted, the next attempt falls through to the native permission prompt and work waits for a human decision.",
    feedback: "SMART_APPROVE_REPLAN_MICROPLAN: xargs was blocked. Your next action MUST be a native tool call, not prose: call glob for a bounded project list, then call read or grep once per known result. Do not use Bash, fan-out wrappers, pipelines, loops, substitutions, aliases, or scripts. If native tools cannot complete this step, stop and explain; after bounded replans are exhausted, the native Bash permission prompt waits for a human decision. xargs turns generated input into additional command invocations, creating fan-out and argument expansion. Use glob for a bounded project list, then one native read or grep operation per known item. Do not replace xargs with a shell loop, sh -c, nested command substitution, or another fan-out wrapper. If no bounded native operation covers the items, stop and explain the blocker; after the bounded replan budget is exhausted, the next attempt falls through to the native permission prompt and work waits for a human decision.",
  }),
  find: Object.freeze({
    unsafeProperty: "find recursively traverses a chosen root and can apply actions to arbitrary paths.",
    nativeAlternative: "Use the native glob tool scoped to the project, then targeted native read or grep calls on known results.",
    shellFallbackProhibition: "Do not broaden the search root, add recursive shell traversal, or use delete or exec actions.",
    nativePromptStopInstruction: "If a bounded native search is insufficient, stop and explain the blocker; after the bounded replan budget is exhausted, the next attempt falls through to the native permission prompt and work waits for a human decision.",
    feedback: "SMART_APPROVE_REPLAN_MICROPLAN: find was blocked. Your next action MUST be a native tool call, not prose: call glob scoped to the project, then inspect returned paths with read or grep. Do not use Bash, recursive shell traversal, wrappers, pipelines, loops, substitutions, aliases, delete, or exec actions. If native tools cannot complete this step, stop and explain; after bounded replans are exhausted, the native Bash permission prompt waits for a human decision. find recursively traverses a chosen root and can apply actions to arbitrary paths. Use the native glob tool scoped to the project, then targeted native read or grep calls on known results. Do not broaden the search root, add recursive shell traversal, or use delete or exec actions. If a bounded native search is insufficient, stop and explain the blocker; after the bounded replan budget is exhausted, the next attempt falls through to the native permission prompt and work waits for a human decision.",
  }),
  env: Object.freeze({
    unsafeProperty: "env changes process environment or command selection and can expose credential-bearing values.",
    nativeAlternative: "Use the native read tool for known project config files with explicit arguments; never inspect process environment data.",
    shellFallbackProhibition: "Do not print, forward, or synthesize environment values, or use a shell wrapper to select another executable.",
    nativePromptStopInstruction: "If an explicit native call cannot perform the operation, stop and explain the blocker; after the bounded replan budget is exhausted, the next attempt falls through to the native permission prompt and work waits for a human decision.",
    feedback: "SMART_APPROVE_REPLAN_MICROPLAN: env was blocked. Your next action MUST be a native tool call, not prose: call read on a specifically named project configuration file. Do not inspect process environment data or use Bash, wrappers, pipelines, loops, substitutions, aliases, or scripts. If a named native call cannot complete this step, stop and explain; after bounded replans are exhausted, the native Bash permission prompt waits for a human decision. env changes process environment or command selection and can expose credential-bearing values. Use the native read tool for known project config files with explicit arguments; never inspect process environment data. Do not print, forward, or synthesize environment values, or use a shell wrapper to select another executable. If an explicit native call cannot perform the operation, stop and explain the blocker; after the bounded replan budget is exhausted, the next attempt falls through to the native permission prompt and work waits for a human decision.",
  }),
  command: Object.freeze({
    unsafeProperty: "command can alter executable lookup and hide the program that is actually invoked.",
    nativeAlternative: "Call the specific native tool directly, such as read, glob, or grep, instead of shell lookup.",
    shellFallbackProhibition: "Do not use command -v, command -V, command -p, aliases, wrappers, or another lookup layer.",
    nativePromptStopInstruction: "If no specific native tool applies, stop and explain the blocker; after the bounded replan budget is exhausted, the next attempt falls through to the native permission prompt and work waits for a human decision.",
    feedback: "SMART_APPROVE_REPLAN_MICROPLAN: command was blocked. Your next action MUST be a native tool call, not prose: call the specific native tool needed, such as read, glob, or grep. Do not use Bash lookup, command -v, wrappers, pipelines, loops, substitutions, aliases, or scripts. If no named native tool applies, stop and explain; after bounded replans are exhausted, the native Bash permission prompt waits for a human decision. command can alter executable lookup and hide the program that is actually invoked. Call the specific native tool directly, such as read, glob, or grep, instead of shell lookup. Do not use command -v, command -V, command -p, aliases, wrappers, or another lookup layer. If no specific native tool applies, stop and explain the blocker; after the bounded replan budget is exhausted, the next attempt falls through to the native permission prompt and work waits for a human decision.",
  }),
  cmp: Object.freeze({
    unsafeProperty: "cmp reads two path operands and depends on file identity and contents outside bounded shell semantics.",
    nativeAlternative: "Use the native read tool on two known project files and compare the returned bounded text in the task context.",
    shellFallbackProhibition: "Do not compare unknown paths, redirect output, or wrap the comparison in another shell command.",
    nativePromptStopInstruction: "If a bounded native comparison is not possible, stop and explain the blocker; after the bounded replan budget is exhausted, the next attempt falls through to the native permission prompt and work waits for a human decision.",
    feedback: "SMART_APPROVE_REPLAN_MICROPLAN: cmp was blocked. Your next action MUST be a native tool call, not prose: call read on the two specifically known project files, then compare the bounded returned text. Do not use Bash, redirection, wrappers, pipelines, loops, substitutions, aliases, or scripts. If a bounded native comparison is impossible, stop and explain; after bounded replans are exhausted, the native Bash permission prompt waits for a human decision. cmp reads two path operands and depends on file identity and contents outside bounded shell semantics. Use the native read tool on two known project files and compare the returned bounded text in the task context. Do not compare unknown paths, redirect output, or wrap the comparison in another shell command. If a bounded native comparison is not possible, stop and explain the blocker; after the bounded replan budget is exhausted, the next attempt falls through to the native permission prompt and work waits for a human decision.",
  }),
});

/** Return only a static entry selected by the typed finite identity. */
export function replanGuidanceFor(identity: ReplanExecutableIdentity): ReplanGuidanceEntry {
  return REPLAN_GUIDANCE_CATALOG[identity];
}

/** Generic no-argument fallback retained for callers without an identity. */
export const REPLAN_GENERIC_FEEDBACK =
  `${REPLAN_GUIDANCE_PREAMBLE} No identity-specific alternative is available. Stop this attempt and explain the blocker; after the bounded replan budget is exhausted, the next attempt falls through to the native permission prompt and work waits for a human decision.` as const;
