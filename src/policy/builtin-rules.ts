import type { BashFeatures } from "../parser/features";

/** Reasons emitted by the deterministic safety boundary. */
export type BuiltinRuleReason =
  | "interpreter"
  | "package_script"
  | "unknown_binary"
  | "dynamic_syntax"
  | "environment_assignment"
  | "dangerous_command";

export interface BuiltinRuleContext {
  readonly command: string;
  readonly features: BashFeatures;
}

export interface BuiltinRule {
  readonly name: BuiltinRuleReason;
  readonly matches: (context: BuiltinRuleContext) => boolean;
}

/** Commands whose syntax is sufficiently ordinary for model review. */
// Recognizing a binary does not approve it. A known command still faces every
// other rule and, under INV-3, can only be granted by the model. Entries are
// added on measured usage, and a candidate has to clear three tests, not two:
// no flag that executes a subprocess, no flag that writes a file, and a reach
// bounded by its own operands. `osascript` executes; `plutil -convert` and
// `base64 -o` write; `ps` and `pgrep` fail the third, which is subtler and is
// why they were briefly listed here. They name no operand at all, so path
// identity has nothing to check, and `ps aux` reports every process on the
// machine including the arguments other tools were launched with — where
// credentials are routinely passed. A reader whose scope is a path can be
// bounded by the path rules already in place. A reader whose scope is the
// machine cannot be bounded by anything this gate knows.
export const KNOWN_COMMANDS = new Set([
  "awk", "basename", "cat", "cd", "cmp", "command", "cut", "date", "dirname", "echo", "env",
  "false", "find", "git", "grep", "head", "join", "jq", "less", "ls", "mkdir", "nl",
  "printf", "pwd", "readlink", "rg", "rm", "sed", "shasum", "sort", "stat", "tail",
  "tee", "test", "tr", "true", "uniq", "wc", "which", "xargs", "realpath",
]);

const INTERPRETERS = /^(?:(?:ba|z|fi|c|k)?sh|python|pypy|node|deno|bun|ruby|perl|php|lua|pwsh|powershell)(?:\d+(?:\.\d+)*)?$/i;
const PACKAGE_MANAGERS = new Set(["npm", "npx", "pnpm", "yarn", "bun"]);

function packageScript(context: BuiltinRuleContext): boolean {
  // Package managers execute lifecycle hooks even for commands that do not
  // spell `run`; keep the whole family on the manual path.
  return commandExecutables(context.command).some((executable) => PACKAGE_MANAGERS.has(executable));
}

function interpreter(context: BuiltinRuleContext): boolean {
  return commandExecutables(context.command).some((executable) => INTERPRETERS.test(executable));
}

function unknownBinary(context: BuiltinRuleContext): boolean {
  const executables = commandExecutables(context.command);
  if (!executables.length) return true;
  return executables.some((executable) =>
    !KNOWN_COMMANDS.has(executable) && !PACKAGE_MANAGERS.has(executable) && !INTERPRETERS.test(executable));
}

function dynamicSyntax(context: BuiltinRuleContext): boolean {
  const features = context.features;
  return features.substitutions || features.processSubstitutions || features.backticks || features.functions ||
    features.loops || features.heredocs || features.eval || features.exec || features.source ||
    features.unresolvedExpansions || features.unsupported.length > 0 ||
    /(?:^|\s)(?:--config(?:=|\s)|--exec-path(?:=|\s)|--git-dir(?:=|\s)|--work-tree(?:=|\s))/.test(context.command);
}

function dangerousCommand(context: BuiltinRuleContext): boolean {
  if (context.features.redirects) return true;
  const command = context.command;
  const executables = commandExecutables(command);
  if (executables.some((executable) => executable === "rm" || executable === "tee" || executable === "mkdir" || executable === "less")) return true;
  if (/(?:^|\s)xargs\b[^;&|]*(?:^|\s)(?:rm|git\s+(?:reset|clean|checkout|restore))(?:\s|$)/.test(command)) return true;
  if (/(?:^|\s)find\b[^;&|]*(?:^|\s)-delete(?:\s|$)/.test(command)) return true;
  if (/(?:^|\s)sed\b[^;&|]*(?:^|\s)-(?:i|[^\s]*i[^\s]*)(?:\s|$)/.test(command)) return true;
  const git = command.match(/(?:^|[;&|]\s*|\b(?:command|env)\s+)git\s+([A-Za-z][A-Za-z-]*)([^;&|]*)/i);
  if (!git) return false;
  const subcommand = git[1]?.toLowerCase();
  const args = git[2] ?? "";
  if (["add", "apply", "checkout", "cherry-pick", "clean", "commit", "merge", "push", "rebase", "reset", "restore", "revert", "stash", "switch", "update-ref"].includes(subcommand ?? "")) return true;
  if (subcommand === "branch" && /(?:^|\s)-(?:d|D|m|M|c|C)(?:\s|$)/.test(args)) return true;
  if (subcommand === "tag" && /(?:^|\s)(?:-d|--delete|-a|-s|-m|-f)(?:\s|=|$)/.test(args)) return true;
  if (subcommand === "remote" && /(?:^|\s)(?:add|remove|rename|set-head|set-url|prune|update)(?:\s|$)/.test(args)) return true;
  return subcommand === "config" && !/(?:^|\s)(?:--get|--get-all|--get-regexp|--list|-l)(?:\s|$)/.test(args);
}

/** Built-in rules are hard blocks only; none can grant or reply. */
export const BUILTIN_RULES: readonly BuiltinRule[] = [
  { name: "interpreter", matches: interpreter },
  { name: "package_script", matches: packageScript },
  { name: "dynamic_syntax", matches: dynamicSyntax },
  { name: "environment_assignment", matches: ({ features }) => features.environmentAssignments },
  { name: "dangerous_command", matches: dangerousCommand },
  { name: "unknown_binary", matches: unknownBinary },
];

export function evaluateBuiltinRules(context: BuiltinRuleContext): readonly BuiltinRuleReason[] {
  return BUILTIN_RULES.filter((rule) => rule.matches(context)).map((rule) => rule.name);
}

export const evaluateBuiltinPolicy = evaluateBuiltinRules;

/** Extract command names from each simple pipeline/list segment. */
function commandExecutables(command: string): string[] {
  return command
    .split(/(?:\|\||&&|[|;&])/)
    .flatMap((segment) => segmentExecutables(segment));
}

/**
 * Return both a wrapper and the command it invokes. Replan identities such
 * as `env` and `command` are retained, but their effective command must also
 * pass the ordinary safety checks (for example, `env -i rm` is dangerous).
 */
function segmentExecutables(segment: string): string[] {
  const tokens = segment.match(/(?:[^\s"']+|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')+/g) ?? [];
  const executables: string[] = [];
  let index = 0;
  while (index < tokens.length && /^(?:[A-Za-z_][A-Za-z0-9_]*=|export$)/.test(tokens[index] ?? "")) index += 1;
  while (index < tokens.length && ["builtin", "exec"].includes(tokens[index] ?? "")) index += 1;

  while (index < tokens.length) {
    const executable = tokens[index]?.replace(/^['"]|['"]$/g, "").split("/").at(-1)?.toLowerCase();
    if (!executable) break;
    executables.push(executable);
    index += 1;

    if (executable === "command") {
      // `command -p/-v/-V` options do not change the following command.
      while (index < tokens.length && /^-/.test(tokens[index] ?? "")) index += 1;
      continue;
    }
    if (executable === "env") {
      // Skip env options and their operands, then inspect the effective command.
      while (index < tokens.length) {
        const token = tokens[index] ?? "";
        if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(token)) { index += 1; continue; }
        if (token === "--") { index += 1; break; }
        if (!token.startsWith("-")) break;
        if (["-u", "--unset", "-C", "--chdir"].includes(token)) index += 2;
        else index += 1;
      }
      continue;
    }
    break;
  }
  return executables;
}
