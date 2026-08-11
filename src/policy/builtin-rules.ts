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
export const KNOWN_COMMANDS = new Set([
  "awk", "basename", "cat", "cd", "cmp", "cut", "date", "dirname", "echo", "env",
  "false", "find", "git", "grep", "head", "join", "less", "ls", "mkdir", "printf",
  "pwd", "readlink", "rg", "rm", "sed", "sort", "stat", "tail", "tee", "test",
  "tr", "true", "uniq", "wc", "which", "xargs", "realpath",
]);

const INTERPRETERS = /^(?:(?:ba|z|fi|c|k)?sh|python|pypy|node|deno|bun|ruby|perl|php|lua|pwsh|powershell)(?:\d+(?:\.\d+)*)?$/i;
const PACKAGE_MANAGERS = new Set(["npm", "npx", "pnpm", "yarn", "bun"]);

function firstCommand(command: string): string | undefined {
  const tokens = command.match(/(?:[^\s"']+|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')+/g) ?? [];
  let index = 0;
  while (index < tokens.length && /^(?:[A-Za-z_][A-Za-z0-9_]*=|export$)/.test(tokens[index] ?? "")) index += 1;
  while (index < tokens.length && ["command", "builtin", "exec", "env"].includes(tokens[index] ?? "")) index += 1;
  return tokens[index]?.replace(/^['"]|['"]$/g, "").split("/").at(-1)?.toLowerCase();
}

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
    .map((segment) => firstCommand(segment))
    .filter((value): value is string => value !== undefined);
}
