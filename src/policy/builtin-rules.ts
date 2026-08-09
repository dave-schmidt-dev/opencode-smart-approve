import type { BashFeatures } from "../parser/features";

/** Reasons emitted by the deterministic safety boundary. */
export type BuiltinRuleReason =
  | "interpreter"
  | "package_script"
  | "unknown_binary"
  | "dynamic_syntax"
  | "environment_assignment";

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
  "tr", "true", "uniq", "wc", "which", "xargs",
]);

const INTERPRETERS = /^(?:(?:ba|z|fi|c|k)?sh|python|pypy|node|deno|bun|ruby|perl|php|lua|pwsh|powershell)(?:\d+(?:\.\d+)*)?$/i;
const PACKAGE_MANAGERS = new Set(["npm", "npx", "pnpm", "yarn", "bun"]);
const PACKAGE_SCRIPT_ACTIONS = new Set([
  "run", "exec", "test", "start", "build", "dev", "serve", "lint", "prepare", "publish",
]);

function firstCommand(command: string): string | undefined {
  const tokens = command.match(/(?:[^\s"']+|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')+/g) ?? [];
  let index = 0;
  while (index < tokens.length && /^(?:[A-Za-z_][A-Za-z0-9_]*=|export$)/.test(tokens[index] ?? "")) index += 1;
  while (index < tokens.length && ["command", "builtin", "exec", "env"].includes(tokens[index] ?? "")) index += 1;
  return tokens[index]?.replace(/^['"]|['"]$/g, "").split("/").at(-1)?.toLowerCase();
}

function packageScript(context: BuiltinRuleContext): boolean {
  const tokens = context.command.match(/(?:[^\s"']+|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')+/g) ?? [];
  const executable = firstCommand(context.command);
  if (!executable || !PACKAGE_MANAGERS.has(executable)) return false;
  return tokens.some((token, index) => index > 0 && PACKAGE_SCRIPT_ACTIONS.has(token.replace(/^[-]+/, "").toLowerCase()));
}

function interpreter(context: BuiltinRuleContext): boolean {
  const executable = firstCommand(context.command);
  return executable !== undefined && INTERPRETERS.test(executable);
}

function unknownBinary(context: BuiltinRuleContext): boolean {
  const executable = firstCommand(context.command);
  if (!executable) return true;
  if (KNOWN_COMMANDS.has(executable) || PACKAGE_MANAGERS.has(executable) || interpreter(context)) return false;
  return true;
}

function dynamicSyntax(context: BuiltinRuleContext): boolean {
  const features = context.features;
  return features.substitutions || features.processSubstitutions || features.backticks || features.functions ||
    features.loops || features.heredocs || features.eval || features.exec || features.source ||
    features.unresolvedExpansions || features.unsupported.length > 0 ||
    /(?:^|\s)(?:-c|--config(?:=|\s)|--exec-path(?:=|\s)|--git-dir(?:=|\s)|--work-tree(?:=|\s))/.test(context.command);
}

/** Built-in rules are hard blocks only; none can grant or reply. */
export const BUILTIN_RULES: readonly BuiltinRule[] = [
  { name: "interpreter", matches: interpreter },
  { name: "package_script", matches: packageScript },
  { name: "dynamic_syntax", matches: dynamicSyntax },
  { name: "environment_assignment", matches: ({ features }) => features.environmentAssignments },
  { name: "unknown_binary", matches: unknownBinary },
];

export function evaluateBuiltinRules(context: BuiltinRuleContext): readonly BuiltinRuleReason[] {
  return BUILTIN_RULES.filter((rule) => rule.matches(context)).map((rule) => rule.name);
}

export const evaluateBuiltinPolicy = evaluateBuiltinRules;
