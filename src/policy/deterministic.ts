import { lstat, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";
import { parseBash, type BashParseResult } from "../parser/bash-parser";
import { scanForSecrets, type SecretScanOptions, type SecretScanResult } from "../privacy/secret-scan";
import { evaluateBuiltinRules, type BuiltinRuleReason } from "./builtin-rules";
import type { SmartApproveConfig } from "../config/schema";

export type DeterministicDecision = "manual" | "model_review";
export type DeterministicReasonCode = BuiltinRuleReason | "parse_failure" | "privacy" | "path_identity" | "model_disabled" | "user_rule" | "invalid_command";
export type PolicyPathClass = "project" | "none";

export interface PathIdentityOptions {
  /** Directory against which relative command paths are resolved. */
  readonly cwd?: string;
  /** Paths must remain beneath this owned directory. Defaults to cwd. */
  readonly ownedRoot?: string;
  /** Metadata-only hooks allow deterministic tests without opening file data. */
  readonly lstat?: (path: string) => Promise<{ readonly uid?: number; readonly isSymbolicLink: () => boolean }>;
  readonly realpath?: (path: string) => Promise<string>;
}

export interface DeterministicPolicyOptions {
  readonly config?: {
    readonly model?: Pick<SmartApproveConfig["model"], "enabled">;
    readonly policy?: {
      readonly rules?: SmartApproveConfig["policy"]["rules"];
      readonly sensitivePathPatterns?: SmartApproveConfig["policy"]["sensitivePathPatterns"];
      readonly secretPatterns?: SmartApproveConfig["policy"]["secretPatterns"];
    };
  };
  readonly privacy?: SecretScanResult;
  readonly secretScan?: SecretScanOptions;
  readonly pathIdentity?: PathIdentityOptions;
}

export interface DeterministicPolicyResult {
  readonly status: DeterministicDecision;
  readonly decision: DeterministicDecision;
  readonly reasonCodes: readonly DeterministicReasonCode[];
  readonly parse: BashParseResult | undefined;
  readonly privacy: SecretScanResult | undefined;
  readonly pathClasses?: readonly PolicyPathClass[];
}

const manual = (
  reasonCodes: readonly DeterministicReasonCode[],
  parse?: BashParseResult,
  privacy?: SecretScanResult,
  pathClasses?: readonly PolicyPathClass[],
): DeterministicPolicyResult => ({ status: "manual", decision: "manual", reasonCodes, parse, privacy, pathClasses });

/**
 * Run the parser, privacy boundary, and deterministic rules in precedence order.
 * This function intentionally has no approval adapter and can only return the
 * two routing states consumed by the reviewer coordinator.
 */
export async function evaluateDeterministicPolicy(
  command: string,
  options: DeterministicPolicyOptions = {},
): Promise<DeterministicPolicyResult> {
  if (typeof command !== "string" || command.length === 0) return manual(["invalid_command"]);
  if (options.config?.model?.enabled === false) return manual(["model_disabled"]);

  const parse = await parseBash(command);
  if (!parse.ok) return manual(["parse_failure"], parse);

  const configuredPolicy = options.config?.policy;
  const privacy = options.privacy ?? scanForSecrets(command, {
    ...options.secretScan,
    ...((options.secretScan?.additionalPatterns?.length || configuredPolicy?.sensitivePathPatterns?.length)
      ? { additionalPatterns: [...(options.secretScan?.additionalPatterns ?? []), ...(configuredPolicy?.sensitivePathPatterns ?? [])] }
      : {}),
    ...((options.secretScan?.additionalSecretPatterns?.length || configuredPolicy?.secretPatterns?.length)
      ? { additionalSecretPatterns: [...(options.secretScan?.additionalSecretPatterns ?? []), ...(configuredPolicy?.secretPatterns ?? [])] }
      : {}),
  });
  if (privacy.status === "manual" || privacy.suspected || containsSensitivePathToken(command)) return manual(["privacy"], parse, privacy);

  const pathIdentity = await classifyPathIdentity(command, options.pathIdentity);
  if (!pathIdentity.stable) return manual(["path_identity"], parse, privacy, pathIdentity.pathClasses);

  const reasons = [...evaluateBuiltinRules({ command, features: parse.features })];
  if (reasons.length) return manual(reasons, parse, privacy);

  const userRules = options.config?.policy?.rules ?? [];
  for (const rule of userRules) {
    if (rule.pattern && command.includes(rule.pattern) && rule.action === "manual") {
      return manual(["user_rule"], parse, privacy);
    }
  }
  return { status: "model_review", decision: "model_review", reasonCodes: [], parse, privacy, pathClasses: pathIdentity.pathClasses };
}

export const evaluatePolicy = evaluateDeterministicPolicy;
export const deterministicPolicy = evaluateDeterministicPolicy;

// The privacy scanner deliberately treats paths as tokens. Keep a small
// basename check here as well so root-relative names such as `.env` (which do
// not contain a slash) remain hard blocked.
function containsSensitivePathToken(command: string): boolean {
  return /(?:^|[/\\\s"'=])(?:\.env(?:\.[^\s/;&|]*)?|\.npmrc|\.pypirc|\.netrc|credentials?(?:\.[^\s/;&|]*)?|secrets?(?:\.[^\s/;&|]*)?|.*(?:keychain|private.key|id_(?:rsa|dsa|ecdsa|ed25519))(?:\.[^\s/;&|]*)?)(?=$|[\s"';&|])/i.test(command);
}

const PATH_COMMANDS = new Set([
  "basename", "cat", "cd", "cmp", "cut", "dirname", "find", "grep", "head", "join", "less", "ls",
  "mkdir", "readlink", "realpath", "rm", "sed", "sort", "stat", "tail", "tee", "test", "uniq", "wc",
]);

/**
 * Check only path-shaped operands and redirection targets. This uses lstat and
 * realpath metadata, never readFile/open, and fails closed for identity gaps.
 */
async function classifyPathIdentity(
  command: string,
  options: PathIdentityOptions = {},
): Promise<{ readonly stable: boolean; readonly pathClasses: readonly PolicyPathClass[] }> {
  const tokens = shellTokens(command);
  const executables = command.split(/(?:\|\||&&|[|;&])/).map(firstToken).filter((token): token is string => token !== undefined);
  const pathTokens = new Set<string>();
  let segment = 0;
  let seenCommand = false;
  let redirectPending = false;
  for (const token of tokens) {
    if (/^(?:\|\||&&|[|;&])$/.test(token)) {
      segment += 1;
      seenCommand = false;
      redirectPending = false;
      continue;
    }
    if (/^(?:\d*[<>]{1,2}|&>)$/.test(token)) {
      redirectPending = true;
      continue;
    }
    const value = unquote(token).replace(/^(?:\d*[<>]{1,2}|&>)/, "");
    if (!value || value.startsWith("-")) continue;
    if (redirectPending) {
      pathTokens.add(value);
      redirectPending = false;
      continue;
    }
    if (!seenCommand) {
      seenCommand = true;
      continue;
    }
    const executable = executables[segment];
    if (isPathToken(value) || (executable !== undefined && PATH_COMMANDS.has(executable))) pathTokens.add(value);
  }
  // Bare redirect targets are path identity inputs even when the command has
  // no file-oriented executable (for example `echo value > output`).
  for (const token of tokens) {
    const target = token.match(/^(?:\d*[<>]{1,2}|&>)(.+)$/)?.[1];
    if (target) pathTokens.add(unquote(target));
  }
  for (const token of pathTokens) {
    if (!token || token === "/" || token === "." || token === ".." || /(?:^|[/\\])\.\.(?:[/\\]|$)/.test(token) || token.startsWith("~") || token.includes("$")) return { stable: false, pathClasses: ["none"] };
    const cwd = options.cwd ?? process.cwd();
    const root = resolve(options.ownedRoot ?? cwd);
    const candidate = resolve(cwd, token);
    if (!isWithin(root, candidate)) return { stable: false, pathClasses: ["none"] };
    try {
      const metadata = options.lstat ?? (async (path: string) => lstat(path));
      for (const path of pathChain(root, candidate)) {
        const stat = await metadata(path);
        if (stat.isSymbolicLink()) return { stable: false, pathClasses: ["none"] };
        if (typeof stat.uid !== "number" || typeof process.getuid !== "function" || stat.uid !== process.getuid()) return { stable: false, pathClasses: ["none"] };
      }
      const canonical = await (options.realpath ?? ((path: string) => realpath(path)))(candidate);
      if (!isWithin(root, canonical)) return { stable: false, pathClasses: ["none"] };
    } catch {
      return { stable: false, pathClasses: ["none"] };
    }
  }
  return { stable: true, pathClasses: pathTokens.size > 0 ? ["project"] : ["none"] };
}

function shellTokens(command: string): string[] {
  return command.match(/(?:[^\s"';&|]+|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\|\||&&|[;&|])/g) ?? [];
}

function firstToken(segment: string): string | undefined {
  const token = shellTokens(segment).find((value) => !/^(?:[A-Za-z_][A-Za-z0-9_]*=|export$|command$|builtin$|exec$|env$)/.test(value));
  return token ? unquote(token).split("/").at(-1)?.toLowerCase() : undefined;
}

function unquote(value: string): string {
  return value.replace(/^(['"])(.*)\1$/, "$2");
}

function isPathToken(value: string): boolean {
  return isAbsolute(value) || value === "." || value === ".." || value.startsWith("./") || value.startsWith("../") || value.includes("/") || /^[A-Za-z]:[\\/]/.test(value);
}

function isWithin(root: string, candidate: string): boolean {
  const remainder = relative(root, candidate);
  return remainder === "" || (!remainder.startsWith("..") && !isAbsolute(remainder));
}

function pathChain(root: string, candidate: string): string[] {
  const remainder = relative(root, candidate);
  if (!remainder) return [root];
  const parts = remainder.split(/[\\/]+/).filter(Boolean);
  const chain = [root];
  let current = root;
  for (const part of parts) {
    current = resolve(current, part);
    chain.push(current);
  }
  return chain;
}
