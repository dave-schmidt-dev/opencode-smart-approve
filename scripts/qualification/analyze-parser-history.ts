/**
 * Aggregate-only parser-history analyzer.
 *
 * Classifies distinct commands from local agent session history by parser failure reason,
 * separates Bash-invalid syntax from tree-sitter divergence using /bin/bash -n stdin parsing,
 * splits limit violations (AST depth vs segments), identifies which limit failures are already
 * manual under built-in rules, and tracks unsupported constructs.
 *
 * Emits no raw commands, operands, cwd paths, prompts, responses, secrets, or content hashes.
 */
import { spawnSync } from "node:child_process";
import { parseBash, type BashParseResult } from "../../src/parser/bash-parser";
import { evaluateBuiltinRules } from "../../src/policy/builtin-rules";
import { collectLocalExecutions, type LocalExecution } from "./harvest-usage";

export interface LimitViolationBreakdown {
  readonly astDepth: number;
  readonly segments: number;
  readonly inputBytes: number;
  readonly alreadyManualUnderBuiltinRules: number;
  readonly notManualUnderBuiltinRules: number;
}

export interface UnsupportedConstructsSummary {
  readonly total: number;
  readonly byConstruct: Readonly<Record<string, number>>;
}

export interface ParserHistoryAnalysis {
  readonly cutoff: string;
  readonly totalExecutions: number;
  readonly distinctCommands: number;
  readonly parsedCleanly: number;
  /** `missing_node` + `parse_error` + `limit_exceeded`; excludes unsupported constructs. */
  readonly targetFailures: number;
  /** All non-ok parser results, including fail-closed unsupported constructs. */
  readonly parseFailures: number;
  readonly failuresByReason: Readonly<Record<string, number>>;
  readonly bashInvalidSyntax: number;
  readonly divergence: number;
  readonly limitViolations: LimitViolationBreakdown;
  readonly unsupportedConstructs: UnsupportedConstructsSummary;
}

export interface AnalyzeParserHistoryOptions {
  readonly home?: string;
  readonly cutoff: string;
  readonly executions?: readonly LocalExecution[];
  readonly parseBash?: (command: string) => Promise<BashParseResult>;
  readonly checkBashSyntax?: (command: string) => boolean | Promise<boolean>;
  readonly onProgress?: (processed: number, total: number) => void;
}

/**
 * Validate syntax using fixed /bin/bash -n over stdin with stdout/stderr suppressed.
 */
export function checkBashSyntaxWithBashN(command: string): boolean {
  try {
    const proc = spawnSync("/bin/bash", ["-n"], {
      input: command,
      stdio: ["pipe", "ignore", "ignore"],
      timeout: 5000,
    });
    return proc.status === 0;
  } catch {
    return false;
  }
}

export function parseArgs(args: readonly string[]): { cutoff?: string; home?: string } {
  let cutoff: string | undefined;
  let home: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === "--cutoff") {
      cutoff = args[++i];
    } else if (arg.startsWith("--cutoff=")) {
      cutoff = arg.slice("--cutoff=".length);
    } else if (arg === "--home") {
      home = args[++i];
    } else if (arg.startsWith("--home=")) {
      home = arg.slice("--home=".length);
    }
  }
  return { cutoff, home };
}

export async function analyzeParserHistory(options: AnalyzeParserHistoryOptions): Promise<ParserHistoryAnalysis> {
  if (!options.cutoff) {
    throw new Error("Mandatory CLI ISO cutoff is required");
  }
  const cutoffDate = new Date(options.cutoff);
  if (isNaN(cutoffDate.getTime())) {
    throw new Error(`Invalid cutoff ISO timestamp: ${options.cutoff}`);
  }
  const cutoffMs = cutoffDate.getTime();

  const rawExecutions = options.executions ?? collectLocalExecutions(options.home);
  const filteredExecutions: LocalExecution[] = [];
  for (const entry of rawExecutions) {
    if (!entry.recordedAt) continue;
    const entryDate = new Date(entry.recordedAt);
    if (isNaN(entryDate.getTime())) continue;
    if (entryDate.getTime() <= cutoffMs) {
      filteredExecutions.push(entry);
    }
  }

  const distinctCommands = [...new Set(filteredExecutions.map((e) => e.command))].sort();
  const parser = options.parseBash ?? parseBash;
  const syntaxChecker = options.checkBashSyntax ?? checkBashSyntaxWithBashN;

  let parsedCleanly = 0;
  let parseFailures = 0;
  const failuresByReason: Record<string, number> = {};
  let bashInvalidSyntax = 0;
  let divergence = 0;
  let astDepthViolations = 0;
  let segmentViolations = 0;
  let inputByteViolations = 0;
  let alreadyManualLimitViolations = 0;
  let notManualLimitViolations = 0;
  let unsupportedTotal = 0;
  const unsupportedByConstruct: Record<string, number> = {};

  const total = distinctCommands.length;
  let lastProgressAt = Date.now();
  if (!options.onProgress) {
    process.stderr.write(`Analyzing parser history: 0/${total} commands processed\n`);
  }
  for (let i = 0; i < total; i++) {
    const command = distinctCommands[i]!;
    const parseResult = await parser(command);

    if (parseResult.ok) {
      parsedCleanly++;
    } else {
      parseFailures++;
      const reason = parseResult.reason;
      failuresByReason[reason] = (failuresByReason[reason] ?? 0) + 1;

      if (reason === "limit_exceeded") {
        const limits = parseResult.limits ?? [];
        for (const lim of limits) {
          if (lim.limit === "ast_depth") astDepthViolations++;
          else if (lim.limit === "segments") segmentViolations++;
          else if (lim.limit === "input_bytes") inputByteViolations++;
        }
        const builtinReasons = evaluateBuiltinRules({ command, features: parseResult.features });
        if (builtinReasons.length > 0) {
          alreadyManualLimitViolations++;
        } else {
          notManualLimitViolations++;
        }
      } else if (reason === "unsupported_construct") {
        unsupportedTotal++;
        for (const construct of parseResult.features.unsupported) {
          unsupportedByConstruct[construct] = (unsupportedByConstruct[construct] ?? 0) + 1;
        }
      }

      if (reason === "parse_error" || reason === "missing_node") {
        const isBashSyntaxValid = await syntaxChecker(command);
        if (isBashSyntaxValid) divergence++;
        else bashInvalidSyntax++;
      }
    }

    if (options.onProgress) {
      options.onProgress(i + 1, total);
    } else if (Date.now() - lastProgressAt >= 5000 || i + 1 === total) {
      process.stderr.write(`Analyzing parser history: ${i + 1}/${total} commands processed\n`);
      lastProgressAt = Date.now();
    }
  }

  return {
    cutoff: options.cutoff,
    totalExecutions: filteredExecutions.length,
    distinctCommands: distinctCommands.length,
    parsedCleanly,
    targetFailures: (failuresByReason.missing_node ?? 0)
      + (failuresByReason.parse_error ?? 0)
      + (failuresByReason.limit_exceeded ?? 0),
    parseFailures,
    failuresByReason,
    bashInvalidSyntax,
    divergence,
    limitViolations: {
      astDepth: astDepthViolations,
      segments: segmentViolations,
      inputBytes: inputByteViolations,
      alreadyManualUnderBuiltinRules: alreadyManualLimitViolations,
      notManualUnderBuiltinRules: notManualLimitViolations,
    },
    unsupportedConstructs: {
      total: unsupportedTotal,
      byConstruct: unsupportedByConstruct,
    },
  };
}

async function main(): Promise<number> {
  const { cutoff, home } = parseArgs(process.argv.slice(2));
  if (!cutoff) {
    process.stderr.write("Error: --cutoff <ISO-8601-timestamp> is required\n");
    return 1;
  }
  const cutoffDate = new Date(cutoff);
  if (isNaN(cutoffDate.getTime())) {
    process.stderr.write(`Error: Invalid cutoff ISO timestamp: ${cutoff}\n`);
    return 1;
  }

  try {
    const analysis = await analyzeParserHistory({ cutoff, home });
    console.log(JSON.stringify(analysis, null, 2));
    return 0;
  } catch (error) {
    process.stderr.write(`Error: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}

if (import.meta.main) {
  process.exit(await main());
}
