import { mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  DEFAULT_MODEL,
  FEEDBACK_VARIANT_HASHES,
  REQUIRED_RUNTIME_VERSION,
  SCENARIO_DEFINITION_HASH,
  runTrial,
  type FeedbackArm,
  type TrialReceipt,
  validateTrialReceipt,
} from "./deny-replan-usefulness-trial";

/** Paired A/B trial for the old one-line feedback versus current guidance. */

export const DEFAULT_OUTPUT_DIRECTORY = resolve(process.cwd(), "eval-results/deny-replan-ab");
export const AB_METRICS = [
  "attempted_blocks",
  "model_retries",
  "native_tool_recoveries",
  "budget_exhaustions",
  "task_completions",
  "task_abandonments",
] as const;
export const AB_TELEMETRY_METRICS = [
  "target_attempts",
  "target_blocks",
  "target_recoveries",
  "target_repeated_calls",
  "pipeline_attempts",
  "pipeline_blocks",
  "pipeline_recoveries",
  "target_next_read",
  "target_next_glob",
  "target_next_grep",
  "target_next_bash",
  "target_next_other",
  "target_next_none",
] as const;
export const ALL_AB_METRICS = [...AB_METRICS, ...AB_TELEMETRY_METRICS] as const;
export type ABMetric = (typeof ALL_AB_METRICS)[number];

export interface ABRun {
  readonly repetition: number;
  readonly arm: FeedbackArm;
  readonly feedback_arm: FeedbackArm;
  readonly feedback_variant_hash: string;
  readonly global_config_hash: string;
  readonly receipt_file: string;
  readonly counters: Readonly<Record<ABMetric, number>>;
  readonly terminal_outcomes: TrialReceipt["terminal_outcomes"];
  readonly global_config_hashes_equal: boolean;
  readonly owner_opt_in: false;
  readonly model_approval_qualified: false;
}

export interface ABAverageSummary {
  readonly runs: number;
  readonly totals: Readonly<Record<ABMetric, number>>;
  readonly averages: Readonly<Record<ABMetric, number>>;
}

export interface ABTrialReceipt {
  readonly schema_version: "deny-replan-ab/v4" | "deny-replan-ab/v5";
  readonly runtime: typeof REQUIRED_RUNTIME_VERSION;
  readonly scenario_count: 7;
  readonly repetitions: number;
  readonly order: "alternate" | "control-first" | "treatment-first";
  readonly comparison: "legacy-vs-catalog" | "bare-microplan-vs-enriched-catalog" | "enriched-catalog-vs-compact-catalog";
  readonly runs: readonly ABRun[];
  /** Summaries retain the historical control/treatment labels; comparison identifies which feedback arm treatment used. */
  readonly arms: Readonly<Pick<Record<FeedbackArm, ABAverageSummary>, "control" | "treatment">>;
  readonly treatment_minus_control: Readonly<Record<ABMetric, number>>;
  readonly all_global_config_hashes_equal: boolean;
  readonly owner_opt_in: false;
  readonly model_approval_qualified: false;
  readonly scenario_definition_hash: string;
  readonly feedback_variant_hashes: Readonly<Record<string, string>>;
}

export interface ABTrialOptions {
  readonly confirm?: boolean;
  readonly fake?: boolean;
  readonly repeats?: number;
  readonly outputDirectory?: string;
  readonly overwrite?: boolean;
  readonly scenarioTimeoutMs?: number;
  readonly model?: string;
  readonly order?: ABTrialReceipt["order"];
  readonly comparison?: ABTrialReceipt["comparison"];
}

const integer = (value: string, minimum: number, maximum: number): number => {
  if (!/^\d+$/.test(value)) throw new Error("expected a bounded integer");
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) throw new Error("integer is outside the allowed range");
  return parsed;
};

function counters(receipt: TrialReceipt): Readonly<Record<ABMetric, number>> {
  const scenarios = receipt.scenarios;
  const target = scenarios.filter((scenario) => scenario.first_bash_matches_expected);
  const pipeline = scenarios.filter((scenario) => scenario.first_bash_pipeline);
  const values: Record<ABMetric, number> = {
    attempted_blocks: receipt.attempted_blocks,
    model_retries: receipt.model_retries,
    native_tool_recoveries: receipt.native_tool_recoveries,
    budget_exhaustions: receipt.budget_exhaustions,
    task_completions: receipt.task_completions,
    task_abandonments: receipt.task_abandonments,
    target_attempts: target.length,
    target_blocks: target.filter((scenario) => scenario.replan_block_observed).length,
    target_recoveries: target.filter((scenario) => scenario.replan_block_observed && scenario.terminal_outcome === "native_tool_recovery").length,
    target_repeated_calls: scenarios.reduce((sum, scenario) => sum + Math.max(0, scenario.bash_target_call_count - 1), 0),
    pipeline_attempts: pipeline.length,
    pipeline_blocks: pipeline.filter((scenario) => scenario.replan_block_observed).length,
    pipeline_recoveries: pipeline.filter((scenario) => scenario.replan_block_observed && scenario.terminal_outcome === "native_tool_recovery").length,
    target_next_read: target.filter((scenario) => scenario.replan_block_observed && scenario.first_tool_after_target === "read").length,
    target_next_glob: target.filter((scenario) => scenario.replan_block_observed && scenario.first_tool_after_target === "glob").length,
    target_next_grep: target.filter((scenario) => scenario.replan_block_observed && scenario.first_tool_after_target === "grep").length,
    target_next_bash: target.filter((scenario) => scenario.replan_block_observed && scenario.first_tool_after_target === "bash").length,
    target_next_other: target.filter((scenario) => scenario.replan_block_observed && scenario.first_tool_after_target === "other").length,
    target_next_none: target.filter((scenario) => scenario.replan_block_observed && scenario.first_tool_after_target === "none").length,
  };
  return values;
}

function makeSummary(runs: readonly ABRun[]): ABAverageSummary {
  const totals = Object.fromEntries(ALL_AB_METRICS.map((key) => [key, runs.reduce((sum, run) => sum + run.counters[key], 0)])) as Record<ABMetric, number>;
  const averages = Object.fromEntries(ALL_AB_METRICS.map((key) => [key, Number((totals[key] / runs.length).toFixed(3))])) as Record<ABMetric, number>;
  return { runs: runs.length, totals, averages };
}

export function validateABReceipt(value: unknown): ABTrialReceipt {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("A/B receipt is not an object");
  const candidate = value as Record<string, unknown>;
  const version = candidate.schema_version;
  const isV4 = version === "deny-replan-ab/v4";
  if ((!isV4 && version !== "deny-replan-ab/v5") || candidate.runtime !== REQUIRED_RUNTIME_VERSION || candidate.scenario_count !== 7 || candidate.owner_opt_in !== false || candidate.model_approval_qualified !== false || !["legacy-vs-catalog", "bare-microplan-vs-enriched-catalog", "enriched-catalog-vs-compact-catalog"].includes(String(candidate.comparison)) || (isV4 && candidate.comparison === "enriched-catalog-vs-compact-catalog")) throw new Error("A/B receipt metadata is invalid");
  if (typeof candidate.scenario_definition_hash !== "string" || !/^[a-f0-9]{64}$/.test(candidate.scenario_definition_hash)) throw new Error("A/B definition hash is invalid");
  if (candidate.scenario_definition_hash !== SCENARIO_DEFINITION_HASH) throw new Error("A/B definition hash does not match current frozen scenarios");
  const hashes = candidate.feedback_variant_hashes;
  const requiredHashes = isV4 ? ["control", "catalog", "historical_bare"] : ["control", "catalog", "historical_bare", "compact_catalog"];
  if (!hashes || typeof hashes !== "object" || Array.isArray(hashes) || !requiredHashes.every((key) => typeof (hashes as Record<string, unknown>)[key] === "string" && /^[a-f0-9]{64}$/.test((hashes as Record<string, unknown>)[key] as string))) throw new Error("A/B feedback hashes are invalid");
  const expectedHashes = isV4 ? { control: FEEDBACK_VARIANT_HASHES.control, catalog: FEEDBACK_VARIANT_HASHES.catalog, historical_bare: FEEDBACK_VARIANT_HASHES.historical_bare } : FEEDBACK_VARIANT_HASHES;
  if (JSON.stringify(hashes) !== JSON.stringify(expectedHashes)) throw new Error("A/B feedback hashes do not match current variants");
  if (!Number.isInteger(candidate.repetitions) || Number(candidate.repetitions) < 1 || Number(candidate.repetitions) > 5) throw new Error("A/B repetition count is invalid");
  if (!["alternate", "control-first", "treatment-first"].includes(String(candidate.order))) throw new Error("A/B order is invalid");
  if (!Array.isArray(candidate.runs) || candidate.runs.length !== Number(candidate.repetitions) * 2) throw new Error("A/B run count is invalid");
  for (const item of candidate.runs) {
    if (!item || typeof item !== "object" || !["control", "treatment"].includes(String((item as Record<string, unknown>).arm)) || !["control", "treatment", "historical_bare", "compact_catalog"].includes(String((item as Record<string, unknown>).feedback_arm)) || (isV4 && (item as Record<string, unknown>).feedback_arm === "compact_catalog")) throw new Error("A/B run arm is invalid");
    const run = item as Record<string, unknown>;
    if (!Number.isInteger(run.repetition) || Number(run.repetition) < 1 || Number(run.repetition) > Number(candidate.repetitions)) throw new Error("A/B run repetition is invalid");
    if (typeof run.receipt_file !== "string" || !/^(?:control|treatment)-[1-5]\.json$/.test(run.receipt_file)) throw new Error("A/B receipt filename is invalid");
    if (run.global_config_hashes_equal !== true || run.owner_opt_in !== false || run.model_approval_qualified !== false || !/^(?:absent|[a-f0-9]{64})$/.test(String(run.global_config_hash)) || !Object.values(expectedHashes).includes(String(run.feedback_variant_hash))) throw new Error("A/B run safety metadata is invalid");
    const expectedFeedbackArm = candidate.comparison === "bare-microplan-vs-enriched-catalog" ? (run.arm === "control" ? "historical_bare" : "treatment") : candidate.comparison === "enriched-catalog-vs-compact-catalog" ? (run.arm === "control" ? "treatment" : "compact_catalog") : (run.arm === "control" ? "control" : "treatment");
    if (run.feedback_arm !== expectedFeedbackArm) throw new Error("A/B feedback arm does not match comparison");
    const expectedFeedbackHash = expectedFeedbackArm === "treatment" ? FEEDBACK_VARIANT_HASHES.catalog : FEEDBACK_VARIANT_HASHES[expectedFeedbackArm];
    if (run.feedback_variant_hash !== expectedFeedbackHash) throw new Error("A/B feedback hash does not match feedback arm");
    const runCounters = run.counters;
    if (!runCounters || typeof runCounters !== "object" || Array.isArray(runCounters)) throw new Error("A/B counters are missing");
    for (const key of ALL_AB_METRICS) if (!Number.isInteger((runCounters as Record<string, unknown>)[key]) || Number((runCounters as Record<string, unknown>)[key]) < 0) throw new Error(`A/B counter is invalid: ${key}`);
  }
  const runs = candidate.runs as ABRun[];
  const expectedControl = makeSummary(runs.filter((run) => run.arm === "control"));
  const expectedTreatment = makeSummary(runs.filter((run) => run.arm === "treatment"));
  const arms = candidate.arms as Record<string, ABAverageSummary>;
  if (!arms || JSON.stringify(arms.control) !== JSON.stringify(expectedControl) || JSON.stringify(arms.treatment) !== JSON.stringify(expectedTreatment)) throw new Error("A/B arm summaries do not match runs");
  const expectedDelta = Object.fromEntries(ALL_AB_METRICS.map((key) => [key, Number((expectedTreatment.averages[key] - expectedControl.averages[key]).toFixed(3))]));
  if (JSON.stringify(candidate.treatment_minus_control) !== JSON.stringify(expectedDelta)) throw new Error("A/B delta does not match runs");
  const hashesEqual = runs.every((run) => run.global_config_hash === runs[0]?.global_config_hash);
  if (candidate.all_global_config_hashes_equal !== hashesEqual || !hashesEqual) throw new Error("A/B global configuration check failed");
  return candidate as unknown as ABTrialReceipt;
}

function armOrder(repetition: number, order: ABTrialReceipt["order"]): readonly FeedbackArm[] {
  if (order === "control-first") return ["control", "treatment"];
  if (order === "treatment-first") return ["treatment", "control"];
  return repetition % 2 === 1 ? ["control", "treatment"] : ["treatment", "control"];
}

function buildReceipt(runs: readonly ABRun[], repetitions: number, order: ABTrialReceipt["order"], comparison: ABTrialReceipt["comparison"]): ABTrialReceipt {
  const control = runs.filter((run) => run.arm === "control");
  const treatment = runs.filter((run) => run.arm === "treatment");
  const arms = { control: makeSummary(control), treatment: makeSummary(treatment) };
  const treatment_minus_control = Object.fromEntries(ALL_AB_METRICS.map((key) => [key, Number((arms.treatment.averages[key] - arms.control.averages[key]).toFixed(3))])) as Record<ABMetric, number>;
  const receipt: ABTrialReceipt = {
    schema_version: "deny-replan-ab/v5",
    runtime: REQUIRED_RUNTIME_VERSION,
    scenario_count: 7,
    repetitions,
    order,
    comparison,
    runs,
    arms,
    treatment_minus_control,
    all_global_config_hashes_equal: runs.every((run) => run.global_config_hash === runs[0]?.global_config_hash),
    owner_opt_in: false,
    model_approval_qualified: false,
    scenario_definition_hash: SCENARIO_DEFINITION_HASH,
    feedback_variant_hashes: FEEDBACK_VARIANT_HASHES,
  };
  return validateABReceipt(receipt);
}

async function writeJSON(path: string, value: unknown, overwrite: boolean): Promise<void> {
  await mkdir(resolve(path, ".."), { recursive: true });
  if (!overwrite) {
    const existing = await Bun.file(path).exists();
    if (existing) throw new Error(`output already exists: ${path}; use --overwrite`);
  }
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}

export async function runABTrial(options: ABTrialOptions = {}): Promise<ABTrialReceipt> {
  const repetitions = options.repeats ?? 1;
  if (!Number.isInteger(repetitions) || repetitions < 1 || repetitions > 5) throw new Error("repeats must be 1..5");
  const order = options.order ?? "alternate";
  const comparison = options.comparison ?? "legacy-vs-catalog";
  const outputDirectory = resolve(options.outputDirectory ?? DEFAULT_OUTPUT_DIRECTORY);
  const runs: ABRun[] = [];
  for (let repetition = 1; repetition <= repetitions; repetition += 1) {
    for (const arm of armOrder(repetition, order)) {
      const receiptFile = `${arm}-${repetition}.json`;
      const receiptPath = join(outputDirectory, receiptFile);
      process.stderr.write(`[deny-replan-ab] repetition ${repetition}/${repetitions} arm=${arm} starting\n`);
      const feedbackArm: FeedbackArm = comparison === "bare-microplan-vs-enriched-catalog" ? (arm === "control" ? "historical_bare" : "treatment") : comparison === "enriched-catalog-vs-compact-catalog" ? (arm === "control" ? "treatment" : "compact_catalog") : arm;
      const receipt = await runTrial({
        fake: options.fake,
        confirm: options.confirm,
        overwrite: options.overwrite === true,
        output: receiptPath,
        scenarioTimeoutMs: options.scenarioTimeoutMs,
        model: options.model ?? DEFAULT_MODEL,
        feedbackArm,
      });
      validateTrialReceipt(receipt);
      runs.push({
        repetition,
        arm,
        feedback_arm: feedbackArm,
        feedback_variant_hash: receipt.feedback_variant_hash,
        global_config_hash: receipt.global_config_before_hash,
        receipt_file: receiptFile,
        counters: counters(receipt),
        terminal_outcomes: receipt.terminal_outcomes,
        global_config_hashes_equal: receipt.global_config_before_hash === receipt.global_config_after_hash,
        owner_opt_in: receipt.owner_opt_in,
        model_approval_qualified: receipt.model_approval_qualified,
      });
      process.stderr.write(`[deny-replan-ab] repetition ${repetition}/${repetitions} arm=${arm} complete\n`);
    }
  }
  const result = buildReceipt(runs, repetitions, order, comparison);
  await writeJSON(join(outputDirectory, "ab-summary.json"), result, options.overwrite === true);
  return result;
}

function parseArgs(argv: readonly string[]): ABTrialOptions & { readonly help: boolean } {
  const options: { confirm?: boolean; fake?: boolean; repeats?: number; outputDirectory?: string; overwrite?: boolean; scenarioTimeoutMs?: number; model?: string; order?: ABTrialReceipt["order"]; comparison?: ABTrialReceipt["comparison"]; help: boolean } = { help: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]!;
    if (arg === "--help" || arg === "-h") { options.help = true; continue; }
    if (arg === "--confirm") { options.confirm = true; continue; }
    if (arg === "--fake") { options.fake = true; continue; }
    if (arg === "--overwrite") { options.overwrite = true; continue; }
    if (arg === "--repeats") { options.repeats = integer(argv[++index] ?? "", 1, 5); continue; }
    if (arg === "--timeout-ms") { options.scenarioTimeoutMs = integer(argv[++index] ?? "", 10_000, 300_000); continue; }
    if (arg === "--output-dir") { const next = argv[++index]; if (!next) throw new Error("--output-dir requires a path"); options.outputDirectory = resolve(next); continue; }
    if (arg === "--model") { const next = argv[++index]; if (!next) throw new Error("--model requires provider/model"); options.model = next; continue; }
    if (arg === "--order") { const next = argv[++index]; if (next !== "alternate" && next !== "control-first" && next !== "treatment-first") throw new Error("--order must be alternate, control-first, or treatment-first"); options.order = next; continue; }
    if (arg === "--comparison") { const next = argv[++index]; if (next !== "legacy-vs-catalog" && next !== "bare-microplan-vs-enriched-catalog" && next !== "enriched-catalog-vs-compact-catalog") throw new Error("--comparison must be legacy-vs-catalog, bare-microplan-vs-enriched-catalog, or enriched-catalog-vs-compact-catalog"); options.comparison = next; continue; }
    throw new Error(`unknown option: ${arg}`);
  }
  return options;
}

function printHelp(): void {
  process.stdout.write("Usage: bun run scripts/deny-replan-ab-trial.ts --confirm [options]\n\n");
  process.stdout.write("  --confirm       explicit owner authorization for real paired runs\n");
  process.stdout.write("  --fake          provider-free validation run\n");
  process.stdout.write("  --repeats N     paired repetitions, 1..5 (default 1)\n");
  process.stdout.write("  --timeout-ms N  per-scenario timeout, 10000..300000\n");
  process.stdout.write("  --output-dir P  receipt directory\n");
  process.stdout.write("  --order MODE    alternate, control-first, or treatment-first\n");
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  try {
    const options = parseArgs(argv);
    if (options.help) { printHelp(); return 0; }
    if (!options.fake && options.confirm !== true) throw new Error("real A/B trial requires explicit --confirm");
    const result = await runABTrial(options);
    process.stdout.write(`${JSON.stringify({ schema_version: result.schema_version, repetitions: result.repetitions, treatment_minus_control: result.treatment_minus_control })}\n`);
    return 0;
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "A/B trial failed"}\n`);
    return 1;
  }
}

if (import.meta.main) process.exit(await main());
