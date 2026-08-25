/**
 * Routing-equivalence snapshot for the development corpus.
 *
 * A frozen candidate binds a SHA-256 hash over every file in
 * `SOURCE_MANIFEST_FILES`, so editing any listed file invalidates the freeze
 * whether or not the edit can move a single measurement. That check is coarse
 * by design and cannot distinguish an inert change from a meaningful one.
 *
 * This tool answers the narrower question: across the development corpus,
 * would the model receive byte-identical input over the same set of fixtures
 * before and after a change? It records two digests per snapshot.
 *
 * - `reviewerInput` covers what the model actually sees: which fixtures route
 *   to the reviewer at all, and for each of those the exact system prompt,
 *   data prompt, output schema, temperature, model identity, and tool and
 *   permission denials. If this digest is unchanged, a fresh draw would
 *   re-measure an identical experiment.
 * - `policy` covers the full deterministic result including internals the
 *   reviewer never sees. It is deliberately over-sensitive: it fails toward
 *   "re-run", which is the safe direction.
 * - `acceptance` covers what turns observations into a verdict: the corpus
 *   labels a draw scores against, the per-category minimums, and the timing
 *   and concurrency thresholds. Identical model input can still produce a
 *   different pass/fail if these move, and `MAX_P95_MS` in particular is
 *   pinned by nothing else the checker reads.
 *
 * The three `errorPath` fixtures are forced to a deterministic manual outcome
 * by the draw regardless of what policy returns, so their measured behavior is
 * invariant while their underlying policy result is not. Both are recorded:
 * `measured` is what a draw would observe, `policy` is what could drift
 * silently underneath it.
 *
 * What no digest can settle is the threshold *logic* inside
 * `assertCorpusReport`. A rewrite of how a minimum is applied changes the
 * verdict with every recorded input unchanged.
 *
 * This tool changes no gate. INV-7 still requires a fresh draw against a
 * source-current candidate; TASK-029 covers the contract change that would let
 * a matching snapshot substitute for one.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { evaluateDeterministicPolicy } from "../../src/policy/deterministic";
import { buildReviewerContract } from "../../src/reviewer/contract";
import { ACTIVE_PRODUCTION_PROFILE, type ModelProfile } from "../../src/reviewer/model-profile";
import type { ReviewerPathClass } from "../../src/reviewer/prompt";
import { loadDevelopmentCorpus } from "../classifier-gate";
import {
  canonical,
  MAX_CONCURRENT_REVIEWERS,
  MAX_P95_MS,
  MINIMUMS,
  REPEAT_COUNT,
  REVIEW_TIMEOUT_MS,
  sha256,
  TEMPERATURE,
  type Fixture,
  type FixtureCategory,
  type Route,
} from "./core";

const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const DEVELOPMENT_CORPUS_PATH = resolve(PROJECT_ROOT, "fixtures/eval/development.json");

/** Committed so routing drift is visible in review; `eval-results/` is gitignored. */
export const DEFAULT_BASELINE_PATH = resolve(PROJECT_ROOT, "fixtures/eval/routing-equivalence-baseline.json");
export const ROUTING_EQUIVALENCE_SCHEMA_VERSION = "routing-equivalence/v1" as const;

/** Stand-ins for per-run contract fields the model never sees. */
const STABLE_COORDINATOR_ID = "coord_00000000-0000-0000-0000-000000000000";

export interface MeasuredRouting {
  /** The route a draw records, after `errorPath` forcing. */
  readonly route: Route;
  /** Null when the reviewer decides; the policy layer never grants. */
  readonly decision: "manual" | null;
  readonly reasonCodes: readonly string[];
  /** True when the draw overrides the policy result for a safety-routing fixture. */
  readonly forced: boolean;
}

export interface PolicyRouting {
  readonly status: string;
  readonly decision: string;
  readonly reasonCodes: readonly string[];
  readonly pathClasses: readonly string[] | null;
  readonly parseOk: boolean;
  readonly parseReason: string | null;
  readonly features: Record<string, unknown> | null;
}

export interface ReviewerInput {
  readonly system: string;
  readonly prompt: string;
  readonly schema: unknown;
  readonly temperature: number;
  readonly requestedModel: string;
  readonly requestedVariant: string | null;
  readonly tools: unknown;
  readonly permissions: unknown;
}

export interface RoutingEntry {
  readonly id: string;
  readonly category: string;
  /** The corpus label a draw scores the observation against. */
  readonly expectedDecision: string;
  readonly errorPath: boolean;
  readonly measured: MeasuredRouting;
  readonly policy: PolicyRouting;
  /** Null when the fixture never reaches a provider. */
  readonly reviewerInput: ReviewerInput | null;
  /** Set when the bounded prompt envelope rejected the payload. */
  readonly reviewerInputError: string | null;
}

export interface RoutingEquivalenceSnapshot {
  readonly schemaVersion: typeof ROUTING_EQUIVALENCE_SCHEMA_VERSION;
  readonly profile: ModelProfile;
  /** The same six the frozen candidate's source manifest records. */
  readonly parameters: {
    readonly temperature: number;
    readonly repeats: number;
    readonly timeoutMs: number;
    readonly maxP95Ms: number;
    readonly maxConcurrentReviewers: number;
  };
  readonly minimums: Record<FixtureCategory, number>;
  readonly developmentCorpusHash: string;
  readonly entries: readonly RoutingEntry[];
  readonly digests: {
    readonly reviewerInput: string;
    readonly policy: string;
    readonly acceptance: string;
  };
}

function reviewerInputFor(
  fixture: Fixture,
  pathClasses: readonly ReviewerPathClass[],
  features: Record<string, boolean | number | string | readonly string[]> | undefined,
  profile: ModelProfile,
): { readonly input: ReviewerInput | null; readonly error: string | null } {
  try {
    // Mirrors the draw's reviewer call in scripts/classifier-gate.ts.
    const contract = buildReviewerContract({
      coordinatorID: STABLE_COORDINATOR_ID,
      providerID: profile.providerID,
      modelID: profile.modelID,
      ...(profile.requestedVariant === null ? {} : { requestedVariant: profile.requestedVariant }),
      timeoutMs: REVIEW_TIMEOUT_MS,
      prompt: fixture.command,
      redactedCommand: fixture.command,
      ...(features ? { parserFeatures: features } : {}),
      policyFacts: ["model_review", "parser.clear", "privacy.clear", ...pathClasses.map((value) => `path.${value}`)],
      pathClasses,
    });
    return {
      input: {
        system: contract.system,
        prompt: contract.prompt,
        schema: contract.schema,
        temperature: contract.temperature,
        requestedModel: contract.requestedModel,
        requestedVariant: contract.requestedVariant ?? null,
        tools: contract.tools,
        permissions: contract.permissions,
      },
      error: null,
    };
  } catch (error) {
    return { input: null, error: error instanceof Error ? error.message : "reviewer contract failed" };
  }
}

/** Evaluate every development fixture through the deterministic layer exactly as a draw does. */
export async function buildRoutingEquivalenceSnapshot(
  profile: ModelProfile = ACTIVE_PRODUCTION_PROFILE,
): Promise<RoutingEquivalenceSnapshot> {
  const { corpus } = loadDevelopmentCorpus(DEVELOPMENT_CORPUS_PATH);
  const entries: RoutingEntry[] = [];
  for (const fixture of corpus.fixtures) {
    const deterministic = await evaluateDeterministicPolicy(fixture.command, {
      pathIdentity: { cwd: PROJECT_ROOT, ownedRoot: PROJECT_ROOT },
    });
    const errorPath = fixture.errorPath === true;
    const routesToReviewer = !errorPath && deterministic.status === "model_review";
    const pathClasses = (deterministic.pathClasses ?? ["unknown"]) as readonly ReviewerPathClass[];
    const features = deterministic.parse?.features ? { ...deterministic.parse.features } : undefined;
    const reviewer = routesToReviewer
      ? reviewerInputFor(fixture, pathClasses, features, profile)
      : { input: null, error: null };
    entries.push({
      id: fixture.id,
      category: fixture.category,
      expectedDecision: fixture.expectedDecision,
      errorPath,
      measured: errorPath
        ? { route: "deterministic", decision: "manual", reasonCodes: ["policy_error"], forced: true }
        : {
            route: routesToReviewer ? "reviewer" : "deterministic",
            decision: routesToReviewer ? null : "manual",
            // Raw, not the bounded projection a record stores: strictly more
            // sensitive, so it fails toward re-running.
            reasonCodes: [...deterministic.reasonCodes],
            forced: false,
          },
      policy: {
        status: deterministic.status,
        decision: deterministic.decision,
        reasonCodes: [...deterministic.reasonCodes],
        pathClasses: deterministic.pathClasses ? [...deterministic.pathClasses] : null,
        parseOk: deterministic.parse?.ok ?? false,
        parseReason: deterministic.parse && !deterministic.parse.ok ? deterministic.parse.reason : null,
        features: features ?? null,
      },
      reviewerInput: reviewer.input,
      reviewerInputError: reviewer.error,
    });
  }
  entries.sort((left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0);
  const parameters = {
    temperature: TEMPERATURE,
    repeats: REPEAT_COUNT,
    timeoutMs: REVIEW_TIMEOUT_MS,
    maxP95Ms: MAX_P95_MS,
    maxConcurrentReviewers: MAX_CONCURRENT_REVIEWERS,
  };
  const minimums = { ...MINIMUMS };
  const developmentCorpusHash = sha256(readFileSync(DEVELOPMENT_CORPUS_PATH, "utf8"));
  const digests = {
    // Model-visible only. Harness parameters such as maxP95Ms belong to the
    // acceptance digest; folding them in here made the tool claim the model
    // would see different input when it would not.
    reviewerInput: sha256(canonical({
      schemaVersion: ROUTING_EQUIVALENCE_SCHEMA_VERSION,
      profile,
      entries: entries.map((entry) => ({
        id: entry.id,
        route: entry.measured.route,
        reviewerInput: entry.reviewerInput,
        reviewerInputError: entry.reviewerInputError,
      })),
    })),
    policy: sha256(canonical({
      schemaVersion: ROUTING_EQUIVALENCE_SCHEMA_VERSION,
      developmentCorpusHash,
      entries: entries.map((entry) => ({
        id: entry.id,
        category: entry.category,
        expectedDecision: entry.expectedDecision,
        measured: entry.measured,
        policy: entry.policy,
      })),
    })),
    // What turns observations into a verdict. Model input can be byte-identical
    // and the pass/fail still move if any of this does.
    acceptance: sha256(canonical({
      schemaVersion: ROUTING_EQUIVALENCE_SCHEMA_VERSION,
      developmentCorpusHash,
      parameters,
      minimums,
      labels: entries.map((entry) => ({ id: entry.id, category: entry.category, expectedDecision: entry.expectedDecision })),
    })),
  };
  return {
    schemaVersion: ROUTING_EQUIVALENCE_SCHEMA_VERSION,
    profile,
    parameters,
    minimums,
    developmentCorpusHash,
    entries,
    digests,
  };
}

export interface RoutingDifference {
  readonly id: string;
  readonly field: string;
  readonly baseline: string;
  readonly current: string;
}

const ABSENT = "<absent>";

function compareEntries(baseline: RoutingEntry, current: RoutingEntry): RoutingDifference[] {
  const differences: RoutingDifference[] = [];
  const push = (field: string, left: unknown, right: unknown) => {
    const a = canonical(left);
    const b = canonical(right);
    if (a !== b) differences.push({ id: baseline.id, field, baseline: a, current: b });
  };
  push("category", baseline.category, current.category);
  push("expectedDecision", baseline.expectedDecision, current.expectedDecision);
  push("measured.route", baseline.measured.route, current.measured.route);
  push("measured.decision", baseline.measured.decision, current.measured.decision);
  push("measured.reasonCodes", baseline.measured.reasonCodes, current.measured.reasonCodes);
  push("policy.status", baseline.policy.status, current.policy.status);
  push("policy.reasonCodes", baseline.policy.reasonCodes, current.policy.reasonCodes);
  push("policy.pathClasses", baseline.policy.pathClasses, current.policy.pathClasses);
  push("policy.parseOk", baseline.policy.parseOk, current.policy.parseOk);
  push("policy.parseReason", baseline.policy.parseReason, current.policy.parseReason);
  push("policy.features", baseline.policy.features, current.policy.features);
  push("reviewerInputError", baseline.reviewerInputError, current.reviewerInputError);
  if (baseline.reviewerInput === null || current.reviewerInput === null) {
    push("reviewerInput", baseline.reviewerInput === null ? null : "<present>", current.reviewerInput === null ? null : "<present>");
    return differences;
  }
  for (const key of Object.keys(baseline.reviewerInput).sort()) {
    push(`reviewerInput.${key}`, baseline.reviewerInput[key as keyof ReviewerInput], current.reviewerInput[key as keyof ReviewerInput]);
  }
  return differences;
}

/** Per-fixture differences between two snapshots, including added and removed fixtures. */
export function diffSnapshots(
  baseline: RoutingEquivalenceSnapshot,
  current: RoutingEquivalenceSnapshot,
): readonly RoutingDifference[] {
  const differences: RoutingDifference[] = [];
  if (canonical(baseline.profile) !== canonical(current.profile)) {
    differences.push({ id: "<snapshot>", field: "profile", baseline: canonical(baseline.profile), current: canonical(current.profile) });
  }
  if (canonical(baseline.parameters) !== canonical(current.parameters)) {
    differences.push({ id: "<snapshot>", field: "parameters", baseline: canonical(baseline.parameters), current: canonical(current.parameters) });
  }
  if (canonical(baseline.minimums) !== canonical(current.minimums)) {
    differences.push({ id: "<snapshot>", field: "minimums", baseline: canonical(baseline.minimums), current: canonical(current.minimums) });
  }
  if (baseline.developmentCorpusHash !== current.developmentCorpusHash) {
    differences.push({ id: "<snapshot>", field: "developmentCorpusHash", baseline: baseline.developmentCorpusHash, current: current.developmentCorpusHash });
  }
  const currentByID = new Map(current.entries.map((entry) => [entry.id, entry]));
  for (const entry of baseline.entries) {
    const match = currentByID.get(entry.id);
    if (!match) {
      differences.push({ id: entry.id, field: "fixture", baseline: "<present>", current: ABSENT });
      continue;
    }
    differences.push(...compareEntries(entry, match));
  }
  const baselineIDs = new Set(baseline.entries.map((entry) => entry.id));
  for (const entry of current.entries) {
    if (!baselineIDs.has(entry.id)) differences.push({ id: entry.id, field: "fixture", baseline: ABSENT, current: "<present>" });
  }
  return differences;
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null;

/** Reject anything that is not a snapshot this build can compare against. */
export function parseSnapshot(value: unknown): RoutingEquivalenceSnapshot {
  if (!isRecord(value)) throw new Error("routing-equivalence snapshot is not an object");
  if (value.schemaVersion !== ROUTING_EQUIVALENCE_SCHEMA_VERSION) throw new Error("routing-equivalence snapshot schema version is unsupported");
  if (!Array.isArray(value.entries)) throw new Error("routing-equivalence snapshot has no entries");
  if (!isRecord(value.digests) || typeof value.digests.reviewerInput !== "string" || typeof value.digests.policy !== "string" || typeof value.digests.acceptance !== "string") {
    throw new Error("routing-equivalence snapshot has no digests");
  }
  if (!isRecord(value.minimums)) throw new Error("routing-equivalence snapshot has no minimums");
  return value as unknown as RoutingEquivalenceSnapshot;
}

export function readSnapshot(path: string): RoutingEquivalenceSnapshot {
  return parseSnapshot(JSON.parse(readFileSync(path, "utf8")));
}

export function writeSnapshot(path: string, snapshot: RoutingEquivalenceSnapshot): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(snapshot, null, 2)}\n`, "utf8");
}

function usage(): string {
  return [
    "usage: bun run scripts/qualification/routing-equivalence.ts [--write [path] | --check [path]]",
    "",
    "  --write [path]  record a baseline snapshot (default: fixtures/eval/routing-equivalence-baseline.json)",
    "  --check [path]  compare the working tree against a baseline; exit 1 on any difference",
    "",
    "Digests: reviewerInput (what the model sees), policy (deterministic internals,",
    "over-sensitive), acceptance (corpus labels, minimums, and thresholds a verdict uses).",
    "",
    "This tool changes no gate. A matching snapshot does not satisfy INV-7 on its own.",
  ].join("\n");
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const mode = argv[0] ?? "--check";
  if (mode === "--help" || mode === "-h") {
    console.log(usage());
    return 0;
  }
  if (mode !== "--write" && mode !== "--check") {
    console.error(usage());
    return 2;
  }
  const path = argv[1] ? resolve(process.cwd(), argv[1]) : DEFAULT_BASELINE_PATH;
  const current = await buildRoutingEquivalenceSnapshot();
  if (mode === "--write") {
    writeSnapshot(path, current);
    console.log(`routing-equivalence baseline written: ${path}`);
    console.log(`  reviewer-input digest: ${current.digests.reviewerInput}`);
    console.log(`  policy digest:         ${current.digests.policy}`);
    console.log(`  acceptance digest:     ${current.digests.acceptance}`);
    console.log(`  reviewer-routed:       ${current.entries.filter((entry) => entry.measured.route === "reviewer").length}/${current.entries.length} fixtures`);
    return 0;
  }
  let baseline: RoutingEquivalenceSnapshot;
  try {
    baseline = readSnapshot(path);
  } catch (error) {
    console.error(`routing-equivalence baseline unreadable: ${error instanceof Error ? error.message : "unknown error"}`);
    console.error(`  record one with: bun run scripts/qualification/routing-equivalence.ts --write ${path}`);
    return 1;
  }
  const differences = diffSnapshots(baseline, current);
  const reviewerInputMatches = baseline.digests.reviewerInput === current.digests.reviewerInput;
  const policyMatches = baseline.digests.policy === current.digests.policy;
  const acceptanceMatches = baseline.digests.acceptance === current.digests.acceptance;
  if (reviewerInputMatches && policyMatches && acceptanceMatches && differences.length === 0) {
    console.log("routing-equivalence: identical");
    console.log(`  reviewer-input digest: ${current.digests.reviewerInput}`);
    console.log(`  policy digest:         ${current.digests.policy}`);
    console.log(`  acceptance digest:     ${current.digests.acceptance}`);
    console.log("  A draw against this tree would re-measure the same experiment and score it the same way.");
    console.log("  This does not satisfy INV-7 on its own; see TASK-029.");
    return 0;
  }
  console.error(!reviewerInputMatches
    ? "routing-equivalence: reviewer input CHANGED — the model would see different input"
    : !acceptanceMatches
      ? "routing-equivalence: reviewer input identical, but the acceptance criteria changed"
      : "routing-equivalence: reviewer input identical, deterministic internals changed");
  console.error(`  reviewer-input digest: ${baseline.digests.reviewerInput} -> ${current.digests.reviewerInput}`);
  console.error(`  policy digest:         ${baseline.digests.policy} -> ${current.digests.policy}`);
  console.error(`  acceptance digest:     ${baseline.digests.acceptance} -> ${current.digests.acceptance}`);
  if (!acceptanceMatches && differences.length === 0) {
    console.error("  No recorded per-fixture value moved; a threshold or minimum did.");
  }
  const affected = new Set(differences.map((difference) => difference.id));
  console.error(`  ${differences.length} difference(s) across ${affected.size} fixture(s):`);
  for (const difference of differences) {
    const left = difference.baseline.length > 160 ? `${difference.baseline.slice(0, 160)}…` : difference.baseline;
    const right = difference.current.length > 160 ? `${difference.current.slice(0, 160)}…` : difference.current;
    console.error(`    ${difference.id} ${difference.field}: ${left} -> ${right}`);
  }
  if (reviewerInputMatches) {
    console.error("  No reviewer-visible input moved, but this tool authorizes nothing on its own; see TASK-029.");
  }
  return 1;
}

if (import.meta.main) process.exit(await main());
