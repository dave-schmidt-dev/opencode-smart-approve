import { accessSync, constants, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { createOpencodeClient } from "@opencode-ai/sdk";
import { evaluateDeterministicPolicy } from "../src/policy/deterministic";
import { createReviewerAgent, REVIEWER_MODEL, REVIEWER_VARIANT, type ReviewerSessionClient } from "../src/reviewer/agent";
import {
  CATEGORIES,
  MAX_CONCURRENT_REVIEWERS,
  MAX_P95_MS,
  MINIMUMS,
  QUALIFICATION_MODEL,
  QUALIFICATION_SCHEMA_VERSION,
  QUALIFICATION_VARIANT,
  REPEAT_COUNT,
  REQUIRED_OPENCODE_VERSION,
  REVIEW_TIMEOUT_MS,
  ROUTE_PROVIDER_MATRIX,
  TEMPERATURE,
  THRESHOLD_STATEMENT,
  assertCorpusReport,
  assertFaultReport,
  canonical,
  evaluateCorpus,
  evaluateFaults,
  hashQualificationRecord,
  isReasonCode,
  parseCorpus,
  parseDevelopmentFile,
  sha256,
  validateQualificationRecord,
  type Corpus,
  type CorpusBundle,
  type CorpusReport,
  type Decision,
  type EvaluationHashes,
  type Fixture,
  type FaultReport,
  type QualificationArtifactV3,
  type QualificationRecord,
  type QualificationReport,
  type EvaluationSourceManifest,
  type TerminalKind,
} from "./qualification/core";
import { verifySignedConsumptionCommitment, type SignedConsumptionCommitment } from "./qualification/custody";

export * from "./qualification/core";
export * from "./qualification/custody";

export type RecordedInvocation = QualificationRecord;

export const CANDIDATE_SCHEMA_VERSION = "classifier-candidate/v1" as const;
export const UNATTESTED_PROVIDER_REVISION = "unavailable" as const;
export const UNATTESTED_SERVED_VARIANT = "unavailable" as const;
export const DEVELOPMENT_REPORT_SCHEMA_VERSION = "classifier-development-report/v1" as const;

export interface FrozenCandidateManifest {
  readonly schemaVersion: typeof CANDIDATE_SCHEMA_VERSION;
  readonly generatedAt: string;
  readonly candidate: {
    readonly promptProfile: "smart-approve-reviewer/v1";
    readonly model: typeof QUALIFICATION_MODEL;
    readonly requestedAlias: typeof QUALIFICATION_MODEL;
    readonly requestedVariant: typeof QUALIFICATION_VARIANT;
    readonly contractVersion: typeof QUALIFICATION_SCHEMA_VERSION;
    readonly temperature: typeof TEMPERATURE;
    readonly repeats: typeof REPEAT_COUNT;
    readonly timeoutMs: typeof REVIEW_TIMEOUT_MS;
    readonly maxP95Ms: typeof MAX_P95_MS;
    readonly maxConcurrentReviewers: typeof MAX_CONCURRENT_REVIEWERS;
  };
  readonly hashes: EvaluationHashes;
  readonly sourceManifest: EvaluationSourceManifest;
  readonly providerRevision: typeof UNATTESTED_PROVIDER_REVISION;
  readonly servedVariant: typeof UNATTESTED_SERVED_VARIANT;
  readonly spentHeldout: {
    readonly fixtureIDs: readonly [];
    readonly hashes: readonly [];
  };
  readonly manifestHash: string;
}

export type DevelopmentTerminal = "development-pass" | "stop-disabled";
export type DevelopmentFailureCode = "invalid_run" | "threshold" | "runtime";
export type DevelopmentAggregate = Omit<CorpusReport, "records" | "observationIDs">;
export type DevelopmentFaultAggregate = Omit<FaultReport, "observations" | "observationIDs" | "sharedObservationIDs"> & {
  readonly observationCount: number;
};

/** A public development result. It intentionally contains no per-observation arrays or identifiers. */
export interface DevelopmentCandidateReport {
  readonly schemaVersion: typeof DEVELOPMENT_REPORT_SCHEMA_VERSION;
  readonly generatedAt: string;
  readonly terminal: DevelopmentTerminal;
  readonly failureCode?: DevelopmentFailureCode;
  readonly opencodeVersion: typeof REQUIRED_OPENCODE_VERSION;
  readonly model: typeof QUALIFICATION_MODEL;
  readonly variant: typeof QUALIFICATION_VARIANT;
  readonly candidateManifestHash: string;
  readonly hashes: EvaluationHashes;
  readonly sourceManifest: EvaluationSourceManifest;
  readonly contract: {
    readonly version: typeof QUALIFICATION_SCHEMA_VERSION;
    readonly requestedAlias: typeof QUALIFICATION_MODEL;
    readonly requestedVariant: typeof QUALIFICATION_VARIANT;
    readonly temperature: typeof TEMPERATURE;
    readonly repeats: typeof REPEAT_COUNT;
    readonly timeoutMs: typeof REVIEW_TIMEOUT_MS;
    readonly retryCount: 0;
    readonly contractHash: string;
  };
  readonly development: DevelopmentAggregate;
  readonly faults: DevelopmentFaultAggregate;
  readonly aggregateDigest: string;
}

const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DEVELOPMENT_CORPUS_PATH = resolve(PROJECT_ROOT, "fixtures/eval/development.json");
const LEGACY_COMBINED_CORPUS_PATH = resolve(PROJECT_ROOT, "fixtures/eval/corpus.json");
const ARTIFACT_PATH = resolve(PROJECT_ROOT, "eval-results/classifier-qualification.json");
export const FROZEN_CANDIDATE_PATH = resolve(PROJECT_ROOT, "eval-results/frozen-candidate-manifest.json");
export const DEVELOPMENT_REPORT_PATH = resolve(PROJECT_ROOT, "eval-results/development-candidate-report.json");
const OPENCODE_BIN = resolve(PROJECT_ROOT, "node_modules/.bin/opencode");
const QUALIFICATION_CONFIG = JSON.stringify({
  model: QUALIFICATION_MODEL,
  agent: {
    "smart-approve-reviewer": {
      description: "Tool-free command safety reviewer used only for qualification",
      mode: "subagent",
      model: QUALIFICATION_MODEL,
      variant: QUALIFICATION_VARIANT,
      temperature: TEMPERATURE,
      permission: { bash: "deny", edit: "deny", webfetch: "deny", doom_loop: "deny", external_directory: "deny" },
      tools: { "*": false },
    },
  },
});

let developmentCorpusReadCount = 0;
let legacyCombinedCorpusReadCount = 0;
let privateHeldoutByteReadCount = 0;
let cachedRuntimeBinaryHash: string | undefined;

export interface CorpusReadCounters {
  readonly developmentReads: number;
  readonly combinedBundleReads: number;
  readonly privateHeldoutByteReads: number;
}

export function resetCorpusReadCounters(): void {
  developmentCorpusReadCount = 0;
  legacyCombinedCorpusReadCount = 0;
  privateHeldoutByteReadCount = 0;
}

export function getCorpusReadCounters(): CorpusReadCounters {
  return {
    developmentReads: developmentCorpusReadCount,
    combinedBundleReads: legacyCombinedCorpusReadCount,
    privateHeldoutByteReads: privateHeldoutByteReadCount,
  };
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null;
const isReleaseInputName = (value: string): boolean => /(?:heldout|release|private|combined|bundle|corpus)/i.test(value);

function assertDevelopmentInput(path: string): void {
  const normalized = resolve(path);
  if (normalized === LEGACY_COMBINED_CORPUS_PATH || isReleaseInputName(normalized) && normalized !== DEVELOPMENT_CORPUS_PATH) {
    throw new Error("development qualification refuses combined, held-out, private, or release input");
  }
}

/** Load only the public development corpus. This is the active evaluator path. */
export function loadDevelopmentCorpus(path = DEVELOPMENT_CORPUS_PATH): { readonly file: ReturnType<typeof parseDevelopmentFile>; readonly corpus: Corpus } {
  assertDevelopmentInput(path);
  const value: unknown = JSON.parse(readFileSync(path, "utf8"));
  developmentCorpusReadCount += 1;
  const file = parseDevelopmentFile(value);
  return { file, corpus: file.corpus };
}

/**
 * Compatibility-only reader for the historical combined bundle. No active
 * command, hash, or release validator calls this function.
 */
export function loadCorpusBundle(path = LEGACY_COMBINED_CORPUS_PATH): CorpusBundle {
  if (resolve(path) !== LEGACY_COMBINED_CORPUS_PATH) throw new Error("legacy combined corpus path is fixed and diagnostic-only");
  legacyCombinedCorpusReadCount += 1;
  const value: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!isRecord(value) || value.schemaVersion !== "classifier-eval/v1" || value.repeats !== REPEAT_COUNT || value.temperature !== TEMPERATURE || value.timeoutMs !== REVIEW_TIMEOUT_MS) throw new Error("legacy evaluation corpus header is invalid");
  const minimums = value.minimums;
  if (!isRecord(minimums) || CATEGORIES.some((category) => minimums[category] !== MINIMUMS[category])) throw new Error("legacy evaluation corpus minimums are invalid");
  return {
    schemaVersion: "classifier-eval/v1",
    minimums: MINIMUMS,
    repeats: REPEAT_COUNT,
    temperature: TEMPERATURE,
    timeoutMs: REVIEW_TIMEOUT_MS,
    development: parseCorpus("development", value.development),
    heldout: parseCorpus("heldout", value.heldout),
  };
}

/** The private release stream is deliberately unavailable to this command. */
export function loadReleaseCorpus(): never {
  throw new Error("release corpus is custodian-only and unavailable to development evaluation");
}

const hashFiles = (files: readonly string[]): string => sha256(files.map((path) => `${path}\0${readFileSync(resolve(PROJECT_ROOT, path), "utf8")}`).join("\0"));
const hashFile = (path: string): string => sha256(readFileSync(resolve(PROJECT_ROOT, path), "utf8"));
const runtimeBinaryHash = (): string => cachedRuntimeBinaryHash ??= sha256(readFileSync(OPENCODE_BIN).toString("base64"));

const SOURCE_MANIFEST_FILES = [
  "src/approval/coordinator.ts",
  "src/policy/deterministic.ts",
  "src/policy/builtin-rules.ts",
  "src/privacy/secret-scan.ts",
  "src/privacy/sensitive-paths.ts",
  "src/reviewer/contract.ts",
  "src/reviewer/prompt.ts",
  "src/reviewer/schema.ts",
  "src/reviewer/agent.ts",
  "src/reviewer/client.ts",
  "src/plugin.ts",
  "scripts/classifier-gate.ts",
  "scripts/qualification/core.ts",
  "scripts/qualification/custody.ts",
  "scripts/qualification/verify-terminal.ts",
  "fixtures/eval/development.json",
  "fixtures/eval/authoring-rubric.md",
  "fixtures/eval/qualification-artifact-v3.schema.json",
  "fixtures/eval/qualification-fault-report.schema.json",
  "fixtures/eval/development-candidate-report.schema.json",
  "fixtures/eval/frozen-candidate-manifest.schema.json",
  "fixtures/eval/release-manifest.schema.json",
  "fixtures/eval/release-attestation.schema.json",
  "fixtures/eval/qualification-preflight.schema.json",
  "fixtures/eval/terminal-custody-manifest.schema.json",
  "fixtures/eval/terminal-attestation.schema.json",
  "package.json",
] as const;

/** Source/config bindings are staleness checks, never immutable-weight or served-variant attestations. */
export function currentEvaluationSourceManifest(): EvaluationSourceManifest {
  const files = Object.fromEntries(SOURCE_MANIFEST_FILES.map((path) => [path, hashFile(path)]));
  const base = {
    schemaVersion: "qualification-source-manifest/v1" as const,
    binding: "staleness-only" as const,
    immutableModelRevisionAttested: false as const,
    servedVariantAttested: false as const,
    files,
    parameters: {
      model: QUALIFICATION_MODEL,
      variant: QUALIFICATION_VARIANT,
      requestedAlias: QUALIFICATION_MODEL,
      requestedVariant: QUALIFICATION_VARIANT,
      temperature: TEMPERATURE,
      repeats: REPEAT_COUNT,
      timeoutMs: REVIEW_TIMEOUT_MS,
      maxP95Ms: MAX_P95_MS,
      maxConcurrentReviewers: MAX_CONCURRENT_REVIEWERS,
    },
  };
  return { ...base, manifestHash: sha256(canonical(base)) };
}

/** Bind an attended private-stream digest to the signed one-use custody commitment. */
export function validateReleaseStreamCommitment(streamDigest: string, commitment: SignedConsumptionCommitment): boolean {
  return /^[0-9a-f]{64}$/.test(streamDigest) && streamDigest === commitment.corpusDigest && verifySignedConsumptionCommitment(commitment);
}

function candidateBase(generatedAt: string): Omit<FrozenCandidateManifest, "manifestHash"> {
  return {
    schemaVersion: CANDIDATE_SCHEMA_VERSION,
    generatedAt,
    candidate: {
      promptProfile: "smart-approve-reviewer/v1",
      model: QUALIFICATION_MODEL,
      requestedAlias: QUALIFICATION_MODEL,
      requestedVariant: QUALIFICATION_VARIANT,
      contractVersion: QUALIFICATION_SCHEMA_VERSION,
      temperature: TEMPERATURE,
      repeats: REPEAT_COUNT,
      timeoutMs: REVIEW_TIMEOUT_MS,
      maxP95Ms: MAX_P95_MS,
      maxConcurrentReviewers: MAX_CONCURRENT_REVIEWERS,
    },
    hashes: currentEvaluationHashes(),
    sourceManifest: currentEvaluationSourceManifest(),
    providerRevision: UNATTESTED_PROVIDER_REVISION,
    servedVariant: UNATTESTED_SERVED_VARIANT,
    spentHeldout: { fixtureIDs: [], hashes: [] },
  };
}

/** Create the sole source-current candidate; no release identifiers enter it. */
export function createFrozenCandidateManifest(generatedAt = new Date().toISOString()): FrozenCandidateManifest {
  const base = candidateBase(generatedAt);
  return { ...base, manifestHash: sha256(canonical(base)) };
}

/** Validate one frozen candidate against the current checkout without reading release data. */
export function validateFrozenCandidateManifest(value: unknown): FrozenCandidateManifest {
  assertNoSensitiveFields(value);
  if (!isRecord(value) || value.schemaVersion !== CANDIDATE_SCHEMA_VERSION || typeof value.generatedAt !== "string") throw new Error("candidate manifest metadata is invalid");
  const allowedRoot = ["schemaVersion", "generatedAt", "candidate", "hashes", "sourceManifest", "providerRevision", "servedVariant", "spentHeldout", "manifestHash"];
  if (Object.keys(value).some((key) => !allowedRoot.includes(key)) || ["selection", "comparison", "candidates"].some((key) => key in value)) throw new Error("candidate manifest contains a selection or comparison list");
  if (!isRecord(value.candidate)) throw new Error("candidate manifest candidate is missing");
  const allowedCandidate = ["promptProfile", "model", "requestedAlias", "requestedVariant", "contractVersion", "temperature", "repeats", "timeoutMs", "maxP95Ms", "maxConcurrentReviewers"];
  if (Object.keys(value.candidate).some((key) => !allowedCandidate.includes(key))) throw new Error("candidate manifest candidate is not singular");
  if (canonical(value.candidate) !== canonical(candidateBase(value.generatedAt).candidate)) throw new Error("candidate manifest candidate is stale");
  if (!isRecord(value.hashes) || canonical(value.hashes) !== canonical(currentEvaluationHashes())) throw new Error("candidate manifest hashes are stale");
  if (!isRecord(value.sourceManifest) || canonical(value.sourceManifest) !== canonical(currentEvaluationSourceManifest())) throw new Error("candidate manifest source manifest is stale");
  if (value.providerRevision !== UNATTESTED_PROVIDER_REVISION || value.servedVariant !== UNATTESTED_SERVED_VARIANT) throw new Error("candidate provider identity is unattested");
  if (!isRecord(value.spentHeldout) || !Array.isArray(value.spentHeldout.fixtureIDs) || !Array.isArray(value.spentHeldout.hashes) || value.spentHeldout.fixtureIDs.length !== 0 || value.spentHeldout.hashes.length !== 0) throw new Error("candidate manifest contains spent held-out evidence");
  if (typeof value.manifestHash !== "string") throw new Error("candidate manifest hash is missing");
  const { manifestHash: _manifestHash, ...base } = value;
  if (value.manifestHash !== sha256(canonical(base))) throw new Error("candidate manifest hash is invalid");
  return value as unknown as FrozenCandidateManifest;
}

const DEVELOPMENT_AGGREGATE_KEYS = [
  "corpus", "version", "fixtureCount", "repeats", "temperature", "timeoutMs", "executionMode", "providerCalls", "invocations",
  "classifierDenominator", "invalidRunCount", "capacityObservationCount", "categoryCounts", "confusionMatrix",
  "criticalFalseApprovalCount", "canaryLeakCount", "errorPathTotal", "errorPathManual", "errorPathNonManual", "errorPathManualRate",
  "errorPathManualNumerator", "errorPathManualDenominator", "benignFalseManualNumerator", "benignFalseManualDenominator",
  "benignFalseManualLimit", "criticalDisagreements", "ambiguousDisagreements", "otherDisagreements", "disagreementDenominator",
  "otherDisagreementLimit", "latencyP95Ms", "maxLatencyMs", "allInvocationsBeforeTimeout", "thresholdStatement",
] as const;
const DEVELOPMENT_FAULT_KEYS = ["schemaVersion", "generatedAt", "executionMode", "invalidRunCount", "classifierDenominator", "boundaryCounts", "latencyP95Ms", "observationCount"] as const;
const DEVELOPMENT_REPORT_KEYS = [
  "schemaVersion", "generatedAt", "terminal", "failureCode", "opencodeVersion", "model", "variant", "candidateManifestHash",
  "hashes", "sourceManifest", "contract", "development", "faults", "aggregateDigest",
] as const;
const AGGREGATE_FORBIDDEN_KEY = /^(?:record|records|observation|observations|observationID|observationIDs|fixtureID|fixtureIDs|command|commands|output|prompt|providerResponse|raw|error|errors|providerProse|sharedObservationIDs)$/i;

function assertExactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const allowed = [...expected].sort();
  if (actual.length !== allowed.length || actual.some((key, index) => key !== allowed[index])) throw new Error(`${label} contains unknown or missing fields`);
}

function assertAggregateOnly(value: unknown, parentKey = ""): void {
  if (Array.isArray(value)) throw new Error(`development report contains per-observation output at ${parentKey || "root"}`);
  if (!isRecord(value)) return;
  for (const [key, entry] of Object.entries(value)) {
    if (!(key === "prompt" && parentKey.endsWith("boundaryCounts")) && AGGREGATE_FORBIDDEN_KEY.test(key)) throw new Error(`development report contains forbidden field: ${parentKey ? `${parentKey}.` : ""}${key}`);
    assertAggregateOnly(entry, parentKey ? `${parentKey}.${key}` : key);
  }
}

function aggregateCorpusReport(report: CorpusReport): DevelopmentAggregate {
  const { records: _records, observationIDs: _observationIDs, ...aggregate } = report;
  return aggregate;
}

function aggregateFaultReport(report: FaultReport): DevelopmentFaultAggregate {
  const { observations, observationIDs: _observationIDs, sharedObservationIDs: _sharedObservationIDs, ...aggregate } = report;
  return { ...aggregate, observationCount: observations.length };
}

function developmentContract(): DevelopmentCandidateReport["contract"] {
  return {
    version: QUALIFICATION_SCHEMA_VERSION,
    requestedAlias: QUALIFICATION_MODEL,
    requestedVariant: QUALIFICATION_VARIANT,
    temperature: TEMPERATURE,
    repeats: REPEAT_COUNT,
    timeoutMs: REVIEW_TIMEOUT_MS,
    retryCount: 0,
    contractHash: currentEvaluationHashes().promptHash,
  };
}

function failureCodeFor(report: CorpusReport): DevelopmentFailureCode {
  return report.invalidRunCount > 0 ? "invalid_run" : "threshold";
}

/** Build the public terminal report from the in-memory v3 aggregates only. */
export function createDevelopmentCandidateReport(input: {
  readonly candidate: FrozenCandidateManifest;
  readonly corpusReport: CorpusReport;
  readonly faults: FaultReport;
  readonly terminal: DevelopmentTerminal;
  readonly failureCode?: DevelopmentFailureCode;
  readonly generatedAt?: string;
}): DevelopmentCandidateReport {
  const failureCode = input.terminal === "stop-disabled" ? input.failureCode ?? failureCodeFor(input.corpusReport) : undefined;
  const development = aggregateCorpusReport(input.corpusReport);
  const faults = aggregateFaultReport(input.faults);
  const base = {
    schemaVersion: DEVELOPMENT_REPORT_SCHEMA_VERSION,
    generatedAt: input.generatedAt ?? new Date().toISOString(),
    terminal: input.terminal,
    ...(failureCode ? { failureCode } : {}),
    opencodeVersion: REQUIRED_OPENCODE_VERSION,
    model: QUALIFICATION_MODEL,
    variant: QUALIFICATION_VARIANT,
    candidateManifestHash: input.candidate.manifestHash,
    hashes: currentEvaluationHashes(),
    sourceManifest: currentEvaluationSourceManifest(),
    contract: developmentContract(),
    development,
    faults,
  } satisfies Omit<DevelopmentCandidateReport, "aggregateDigest">;
  const report = { ...base, aggregateDigest: sha256(canonical({ terminal: base.terminal, failureCode: base.failureCode, development, faults })) } as DevelopmentCandidateReport;
  return validateDevelopmentCandidateReport(report, input.candidate);
}

/** Validate one aggregate-only development report against the frozen candidate and checkout. */
export function validateDevelopmentCandidateReport(value: unknown, candidate: FrozenCandidateManifest): DevelopmentCandidateReport {
  assertAggregateOnly(value);
  if (!isRecord(value)) throw new Error("development report is not an object");
  assertExactKeys(value, value.failureCode === undefined ? DEVELOPMENT_REPORT_KEYS.filter((key) => key !== "failureCode") : DEVELOPMENT_REPORT_KEYS, "development report");
  if (value.schemaVersion !== DEVELOPMENT_REPORT_SCHEMA_VERSION || typeof value.generatedAt !== "string" || (value.terminal !== "development-pass" && value.terminal !== "stop-disabled")) throw new Error("development report metadata is invalid");
  if ((value.terminal === "development-pass" && value.failureCode !== undefined) || (value.terminal === "stop-disabled" && !["invalid_run", "threshold", "runtime"].includes(String(value.failureCode)))) throw new Error("development report terminal code is invalid");
  if (value.opencodeVersion !== REQUIRED_OPENCODE_VERSION || value.model !== QUALIFICATION_MODEL || value.variant !== QUALIFICATION_VARIANT || value.candidateManifestHash !== candidate.manifestHash) throw new Error("development report candidate binding is stale");
  if (!isRecord(value.hashes) || canonical(value.hashes) !== canonical(candidate.hashes) || canonical(value.hashes) !== canonical(currentEvaluationHashes())) throw new Error("development report hashes are stale");
  if (!isRecord(value.sourceManifest) || canonical(value.sourceManifest) !== canonical(candidate.sourceManifest) || canonical(value.sourceManifest) !== canonical(currentEvaluationSourceManifest())) throw new Error("development report source manifest is stale");
  if (!isRecord(value.contract) || canonical(value.contract) !== canonical(developmentContract())) throw new Error("development report contract is stale");
  if (!isRecord(value.development)) throw new Error("development report aggregate is missing");
  const development = value.development as unknown as DevelopmentAggregate;
  assertExactKeys(value.development, DEVELOPMENT_AGGREGATE_KEYS, "development aggregate");
  if (development.corpus !== "development" || development.executionMode !== "live" || development.repeats !== REPEAT_COUNT || development.temperature !== TEMPERATURE || development.timeoutMs !== REVIEW_TIMEOUT_MS || !Number.isInteger(development.fixtureCount) || !Number.isInteger(development.invocations) || !Number.isInteger(development.providerCalls) || !Number.isInteger(development.classifierDenominator) || !Number.isInteger(development.invalidRunCount) || development.invocations < 0 || development.providerCalls < 0 || development.invalidRunCount < 0 || development.classifierDenominator !== development.invocations - development.invalidRunCount || development.providerCalls > development.invocations) throw new Error("development aggregate arithmetic is invalid");
  if (value.failureCode !== "runtime" && development.invocations !== development.fixtureCount * REPEAT_COUNT) throw new Error("development aggregate coverage is incomplete");
  if (value.terminal === "development-pass" && development.invalidRunCount !== 0) throw new Error("development pass contains invalid runs");
  if (value.terminal === "development-pass") {
    try {
      assertCorpusReport({ ...development, records: [], observationIDs: [] } as CorpusReport);
    } catch {
      throw new Error("development pass thresholds are invalid");
    }
  }
  if (!isRecord(value.faults)) throw new Error("development fault aggregate is missing");
  const faults = value.faults as unknown as DevelopmentFaultAggregate;
  assertExactKeys(value.faults, DEVELOPMENT_FAULT_KEYS, "development fault aggregate");
  if (faults.schemaVersion !== "classifier-qualification-faults/v1" || faults.executionMode !== "synthetic" || faults.classifierDenominator !== 0 || !Number.isInteger(faults.invalidRunCount) || !Number.isInteger(faults.observationCount) || faults.invalidRunCount !== faults.observationCount || !isRecord(faults.boundaryCounts) || Object.values(faults.boundaryCounts).some((count) => !Number.isInteger(count) || count < 0) || Object.values(faults.boundaryCounts).reduce((sum, count) => sum + Number(count), 0) !== faults.observationCount) throw new Error("development fault aggregate arithmetic is invalid");
  if (typeof value.aggregateDigest !== "string" || value.aggregateDigest !== sha256(canonical({ terminal: value.terminal, failureCode: value.failureCode, development, faults }))) throw new Error("development aggregate digest is invalid");
  return value as unknown as DevelopmentCandidateReport;
}

function writeDevelopmentCandidateReport(path: string, report: DevelopmentCandidateReport): void {
  assertAggregateOnly(report);
  mkdirSync(dirname(resolve(path)), { recursive: true });
  writeFileSync(path, `${JSON.stringify(report, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}

export type QualificationProgressPhase = "startup" | "development" | "release" | "teardown";
export type QualificationProgressState = "started" | "progress" | "finished";

export interface QualificationProgressStatus {
  readonly phase: QualificationProgressPhase;
  readonly state: QualificationProgressState;
  readonly message: string;
  readonly completed?: number;
  readonly total?: number;
  readonly token: string;
}

export interface QualificationProgressReporter {
  readonly start: (phase: QualificationProgressPhase) => void;
  readonly update: (phase: QualificationProgressPhase, completed: number, total: number) => void;
  readonly finish: (phase: QualificationProgressPhase, message?: string) => void;
}

/** Qualification progress is opaque, bounded, and side-channel safe. Sink failures never affect the gate. */
export function createQualificationProgressReporter(options: {
  readonly onStatus?: (status: QualificationProgressStatus) => void;
  readonly sink?: (status: QualificationProgressStatus) => void;
} = {}): QualificationProgressReporter {
  const emit = (status: QualificationProgressStatus): void => {
    for (const observer of [options.onStatus, options.sink]) {
      try { observer?.(status); } catch { /* progress observers cannot change qualification */ }
    }
  };
  return {
    start: (phase) => emit({ phase, state: "started", message: `qualification ${phase} started`, token: `progress_${randomUUID()}` }),
    update: (phase, completed, total) => emit({ phase, state: "progress", message: `qualification ${phase} progress`, completed: Math.max(0, Math.floor(completed)), total: Math.max(0, Math.floor(total)), token: `progress_${randomUUID()}` }),
    finish: (phase, message = `qualification ${phase} finished`) => emit({ phase, state: "finished", message, token: `progress_${randomUUID()}` }),
  };
}

/** Hashes bind the development evaluator inputs; they do not attest to provider weights or served variants. */
export function currentEvaluationHashes(): EvaluationHashes {
  const developmentCorpusHash = sha256(readFileSync(DEVELOPMENT_CORPUS_PATH, "utf8"));
  return {
    corpusHash: developmentCorpusHash,
    developmentCorpusHash,
    schemaHash: hashFiles(["fixtures/eval/qualification-artifact-v3.schema.json", "fixtures/eval/qualification-fault-report.schema.json", "fixtures/eval/development-candidate-report.schema.json"]),
    promptHash: hashFiles(["src/reviewer/prompt.ts", "src/reviewer/schema.ts", "src/reviewer/contract.ts"]),
    policyHash: hashFiles(["src/policy/deterministic.ts", "src/policy/builtin-rules.ts", "src/privacy/secret-scan.ts", "src/privacy/sensitive-paths.ts"]),
    evaluatorHash: hashFiles(["scripts/classifier-gate.ts"]),
    coreHash: hashFiles(["scripts/qualification/core.ts"]),
    routeMatrixHash: sha256(canonical(ROUTE_PROVIDER_MATRIX)),
    runtimeBinaryHash: runtimeBinaryHash(),
  };
}

/** Compatibility hash for old callers; new records must use hashQualificationRecord. */
export function hashNormalizedOutcome(input: Pick<QualificationRecord, "decision" | "route" | "reasonCodes" | "schemaValid"> & Partial<Pick<QualificationRecord, "observationID" | "providerAttempted" | "metricEligible" | "outcome" | "terminalKind">>): string {
  if (input.observationID && input.providerAttempted !== undefined && input.metricEligible !== undefined && input.outcome && input.terminalKind) return hashQualificationRecord(input as QualificationRecord);
  return sha256(canonical({ decision: input.decision, reasonCodes: [...input.reasonCodes], route: input.route, schemaValid: input.schemaValid }));
}

function assertNoSensitiveFields(value: unknown, parentKey = ""): void {
  if (Array.isArray(value)) {
    for (const entry of value) assertNoSensitiveFields(entry, parentKey);
    return;
  }
  if (!isRecord(value)) return;
  for (const [key, entry] of Object.entries(value)) {
    if (!(key === "prompt" && parentKey === "boundaryCounts") && /^(?:command|output|prompt|error|providerResponse|raw|credential|environment|secret(?:Value|Bytes|Canary|Token))$/i.test(key)) throw new Error(`qualification artifact contains forbidden field: ${key}`);
    assertNoSensitiveFields(entry, key);
  }
}

function parseRecord(value: unknown): QualificationRecord {
  if (!isRecord(value)) throw new Error("qualification artifact contains malformed v3 record");
  const record = value as unknown as QualificationRecord;
  validateQualificationRecord(record);
  return record;
}

function validateReportRecords(report: QualificationArtifactV3["reports"][number], corpus?: Corpus): void {
  const ids = new Set<string>();
  const keys = new Set<string>();
  for (const record of report.records) {
    parseRecord(record);
    const key = `${record.fixtureID}:${record.repeat}`;
    if (ids.has(record.observationID)) throw new Error(`${report.corpus} duplicate observation identifier`);
    if (keys.has(key)) throw new Error(`${report.corpus} duplicate invocation identity`);
    ids.add(record.observationID);
    keys.add(key);
    if (corpus) {
      const fixture = corpus.fixtures.find((candidate) => candidate.id === record.fixtureID);
      if (!fixture || fixture.category !== record.category || fixture.expectedDecision !== record.expectedDecision) throw new Error(`${report.corpus} record identity does not match development corpus`);
    }
  }
  if (report.observationIDs.length !== ids.size || report.observationIDs.some((id) => !ids.has(id))) throw new Error(`${report.corpus} observation identifier aggregate mismatch`);
  assertCorpusReport(report, corpus, { allowInvalidRuns: true });
}

export function validateQualificationArtifact(value: unknown, developmentCorpus = loadDevelopmentCorpus().corpus): QualificationReport {
  assertNoSensitiveFields(value);
  if (!isRecord(value) || value.schemaVersion === "classifier-qualification/v2") throw new Error("qualification artifact v2 is incompatible with classifier-qualification/v3");
  if (value.schemaVersion !== QUALIFICATION_SCHEMA_VERSION || value.executionMode !== "live" || value.opencodeVersion !== REQUIRED_OPENCODE_VERSION || value.model !== QUALIFICATION_MODEL || value.variant !== QUALIFICATION_VARIANT || typeof value.generatedAt !== "string" || !isRecord(value.hashes) || !isRecord(value.sourceManifest) || !Array.isArray(value.reports) || (value.reports.length !== 1 && value.reports.length !== 2) || !isRecord(value.faults) || !Array.isArray(value.corpusErrors) || value.corpusErrors.length !== 0) throw new Error("qualification artifact metadata is invalid or simulated");
  const hashes = currentEvaluationHashes();
  for (const key of Object.keys(hashes) as (keyof EvaluationHashes)[]) if (value.hashes[key] !== hashes[key]) throw new Error(`qualification artifact is stale: ${key}`);
  if (canonical(value.sourceManifest) !== canonical(currentEvaluationSourceManifest())) throw new Error("qualification artifact source manifest is stale");
  const reports = value.reports.map((raw) => {
    if (!isRecord(raw) || !Array.isArray(raw.records) || (raw.corpus !== "development" && raw.corpus !== "heldout")) throw new Error("qualification artifact report is malformed");
    return { ...raw, records: raw.records.map(parseRecord) } as unknown as QualificationArtifactV3["reports"][number];
  });
  if (reports[0]?.corpus !== "development" || reports.length === 2 && reports[1]?.corpus !== "heldout") throw new Error("qualification artifact corpus order is invalid");
  for (const report of reports) validateReportRecords(report, report.corpus === "development" ? developmentCorpus : undefined);
  const faults = value.faults as unknown as QualificationArtifactV3["faults"];
  assertFaultReport(faults, reports.flatMap((report) => report.records.filter((record) => record.metricEligible).map((record) => record.observationID)));
  return value as unknown as QualificationReport;
}

export function loadAndValidateQualificationArtifact(path = ARTIFACT_PATH): QualificationReport {
  if (isReleaseInputName(path) && resolve(path) !== ARTIFACT_PATH) throw new Error("development qualification refuses combined, held-out, private, or release input");
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new Error(`development qualification artifact missing or unreadable: ${path}`);
  }
  return validateQualificationArtifact(value);
}

const unwrapData = (value: unknown): unknown => isRecord(value) && "data" in value ? value.data : value;
const sessionIDFrom = (value: unknown): string => {
  const data = unwrapData(value);
  if (isRecord(data) && typeof data.id === "string") return data.id;
  throw new Error("OpenCode session creation failed");
};

async function waitForServer(url: string, child: ReturnType<typeof Bun.spawn>): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error("OpenCode server exited during startup");
    try {
      if ((await fetch(`${url}/session`, { signal: AbortSignal.timeout(500) })).ok) return;
    } catch {
      // Startup is observable through the periodic progress line below.
    }
    await Bun.sleep(100);
  }
  throw new Error("OpenCode server startup timeout");
}

function boundedReasonCodes(values: readonly string[] | undefined, fallback: "manual" | "provider_error" = "manual"): readonly import("./qualification/core").ReasonCode[] {
  const valid = (values ?? []).filter(isReasonCode);
  return valid.length > 0 ? valid : [fallback];
}

function terminalKindFor(value: unknown): TerminalKind {
  if (value === "valid_model" || value === "manual" || value === "malformed" || value === "empty" || value === "truncated" || value === "timeout" || value === "provider_error" || value === "tool_violation" || value === "permission_violation" || value === "prompt_error" || value === "parse_error" || value === "reply_error" || value === "capacity_rejected" || value === "session_create_error") return value;
  return "provider_error";
}

function observationID(fixture: Fixture, repeat: number): string {
  return `obs_${fixture.id}_${repeat}_${randomUUID()}`;
}

async function produceLiveQualification(path: string, candidate: FrozenCandidateManifest): Promise<DevelopmentCandidateReport> {
  const qualificationProgress = createQualificationProgressReporter({
    sink: (status) => console.error(`[classifier-qualification] ${status.message}`),
  });
  qualificationProgress.start("startup");
  try {
    accessSync(OPENCODE_BIN, constants.X_OK);
    if (!statSync(OPENCODE_BIN).isFile()) throw new Error("not a file");
  } catch {
    throw new Error(`pinned local OpenCode ${REQUIRED_OPENCODE_VERSION} binary is missing or not executable`);
  }
  const versionProbe = Bun.spawnSync([OPENCODE_BIN, "--version"], { stdout: "pipe", stderr: "pipe" });
  const version = new TextDecoder().decode(versionProbe.stdout).trim();
  if (versionProbe.exitCode !== 0 || version !== REQUIRED_OPENCODE_VERSION) throw new Error(`OpenCode ${REQUIRED_OPENCODE_VERSION} is required for qualification`);
  const authPath = process.env.OPENCODE_AUTH_PATH;
  if (!authPath || !statSync(authPath).isFile()) throw new Error("OPENCODE_AUTH_PATH must name the existing OpenCode auth file");
  const runtimeRoot = mkdtempSync(join(tmpdir(), "smart-approve-qualification-"));
  const configHome = join(runtimeRoot, "config");
  const dataHome = join(runtimeRoot, "data");
  const cacheHome = join(runtimeRoot, "cache");
  const stateHome = join(runtimeRoot, "state");
  mkdirSync(configHome, { recursive: true });
  mkdirSync(cacheHome, { recursive: true });
  mkdirSync(stateHome, { recursive: true });
  mkdirSync(join(dataHome, "opencode"), { recursive: true });
  symlinkSync(resolve(authPath), join(dataHome, "opencode", "auth.json"));
  const reservation = Bun.serve({ port: 0, fetch: () => new Response("reserved") });
  const port = reservation.port;
  reservation.stop(true);
  if (!port) throw new Error("could not reserve qualification port");
  const baseUrl = `http://127.0.0.1:${port}`;
  const child = Bun.spawn([OPENCODE_BIN, "serve", "--pure", "--hostname", "127.0.0.1", "--port", String(port)], {
    cwd: PROJECT_ROOT,
    env: { ...process.env, XDG_CONFIG_HOME: configHome, XDG_DATA_HOME: dataHome, XDG_CACHE_HOME: cacheHome, XDG_STATE_HOME: stateHome, OPENCODE_CONFIG_CONTENT: QUALIFICATION_CONFIG },
    stdout: "ignore",
    stderr: "ignore",
  });
  const client = createOpencodeClient({ baseUrl, directory: PROJECT_ROOT });
  const reviewer = createReviewerAgent({ client: client as unknown as ReviewerSessionClient, timeoutMs: REVIEW_TIMEOUT_MS, directory: PROJECT_ROOT, model: REVIEWER_MODEL, variant: REVIEWER_VARIANT });
  const { corpus } = loadDevelopmentCorpus();
  let completed = 0;
  const total = corpus.fixtures.length * REPEAT_COUNT;
  qualificationProgress.finish("startup");
  qualificationProgress.start("development");
  const progress = setInterval(() => {
    qualificationProgress.update("development", completed, total);
    console.error(`[classifier-qualification] development ${completed}/${total} invocations complete`);
  }, 8_000);
  try {
    await waitForServer(baseUrl, child);
    const jobs = corpus.fixtures.flatMap((fixture) => Array.from({ length: REPEAT_COUNT }, (_, index) => ({ fixture, repeat: index + 1 as QualificationRecord["repeat"] })));
    const records = new Array<QualificationRecord>(jobs.length);
    let nextJob = 0;
    const worker = async (): Promise<void> => {
      while (true) {
        const jobIndex = nextJob;
        nextJob += 1;
        const job = jobs[jobIndex];
        if (!job) return;
        const { fixture, repeat } = job;
        const started = performance.now();
        let decision: Decision = "manual";
        let route: QualificationRecord["route"] = "deterministic";
        let providerAttempted = false;
        let reasonCodes: readonly import("./qualification/core").ReasonCode[] = ["manual"];
        let schemaValid = true;
        let metricEligible = true;
        let outcome: QualificationRecord["outcome"] = "classifier";
        let terminalKind: TerminalKind = "manual";
        const deterministic = await evaluateDeterministicPolicy(fixture.command, { pathIdentity: { cwd: PROJECT_ROOT, ownedRoot: PROJECT_ROOT } });
        reasonCodes = boundedReasonCodes(deterministic.reasonCodes);
        if (fixture.errorPath) {
          // These are observed safety-routing fixtures: they remain in REQ-011
          // with a 100% manual numerator/denominator and never reach a provider.
          decision = "manual";
          route = "deterministic";
          providerAttempted = false;
          reasonCodes = ["policy_error"];
        } else if (deterministic.status === "model_review") {
          route = "reviewer";
          const pathClasses = deterministic.pathClasses ?? ["unknown"];
          const result = await reviewer.review({ requestID: `eval:${fixture.id}:${repeat}`, prompt: fixture.command, redactedCommand: fixture.command, parserFeatures: deterministic.parse?.features ? { ...deterministic.parse.features } : undefined, policyFacts: ["model_review", "parser.clear", "privacy.clear", ...pathClasses.map((value) => `path.${value}`)], pathClasses });
          providerAttempted = result.outcome?.providerAttempted ?? result.sessionID.length > 0;
          decision = result.decision;
          reasonCodes = boundedReasonCodes(result.reasonCodes, "provider_error");
          const kind = result.outcome?.kind;
          if (kind === "valid_model" || kind === undefined && result.sessionID.length > 0) {
            terminalKind = "valid_model";
          } else {
            terminalKind = kind === "provider_error" && !providerAttempted ? "session_create_error" : terminalKindFor(kind);
            schemaValid = false;
            metricEligible = false;
            outcome = "invalid_run";
          }
        }
        const base = { observationID: observationID(fixture, repeat), fixtureID: fixture.id, category: fixture.category, repeat, expectedDecision: fixture.expectedDecision, decision, route, providerAttempted, reasonCodes, schemaValid, metricEligible, outcome, terminalKind, latencyMs: performance.now() - started } satisfies Omit<QualificationRecord, "responseHash">;
        records[jobIndex] = { ...base, responseHash: hashQualificationRecord(base) };
        completed += 1;
      }
    };
    await Promise.all(Array.from({ length: Math.min(MAX_CONCURRENT_REVIEWERS, jobs.length) }, () => worker()));
    const corpusReport = evaluateCorpus("development", corpus, records);
    const faults = evaluateFaults([]);
    let failureCode: DevelopmentFailureCode | undefined;
    try {
      assertCorpusReport(corpusReport, corpus);
      assertFaultReport(faults, corpusReport.records.filter((record) => record.metricEligible).map((record) => record.observationID));
    } catch {
      failureCode = failureCodeFor(corpusReport);
    }
    const report = createDevelopmentCandidateReport({
      candidate,
      corpusReport,
      faults,
      terminal: failureCode ? "stop-disabled" : "development-pass",
      ...(failureCode ? { failureCode } : {}),
    });
    writeDevelopmentCandidateReport(path, report);
    return report;
  } finally {
    clearInterval(progress);
    qualificationProgress.finish("development");
    qualificationProgress.finish("teardown");
    await reviewer.dispose().catch(() => undefined);
    child.kill("SIGTERM");
    await Promise.race([child.exited, Bun.sleep(3_000)]).catch(() => undefined);
    if (child.exitCode === null) child.kill("SIGKILL");
    rmSync(runtimeRoot, { recursive: true, force: true });
  }
}

function readFrozenCandidateManifest(path = FROZEN_CANDIDATE_PATH): FrozenCandidateManifest {
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new Error(`frozen candidate manifest missing or unreadable: ${path}`);
  }
  return validateFrozenCandidateManifest(value);
}

function createRuntimeFailureReport(candidate: FrozenCandidateManifest): DevelopmentCandidateReport {
  const corpus = loadDevelopmentCorpus().corpus;
  return createDevelopmentCandidateReport({
    candidate,
    corpusReport: evaluateCorpus("development", corpus, [], "live"),
    faults: evaluateFaults([]),
    terminal: "stop-disabled",
    failureCode: "runtime",
  });
}

const RELEASE_INPUT_OPTIONS = new Set(["--heldout", "--heldout-corpus", "--release", "--release-corpus", "--private", "--private-corpus", "--combined", "--combined-corpus", "--bundle", "--corpus", "--release-input", "--live-release"]);
const VALUE_OPTIONS = new Set(["--artifact", "--candidate", "--freeze-candidate", "--validate-candidate", "--validate-development-report"]);

export function validateDevelopmentArguments(argv: readonly string[]): void {
  for (const [index, argument] of argv.entries()) {
    if (index > 0 && VALUE_OPTIONS.has(argv[index - 1]!)) continue;
    const option = argument.includes("=") ? argument.slice(0, argument.indexOf("=")) : argument;
    if (RELEASE_INPUT_OPTIONS.has(option) || isReleaseInputName(argument) && argument !== "--live" && argument !== "--development") throw new Error("development qualification refuses combined, held-out, private, or release input");
    if (argument !== "--live" && argument !== "--development" && argument !== "--help" && !VALUE_OPTIONS.has(argument) && argument !== "--freeze-candidate" && argument !== "--validate-candidate") throw new Error(`unknown development qualification option: ${argument}`);
  }
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  let liveCandidate: FrozenCandidateManifest | undefined;
  let liveReportPath: string | undefined;
  try {
    // Parse and reject release-input options before opening any corpus or artifact.
    validateDevelopmentArguments(argv);
    const freezeCandidateIndex = argv.indexOf("--freeze-candidate");
    const validateCandidateIndex = argv.indexOf("--validate-candidate");
    if (freezeCandidateIndex >= 0 || validateCandidateIndex >= 0) {
      if (freezeCandidateIndex >= 0 && validateCandidateIndex >= 0) throw new Error("candidate command modes are mutually exclusive");
      const optionIndex = freezeCandidateIndex >= 0 ? freezeCandidateIndex : validateCandidateIndex;
      const candidatePath = argv[optionIndex + 1];
      if (!candidatePath || candidatePath.startsWith("--")) throw new Error(`${argv[optionIndex]} requires a candidate manifest path`);
      if (freezeCandidateIndex >= 0) {
        const candidate = createFrozenCandidateManifest();
        mkdirSync(dirname(resolve(candidatePath)), { recursive: true });
        writeFileSync(candidatePath, `${JSON.stringify(candidate, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
        console.log(JSON.stringify({ candidate: candidatePath, manifestHash: candidate.manifestHash, providerRevision: candidate.providerRevision, servedVariant: candidate.servedVariant }));
      } else {
        const candidate = JSON.parse(readFileSync(candidatePath, "utf8")) as unknown;
        const validated = validateFrozenCandidateManifest(candidate);
        console.log(JSON.stringify({ candidate: candidatePath, manifestHash: validated.manifestHash, providerRevision: validated.providerRevision, servedVariant: validated.servedVariant }));
      }
      return 0;
    }
    const candidateIndex = argv.indexOf("--candidate");
    const candidatePath = candidateIndex >= 0 ? argv[candidateIndex + 1] : FROZEN_CANDIDATE_PATH;
    if (candidateIndex >= 0 && (!candidatePath || candidatePath.startsWith("--"))) throw new Error("--candidate requires a frozen candidate manifest path");
    const validateDevelopmentReportIndex = argv.indexOf("--validate-development-report");
    if (validateDevelopmentReportIndex >= 0) {
      const reportPath = argv[validateDevelopmentReportIndex + 1];
      if (!reportPath || reportPath.startsWith("--")) throw new Error("--validate-development-report requires a report path");
      const candidate = readFrozenCandidateManifest(candidatePath);
      let value: unknown;
      try {
        value = JSON.parse(readFileSync(reportPath, "utf8"));
      } catch {
        throw new Error(`development report missing or unreadable: ${reportPath}`);
      }
      const report = validateDevelopmentCandidateReport(value, candidate);
      console.log(JSON.stringify({ report: reportPath, status: report.terminal, candidateManifestHash: report.candidateManifestHash, providerCalls: report.development.providerCalls, classifierDenominator: report.development.classifierDenominator }));
      return 0;
    }
    const artifactIndex = argv.indexOf("--artifact");
    const artifactPath = artifactIndex >= 0 ? argv[artifactIndex + 1] : undefined;
    if (artifactIndex >= 0 && (!artifactPath || artifactPath.startsWith("--"))) throw new Error("--artifact requires a development artifact path");
    if (argv.includes("--live")) {
      liveCandidate = readFrozenCandidateManifest(candidatePath);
      liveReportPath = artifactPath ?? DEVELOPMENT_REPORT_PATH;
      const report = await produceLiveQualification(liveReportPath, liveCandidate);
      console.log(JSON.stringify({ artifact: liveReportPath, generatedAt: report.generatedAt, status: report.terminal, providerCalls: report.development.providerCalls, classifierDenominator: report.development.classifierDenominator }));
      return 0;
    }
    const report = loadAndValidateQualificationArtifact(artifactPath ?? ARTIFACT_PATH);
    console.log(JSON.stringify({ artifact: artifactPath ?? ARTIFACT_PATH, generatedAt: report.generatedAt, providerCalls: report.reports.reduce((sum, item) => sum + item.providerCalls, 0), classifierDenominator: report.reports.reduce((sum, item) => sum + item.classifierDenominator, 0) }));
    return 0;
  } catch (error) {
    if (argv.includes("--live") && liveCandidate && liveReportPath) {
      try {
        const report = createRuntimeFailureReport(liveCandidate);
        writeDevelopmentCandidateReport(liveReportPath, report);
        console.error("classifier gate stopped disabled: runtime failure");
        return 0;
      } catch {
        // Preserve the original fail-closed error when even the terminal receipt cannot be written.
      }
    }
    console.error(error instanceof Error ? error.message : "classifier gate failed");
    return 1;
  }
}

if (import.meta.main) process.exit(await main());
