import { chmodSync, closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import {
  validateDevelopmentCandidateReport,
  validateFrozenCandidateManifest,
  type DevelopmentCandidateReport,
  type FrozenCandidateManifest,
} from "../classifier-gate";
import { canonical, sha256 } from "./core";

export const TERMINAL_PREFLIGHT_SCHEMA_VERSION = "classifier-qualification-preflight/v1" as const;
export const TERMINAL_CUSTODY_SCHEMA_VERSION = "classifier-terminal-custody/v1" as const;
export const TERMINAL_ATTESTATION_SCHEMA_VERSION = "classifier-terminal-attestation/v1" as const;

export interface TerminalPreflightReport {
  readonly schemaVersion: typeof TERMINAL_PREFLIGHT_SCHEMA_VERSION;
  readonly generatedAt: string;
  readonly terminal: "development_failed";
  readonly candidateManifestHash: string;
  readonly developmentReportHash: string;
  readonly developmentAggregateDigest: string;
  readonly development: {
    readonly failureCode: string;
    readonly invocations: number;
    readonly providerCalls: number;
    readonly invalidRunCount: number;
    readonly classifierDenominator: number;
  };
  readonly release: {
    readonly status: "not_created";
    readonly providerCalls: 0;
    readonly privateByteReads: 0;
    readonly namedCorpusRoles: 0;
    readonly custodyTransition: "none";
  };
  readonly productionLock: false;
  readonly preflightHash: string;
}

export interface TerminalCustodyManifest {
  readonly schemaVersion: typeof TERMINAL_CUSTODY_SCHEMA_VERSION;
  readonly generatedAt: string;
  readonly terminal: "development_failed";
  readonly candidateManifestHash: string;
  readonly developmentReportHash: string;
  readonly developmentFailureCode: string;
  readonly status: "not_created";
  readonly providerCalls: 0;
  readonly privateByteReads: 0;
  readonly namedCorpusRoles: 0;
  readonly custodyTransition: "none";
  readonly ledgerState: "not_created";
  readonly manifestHash: string;
}

export interface TerminalAttestation {
  readonly schemaVersion: typeof TERMINAL_ATTESTATION_SCHEMA_VERSION;
  readonly generatedAt: string;
  readonly terminal: "development_failed";
  readonly decision: "release-disabled";
  readonly verification: "not_independently_recomputable";
  readonly candidateManifestHash: string;
  readonly developmentReportHash: string;
  readonly custodyManifestHash: string;
  readonly providerCalls: 0;
  readonly privateByteReads: 0;
  readonly custodyTransition: "none";
  readonly providerWeights: "unattested";
  readonly servedVariant: "unattested";
  readonly productionLock: false;
  readonly attestationHash: string;
}

export interface TerminalVerificationResult {
  readonly preflight: TerminalPreflightReport;
  readonly custody: TerminalCustodyManifest;
  readonly attestation: TerminalAttestation;
  readonly paths: {
    readonly preflight: string;
    readonly custody: string;
    readonly attestation: string;
  };
}

const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
export const DEFAULT_DEVELOPMENT_REPORT_PATH = resolve(PROJECT_ROOT, "eval-results/development-candidate-report.json");
export const DEFAULT_PREFLIGHT_PATH = resolve(PROJECT_ROOT, "eval-results/qualification-preflight-report.json");
const FORBIDDEN_KEYS = /^(?:record|records|observation|observations|observationID|observationIDs|fixtureID|fixtureIDs|command|commands|prompt|providerResponse|raw|error|errors|providerProse|private|secret|credential|label|canary)$/i;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function assertDigest(value: unknown, name: string): asserts value is string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) throw new Error(`${name} must be a SHA-256 digest`);
}

function assertAggregateOnly(value: unknown, path = "root"): void {
  if (Array.isArray(value)) throw new Error(`terminal artifact contains an array at ${path}`);
  if (!isObject(value)) return;
  for (const [key, entry] of Object.entries(value)) {
    if (FORBIDDEN_KEYS.test(key)) throw new Error(`terminal artifact contains forbidden field: ${path}.${key}`);
    assertAggregateOnly(entry, `${path}.${key}`);
  }
}

function assertExactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const allowed = [...expected].sort();
  if (actual.length !== allowed.length || actual.some((key, index) => key !== allowed[index])) throw new Error(`${label} contains unknown or missing fields`);
}

function readJSON(path: string): unknown {
  try {
    return JSON.parse(readFileSync(resolve(path), "utf8"));
  } catch {
    throw new Error(`terminal input is missing or unreadable: ${path}`);
  }
}

function artifactHash(value: Record<string, unknown>, hashKey: string): string {
  const { [hashKey]: _hash, ...base } = value;
  return sha256(canonical(base));
}

function writeJSON(path: string, value: object): void {
  const absolute = resolve(path);
  mkdirSync(dirname(absolute), { recursive: true });
  if (existsSync(absolute)) {
    const existing = readJSON(absolute);
    if (canonical(existing) !== canonical(value)) throw new Error(`refusing to overwrite a different terminal artifact: ${path}`);
    chmodSync(absolute, 0o600);
    return;
  }
  const temporary = `${absolute}.${randomUUID()}.tmp`;
  let fd: number | undefined;
  try {
    fd = openSync(temporary, "wx", 0o600);
    const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    writeSync(fd, bytes, 0, bytes.length);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(temporary, absolute);
    chmodSync(absolute, 0o600);
  } catch (error) {
    if (fd !== undefined) try { closeSync(fd); } catch { /* preserve original error */ }
    try { unlinkSync(temporary); } catch { /* preserve original error */ }
    throw error;
  }
}

/** Check every destination before the first write so a collision cannot leave a partial triad. */
function assertWriteTargets(targets: readonly { readonly path: string; readonly value: object }[]): void {
  for (const target of targets) {
    const absolute = resolve(target.path);
    if (existsSync(absolute) && canonical(readJSON(absolute)) !== canonical(target.value)) {
      throw new Error(`refusing to overwrite a different terminal artifact: ${target.path}`);
    }
  }
}

function readCandidate(path: string): FrozenCandidateManifest {
  return validateFrozenCandidateManifest(readJSON(path));
}

function readDevelopmentReport(path: string, candidate: FrozenCandidateManifest): DevelopmentCandidateReport {
  const report = validateDevelopmentCandidateReport(readJSON(path), candidate);
  if (report.terminal !== "stop-disabled" || report.failureCode === undefined) throw new Error("terminal verifier requires a stop-disabled development report");
  return report;
}

export function createTerminalPreflight(candidate: FrozenCandidateManifest, report: DevelopmentCandidateReport): TerminalPreflightReport {
  if (report.terminal !== "stop-disabled" || report.failureCode === undefined) throw new Error("terminal preflight requires a failed development report");
  const base = {
    schemaVersion: TERMINAL_PREFLIGHT_SCHEMA_VERSION,
    generatedAt: report.generatedAt,
    terminal: "development_failed" as const,
    candidateManifestHash: candidate.manifestHash,
    developmentReportHash: sha256(canonical(report)),
    developmentAggregateDigest: report.aggregateDigest,
    development: {
      failureCode: report.failureCode,
      invocations: report.development.invocations,
      providerCalls: report.development.providerCalls,
      invalidRunCount: report.development.invalidRunCount,
      classifierDenominator: report.development.classifierDenominator,
    },
    release: {
      status: "not_created" as const,
      providerCalls: 0 as const,
      privateByteReads: 0 as const,
      namedCorpusRoles: 0 as const,
      custodyTransition: "none" as const,
    },
    productionLock: false as const,
  };
  return { ...base, preflightHash: artifactHash(base, "preflightHash") };
}

export function validateTerminalPreflight(value: unknown, candidate: FrozenCandidateManifest, report: DevelopmentCandidateReport): TerminalPreflightReport {
  assertAggregateOnly(value);
  if (!isObject(value)) throw new Error("terminal preflight is not an object");
  assertExactKeys(value, ["schemaVersion", "generatedAt", "terminal", "candidateManifestHash", "developmentReportHash", "developmentAggregateDigest", "development", "release", "productionLock", "preflightHash"], "terminal preflight");
  if (value.schemaVersion !== TERMINAL_PREFLIGHT_SCHEMA_VERSION || value.generatedAt !== report.generatedAt || value.terminal !== "development_failed" || value.candidateManifestHash !== candidate.manifestHash || value.developmentReportHash !== sha256(canonical(report)) || value.developmentAggregateDigest !== report.aggregateDigest || value.productionLock !== false) throw new Error("terminal preflight binding is invalid");
  if (!isObject(value.development) || !isObject(value.release)) throw new Error("terminal preflight aggregates are missing");
  assertExactKeys(value.development, ["failureCode", "invocations", "providerCalls", "invalidRunCount", "classifierDenominator"], "terminal development aggregate");
  assertExactKeys(value.release, ["status", "providerCalls", "privateByteReads", "namedCorpusRoles", "custodyTransition"], "terminal release aggregate");
  if (value.development.failureCode !== report.failureCode || value.development.invocations !== report.development.invocations || value.development.providerCalls !== report.development.providerCalls || value.development.invalidRunCount !== report.development.invalidRunCount || value.development.classifierDenominator !== report.development.classifierDenominator) throw new Error("terminal development aggregate does not match the report");
  if (value.release.status !== "not_created" || value.release.providerCalls !== 0 || value.release.privateByteReads !== 0 || value.release.namedCorpusRoles !== 0 || value.release.custodyTransition !== "none") throw new Error("terminal release aggregate is not no-corpus");
  if (typeof value.preflightHash !== "string" || value.preflightHash !== artifactHash(value, "preflightHash")) throw new Error("terminal preflight hash is invalid");
  return value as unknown as TerminalPreflightReport;
}

export function createTerminalCustodyManifest(candidate: FrozenCandidateManifest, report: DevelopmentCandidateReport): TerminalCustodyManifest {
  if (report.terminal !== "stop-disabled" || report.failureCode === undefined) throw new Error("terminal custody requires a failed development report");
  const base = {
    schemaVersion: TERMINAL_CUSTODY_SCHEMA_VERSION,
    generatedAt: report.generatedAt,
    terminal: "development_failed" as const,
    candidateManifestHash: candidate.manifestHash,
    developmentReportHash: sha256(canonical(report)),
    developmentFailureCode: report.failureCode,
    status: "not_created" as const,
    providerCalls: 0 as const,
    privateByteReads: 0 as const,
    namedCorpusRoles: 0 as const,
    custodyTransition: "none" as const,
    ledgerState: "not_created" as const,
  };
  return { ...base, manifestHash: artifactHash(base, "manifestHash") };
}

export function validateTerminalCustodyManifest(value: unknown, candidate: FrozenCandidateManifest, report: DevelopmentCandidateReport): TerminalCustodyManifest {
  assertAggregateOnly(value);
  if (!isObject(value)) throw new Error("terminal custody manifest is not an object");
  assertExactKeys(value, ["schemaVersion", "generatedAt", "terminal", "candidateManifestHash", "developmentReportHash", "developmentFailureCode", "status", "providerCalls", "privateByteReads", "namedCorpusRoles", "custodyTransition", "ledgerState", "manifestHash"], "terminal custody manifest");
  if (value.schemaVersion !== TERMINAL_CUSTODY_SCHEMA_VERSION || value.generatedAt !== report.generatedAt || value.terminal !== "development_failed" || value.candidateManifestHash !== candidate.manifestHash || value.developmentReportHash !== sha256(canonical(report)) || value.developmentFailureCode !== report.failureCode || value.status !== "not_created" || value.providerCalls !== 0 || value.privateByteReads !== 0 || value.namedCorpusRoles !== 0 || value.custodyTransition !== "none" || value.ledgerState !== "not_created") throw new Error("terminal custody manifest is not no-corpus");
  if (typeof value.manifestHash !== "string" || value.manifestHash !== artifactHash(value, "manifestHash")) throw new Error("terminal custody manifest hash is invalid");
  return value as unknown as TerminalCustodyManifest;
}

export function createTerminalAttestation(candidate: FrozenCandidateManifest, report: DevelopmentCandidateReport, custody: TerminalCustodyManifest): TerminalAttestation {
  const base = {
    schemaVersion: TERMINAL_ATTESTATION_SCHEMA_VERSION,
    generatedAt: report.generatedAt,
    terminal: "development_failed" as const,
    decision: "release-disabled" as const,
    verification: "not_independently_recomputable" as const,
    candidateManifestHash: candidate.manifestHash,
    developmentReportHash: sha256(canonical(report)),
    custodyManifestHash: custody.manifestHash,
    providerCalls: 0 as const,
    privateByteReads: 0 as const,
    custodyTransition: "none" as const,
    providerWeights: "unattested" as const,
    servedVariant: "unattested" as const,
    productionLock: false as const,
  };
  return { ...base, attestationHash: artifactHash(base, "attestationHash") };
}

export function validateTerminalAttestation(value: unknown, candidate: FrozenCandidateManifest, report: DevelopmentCandidateReport, custody: TerminalCustodyManifest): TerminalAttestation {
  assertAggregateOnly(value);
  if (!isObject(value)) throw new Error("terminal attestation is not an object");
  assertExactKeys(value, ["schemaVersion", "generatedAt", "terminal", "decision", "verification", "candidateManifestHash", "developmentReportHash", "custodyManifestHash", "providerCalls", "privateByteReads", "custodyTransition", "providerWeights", "servedVariant", "productionLock", "attestationHash"], "terminal attestation");
  if (value.schemaVersion !== TERMINAL_ATTESTATION_SCHEMA_VERSION || value.generatedAt !== report.generatedAt || value.terminal !== "development_failed" || value.decision !== "release-disabled" || value.verification !== "not_independently_recomputable" || value.candidateManifestHash !== candidate.manifestHash || value.developmentReportHash !== sha256(canonical(report)) || value.custodyManifestHash !== custody.manifestHash || value.providerCalls !== 0 || value.privateByteReads !== 0 || value.custodyTransition !== "none" || value.providerWeights !== "unattested" || value.servedVariant !== "unattested" || value.productionLock !== false) throw new Error("terminal attestation is not a no-corpus disabled receipt");
  if (typeof value.attestationHash !== "string" || value.attestationHash !== artifactHash(value, "attestationHash")) throw new Error("terminal attestation hash is invalid");
  return value as unknown as TerminalAttestation;
}

export function verifyTerminal(input: {
  readonly candidatePath: string;
  readonly developmentReportPath?: string;
  readonly preflightPath: string;
  readonly custodyPath: string;
  readonly attestationPath: string;
}): TerminalVerificationResult {
  const candidate = readCandidate(input.candidatePath);
  const report = readDevelopmentReport(input.developmentReportPath ?? DEFAULT_DEVELOPMENT_REPORT_PATH, candidate);
  const preflight = createTerminalPreflight(candidate, report);
  const custody = createTerminalCustodyManifest(candidate, report);
  const attestation = createTerminalAttestation(candidate, report, custody);
  validateTerminalPreflight(preflight, candidate, report);
  validateTerminalCustodyManifest(custody, candidate, report);
  validateTerminalAttestation(attestation, candidate, report, custody);
  assertWriteTargets([
    { path: input.preflightPath, value: preflight },
    { path: input.custodyPath, value: custody },
    { path: input.attestationPath, value: attestation },
  ]);
  writeJSON(input.preflightPath, preflight);
  writeJSON(input.custodyPath, custody);
  writeJSON(input.attestationPath, attestation);
  return {
    preflight,
    custody,
    attestation,
    paths: { preflight: resolve(input.preflightPath), custody: resolve(input.custodyPath), attestation: resolve(input.attestationPath) },
  };
}

const VALUE_OPTIONS = new Set(["--candidate", "--development-report", "--preflight", "--custody", "--attestation"]);

function option(argv: readonly string[], name: string, required: boolean): string | undefined {
  const index = argv.indexOf(name);
  if (index < 0) {
    if (required) throw new Error(`${name} is required`);
    return undefined;
  }
  const value = argv[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${name} requires a path`);
  return value;
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  try {
    const args = argv.filter((argument) => argument !== "--");
    for (let index = 0; index < args.length; index += 1) {
      const argument = args[index]!;
      if (!VALUE_OPTIONS.has(argument)) throw new Error(`unknown terminal-verifier argument at ${index}: ${argument}`);
      if (!args[index + 1] || args[index + 1]!.startsWith("--")) throw new Error(`${argument} requires a path`);
      index += 1;
    }
    const candidatePath = option(args, "--candidate", true)!;
    const result = verifyTerminal({
      candidatePath,
      developmentReportPath: option(args, "--development-report", false),
      preflightPath: option(args, "--preflight", false) ?? DEFAULT_PREFLIGHT_PATH,
      custodyPath: option(args, "--custody", true)!,
      attestationPath: option(args, "--attestation", true)!,
    });
    console.log(JSON.stringify({ terminal: result.attestation.terminal, decision: result.attestation.decision, candidateManifestHash: result.attestation.candidateManifestHash, privateByteReads: result.attestation.privateByteReads, providerCalls: result.attestation.providerCalls, custodyTransition: result.attestation.custodyTransition }));
    return 0;
  } catch (error) {
    console.error(error instanceof Error ? error.message : "terminal verification failed");
    return 1;
  }
}

if (import.meta.main) process.exit(await main());
