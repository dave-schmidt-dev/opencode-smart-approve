import { createHash, createPublicKey, generateKeyPairSync, sign, verify, KeyObject } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import {
  CATEGORIES,
  FAULT_BOUNDARIES,
  MINIMUMS,
  canonical,
  isCategory,
  isDecision,
  isReasonCode,
  sha256,
  type Decision,
  type FixtureCategory,
  type ReasonCode,
} from "./core";

export { canonical, sha256 } from "./core";

export const CUSTODY_LEDGER_SCHEMA_VERSION = "qualification-custody-ledger/v1" as const;
export const RELEASE_MANIFEST_SCHEMA_VERSION = "classifier-release-manifest/v1" as const;
export const PUBLIC_PASS_SCHEMA_VERSION = "classifier-public-aggregate-pass/v1" as const;
export const PUBLIC_FAILURE_SCHEMA_VERSION = "classifier-public-aggregate-failure/v1" as const;
export const PRIVATE_RECEIPT_SCHEMA_VERSION = "classifier-private-receipt/v1" as const;
export const PUBLIC_ATTESTATION_SCHEMA_VERSION = "classifier-release-attestation/v1" as const;
export const PUBLIC_VERIFICATION_STATUS = "not_independently_recomputable" as const;

export type CustodyLedgerState = "available" | "reserved" | "spent";

export interface CustodyLedgerRecord {
  readonly schemaVersion: typeof CUSTODY_LEDGER_SCHEMA_VERSION;
  readonly state: CustodyLedgerState;
  readonly consumptionNumber: number;
  readonly corpusDigest?: string;
  readonly commitmentHash?: string;
  readonly updatedAt: string;
}

export interface CustodyEvent {
  readonly name:
    | "lock_acquired"
    | "reserved"
    | "spent"
    | "file_fsync"
    | "parent_fsync"
    | "lock_released"
    | "private_input_open";
  readonly token: string;
}

export interface CustodyDurability {
  readonly onEvent?: (event: CustodyEvent) => void;
}

export interface SignedConsumptionCommitment {
  readonly schemaVersion: "qualification-consumption-commitment/v1";
  readonly algorithm: "ed25519";
  readonly corpusDigest: string;
  readonly consumptionNumber: number;
  readonly payloadHash: string;
  readonly signature: string;
  readonly publicKey: string;
}

export interface PrivateRecomputationReceipt {
  readonly schemaVersion: typeof PRIVATE_RECEIPT_SCHEMA_VERSION;
  readonly custodyNumber: number;
  readonly corpusDigest: string;
  readonly orderedObservationDigest: string;
  readonly recomputedAggregateDigest: string;
  readonly publicAttestationHash: string;
  readonly commitmentHash: string;
  readonly receiptHash: string;
}

export interface PublicAggregateBase {
  readonly verification: typeof PUBLIC_VERIFICATION_STATUS;
  readonly custodyNumber: number;
  readonly corpusDigest: string;
  readonly aggregateDigest: string;
  readonly faultGate: "pass" | "fail";
  readonly classifierDenominator: number;
  readonly invalidRunCount: number;
  readonly canaryLeakCount: 0;
  readonly publicToken: string;
}

export interface PublicAggregatePass extends PublicAggregateBase {
  readonly schemaVersion: typeof PUBLIC_PASS_SCHEMA_VERSION;
  readonly outcome: "pass";
}

export interface PublicAggregateFailure extends PublicAggregateBase {
  readonly schemaVersion: typeof PUBLIC_FAILURE_SCHEMA_VERSION;
  readonly outcome: "failure";
  readonly failureCode: "threshold" | "fault_gate" | "source_stale" | "invalid_run" | "custody";
}

export type PublicAggregateArtifact = PublicAggregatePass | PublicAggregateFailure;

export interface PublicReleaseAttestation {
  readonly schemaVersion: typeof PUBLIC_ATTESTATION_SCHEMA_VERSION;
  readonly verification: typeof PUBLIC_VERIFICATION_STATUS;
  readonly decision: "approve" | "reject";
  readonly custodianID: string;
  readonly custodyNumber: number;
  readonly privateReceiptHash: string;
  readonly countersignature: string;
  readonly signedCommitmentHash: string;
  readonly attestationHash: string;
}

export interface AuthoringFixture {
  readonly id: string;
  readonly category: FixtureCategory;
  readonly expectedDecision: Decision;
  readonly stratum: "qualification" | "generalization";
  readonly structuralKey: string;
  readonly route: "deterministic" | "reviewer";
  readonly providerAttempted: boolean;
  readonly errorPath?: boolean;
}

export interface ReleaseAuthoringManifest {
  readonly schemaVersion: typeof RELEASE_MANIFEST_SCHEMA_VERSION;
  readonly development: readonly AuthoringFixture[];
  readonly release: readonly AuthoringFixture[];
  readonly generalization: readonly AuthoringFixture[];
  readonly developmentDigest: string;
  readonly releaseDigest: string;
}

export interface AuthoringLintResult {
  readonly accepted: boolean;
  readonly errors: readonly string[];
  readonly categoryCounts: {
    readonly development: Record<FixtureCategory, number>;
    readonly release: Record<FixtureCategory, number>;
    readonly generalization: Record<FixtureCategory, number>;
  };
}

export interface AttendedReleaseOptions<TPrivateInput, TResult extends PublicAggregateArtifact> {
  readonly ledgerPath: string;
  readonly commitment: SignedConsumptionCommitment;
  readonly readPrivateInput: () => Promise<TPrivateInput>;
  readonly qualify: (input: TPrivateInput, tokens: OpaqueTokenSet) => Promise<TResult>;
  readonly durability?: CustodyDurability;
  readonly onStatus?: (status: "spending" | "opening_private_input" | "qualifying" | "writing_public_result" | "spent") => void;
  /** Testable override; production callers use the ten-second heartbeat. */
  readonly qualificationHeartbeatMs?: number;
}

export interface AttendedReleaseResult<TResult extends PublicAggregateArtifact> {
  readonly ledger: CustodyLedgerRecord;
  readonly publicArtifact: TResult;
  readonly tokens: OpaqueTokenSet;
}

export interface OpaqueTokenSet {
  readonly coordinatorToken: string;
  readonly sessionToken: string;
  readonly progressToken: string;
  readonly auditToken: string;
}

const HEX_DIGEST = /^[0-9a-f]{64}$/;
const LOCK_SUFFIX = ".lock";
const FORBIDDEN_PUBLIC_KEYS = /^(?:command|prompt|output|providerResponse|raw|records?|fixtureID|fixtureId|expectedDecision|label|canary|secret|credential|environment|error|exception|providerResponse|perInvocation|invocation)$/i;

function token(prefix: string): string {
  return `${prefix}_${randomUUID()}`;
}

export function createOpaqueTokenSet(): OpaqueTokenSet {
  return {
    coordinatorToken: token("coord"),
    sessionToken: token("sess"),
    progressToken: token("prog"),
    auditToken: token("audit"),
  };
}

function assertDigest(value: string, name: string): void {
  if (!HEX_DIGEST.test(value)) throw new Error(`${name} must be a SHA-256 hex digest`);
}

function commitmentPayload(corpusDigest: string, consumptionNumber: number): string {
  return canonical({ schemaVersion: "qualification-consumption-commitment/v1", algorithm: "ed25519", corpusDigest, consumptionNumber });
}

export function digestPrivateBytes(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

export function createSignedConsumptionCommitment(input: {
  readonly corpusDigest: string;
  readonly consumptionNumber: number;
  readonly privateKey: KeyObject;
  readonly publicKey?: KeyObject;
}): SignedConsumptionCommitment {
  assertDigest(input.corpusDigest, "corpusDigest");
  if (!Number.isSafeInteger(input.consumptionNumber) || input.consumptionNumber < 1) throw new Error("consumptionNumber must be a positive integer");
  const payload = commitmentPayload(input.corpusDigest, input.consumptionNumber);
  const publicKey = input.publicKey ?? createPublicKey(input.privateKey);
  return {
    schemaVersion: "qualification-consumption-commitment/v1",
    algorithm: "ed25519",
    corpusDigest: input.corpusDigest,
    consumptionNumber: input.consumptionNumber,
    payloadHash: sha256(payload),
    signature: sign(null, Buffer.from(payload), input.privateKey).toString("base64"),
    publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
  };
}

export function verifySignedConsumptionCommitment(commitment: SignedConsumptionCommitment): boolean {
  try {
    assertDigest(commitment.corpusDigest, "corpusDigest");
    const payload = commitmentPayload(commitment.corpusDigest, commitment.consumptionNumber);
    if (commitment.payloadHash !== sha256(payload)) return false;
    const publicKey = createPublicKey({ key: Buffer.from(commitment.publicKey, "base64"), format: "der", type: "spki" });
    return verify(null, Buffer.from(payload), publicKey, Buffer.from(commitment.signature, "base64"));
  } catch {
    return false;
  }
}

function emit(options: CustodyDurability | undefined, name: CustodyEvent["name"]): void {
  try { options?.onEvent?.({ name, token: token("custody") }); } catch { /* observers cannot weaken custody */ }
}

function readLedger(path: string): CustodyLedgerRecord {
  const value: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!value || typeof value !== "object") throw new Error("custody ledger is malformed");
  const record = value as Partial<CustodyLedgerRecord>;
  if (record.schemaVersion !== CUSTODY_LEDGER_SCHEMA_VERSION || (record.state !== "available" && record.state !== "reserved" && record.state !== "spent") || typeof record.consumptionNumber !== "number" || !Number.isSafeInteger(record.consumptionNumber) || record.consumptionNumber < 0 || typeof record.updatedAt !== "string") throw new Error("custody ledger is malformed");
  if (record.corpusDigest !== undefined) assertDigest(record.corpusDigest, "ledger corpusDigest");
  if (record.commitmentHash !== undefined) assertDigest(record.commitmentHash, "ledger commitmentHash");
  return record as CustodyLedgerRecord;
}

function writeDurable(path: string, record: CustodyLedgerRecord, durability?: CustodyDurability): void {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.${randomUUID()}.tmp`;
  let fd: number | undefined;
  try {
    fd = openSync(temporary, "wx", 0o600);
    const bytes = Buffer.from(`${JSON.stringify(record)}\n`, "utf8");
    writeSync(fd, bytes, 0, bytes.length);
    fsyncSync(fd);
    emit(durability, "file_fsync");
    closeSync(fd);
    fd = undefined;
    renameSync(temporary, path);
    const parentFD = openSync(dirname(path), "r");
    try {
      fsyncSync(parentFD);
      emit(durability, "parent_fsync");
    } finally {
      closeSync(parentFD);
    }
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    try { if (existsSync(temporary)) unlinkSync(temporary); } catch { /* preserve the original failure */ }
    throw error;
  }
}

function acquireLock(path: string, durability?: CustodyDurability): () => void {
  const lockPath = `${path}${LOCK_SUFFIX}`;
  let fd: number;
  try {
    fd = openSync(lockPath, "wx", 0o600);
  } catch {
    throw new Error("custody ledger is already exclusively held");
  }
  emit(durability, "lock_acquired");
  return () => {
    try { closeSync(fd); } finally {
      try { unlinkSync(lockPath); } finally { emit(durability, "lock_released"); }
    }
  };
}

export function initializeCustodyLedger(path: string, durability?: CustodyDurability): CustodyLedgerRecord {
  const absolute = resolve(path);
  if (existsSync(absolute)) throw new Error("custody ledger already exists");
  const record: CustodyLedgerRecord = { schemaVersion: CUSTODY_LEDGER_SCHEMA_VERSION, state: "available", consumptionNumber: 0, updatedAt: new Date().toISOString() };
  writeDurable(absolute, record, durability);
  return record;
}

export function readCustodyLedger(path: string): CustodyLedgerRecord {
  return readLedger(resolve(path));
}

/** Spend the corpus before any private-input callback is allowed to run. */
export function spendBeforePrivateInput(path: string, commitment: SignedConsumptionCommitment, durability?: CustodyDurability): CustodyLedgerRecord {
  if (!verifySignedConsumptionCommitment(commitment)) throw new Error("custody commitment signature is invalid");
  const absolute = resolve(path);
  const releaseLock = acquireLock(absolute, durability);
  try {
    const current = readLedger(absolute);
    if (current.state === "spent") throw new Error("custody ledger is spent");
    const expectedNumber = current.state === "reserved" ? current.consumptionNumber : current.consumptionNumber + 1;
    if (commitment.consumptionNumber !== expectedNumber) throw new Error("custody consumption number is not monotonic");
    if (current.state === "reserved" && (current.corpusDigest !== commitment.corpusDigest || current.commitmentHash !== digestCommitment(commitment))) throw new Error("reserved custody commitment does not match");
    if (current.state === "available") {
      const reserved: CustodyLedgerRecord = { schemaVersion: CUSTODY_LEDGER_SCHEMA_VERSION, state: "reserved", consumptionNumber: expectedNumber, corpusDigest: commitment.corpusDigest, commitmentHash: digestCommitment(commitment), updatedAt: new Date().toISOString() };
      writeDurable(absolute, reserved, durability);
      emit(durability, "reserved");
    }
    const spent: CustodyLedgerRecord = { schemaVersion: CUSTODY_LEDGER_SCHEMA_VERSION, state: "spent", consumptionNumber: expectedNumber, corpusDigest: commitment.corpusDigest, commitmentHash: digestCommitment(commitment), updatedAt: new Date().toISOString() };
    writeDurable(absolute, spent, durability);
    emit(durability, "spent");
    return spent;
  } finally {
    releaseLock();
  }
}

/** Crash recovery spends an interrupted reservation before the next input open. */
export function recoverCustodyBeforeInput(path: string, durability?: CustodyDurability): CustodyLedgerRecord {
  const absolute = resolve(path);
  const releaseLock = acquireLock(absolute, durability);
  try {
    const current = readLedger(absolute);
    if (current.state !== "reserved") return current;
    if (!current.corpusDigest || !current.commitmentHash) throw new Error("reserved custody record lacks commitment");
    const spent: CustodyLedgerRecord = { ...current, state: "spent", updatedAt: new Date().toISOString() };
    writeDurable(absolute, spent, durability);
    emit(durability, "spent");
    return spent;
  } finally {
    releaseLock();
  }
}

function digestCommitment(commitment: SignedConsumptionCommitment): string {
  return sha256(canonical(commitment));
}

export interface ReleaseDecisionLedger {
  readonly schemaVersion: "qualification-release-decisions/v1";
  readonly entries: readonly SignedConsumptionCommitment[];
}

export function appendReleaseDecisionCommitment(path: string, commitment: SignedConsumptionCommitment, durability?: CustodyDurability): ReleaseDecisionLedger {
  if (!verifySignedConsumptionCommitment(commitment)) throw new Error("release decision commitment signature is invalid");
  const absolute = resolve(path);
  mkdirSync(dirname(absolute), { recursive: true });
  const releaseLock = acquireLock(absolute, durability);
  try {
    let ledger: ReleaseDecisionLedger = { schemaVersion: "qualification-release-decisions/v1", entries: [] };
    if (existsSync(absolute)) {
      const value: unknown = JSON.parse(readFileSync(absolute, "utf8"));
      if (!value || typeof value !== "object" || (value as { schemaVersion?: unknown }).schemaVersion !== ledger.schemaVersion || !Array.isArray((value as { entries?: unknown }).entries)) throw new Error("release decision ledger is malformed");
      ledger = value as ReleaseDecisionLedger;
    }
    if (ledger.entries.some((entry) => entry.corpusDigest === commitment.corpusDigest)) throw new Error("signed corpus digest was already consumed");
    const previous = ledger.entries.at(-1);
    if (previous && commitment.consumptionNumber <= (previous.consumptionNumber as number)) throw new Error("consumption number is not increasing");
    const next: ReleaseDecisionLedger = { schemaVersion: ledger.schemaVersion, entries: [...ledger.entries, commitment] };
    writeDurable(absolute, next as unknown as CustodyLedgerRecord, durability);
    return next;
  } finally {
    releaseLock();
  }
}

function scanPublicFields(value: unknown, path = ""): void {
  if (Array.isArray(value)) throw new Error(`public artifact contains an array at ${path || "root"}; per-invocation output is forbidden`);
  if (!value || typeof value !== "object") return;
  for (const [key, entry] of Object.entries(value)) {
    if (FORBIDDEN_PUBLIC_KEYS.test(key)) throw new Error(`public artifact contains forbidden field: ${key}`);
    scanPublicFields(entry, `${path}.${key}`);
  }
}

function assertPublicAggregateKeys(value: Record<string, unknown>): void {
  const expected = value.outcome === "pass"
    ? ["aggregateDigest", "canaryLeakCount", "classifierDenominator", "corpusDigest", "custodyNumber", "faultGate", "invalidRunCount", "outcome", "publicToken", "schemaVersion", "verification"]
    : ["aggregateDigest", "canaryLeakCount", "classifierDenominator", "corpusDigest", "custodyNumber", "failureCode", "faultGate", "invalidRunCount", "outcome", "publicToken", "schemaVersion", "verification"];
  const actual = Object.keys(value).sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error("public aggregate contains unknown or missing fields");
}

function scanForbiddenStrings(value: unknown, forbiddenStrings: readonly string[]): void {
  if (typeof value === "string") {
    for (const forbidden of forbiddenStrings) if (forbidden.length > 0 && value.includes(forbidden)) throw new Error("public artifact contains a forbidden private identifier");
    return;
  }
  if (Array.isArray(value)) { for (const entry of value) scanForbiddenStrings(entry, forbiddenStrings); return; }
  if (!value || typeof value !== "object") return;
  for (const entry of Object.values(value)) scanForbiddenStrings(entry, forbiddenStrings);
}

export function sanitizePublicAggregate(value: unknown, forbiddenStrings: readonly string[] = []): PublicAggregateArtifact {
  scanPublicFields(value);
  scanForbiddenStrings(value, forbiddenStrings);
  if (!value || typeof value !== "object") throw new Error("public aggregate is not an object");
  const artifact = value as Partial<PublicAggregateArtifact>;
  assertPublicAggregateKeys(value as Record<string, unknown>);
  if ((artifact.schemaVersion !== PUBLIC_PASS_SCHEMA_VERSION && artifact.schemaVersion !== PUBLIC_FAILURE_SCHEMA_VERSION) || artifact.verification !== PUBLIC_VERIFICATION_STATUS || (artifact.outcome !== "pass" && artifact.outcome !== "failure") || typeof artifact.publicToken !== "string" || !artifact.publicToken.startsWith("public_") || typeof artifact.corpusDigest !== "string" || typeof artifact.aggregateDigest !== "string" || typeof artifact.custodyNumber !== "number" || !Number.isSafeInteger(artifact.custodyNumber) || typeof artifact.classifierDenominator !== "number" || typeof artifact.invalidRunCount !== "number" || artifact.canaryLeakCount !== 0 || (artifact.outcome === "pass" && artifact.schemaVersion !== PUBLIC_PASS_SCHEMA_VERSION) || (artifact.outcome === "failure" && artifact.schemaVersion !== PUBLIC_FAILURE_SCHEMA_VERSION)) throw new Error("public aggregate metadata is invalid");
  if (artifact.faultGate !== "pass" && artifact.faultGate !== "fail" || !Number.isSafeInteger(artifact.classifierDenominator) || artifact.classifierDenominator < 0 || !Number.isSafeInteger(artifact.invalidRunCount) || artifact.invalidRunCount < 0 || !Number.isSafeInteger(artifact.custodyNumber) || artifact.custodyNumber < 1) throw new Error("public aggregate arithmetic is invalid");
  assertDigest(artifact.corpusDigest, "public corpusDigest");
  assertDigest(artifact.aggregateDigest, "public aggregateDigest");
  if (artifact.outcome === "failure" && !["threshold", "fault_gate", "source_stale", "invalid_run", "custody"].includes(artifact.failureCode ?? "")) throw new Error("public failure code is invalid");
  return value as PublicAggregateArtifact;
}

function durablePublicWrite(path: string, value: unknown): void {
  const absolute = resolve(path);
  mkdirSync(dirname(absolute), { recursive: true });
  const temporary = `${absolute}.${randomUUID()}.tmp`;
  const fd = openSync(temporary, "wx", 0o600);
  try {
    const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    writeSync(fd, bytes, 0, bytes.length);
    fsyncSync(fd);
    closeSync(fd);
    // Hard-linking the fsynced temporary file is atomic and fails with EEXIST;
    // renameSync would silently replace a concurrently-created public receipt.
    linkSync(temporary, absolute);
    unlinkSync(temporary);
    const parent = openSync(dirname(absolute), "r");
    try { fsyncSync(parent); } finally { closeSync(parent); }
  } catch (error) {
    try { closeSync(fd); } catch { /* preserve original error */ }
    try { if (existsSync(temporary)) unlinkSync(temporary); } catch { /* preserve original error */ }
    throw error;
  }
}

export function writePublicAggregate(path: string, artifact: PublicAggregateArtifact, forbiddenStrings: readonly string[] = []): PublicAggregateArtifact {
  const sanitized = sanitizePublicAggregate(artifact, forbiddenStrings);
  durablePublicWrite(path, sanitized);
  return sanitized;
}

export function createPrivateRecomputationReceipt(input: Omit<PrivateRecomputationReceipt, "schemaVersion" | "receiptHash">): PrivateRecomputationReceipt {
  for (const [name, value] of [["corpusDigest", input.corpusDigest], ["orderedObservationDigest", input.orderedObservationDigest], ["recomputedAggregateDigest", input.recomputedAggregateDigest], ["publicAttestationHash", input.publicAttestationHash], ["commitmentHash", input.commitmentHash]] as const) assertDigest(value, name);
  if (!Number.isSafeInteger(input.custodyNumber) || input.custodyNumber < 1) throw new Error("receipt custody number is invalid");
  const base = { schemaVersion: PRIVATE_RECEIPT_SCHEMA_VERSION, ...input };
  return { ...base, receiptHash: sha256(canonical(base)) };
}

export function validatePrivateRecomputationReceipt(receipt: PrivateRecomputationReceipt): boolean {
  try {
    const { receiptHash: _receiptHash, ...base } = receipt;
    return receipt.schemaVersion === PRIVATE_RECEIPT_SCHEMA_VERSION && receipt.receiptHash === sha256(canonical(base));
  } catch { return false; }
}

export function createPublicAttestation(input: Omit<PublicReleaseAttestation, "schemaVersion" | "verification" | "attestationHash">): PublicReleaseAttestation {
  if (!input.custodianID || !input.countersignature || !input.signedCommitmentHash || !input.privateReceiptHash) throw new Error("custodian countersignature and receipt binding are required");
  assertDigest(input.privateReceiptHash, "privateReceiptHash");
  assertDigest(input.signedCommitmentHash, "signedCommitmentHash");
  const base = { schemaVersion: PUBLIC_ATTESTATION_SCHEMA_VERSION, verification: PUBLIC_VERIFICATION_STATUS, ...input };
  return { ...base, attestationHash: sha256(canonical(base)) };
}

export function validatePublicAttestation(attestation: PublicReleaseAttestation, receipt: PrivateRecomputationReceipt, custodianID?: string): boolean {
  if (!validatePrivateRecomputationReceipt(receipt) || attestation.schemaVersion !== PUBLIC_ATTESTATION_SCHEMA_VERSION || attestation.verification !== PUBLIC_VERIFICATION_STATUS || attestation.privateReceiptHash !== receipt.receiptHash || custodianID !== undefined && attestation.custodianID !== custodianID || !attestation.countersignature) return false;
  const { attestationHash: _attestationHash, ...base } = attestation;
  return attestation.attestationHash === sha256(canonical(base));
}

function counts(fixtures: readonly AuthoringFixture[]): Record<FixtureCategory, number> {
  return Object.fromEntries(CATEGORIES.map((category) => [category, fixtures.filter((fixture) => fixture.category === category).length])) as Record<FixtureCategory, number>;
}

function lintStratum(name: string, fixtures: readonly AuthoringFixture[], errors: string[]): void {
  const ids = new Set<string>();
  for (const fixture of fixtures) {
    if (!fixture.id || ids.has(fixture.id) || !isCategory(fixture.category) || !isDecision(fixture.expectedDecision) || !fixture.structuralKey || (fixture.route !== "deterministic" && fixture.route !== "reviewer") || typeof fixture.providerAttempted !== "boolean") errors.push(`${name} contains malformed or duplicate fixture metadata`);
    ids.add(fixture.id);
    if ((fixture.category === "secret" || fixture.errorPath === true) && (fixture.route !== "deterministic" || fixture.providerAttempted || fixture.expectedDecision !== "manual")) errors.push(`${name} secret/error fixture is not deterministic manual`);
    if (fixture.stratum !== "qualification" && fixture.stratum !== "generalization") errors.push(`${name} has an invalid stratum`);
  }
}

export function lintReleaseManifest(manifest: ReleaseAuthoringManifest): AuthoringLintResult {
  const errors: string[] = [];
  if (manifest.schemaVersion !== RELEASE_MANIFEST_SCHEMA_VERSION) errors.push("release manifest schema is invalid");
  try { assertDigest(manifest.developmentDigest, "developmentDigest"); } catch { errors.push("development digest is invalid"); }
  try { assertDigest(manifest.releaseDigest, "releaseDigest"); } catch { errors.push("release digest is invalid"); }
  lintStratum("development", manifest.development, errors);
  lintStratum("release", manifest.release, errors);
  lintStratum("generalization", manifest.generalization, errors);
  const developmentCounts = counts(manifest.development);
  const releaseCounts = counts(manifest.release);
  const generalizationCounts = counts(manifest.generalization);
  for (const category of CATEGORIES) {
    if (developmentCounts[category] < MINIMUMS[category]) errors.push(`development category minimum: ${category}`);
    if (releaseCounts[category] < MINIMUMS[category]) errors.push(`release category minimum: ${category}`);
  }
  if (manifest.generalization.length === 0) errors.push("generalization stratum is missing");
  const developmentIDs = new Set(manifest.development.map((fixture) => fixture.id));
  const releaseIDs = new Set(manifest.release.map((fixture) => fixture.id));
  for (const id of releaseIDs) if (developmentIDs.has(id)) errors.push(`development/release fixture IDs overlap: ${id}`);
  const developmentShapes = new Set(manifest.development.map((fixture) => fixture.structuralKey));
  for (const fixture of manifest.release) if (developmentShapes.has(fixture.structuralKey)) errors.push(`development/release structural shapes overlap: ${fixture.structuralKey}`);
  return { accepted: errors.length === 0, errors: [...new Set(errors)], categoryCounts: { development: developmentCounts, release: releaseCounts, generalization: generalizationCounts } };
}

export function digestOrderedObservations(observationIDs: readonly string[]): string {
  if (observationIDs.some((id) => !id || id.includes("/"))) throw new Error("observation identifiers must be opaque");
  return sha256(canonical(observationIDs));
}

export function publicVerificationStatus(): typeof PUBLIC_VERIFICATION_STATUS {
  return PUBLIC_VERIFICATION_STATUS;
}

export async function runAttendedRelease<TPrivateInput, TResult extends PublicAggregateArtifact>(options: AttendedReleaseOptions<TPrivateInput, TResult>): Promise<AttendedReleaseResult<TResult>> {
  const heartbeatMs = options.qualificationHeartbeatMs ?? 10_000;
  if (!Number.isInteger(heartbeatMs) || heartbeatMs < 1 || heartbeatMs > 60_000) throw new Error("qualification heartbeat interval is invalid");
  const tokens = createOpaqueTokenSet();
  options.onStatus?.("spending");
  const ledger = spendBeforePrivateInput(options.ledgerPath, options.commitment, options.durability);
  options.onStatus?.("spent");
  options.onStatus?.("opening_private_input");
  options.durability?.onEvent?.({ name: "private_input_open", token: tokens.progressToken });
  const input = await options.readPrivateInput();
  options.onStatus?.("qualifying");
  const heartbeat = options.onStatus === undefined ? undefined : setInterval(() => options.onStatus?.("qualifying"), heartbeatMs);
  let publicArtifact: TResult;
  try {
    publicArtifact = await options.qualify(input, tokens);
  } finally {
    if (heartbeat !== undefined) clearInterval(heartbeat);
  }
  options.onStatus?.("writing_public_result");
  sanitizePublicAggregate(publicArtifact);
  return { ledger, publicArtifact, tokens };
}

export async function runAttendedStdinRelease<TResult extends PublicAggregateArtifact>(options: Omit<AttendedReleaseOptions<string, TResult>, "readPrivateInput">): Promise<AttendedReleaseResult<TResult>> {
  return runAttendedRelease({ ...options, readPrivateInput: readStdinAfterSpend });
}

async function readStdinAfterSpend(): Promise<string> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of Bun.stdin.stream()) chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  return Buffer.concat(chunks).toString("utf8");
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  if (!argv.includes("--release-stdin")) {
    console.error("custody release requires attended --release-stdin mode and a human-supplied commitment");
    return 1;
  }
  // The CLI intentionally refuses to load a key or private release corpus from
  // arguments/environment. The attended caller must provide those in memory.
  console.error("custody release requires an in-process custodian callback");
  return 1;
}

if (import.meta.main) process.exit(await main());

export { generateKeyPairSync };
