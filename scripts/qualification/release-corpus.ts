import { createPublicKey, sign, verify, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  CATEGORIES,
  MINIMUMS,
  REPEAT_COUNT,
  REVIEW_TIMEOUT_MS,
  TEMPERATURE,
  canonical,
  isCategory,
  isDecision,
  type Corpus,
  type Decision,
  type FixtureCategory,
} from "./core";
import { digestPrivateBytes } from "./custody";
import type { AuthoringFixture, ReleaseAuthoringManifest } from "./custody";

export const AUTOMATED_DRAFT_SCHEMA = "classifier-eval/private-release-draft/v1" as const;
export const HUMAN_RELEASE_SCHEMA = "classifier-eval/private-release/v1" as const;
export const HUMAN_ADJUDICATION_SCHEMA = "classifier-eval/human-adjudication/v1" as const;
export const HUMAN_ADJUDICATION_ALGORITHM = "ed25519" as const;
export const AUTOMATED_DRAFT_AUTHORITY = "automated-draft" as const;
export const HUMAN_RELEASE_AUTHORITY = "human-adjudicated" as const;
export const RELEASE_RUBRIC_BINDING = "fixtures/eval/authoring-rubric.md" as const;
export const RELEASE_AUTHORING_METADATA_SCHEMA = "classifier-release-authoring-metadata/v1" as const;
export const PUBLIC_RELEASE_MANIFEST_SCHEMA = "classifier-eval/public-release-manifest/v1" as const;

type ISODate = string;
type Digest = string;

export interface PrivateReleaseCanaries {
  readonly structural: string;
  readonly label: string;
  readonly secret?: string;
}

export interface PrivateReleaseFixture {
  readonly id: string;
  readonly category: FixtureCategory;
  readonly command: string;
  readonly expectedDecision: Decision;
  readonly stratum: "qualification" | "generalization";
  readonly structuralKey: string;
  readonly route: "deterministic" | "reviewer";
  readonly providerAttempted: boolean;
  readonly errorPath?: boolean;
  readonly canaries: PrivateReleaseCanaries;
}

export interface ReleaseCorpusBindings {
  readonly candidateManifestHash: Digest;
  readonly rubric: typeof RELEASE_RUBRIC_BINDING;
}

export interface ReleaseCorpusRoles {
  readonly authorID: string;
  readonly adjudicatorID: string;
  readonly custodianID: string;
}

/** Out-of-band trust binding supplied by the custodian, never read from the corpus. */
export interface AuthorizedAdjudicator {
  readonly adjudicatorID: string;
  readonly publicKey: string;
}

export interface ReleaseCorpusTimestamps {
  readonly authoredAt: ISODate;
  readonly adjudicatedAt: ISODate;
  readonly custodyAt: ISODate;
}

export interface HumanAdjudicationAttestation {
  readonly schemaVersion: typeof HUMAN_ADJUDICATION_SCHEMA;
  readonly algorithm: typeof HUMAN_ADJUDICATION_ALGORITHM;
  readonly subjectDigest: Digest;
  readonly candidateManifestHash: Digest;
  readonly authorID: string;
  readonly adjudicatorID: string;
  readonly custodianID: string;
  readonly authoredAt: ISODate;
  readonly adjudicatedAt: ISODate;
  readonly custodyAt: ISODate;
  readonly payloadHash: Digest;
  readonly signature: string;
  readonly publicKey: string;
}

interface ReleaseCorpusBase {
  readonly bindings: ReleaseCorpusBindings;
  readonly corpusVersion: string;
  readonly minimums: Readonly<Record<FixtureCategory, number>>;
  readonly repeats: typeof REPEAT_COUNT;
  readonly temperature: typeof TEMPERATURE;
  readonly timeoutMs: typeof REVIEW_TIMEOUT_MS;
  readonly generatedAt: ISODate;
  readonly release: readonly PrivateReleaseFixture[];
  readonly generalization: readonly PrivateReleaseFixture[];
}

export interface AutomatedDraftCorpus extends ReleaseCorpusBase {
  readonly schemaVersion: typeof AUTOMATED_DRAFT_SCHEMA;
  readonly authority: typeof AUTOMATED_DRAFT_AUTHORITY;
  readonly releaseEligible: false;
}

export interface HumanReleaseCorpus extends ReleaseCorpusBase {
  readonly schemaVersion: typeof HUMAN_RELEASE_SCHEMA;
  readonly authority: typeof HUMAN_RELEASE_AUTHORITY;
  readonly releaseEligible: true;
  readonly roles: ReleaseCorpusRoles;
  readonly timestamps: ReleaseCorpusTimestamps;
  readonly adjudication: HumanAdjudicationAttestation;
}

export type PrivateReleaseCorpus = AutomatedDraftCorpus | HumanReleaseCorpus;
export type ReleaseCorpusEnvelope = PrivateReleaseCorpus;

/** Public authoring metadata. It deliberately has no command, label, or canary fields. */
export interface AuthoringFixtureMetadata {
  readonly id: string;
  readonly category: FixtureCategory;
  readonly stratum: "qualification" | "generalization";
  readonly structuralKey: string;
  readonly route: "deterministic" | "reviewer";
  readonly providerAttempted: boolean;
  readonly errorPath?: boolean;
}

export interface ReleaseAuthoringManifestMetadata {
  readonly schemaVersion: typeof RELEASE_AUTHORING_METADATA_SCHEMA;
  readonly development: readonly AuthoringFixtureMetadata[];
  readonly release: readonly AuthoringFixtureMetadata[];
  readonly generalization: readonly AuthoringFixtureMetadata[];
  readonly developmentDigest: Digest;
  readonly releaseDigest: Digest;
}

export interface PublicReleaseManifest {
  readonly schemaVersion: typeof PUBLIC_RELEASE_MANIFEST_SCHEMA;
  readonly corpusVersion: string;
  readonly corpusDigest: Digest;
  readonly candidateManifestHash: Digest;
  readonly rubricHash: Digest;
  readonly fixtureCount: number;
  readonly categoryCounts: Readonly<Record<FixtureCategory, number>>;
  readonly generalizationCount: number;
  readonly authority: typeof HUMAN_RELEASE_AUTHORITY;
  readonly releaseEligible: true;
  readonly custodyState: "unused";
  readonly roles: ReleaseCorpusRoles;
  readonly timestamps: ReleaseCorpusTimestamps;
}

export interface ParseReleaseCorpusOptions {
  readonly developmentCorpus?: unknown;
  readonly expectedDigest?: Digest;
  readonly authorizedAdjudicator?: AuthorizedAdjudicator;
}

const DIGEST = /^[0-9a-f]{64}$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const RELEASE_FIXTURE_MINIMUM = CATEGORIES.reduce((sum, category) => sum + MINIMUMS[category], 0);
const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

function releaseRubricDigest(): Digest {
  return digestPrivateBytes(readFileSync(resolve(PROJECT_ROOT, RELEASE_RUBRIC_BINDING)));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function exactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): void {
  const allowed = new Set([...required, ...optional]);
  const missing = required.find((key) => !(key in value));
  if (missing) throw new Error(`release corpus is missing ${missing}`);
  const extra = Object.keys(value).find((key) => !allowed.has(key));
  if (extra) throw new Error(`release corpus contains an unknown field: ${extra}`);
}

function nonempty(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 512) throw new Error(`release corpus ${name} is invalid`);
  return value;
}

function digest(value: unknown, name: string): Digest {
  const result = nonempty(value, name);
  if (!DIGEST.test(result)) throw new Error(`release corpus ${name} is invalid`);
  return result;
}

function timestamp(value: unknown, name: string): ISODate {
  const result = nonempty(value, name);
  if (!ISO_UTC.test(result) || Number.isNaN(Date.parse(result))) throw new Error(`release corpus ${name} is invalid`);
  return result;
}

function encoded(value: unknown, name: string): string {
  return nonempty(value, name);
}

function humanAdjudicationPayload(input: Pick<HumanAdjudicationAttestation, "subjectDigest" | "candidateManifestHash" | "authorID" | "adjudicatorID" | "custodianID" | "authoredAt" | "adjudicatedAt" | "custodyAt">): string {
  return canonical({
    schemaVersion: HUMAN_ADJUDICATION_SCHEMA,
    algorithm: HUMAN_ADJUDICATION_ALGORITHM,
    subjectDigest: input.subjectDigest,
    candidateManifestHash: input.candidateManifestHash,
    authorID: input.authorID,
    adjudicatorID: input.adjudicatorID,
    custodianID: input.custodianID,
    authoredAt: input.authoredAt,
    adjudicatedAt: input.adjudicatedAt,
    custodyAt: input.custodyAt,
  });
}

export function humanReleaseSubjectDigest(value: Omit<HumanReleaseCorpus, "adjudication"> | HumanReleaseCorpus): Digest {
  const { adjudication: _adjudication, ...subject } = value as HumanReleaseCorpus;
  return digestPrivateBytes(canonical(subject));
}

export function createHumanAdjudicationAttestation(input: {
  readonly subject: Omit<HumanReleaseCorpus, "adjudication">;
  readonly privateKey: KeyObject;
  readonly publicKey?: KeyObject;
}): HumanAdjudicationAttestation {
  if (input.subject.schemaVersion !== HUMAN_RELEASE_SCHEMA || input.subject.authority !== HUMAN_RELEASE_AUTHORITY || !input.subject.releaseEligible) throw new Error("human adjudication subject is invalid");
  const subjectDigest = humanReleaseSubjectDigest(input.subject);
  const payloadInput = {
    subjectDigest,
    candidateManifestHash: input.subject.bindings.candidateManifestHash,
    authorID: input.subject.roles.authorID,
    adjudicatorID: input.subject.roles.adjudicatorID,
    custodianID: input.subject.roles.custodianID,
    authoredAt: input.subject.timestamps.authoredAt,
    adjudicatedAt: input.subject.timestamps.adjudicatedAt,
    custodyAt: input.subject.timestamps.custodyAt,
  } satisfies Pick<HumanAdjudicationAttestation, "subjectDigest" | "candidateManifestHash" | "authorID" | "adjudicatorID" | "custodianID" | "authoredAt" | "adjudicatedAt" | "custodyAt">;
  const payload = humanAdjudicationPayload(payloadInput);
  const publicKey = input.publicKey ?? createPublicKey(input.privateKey);
  return {
    schemaVersion: HUMAN_ADJUDICATION_SCHEMA,
    algorithm: HUMAN_ADJUDICATION_ALGORITHM,
    ...payloadInput,
    payloadHash: digestPrivateBytes(payload),
    signature: sign(null, Buffer.from(payload, "utf8"), input.privateKey).toString("base64"),
    publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
  };
}

export function verifyHumanAdjudicationAttestation(attestation: HumanAdjudicationAttestation, corpus: HumanReleaseCorpus, authorizedAdjudicator?: AuthorizedAdjudicator): boolean {
  try {
    if (attestation.schemaVersion !== HUMAN_ADJUDICATION_SCHEMA || attestation.algorithm !== HUMAN_ADJUDICATION_ALGORITHM) return false;
    if (attestation.subjectDigest !== humanReleaseSubjectDigest(corpus) || attestation.candidateManifestHash !== corpus.bindings.candidateManifestHash) return false;
    if (attestation.authorID !== corpus.roles.authorID || attestation.adjudicatorID !== corpus.roles.adjudicatorID || attestation.custodianID !== corpus.roles.custodianID) return false;
    if (attestation.authoredAt !== corpus.timestamps.authoredAt || attestation.adjudicatedAt !== corpus.timestamps.adjudicatedAt || attestation.custodyAt !== corpus.timestamps.custodyAt) return false;
    if (!authorizedAdjudicator || attestation.adjudicatorID !== authorizedAdjudicator.adjudicatorID || attestation.publicKey !== authorizedAdjudicator.publicKey) return false;
    const payload = humanAdjudicationPayload(attestation);
    if (attestation.payloadHash !== digestPrivateBytes(payload)) return false;
    const publicKey = createPublicKey({ key: Buffer.from(attestation.publicKey, "base64"), format: "der", type: "spki" });
    return verify(null, Buffer.from(payload, "utf8"), publicKey, Buffer.from(attestation.signature, "base64"));
  } catch {
    return false;
  }
}

function parseAdjudication(value: unknown): HumanAdjudicationAttestation {
  if (!isRecord(value)) throw new Error("human adjudication attestation is required");
  exactKeys(value, ["schemaVersion", "algorithm", "subjectDigest", "candidateManifestHash", "authorID", "adjudicatorID", "custodianID", "authoredAt", "adjudicatedAt", "custodyAt", "payloadHash", "signature", "publicKey"]);
  if (value.schemaVersion !== HUMAN_ADJUDICATION_SCHEMA || value.algorithm !== HUMAN_ADJUDICATION_ALGORITHM) throw new Error("human adjudication attestation metadata is invalid");
  return {
    schemaVersion: HUMAN_ADJUDICATION_SCHEMA,
    algorithm: HUMAN_ADJUDICATION_ALGORITHM,
    subjectDigest: digest(value.subjectDigest, "adjudication subject digest"),
    candidateManifestHash: digest(value.candidateManifestHash, "adjudication candidate binding"),
    authorID: nonempty(value.authorID, "adjudication author role"),
    adjudicatorID: nonempty(value.adjudicatorID, "adjudication adjudicator role"),
    custodianID: nonempty(value.custodianID, "adjudication custodian role"),
    authoredAt: timestamp(value.authoredAt, "adjudication authoredAt"),
    adjudicatedAt: timestamp(value.adjudicatedAt, "adjudication adjudicatedAt"),
    custodyAt: timestamp(value.custodyAt, "adjudication custodyAt"),
    payloadHash: digest(value.payloadHash, "adjudication payload hash"),
    signature: encoded(value.signature, "adjudication signature"),
    publicKey: encoded(value.publicKey, "adjudication public key"),
  };
}

function parseCanaries(value: unknown, category: FixtureCategory): PrivateReleaseCanaries {
  if (!isRecord(value)) throw new Error("release corpus canaries are invalid");
  exactKeys(value, ["structural", "label"], ["secret"]);
  const structural = nonempty(value.structural, "structural canary");
  const label = nonempty(value.label, "label canary");
  if (category === "secret" && typeof value.secret !== "string") throw new Error("release corpus secret canary is missing");
  if (category !== "secret" && value.secret !== undefined) throw new Error("release corpus has an unexpected secret canary");
  return { structural, label, ...(typeof value.secret === "string" ? { secret: value.secret } : {}) };
}

function parseFixture(value: unknown): PrivateReleaseFixture {
  if (!isRecord(value)) throw new Error("release corpus fixture is invalid");
  exactKeys(value, ["id", "category", "command", "expectedDecision", "stratum", "structuralKey", "route", "providerAttempted", "canaries"], ["errorPath"]);
  if (!isCategory(value.category) || !isDecision(value.expectedDecision)) throw new Error("release corpus fixture label is invalid");
  if (value.stratum !== "qualification" && value.stratum !== "generalization") throw new Error("release corpus fixture stratum is invalid");
  if (value.route !== "deterministic" && value.route !== "reviewer") throw new Error("release corpus fixture route is invalid");
  if (typeof value.providerAttempted !== "boolean") throw new Error("release corpus fixture provider flag is invalid");
  if (value.errorPath !== undefined && typeof value.errorPath !== "boolean") throw new Error("release corpus fixture error path is invalid");
  return {
    id: nonempty(value.id, "fixture id"),
    category: value.category,
    command: nonempty(value.command, "fixture command"),
    expectedDecision: value.expectedDecision,
    stratum: value.stratum,
    structuralKey: nonempty(value.structuralKey, "structural key"),
    route: value.route,
    providerAttempted: value.providerAttempted,
    ...(value.errorPath === true ? { errorPath: true } : {}),
    canaries: parseCanaries(value.canaries, value.category),
  };
}

function parseShape(value: unknown, authorizedAdjudicator?: AuthorizedAdjudicator): PrivateReleaseCorpus {
  if (typeof value === "string" || value instanceof Uint8Array) {
    try { value = JSON.parse(new TextDecoder().decode(value instanceof Uint8Array ? value : new TextEncoder().encode(value))); }
    catch { throw new Error("release corpus JSON is invalid"); }
  }
  if (!isRecord(value)) throw new Error("release corpus is not an object");
  const isDraft = value.schemaVersion === AUTOMATED_DRAFT_SCHEMA;
  const isHuman = value.schemaVersion === HUMAN_RELEASE_SCHEMA;
  if (!isDraft && !isHuman) throw new Error("release corpus schema is invalid");
  const required = ["schemaVersion", "authority", "releaseEligible", "bindings", "corpusVersion", "minimums", "repeats", "temperature", "timeoutMs", "generatedAt", "release", "generalization"];
  exactKeys(value, required, isHuman ? ["roles", "timestamps", "adjudication"] : []);
  if (value.authority !== (isDraft ? AUTOMATED_DRAFT_AUTHORITY : HUMAN_RELEASE_AUTHORITY) || value.releaseEligible !== !isDraft) throw new Error("release corpus authority binding is invalid");
  if (value.repeats !== REPEAT_COUNT || value.temperature !== TEMPERATURE || value.timeoutMs !== REVIEW_TIMEOUT_MS) throw new Error("release corpus execution contract is invalid");
  const bindings = value.bindings;
  if (!isRecord(bindings)) throw new Error("release corpus bindings are invalid");
  exactKeys(bindings, ["candidateManifestHash", "rubric"]);
  const candidateManifestHash = digest(bindings.candidateManifestHash, "candidate manifest binding");
  if (bindings.rubric !== RELEASE_RUBRIC_BINDING) throw new Error("release corpus rubric binding is invalid");
  const minimums = value.minimums;
  if (!isRecord(minimums)) throw new Error("release corpus minimums are invalid");
  exactKeys(minimums, CATEGORIES);
  if (CATEGORIES.some((category) => minimums[category] !== MINIMUMS[category])) throw new Error("release corpus minimums are invalid");
  if (!Array.isArray(value.release) || !Array.isArray(value.generalization)) throw new Error("release corpus strata are invalid");
  const base: ReleaseCorpusBase = {
    bindings: { candidateManifestHash, rubric: RELEASE_RUBRIC_BINDING },
    corpusVersion: nonempty(value.corpusVersion, "corpus version"),
    minimums: MINIMUMS,
    repeats: REPEAT_COUNT,
    temperature: TEMPERATURE,
    timeoutMs: REVIEW_TIMEOUT_MS,
    generatedAt: timestamp(value.generatedAt, "generatedAt"),
    release: value.release.map(parseFixture),
    generalization: value.generalization.map(parseFixture),
  };
  if (isDraft) return { ...base, schemaVersion: AUTOMATED_DRAFT_SCHEMA, authority: AUTOMATED_DRAFT_AUTHORITY, releaseEligible: false };
  if (!isRecord(value.roles) || !isRecord(value.timestamps)) throw new Error("human release roles and timestamps are required");
  exactKeys(value.roles, ["authorID", "adjudicatorID", "custodianID"]);
  exactKeys(value.timestamps, ["authoredAt", "adjudicatedAt", "custodyAt"]);
  const roles: ReleaseCorpusRoles = {
    authorID: nonempty(value.roles.authorID, "author role"),
    adjudicatorID: nonempty(value.roles.adjudicatorID, "adjudicator role"),
    custodianID: nonempty(value.roles.custodianID, "custodian role"),
  };
  const timestamps: ReleaseCorpusTimestamps = {
    authoredAt: timestamp(value.timestamps.authoredAt, "authoredAt"),
    adjudicatedAt: timestamp(value.timestamps.adjudicatedAt, "adjudicatedAt"),
    custodyAt: timestamp(value.timestamps.custodyAt, "custodyAt"),
  };
  if (new Set([roles.authorID, roles.adjudicatorID, roles.custodianID]).size !== 3) throw new Error("human release roles must be distinct");
  const unsigned: Omit<HumanReleaseCorpus, "adjudication"> = {
    ...base,
    schemaVersion: HUMAN_RELEASE_SCHEMA,
    authority: HUMAN_RELEASE_AUTHORITY,
    releaseEligible: true,
    roles,
    timestamps,
  };
  const corpus: HumanReleaseCorpus = { ...unsigned, adjudication: parseAdjudication(value.adjudication) };
  if (!verifyHumanAdjudicationAttestation(corpus.adjudication, corpus, authorizedAdjudicator)) throw new Error("human adjudication attestation is invalid or not authorized");
  return corpus;
}

function developmentFixtures(value: unknown): readonly Record<string, unknown>[] {
  if (Array.isArray(value)) return value.filter(isRecord);
  if (!isRecord(value)) return [];
  if (Array.isArray(value.development)) return value.development.filter(isRecord);
  if (isRecord(value.corpus) && Array.isArray(value.corpus.fixtures)) return value.corpus.fixtures.filter(isRecord);
  if (Array.isArray(value.fixtures)) return value.fixtures.filter(isRecord);
  return [];
}

function validateParsedCorpus(corpus: PrivateReleaseCorpus, developmentCorpus?: unknown, authorizedAdjudicator?: AuthorizedAdjudicator): string[] {
  const errors: string[] = [];
  const counts = Object.fromEntries(CATEGORIES.map((category) => [category, corpus.release.filter((fixture) => fixture.category === category).length])) as Record<FixtureCategory, number>;
  for (const category of CATEGORIES) if (counts[category] < MINIMUMS[category]) errors.push(`release category minimum: ${category}`);
  if (corpus.release.length < RELEASE_FIXTURE_MINIMUM) errors.push(`release corpus requires at least ${RELEASE_FIXTURE_MINIMUM} fixtures`);
  if (corpus.generalization.length === 0) errors.push("generalization stratum is missing");
  const ids = new Set<string>();
  const structuralKeys = new Set<string>();
  for (const fixture of [...corpus.release, ...corpus.generalization]) {
    if (fixture.stratum !== (corpus.release.includes(fixture) ? "qualification" : "generalization")) errors.push("fixture stratum does not match its envelope stratum");
    if (ids.has(fixture.id)) errors.push("release corpus fixture IDs are not unique");
    ids.add(fixture.id);
    if (structuralKeys.has(fixture.structuralKey)) errors.push("release corpus structural keys are not unique");
    structuralKeys.add(fixture.structuralKey);
    if ((fixture.category === "secret" || fixture.errorPath === true) && (fixture.route !== "deterministic" || fixture.providerAttempted || fixture.expectedDecision !== "manual")) errors.push("secret/error fixture is not deterministic manual");
  }
  const developmentIDs = new Set<string>();
  const developmentShapes = new Set<string>();
  for (const fixture of developmentFixtures(developmentCorpus)) {
    if (typeof fixture.id === "string") developmentIDs.add(fixture.id);
    if (typeof fixture.structuralKey === "string") developmentShapes.add(fixture.structuralKey);
  }
  for (const fixture of corpus.release) {
    if (developmentIDs.has(fixture.id)) errors.push("development/release fixture IDs overlap");
    if (developmentShapes.has(fixture.structuralKey)) errors.push("development/release structural keys overlap");
  }
  if (corpus.schemaVersion === HUMAN_RELEASE_SCHEMA && new Set([corpus.roles.authorID, corpus.roles.adjudicatorID, corpus.roles.custodianID]).size !== 3) errors.push("human release roles must be distinct");
  if (corpus.schemaVersion === HUMAN_RELEASE_SCHEMA && !verifyHumanAdjudicationAttestation(corpus.adjudication, corpus, authorizedAdjudicator)) errors.push("human adjudication attestation is invalid or not authorized");
  if (corpus.schemaVersion === AUTOMATED_DRAFT_SCHEMA && corpus.releaseEligible) errors.push("automated draft cannot be release eligible");
  return [...new Set(errors)];
}

export function validateReleaseCorpus(value: unknown, developmentCorpus?: unknown, options: ParseReleaseCorpusOptions = {}): string[] {
  try {
    const parsed = parseShape(value, options.authorizedAdjudicator);
    return validateParsedCorpus(parsed, developmentCorpus, options.authorizedAdjudicator);
  } catch (error) {
    return [error instanceof Error ? error.message : "release corpus is invalid"];
  }
}

export function parseReleaseCorpus(value: unknown, options: ParseReleaseCorpusOptions = {}): PrivateReleaseCorpus {
  const parsed = parseShape(value, options.authorizedAdjudicator);
  const errors = validateParsedCorpus(parsed, options.developmentCorpus, options.authorizedAdjudicator);
  if (options.expectedDigest !== undefined) {
    if (!DIGEST.test(options.expectedDigest) || digestPrivateBytes(canonical(parsed)) !== options.expectedDigest) errors.push("release corpus digest does not match expected digest");
  }
  if (errors.length > 0) throw new Error(errors.join("; "));
  return parsed;
}

export function releaseCorpusDigest(value: PrivateReleaseCorpus | string | Uint8Array, options: ParseReleaseCorpusOptions = {}): Digest {
  const parsed = parseReleaseCorpus(value, options);
  return digestPrivateBytes(canonical(parsed));
}

function metadataFixture(value: Record<string, unknown>): AuthoringFixtureMetadata {
  if (typeof value.id !== "string" || !isCategory(value.category) || (value.stratum !== "qualification" && value.stratum !== "generalization") || typeof value.structuralKey !== "string" || (value.route !== "deterministic" && value.route !== "reviewer") || typeof value.providerAttempted !== "boolean") throw new Error("development authoring metadata is invalid");
  return {
    id: value.id,
    category: value.category,
    stratum: value.stratum,
    structuralKey: value.structuralKey,
    route: value.route,
    providerAttempted: value.providerAttempted,
    ...(value.errorPath === true ? { errorPath: true } : {}),
  };
}

function publicFixture(fixture: PrivateReleaseFixture): AuthoringFixtureMetadata {
  const { id, category, stratum, structuralKey, route, providerAttempted, errorPath } = fixture;
  return { id, category, stratum, structuralKey, route, providerAttempted, ...(errorPath === true ? { errorPath: true } : {}) };
}

function privateAuthoringFixture(fixture: PrivateReleaseFixture): AuthoringFixture {
  const { id, category, expectedDecision, stratum, structuralKey, route, providerAttempted, errorPath } = fixture;
  return { id, category, expectedDecision, stratum, structuralKey, route, providerAttempted, ...(errorPath === true ? { errorPath: true } : {}) };
}

function privateDevelopmentFixture(value: Record<string, unknown>): AuthoringFixture {
  const metadata = metadataFixture(value);
  if (!isDecision(value.expectedDecision)) throw new Error("development authoring label is required in memory");
  return { ...metadata, expectedDecision: value.expectedDecision };
}

export function toReleaseAuthoringManifest(value: unknown, developmentManifest?: unknown, options: ParseReleaseCorpusOptions = {}): ReleaseAuthoringManifestMetadata {
  const corpus = parseReleaseCorpus(value, options);
  const development = developmentFixtures(developmentManifest).map(metadataFixture);
  return {
    schemaVersion: RELEASE_AUTHORING_METADATA_SCHEMA,
    development,
    release: corpus.release.map(publicFixture),
    generalization: corpus.generalization.map(publicFixture),
    developmentDigest: isRecord(developmentManifest) && typeof developmentManifest.developmentDigest === "string" && DIGEST.test(developmentManifest.developmentDigest)
      ? developmentManifest.developmentDigest
      : digestPrivateBytes(canonical(development)),
    releaseDigest: releaseCorpusDigest(corpus, options),
  };
}

/** Reconstruct the existing custody authoring shape in memory, including labels. */
export function toPrivateAuthoringManifest(value: unknown, developmentManifest?: unknown, options: ParseReleaseCorpusOptions = {}): ReleaseAuthoringManifest {
  const corpus = parseReleaseCorpus(value, options);
  const development = developmentFixtures(developmentManifest).map(privateDevelopmentFixture);
  const developmentDigest = isRecord(developmentManifest) && typeof developmentManifest.developmentDigest === "string" && DIGEST.test(developmentManifest.developmentDigest)
    ? developmentManifest.developmentDigest
    : digestPrivateBytes(canonical(development));
  return {
    schemaVersion: "classifier-release-manifest/v1",
    development,
    release: corpus.release.map(privateAuthoringFixture),
    generalization: corpus.generalization.map(privateAuthoringFixture),
    developmentDigest,
    releaseDigest: releaseCorpusDigest(corpus, options),
  };
}

/** Opaque values used to prevent private identifiers entering public aggregates. */
export function releaseCorpusIdentifiers(value: PrivateReleaseCorpus | unknown, options: ParseReleaseCorpusOptions = {}): readonly string[] {
  const corpus = parseReleaseCorpus(value, options);
  return [...new Set([...corpus.release, ...corpus.generalization].flatMap((fixture) => [fixture.id, fixture.command, fixture.structuralKey, fixture.canaries.structural, fixture.canaries.label, ...(fixture.canaries.secret ? [fixture.canaries.secret] : [])]))];
}

function assertPublicReleaseManifest(value: PublicReleaseManifest, privateCorpus: HumanReleaseCorpus, options: ParseReleaseCorpusOptions): void {
  const forbiddenKeys = /^(?:command|expectedDecision|label|canary|canaries|structuralKey|raw|prompt|output|providerResponse)$/i;
  const forbiddenValues = releaseCorpusIdentifiers(privateCorpus, options);
  const scan = (entry: unknown): void => {
    if (Array.isArray(entry)) { entry.forEach(scan); return; }
    if (!isRecord(entry)) {
      if (typeof entry === "string" && forbiddenValues.some((forbidden) => forbidden.length > 0 && entry.includes(forbidden))) throw new Error("public release manifest contains a private value");
      return;
    }
    for (const [key, nested] of Object.entries(entry)) {
      if (forbiddenKeys.test(key)) throw new Error(`public release manifest contains a private field: ${key}`);
      scan(nested);
    }
  };
  scan(value);
  if (!/^classifier-eval\/public-release-manifest\/v1$/.test(value.schemaVersion)) throw new Error("public release manifest schema is invalid");
}

export function toPublicReleaseManifest(value: unknown, options: ParseReleaseCorpusOptions = {}): PublicReleaseManifest {
  const corpus = parseReleaseCorpus(value, options);
  if (corpus.schemaVersion !== HUMAN_RELEASE_SCHEMA || corpus.authority !== HUMAN_RELEASE_AUTHORITY || !corpus.releaseEligible) throw new Error("public release manifest requires human adjudication");
  const categoryCounts = Object.fromEntries(CATEGORIES.map((category) => [category, corpus.release.filter((fixture) => fixture.category === category).length])) as Record<FixtureCategory, number>;
  const manifest: PublicReleaseManifest = {
    schemaVersion: PUBLIC_RELEASE_MANIFEST_SCHEMA,
    corpusVersion: corpus.corpusVersion,
    corpusDigest: releaseCorpusDigest(corpus, options),
    candidateManifestHash: corpus.bindings.candidateManifestHash,
    rubricHash: releaseRubricDigest(),
    fixtureCount: corpus.release.length,
    categoryCounts,
    generalizationCount: corpus.generalization.length,
    authority: corpus.authority,
    releaseEligible: corpus.releaseEligible,
    custodyState: "unused",
    roles: corpus.roles,
    timestamps: corpus.timestamps,
  };
  assertPublicReleaseManifest(manifest, corpus, options);
  return manifest;
}

export { canonical };
export type { Corpus };
