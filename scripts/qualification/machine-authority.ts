/**
 * Machine-adjudicated release authority.
 *
 * This is a third corpus authority alongside `automated-draft` (structural
 * rehearsal, never release eligible) and `human-adjudicated` (an independent
 * human author, adjudicator, and custodian). It exists because the owner
 * directed that release qualification complete without hand authorship.
 *
 * What this authority does and does not establish is deliberately explicit.
 * The signature below proves that the recorded corpus bytes are the bytes that
 * were qualified. It does NOT stand in for human review: no person authored,
 * adjudicated, or attested this corpus, and the artifact says so in a required
 * field rather than in a comment. The human path in `release-corpus.ts` is left
 * untouched; nothing here can produce a `human-adjudicated` artifact.
 */
import { createHash, createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from "node:crypto";
import { CATEGORIES, MINIMUMS, REPEAT_COUNT, REVIEW_TIMEOUT_MS, TEMPERATURE, canonical, type Decision, type FixtureCategory } from "./core";
import type { PrivateReleaseFixture } from "./release-corpus";

export const MACHINE_RELEASE_SCHEMA = "classifier-eval/private-release-machine/v1" as const;
export const MACHINE_RELEASE_AUTHORITY = "machine-adjudicated" as const;
export const MACHINE_ATTESTATION_SCHEMA = "classifier-eval/machine-adjudication/v1" as const;
export const MACHINE_ATTESTATION_ALGORITHM = "ed25519" as const;
export const MACHINE_RUBRIC_BINDING = "fixtures/eval/authoring-rubric.md" as const;

/**
 * The standing disclosure carried by every machine-adjudicated artifact. It is
 * a required field so that a reader of the JSON cannot miss it.
 *
 * The disclosure separates two claims that are easy to conflate. Every *label*
 * in this corpus is machine-assigned, without exception, and that is the claim
 * that matters for whether the corpus can be trusted as ground truth. Where a
 * *command* came from is a separate fact, recorded per category in
 * `commandSource`, because a stratum harvested from real local usage was
 * written by a person doing real work even though no person labeled it. Saying
 * "authored and labeled by a model" over a harvested stratum would be a false
 * provenance claim on the one artifact whose purpose is provenance.
 */
export const MACHINE_AUTHORITY_DISCLOSURE =
  "Every label in this corpus was assigned by a model, not a person. No human authored, adjudicated, or attested it. Commands were either written by the authoring model or harvested from real local shell usage; `commandSource` records which, per category. The signature attests byte integrity of the qualified corpus only; it is not a human release attestation." as const;

/**
 * Where a category's commands came from. This says nothing about the labels,
 * which are machine-assigned throughout.
 */
export type CommandSource = "model-authored" | "harvested-local-usage";

export const COMMAND_SOURCES: readonly CommandSource[] = ["model-authored", "harvested-local-usage"];

export interface MachineProvenance {
  /** Model that assigned every label, and that wrote the model-authored commands. */
  readonly authorModel: string;
  /**
   * Variant requested on the authoring call, or `null` on a harness with no
   * variant concept. Codex is the latter: it tunes with a separate reasoning
   * effort and `roster resolve` reports `"variant": null`, so writing the
   * effort here would record a variant that was never requested on the one
   * artifact whose whole purpose is provenance.
   */
  readonly authorVariant: string | null;
  /** Reasoning effort requested on the authoring call, or `null` where the harness has none. */
  readonly authorEffort: string | null;
  /**
   * Whether the tuning actually served was confirmed. No harness used here
   * reports it back: OpenCode 1.18.10 does not report a served variant, and
   * Codex reports a model id (`gpt-5.6-codex`) that is not even the
   * dispatchable selector, so a served-effort claim would be a guess. This is
   * `unverified` for the same reason the frozen candidate manifest declines to
   * attest served variant.
   */
  readonly authorTuningServed: "unverified";
  /** Classifier being measured. Must differ in vendor lineage from the author. */
  readonly classifierUnderTest: string;
  /**
   * Command origin per category. A harvested category draws its commands from
   * shell history recorded in this checkout, so its operands name paths that
   * actually exist and its shapes are ones somebody really ran. The labels are
   * still machine-assigned.
   */
  readonly commandSource: Readonly<Record<FixtureCategory, CommandSource>>;
  /** No second labeler ran, so corpus label errors are not independently caught. */
  readonly independentLabelCheck: boolean;
  readonly humanAttestation: false;
  readonly disclosure: typeof MACHINE_AUTHORITY_DISCLOSURE;
}

export interface MachineAdjudicationAttestation {
  readonly schemaVersion: typeof MACHINE_ATTESTATION_SCHEMA;
  readonly algorithm: typeof MACHINE_ATTESTATION_ALGORITHM;
  readonly subjectDigest: string;
  readonly candidateManifestHash: string;
  readonly provenance: MachineProvenance;
  readonly authoredAt: string;
  readonly payloadHash: string;
  readonly signature: string;
  readonly publicKey: string;
}

export interface MachineReleaseCorpus {
  readonly schemaVersion: typeof MACHINE_RELEASE_SCHEMA;
  readonly authority: typeof MACHINE_RELEASE_AUTHORITY;
  readonly releaseEligible: true;
  readonly bindings: { readonly candidateManifestHash: string; readonly rubric: typeof MACHINE_RUBRIC_BINDING };
  readonly corpusVersion: string;
  readonly minimums: Readonly<Record<FixtureCategory, number>>;
  readonly repeats: typeof REPEAT_COUNT;
  readonly temperature: typeof TEMPERATURE;
  readonly timeoutMs: typeof REVIEW_TIMEOUT_MS;
  readonly generatedAt: string;
  readonly provenance: MachineProvenance;
  readonly release: readonly PrivateReleaseFixture[];
  readonly generalization: readonly PrivateReleaseFixture[];
  readonly adjudication: MachineAdjudicationAttestation;
}

/** The only shape the reviewer may ever see. No label, category, or canary. */
export interface BlindedFixture {
  readonly id: string;
  readonly command: string;
}

const DIGEST = /^[0-9a-f]{64}$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/**
 * Strip every fixture field except the identifier and the command.
 *
 * Blinding is enforced here structurally rather than by convention: the
 * reviewer path takes `BlindedFixture[]`, so a label cannot travel with a
 * command even if a caller passes full fixtures by mistake. Results are joined
 * back on `id` after the reviewer has answered.
 */
export function blindFixtures(fixtures: readonly PrivateReleaseFixture[]): readonly BlindedFixture[] {
  return fixtures.map((fixture) => ({ id: fixture.id, command: fixture.command }));
}

/** Rebuild the label side after the reviewer has answered, keyed by id. */
export function labelIndex(fixtures: readonly PrivateReleaseFixture[]): ReadonlyMap<string, PrivateReleaseFixture> {
  return new Map(fixtures.map((fixture) => [fixture.id, fixture]));
}

function attestationPayload(input: {
  readonly subjectDigest: string;
  readonly candidateManifestHash: string;
  readonly provenance: MachineProvenance;
  readonly authoredAt: string;
}): string {
  return canonical({
    schemaVersion: MACHINE_ATTESTATION_SCHEMA,
    algorithm: MACHINE_ATTESTATION_ALGORITHM,
    subjectDigest: input.subjectDigest,
    candidateManifestHash: input.candidateManifestHash,
    provenance: input.provenance,
    authoredAt: input.authoredAt,
  });
}

/** Digest of the corpus with the signature field removed. */
export function machineSubjectDigest(corpus: Omit<MachineReleaseCorpus, "adjudication">): string {
  return sha256(canonical(corpus));
}

export function createMachineKeyPair(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync("ed25519");
}

export function signMachineAdjudication(input: {
  readonly subject: Omit<MachineReleaseCorpus, "adjudication">;
  readonly authoredAt: string;
  readonly privateKey: KeyObject;
  readonly publicKey?: KeyObject;
}): MachineAdjudicationAttestation {
  const subjectDigest = machineSubjectDigest(input.subject);
  if (!ISO_UTC.test(input.authoredAt)) throw new Error("machine attestation authoredAt must be an ISO-8601 UTC millisecond timestamp");
  const payload = attestationPayload({
    subjectDigest,
    candidateManifestHash: input.subject.bindings.candidateManifestHash,
    provenance: input.subject.provenance,
    authoredAt: input.authoredAt,
  });
  const publicKey = input.publicKey ?? createPublicKey(input.privateKey);
  return {
    schemaVersion: MACHINE_ATTESTATION_SCHEMA,
    algorithm: MACHINE_ATTESTATION_ALGORITHM,
    subjectDigest,
    candidateManifestHash: input.subject.bindings.candidateManifestHash,
    provenance: input.subject.provenance,
    authoredAt: input.authoredAt,
    payloadHash: sha256(payload),
    signature: sign(null, Buffer.from(payload, "utf8"), input.privateKey).toString("base64"),
    publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
  };
}

export function verifyMachineAdjudication(corpus: MachineReleaseCorpus): boolean {
  try {
    const { adjudication, ...subject } = corpus;
    if (adjudication.schemaVersion !== MACHINE_ATTESTATION_SCHEMA || adjudication.algorithm !== MACHINE_ATTESTATION_ALGORITHM) return false;
    if (adjudication.subjectDigest !== machineSubjectDigest(subject)) return false;
    if (adjudication.candidateManifestHash !== corpus.bindings.candidateManifestHash) return false;
    if (canonical(adjudication.provenance) !== canonical(corpus.provenance)) return false;
    const payload = attestationPayload({
      subjectDigest: adjudication.subjectDigest,
      candidateManifestHash: adjudication.candidateManifestHash,
      provenance: adjudication.provenance,
      authoredAt: adjudication.authoredAt,
    });
    if (adjudication.payloadHash !== sha256(payload)) return false;
    const publicKey = createPublicKey({ key: Buffer.from(adjudication.publicKey, "base64"), format: "der", type: "spki" });
    return verify(null, Buffer.from(payload, "utf8"), publicKey, Buffer.from(adjudication.signature, "base64"));
  } catch {
    return false;
  }
}

function isCategory(value: unknown): value is FixtureCategory {
  return typeof value === "string" && (CATEGORIES as readonly string[]).includes(value);
}

function isDecision(value: unknown): value is Decision {
  return value === "allow" || value === "manual";
}

/**
 * Structural validation for the machine authority.
 *
 * These are the same content rules the human path enforces — category
 * minimums, unique ids and shapes, no overlap with the development corpus, and
 * deterministic routing for secret/error fixtures. Only the provenance and
 * attestation rules differ, because those are what the authority changes.
 */
export function validateMachineReleaseCorpus(
  corpus: MachineReleaseCorpus,
  developmentIDs: ReadonlySet<string>,
  developmentShapes: ReadonlySet<string>,
): readonly string[] {
  const errors: string[] = [];
  if (corpus.schemaVersion !== MACHINE_RELEASE_SCHEMA) errors.push("machine release schema is invalid");
  if (corpus.authority !== MACHINE_RELEASE_AUTHORITY) errors.push("machine release authority is invalid");
  if (corpus.releaseEligible !== true) errors.push("machine release corpus must be release eligible");
  if (!DIGEST.test(corpus.bindings.candidateManifestHash)) errors.push("candidate manifest binding is invalid");
  if (corpus.bindings.rubric !== MACHINE_RUBRIC_BINDING) errors.push("rubric binding is invalid");
  if (corpus.repeats !== REPEAT_COUNT || corpus.temperature !== TEMPERATURE || corpus.timeoutMs !== REVIEW_TIMEOUT_MS) errors.push("execution contract is invalid");
  if (corpus.provenance.humanAttestation !== false) errors.push("machine authority must declare humanAttestation false");
  if (corpus.provenance.disclosure !== MACHINE_AUTHORITY_DISCLOSURE) errors.push("machine authority disclosure is missing or altered");
  if (!corpus.provenance.authorModel || !corpus.provenance.classifierUnderTest) errors.push("machine provenance must name the author and the classifier under test");
  if (corpus.provenance.authorModel === corpus.provenance.classifierUnderTest) errors.push("machine author and classifier under test must differ");
  // A tuning field must be a real requested value or an explicit `null`. Empty
  // string is neither, and would read in the artifact as "no tuning recorded"
  // when it actually means "someone forgot", which are different claims.
  for (const [field, value] of [["authorVariant", corpus.provenance.authorVariant], ["authorEffort", corpus.provenance.authorEffort]] as const) {
    if (value !== null && (typeof value !== "string" || value.length === 0)) errors.push(`machine provenance ${field} must be a requested value or null`);
  }
  if (corpus.provenance.authorTuningServed !== "unverified") errors.push("machine provenance cannot claim a served tuning it did not confirm");
  // Command origin is declared per category and is signed with the rest of the
  // provenance. A missing or unrecognized entry fails rather than defaulting,
  // because the default a reader would assume is the one the disclosure would
  // then misstate.
  const declaredSources = corpus.provenance.commandSource as Record<string, unknown> | undefined;
  if (!declaredSources || CATEGORIES.some((category) => !COMMAND_SOURCES.includes(declaredSources[category] as CommandSource))) {
    errors.push("machine provenance must declare a known command source for every category");
  }

  const counts = Object.fromEntries(CATEGORIES.map((category) => [category, corpus.release.filter((fixture) => fixture.category === category).length])) as Record<FixtureCategory, number>;
  for (const category of CATEGORIES) if (counts[category] < MINIMUMS[category]) errors.push(`release category minimum: ${category}`);
  if (corpus.generalization.length === 0) errors.push("generalization stratum is missing");

  const ids = new Set<string>();
  const shapes = new Set<string>();
  for (const fixture of [...corpus.release, ...corpus.generalization]) {
    if (!isCategory(fixture.category) || !isDecision(fixture.expectedDecision)) errors.push("fixture label is invalid");
    if (ids.has(fixture.id)) errors.push("fixture IDs are not unique");
    ids.add(fixture.id);
    if (shapes.has(fixture.structuralKey)) errors.push("structural keys are not unique");
    shapes.add(fixture.structuralKey);
    if ((fixture.category === "secret" || fixture.errorPath === true) && (fixture.route !== "deterministic" || fixture.providerAttempted || fixture.expectedDecision !== "manual")) {
      errors.push("secret/error fixture is not deterministic manual");
    }
  }
  for (const fixture of corpus.release) {
    if (developmentIDs.has(fixture.id)) errors.push("development/release fixture IDs overlap");
    if (developmentShapes.has(fixture.structuralKey)) errors.push("development/release structural keys overlap");
  }
  if (!verifyMachineAdjudication(corpus)) errors.push("machine adjudication signature is invalid");
  return [...new Set(errors)];
}
