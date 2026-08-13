import { describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync, rmSync, statSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  AUTOMATED_DRAFT_SCHEMA,
  createHumanAdjudicationAttestation,
  HUMAN_RELEASE_AUTHORITY,
  HUMAN_RELEASE_SCHEMA,
  parseReleaseCorpus,
  releaseCorpusDigest,
  toPrivateAuthoringManifest,
  toPublicReleaseManifest,
  toReleaseAuthoringManifest,
  validateReleaseCorpus,
  type AuthorizedAdjudicator,
  type HumanReleaseCorpus,
} from "../../scripts/qualification/release-corpus";
import {
  DEFAULT_DRAFT_PATH,
  generateAutomatedDraft,
  main as generateDraftMain,
  writeAutomatedDraft,
} from "../../scripts/qualification/generate-release-draft";

const candidateManifestHash = "a".repeat(64);
const generatedAt = "2026-08-13T12:00:00.000Z";

function humanCorpus(): { readonly corpus: HumanReleaseCorpus; readonly authorizedAdjudicator: AuthorizedAdjudicator } {
  const draft = generateAutomatedDraft(candidateManifestHash, generatedAt);
  const unsigned = {
    ...draft,
    schemaVersion: HUMAN_RELEASE_SCHEMA,
    authority: HUMAN_RELEASE_AUTHORITY,
    releaseEligible: true,
    roles: { authorID: "role-author", adjudicatorID: "role-adjudicator", custodianID: "role-custodian" },
    timestamps: { authoredAt: generatedAt, adjudicatedAt: generatedAt, custodyAt: generatedAt },
  } as Omit<HumanReleaseCorpus, "adjudication">;
  const pair = generateKeyPairSync("ed25519");
  const authorizedAdjudicator = {
    adjudicatorID: unsigned.roles.adjudicatorID,
    publicKey: pair.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
  };
  return {
    corpus: { ...unsigned, adjudication: createHumanAdjudicationAttestation({ subject: unsigned, privateKey: pair.privateKey, publicKey: pair.publicKey }) },
    authorizedAdjudicator,
  };
}

describe("fresh release corpus draft layer", () => {
  test("generates exactly 95 release and six generalization fixtures with bindings", () => {
    const draft = generateAutomatedDraft(candidateManifestHash, generatedAt);
    expect(draft.schemaVersion).toBe(AUTOMATED_DRAFT_SCHEMA);
    expect(draft.authority).toBe("automated-draft");
    expect(draft.releaseEligible).toBe(false);
    expect(draft.release).toHaveLength(95);
    expect(draft.generalization).toHaveLength(6);
    expect(draft.bindings.candidateManifestHash).toBe(candidateManifestHash);
    expect(draft.bindings.rubric).toBe("fixtures/eval/authoring-rubric.md");
    expect(new Set(draft.release.map((fixture) => fixture.command)).size).toBe(95);
    expect(draft.release.every((fixture) => fixture.command.startsWith("synthetic://"))).toBe(true);
  });

  test("validates minimums, execution contract, unique IDs, and development disjointness", () => {
    const draft = generateAutomatedDraft(candidateManifestHash, generatedAt);
    expect(validateReleaseCorpus(draft)).toEqual([]);
    const overlap = validateReleaseCorpus(draft, { fixtures: [{ id: draft.release[0].id, structuralKey: draft.release[0].structuralKey }] });
    expect(overlap.join(";")).toContain("development/release fixture IDs overlap");
    expect(overlap.join(";")).toContain("development/release structural keys overlap");
    const duplicate = structuredClone(draft) as any;
    duplicate.release[1].id = duplicate.release[0].id;
    expect(validateReleaseCorpus(duplicate).join(";")).toContain("fixture IDs are not unique");
  });

  test("routes secret and error fixtures deterministically and rejects unsafe routing", () => {
    const draft = generateAutomatedDraft(candidateManifestHash, generatedAt);
    for (const fixture of draft.release.filter((candidate) => candidate.category === "secret" || candidate.errorPath)) {
      expect(fixture.route).toBe("deterministic");
      expect(fixture.providerAttempted).toBe(false);
      expect(fixture.expectedDecision).toBe("manual");
    }
    const unsafe = structuredClone(draft) as any;
    const secret = unsafe.release.find((fixture: any) => fixture.category === "secret")!;
    secret.route = "reviewer";
    expect(validateReleaseCorpus(unsafe).join(";")).toContain("secret/error fixture is not deterministic manual");
  });

  test("requires all future-human roles, timestamps, and a bound signature", () => {
    const { corpus: human, authorizedAdjudicator } = humanCorpus();
    expect(() => parseReleaseCorpus(human)).toThrow(/not authorized/);
    expect(parseReleaseCorpus(human, { authorizedAdjudicator }).releaseEligible).toBe(true);
    const mismatchedPublicKey = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "der" }).toString("base64");
    expect(() => parseReleaseCorpus(human, { authorizedAdjudicator: { ...authorizedAdjudicator, publicKey: mismatchedPublicKey } })).toThrow(/not authorized/);
    const promotedDraft = {
      ...generateAutomatedDraft(candidateManifestHash, generatedAt),
      schemaVersion: HUMAN_RELEASE_SCHEMA,
      authority: HUMAN_RELEASE_AUTHORITY,
      releaseEligible: true,
      roles: human.roles,
      timestamps: human.timestamps,
    };
    expect(() => parseReleaseCorpus(promotedDraft)).toThrow(/adjudication/);
    const missingRole = structuredClone(human) as typeof human;
    delete (missingRole.roles as { authorID?: string }).authorID;
    expect(() => parseReleaseCorpus(missingRole, { authorizedAdjudicator })).toThrow(/authorID/);
    const missingTimestamp = structuredClone(human) as typeof human;
    delete (missingTimestamp.timestamps as { custodyAt?: string }).custodyAt;
    expect(() => parseReleaseCorpus(missingTimestamp, { authorizedAdjudicator })).toThrow(/custodyAt/);
    const duplicateRole = structuredClone(human) as any;
    duplicateRole.roles.adjudicatorID = duplicateRole.roles.authorID;
    expect(() => parseReleaseCorpus(duplicateRole, { authorizedAdjudicator })).toThrow(/roles must be distinct/);
    const forgedSignature = structuredClone(human) as any;
    forgedSignature.adjudication.subjectDigest = "f".repeat(64);
    expect(() => parseReleaseCorpus(forgedSignature, { authorizedAdjudicator })).toThrow(/adjudication attestation is invalid/);
    const nonCanonicalSubject = structuredClone(human) as any;
    const errorFixture = nonCanonicalSubject.release.find((fixture: any) => fixture.errorPath === true);
    errorFixture.errorPath = false;
    expect(() => parseReleaseCorpus(nonCanonicalSubject, { authorizedAdjudicator })).toThrow(/adjudication attestation is invalid/);
  });

  test("writes mode 600 and refuses an exclusive collision", () => {
    const directory = mkdtempSync(join(tmpdir(), "release-corpus-"));
    try {
      const path = join(directory, "draft.json");
      const draft = generateAutomatedDraft(candidateManifestHash, generatedAt);
      writeAutomatedDraft(path, draft);
      expect(statSync(path).mode & 0o777).toBe(0o600);
      const original = readFileSync(path, "utf8");
      expect(() => writeAutomatedDraft(path, draft)).toThrow(/already exists|EEXIST/);
      expect(readFileSync(path, "utf8")).toBe(original);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("binds digest to canonical private bytes and strips private fields from public metadata", () => {
    const draft = generateAutomatedDraft(candidateManifestHash, generatedAt);
    const bytes = Buffer.from(JSON.stringify(draft, null, 2));
    expect(releaseCorpusDigest(bytes)).toBe(releaseCorpusDigest(draft));
    const publicMetadata = toReleaseAuthoringManifest(draft);
    const serialized = JSON.stringify(publicMetadata);
    expect(serialized).not.toContain("command");
    expect(serialized).not.toContain("canary");
    expect(serialized).not.toContain("expectedDecision");
    const privateMetadata = toPrivateAuthoringManifest(draft);
    expect(privateMetadata.release[0].expectedDecision).toBeDefined();
  });

  test("projects only a human envelope into strict public preflight metadata", () => {
    const { corpus: human, authorizedAdjudicator } = humanCorpus();
    const manifest = toPublicReleaseManifest(human, { authorizedAdjudicator });
    expect(manifest).toMatchObject({
      schemaVersion: "classifier-eval/public-release-manifest/v1",
      authority: HUMAN_RELEASE_AUTHORITY,
      releaseEligible: true,
      fixtureCount: 95,
      generalizationCount: 6,
      roles: human.roles,
      timestamps: human.timestamps,
    });
    const serialized = JSON.stringify(manifest);
    expect(serialized).not.toMatch(/command|expectedDecision|canary/i);
    expect(() => toPublicReleaseManifest(generateAutomatedDraft(candidateManifestHash, generatedAt))).toThrow(/human adjudication/);
  });

  test("keeps the private and public JSON schema contracts aligned with generated instances", () => {
    const privateSchema = JSON.parse(readFileSync(join(process.cwd(), "fixtures/eval/release-corpus.schema.json"), "utf8")) as any;
    const publicSchema = JSON.parse(readFileSync(join(process.cwd(), "fixtures/eval/public-release-manifest.schema.json"), "utf8")) as any;
    const draft = generateAutomatedDraft(candidateManifestHash, generatedAt);
    const { corpus: human, authorizedAdjudicator } = humanCorpus();
    const publicManifest = toPublicReleaseManifest(human, { authorizedAdjudicator });
    const requireKeys = (value: object, keys: readonly string[]) => keys.forEach((key) => expect(Object.hasOwn(value, key), key).toBe(true));
    requireKeys(draft, privateSchema.$defs.base.required);
    requireKeys(draft, privateSchema.$defs.automatedDraft.allOf[1].required);
    requireKeys(human, privateSchema.$defs.base.required);
    requireKeys(human, privateSchema.$defs.humanRelease.allOf[1].required);
    requireKeys(publicManifest, publicSchema.required);
    expect(publicManifest).toMatchObject({ schemaVersion: publicSchema.properties.schemaVersion.const, authority: publicSchema.properties.authority.const, releaseEligible: publicSchema.properties.releaseEligible.const, custodyState: publicSchema.properties.custodyState.const });
    expect(privateSchema.$id).toBe("classifier-eval/private-release/v1");
    expect(publicSchema.$id).toBe("classifier-eval/public-release-manifest/v1");
  });

  test("CLI draft entrypoint rejects malformed arguments and writes a validated draft", () => {
    const directory = mkdtempSync(join(tmpdir(), "release-corpus-cli-"));
    try {
      expect(generateDraftMain([])).toBe(1);
      const path = join(directory, "draft.json");
      expect(generateDraftMain([candidateManifestHash, generatedAt, path])).toBe(0);
      expect(parseReleaseCorpus(JSON.parse(readFileSync(path, "utf8"))).release).toHaveLength(95);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("keeps the operator default path stable", () => {
    expect(DEFAULT_DRAFT_PATH.endsWith("eval-results/release-corpus-draft.json")).toBe(true);
  });
});
