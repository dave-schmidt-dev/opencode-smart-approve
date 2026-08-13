import { describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  CUSTODY_LEDGER_SCHEMA_VERSION,
  PUBLIC_VERIFICATION_STATUS,
  createSignedConsumptionCommitment,
  digestPrivateBytes,
  initializeCustodyLedger,
  readCustodyLedger,
  type AuthoringFixture,
  type PublicAggregateArtifact,
} from "../../scripts/qualification/custody";
import {
  createDevelopmentCandidateReport,
  createFrozenCandidateManifest,
  evaluateCorpus,
  evaluateFaults,
  hashQualificationRecord,
  loadDevelopmentCorpus,
  type Corpus,
  type Decision,
  type QualificationRecord,
  type DevelopmentCandidateReport,
  type FrozenCandidateManifest,
} from "../../scripts/classifier-gate";
import { generateAutomatedDraft } from "../../scripts/qualification/generate-release-draft";
import { createHumanAdjudicationAttestation, HUMAN_RELEASE_AUTHORITY, HUMAN_RELEASE_SCHEMA, type AuthorizedAdjudicator, type HumanReleaseCorpus } from "../../scripts/qualification/release-corpus";
import { main as releaseOperatorMain, runAttendedFileRelease, type AttendedQualificationContext } from "../../scripts/qualification/release-operator";

const generatedAt = "2026-08-13T12:00:00.000Z";

function root(): string {
  return mkdtempSync(join(tmpdir(), "smart-approve-release-operator-"));
}

function authorizedAdjudicator(adjudicatorID = "role-adjudicator"): AuthorizedAdjudicator {
  const pair = generateKeyPairSync("ed25519");
  return {
    adjudicatorID,
    publicKey: pair.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
  };
}

function humanCorpus(candidateManifestHash: string): { readonly corpus: HumanReleaseCorpus; readonly authorizedAdjudicator: AuthorizedAdjudicator } {
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
  return {
    corpus: { ...unsigned, adjudication: createHumanAdjudicationAttestation({ subject: unsigned, privateKey: pair.privateKey, publicKey: pair.publicKey }) },
    authorizedAdjudicator: {
      adjudicatorID: unsigned.roles.adjudicatorID,
      publicKey: pair.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    },
  };
}

const deterministicFor = (fixture: Corpus["fixtures"][number]): boolean => fixture.errorPath === true || fixture.category === "secret" || fixture.category === "dangerous" || fixture.category === "obfuscated";

function developmentRecords(corpus: Corpus): QualificationRecord[] {
  return corpus.fixtures.flatMap((fixture) => Array.from({ length: 5 }, (_, index) => {
    const deterministic = deterministicFor(fixture);
    const decision: Decision = fixture.category === "benign" ? "allow" : "manual";
    const base = {
      observationID: `obs_${fixture.id}_${index + 1}`,
      fixtureID: fixture.id,
      category: fixture.category,
      repeat: (index + 1) as QualificationRecord["repeat"],
      expectedDecision: fixture.expectedDecision,
      decision,
      route: deterministic ? "deterministic" : "reviewer",
      providerAttempted: !deterministic,
      reasonCodes: [deterministic ? "manual" : decision === "allow" ? "safe" : "ambiguous"],
      schemaValid: true,
      metricEligible: true,
      outcome: "classifier" as const,
      terminalKind: deterministic ? "manual" : "valid_model",
      latencyMs: 100 + index,
    } satisfies Omit<QualificationRecord, "responseHash">;
    return { ...base, responseHash: hashQualificationRecord(base) };
  }));
}

function developmentEvaluation(): { readonly candidate: FrozenCandidateManifest; readonly report: DevelopmentCandidateReport } {
  const candidate = createFrozenCandidateManifest("2026-08-13T00:00:00.000Z");
  const { corpus } = loadDevelopmentCorpus();
  const corpusReport = evaluateCorpus("development", corpus, developmentRecords(corpus));
  const report = createDevelopmentCandidateReport({ candidate, corpusReport, faults: evaluateFaults([]), terminal: "development-pass", generatedAt: "2026-08-13T00:01:00.000Z" });
  return { candidate, report };
}

function developmentManifest(): { readonly development: AuthoringFixture[] } {
  const categories: Array<[AuthoringFixture["category"], number]> = [["benign", 40], ["dangerous", 15], ["ambiguous", 10], ["injection", 10], ["secret", 10], ["obfuscated", 10]];
  return {
    development: categories.flatMap(([category, count]) => Array.from({ length: count }, (_, index) => {
      const secret = category === "secret";
      return {
        id: `development-${category}-${index}`,
        category,
        expectedDecision: category === "benign" ? "allow" : "manual",
        stratum: "qualification" as const,
        structuralKey: `development-shape-${category}-${index}`,
        route: secret ? "deterministic" as const : "reviewer" as const,
        providerAttempted: !secret,
      };
    })),
  };
}

function publicAggregate(context: AttendedQualificationContext, outcome: "pass" | "failure" = "pass", bound = true): PublicAggregateArtifact {
  const base = {
    verification: PUBLIC_VERIFICATION_STATUS,
    custodyNumber: bound ? context.custodyNumber : 1,
    corpusDigest: bound ? context.corpusDigest : "b".repeat(64),
    aggregateDigest: "c".repeat(64),
    faultGate: outcome === "pass" ? "pass" as const : "fail" as const,
    classifierDenominator: outcome === "pass" ? 475 : 0,
    invalidRunCount: outcome === "pass" ? 0 : 1,
    canaryLeakCount: 0 as const,
    publicToken: "public_synthetic-release",
  };
  return outcome === "pass"
    ? { schemaVersion: "classifier-public-aggregate-pass/v1", outcome, ...base }
    : { schemaVersion: "classifier-public-aggregate-failure/v1", outcome, failureCode: "threshold", ...base };
}

function writeCorpus(path: string, value: unknown): Buffer {
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
  writeFileSync(path, bytes, { mode: 0o600 });
  return bytes;
}

function signedCommitment(bytes: Buffer, consumptionNumber = 1) {
  const pair = generateKeyPairSync("ed25519");
  return createSignedConsumptionCommitment({
    corpusDigest: digestPrivateBytes(bytes),
    consumptionNumber,
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
  });
}

async function run(options: { readonly directory: string; readonly corpus: unknown; readonly authorizedAdjudicator: AuthorizedAdjudicator; readonly candidate: FrozenCandidateManifest; readonly report: DevelopmentCandidateReport; readonly commitmentBytes?: Buffer; readonly publicExists?: boolean; readonly boundAggregate?: boolean } ) {
  const corpusPath = join(options.directory, "release.json");
  const ledgerPath = join(options.directory, "ledger.json");
  const publicPath = join(options.directory, "public.json");
  const bytes = writeCorpus(corpusPath, options.corpus);
  const commitment = signedCommitment(options.commitmentBytes ?? bytes);
  initializeCustodyLedger(ledgerPath);
  if (options.publicExists) writeFileSync(publicPath, "existing\n", { mode: 0o600 });
  const statuses: string[] = [];
  const calls: string[] = [];
  const result = await runAttendedFileRelease({
    corpusPath,
    candidate: options.candidate,
    developmentReport: options.report,
    developmentManifest: developmentManifest(),
    authorizedAdjudicator: options.authorizedAdjudicator,
    ledgerPath,
    publicArtifactPath: publicPath,
    commitment,
    onStatus: (status) => statuses.push(status),
    qualify: async (input, _tokens, context) => {
      calls.push(input.authority);
      return publicAggregate(context, "pass", options.boundAggregate ?? true);
    },
  });
  return { result, statuses, calls, corpusPath, ledgerPath, publicPath, bytes };
}

describe("attended release operator", () => {
  test("CLI entrypoint refuses unattended execution", async () => {
    expect(await releaseOperatorMain([])).toBe(1);
    expect(await releaseOperatorMain(["--attended"])).toBe(1);
  });

  test("spends before opening, validates the human envelope, and writes aggregate-only output", async () => {
    const directory = root();
    try {
      const evaluation = developmentEvaluation();
      const human = humanCorpus(evaluation.candidate.manifestHash);
      const corpus = human.corpus;
      const output = await run({ directory, corpus, authorizedAdjudicator: human.authorizedAdjudicator, ...evaluation });
      expect(output.calls).toEqual([HUMAN_RELEASE_AUTHORITY]);
      expect(output.statuses.indexOf("spent")).toBeLessThan(output.statuses.indexOf("opening_private_input"));
      expect(output.result.ledger.state).toBe("spent");
      expect(output.result.fixtureCount).toBe(95);
      expect(output.result.observationCount).toBe(475);
      expect(statSync(output.publicPath).mode & 0o777).toBe(0o600);
      const publicText = readFileSync(output.publicPath, "utf8");
      expect(publicText).not.toContain(corpus.release[0].command);
      expect(publicText).not.toContain(corpus.release[0].canaries.structural);
      expect(publicText).not.toContain("expectedDecision");
      expect(JSON.parse(publicText)).toMatchObject({ outcome: "pass", classifierDenominator: 475 });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("rejects an automated draft after custody spend and never invokes qualification", async () => {
    const directory = root();
    try {
      const evaluation = developmentEvaluation();
      const corpus = generateAutomatedDraft(evaluation.candidate.manifestHash, generatedAt);
      const authorized = authorizedAdjudicator();
      const corpusPath = join(directory, "release.json");
      const ledgerPath = join(directory, "ledger.json");
      const publicPath = join(directory, "public.json");
      const bytes = writeCorpus(corpusPath, corpus);
      initializeCustodyLedger(ledgerPath);
      let calls = 0;
      await expect(runAttendedFileRelease({
        corpusPath,
        candidate: evaluation.candidate,
        developmentReport: evaluation.report,
        developmentManifest: developmentManifest(),
        authorizedAdjudicator: authorized,
        ledgerPath,
        publicArtifactPath: publicPath,
        commitment: signedCommitment(bytes),
        qualify: async () => { calls += 1; return publicAggregate({ candidateManifestHash: evaluation.candidate.manifestHash, corpusDigest: "b".repeat(64), custodyNumber: 1 }); },
      })).rejects.toThrow(/not eligible/);
      expect(calls).toBe(0);
      expect(readCustodyLedger(ledgerPath).state).toBe("spent");
      expect(existsSync(publicPath)).toBe(false);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("spends on digest mismatch and on provider failure, then refuses reuse", async () => {
    const directory = root();
    try {
      const evaluation = developmentEvaluation();
      const human = humanCorpus(evaluation.candidate.manifestHash);
      const corpus = human.corpus;
      const corpusPath = join(directory, "release.json");
      const ledgerPath = join(directory, "ledger.json");
      const publicPath = join(directory, "public.json");
      const bytes = writeCorpus(corpusPath, corpus);
      initializeCustodyLedger(ledgerPath);
      const mismatched = signedCommitment(Buffer.from("different\n", "utf8"));
      await expect(runAttendedFileRelease({ corpusPath, candidate: evaluation.candidate, developmentReport: evaluation.report, developmentManifest: developmentManifest(), authorizedAdjudicator: human.authorizedAdjudicator, ledgerPath, publicArtifactPath: publicPath, commitment: mismatched, qualify: async (_input, _tokens, context) => publicAggregate(context) })).rejects.toThrow(/digest/);
      expect(readCustodyLedger(ledgerPath).state).toBe("spent");

      const secondDirectory = root();
      try {
        const secondCorpusPath = join(secondDirectory, "release.json");
        const secondLedgerPath = join(secondDirectory, "ledger.json");
        const secondPublicPath = join(secondDirectory, "public.json");
        const secondBytes = writeCorpus(secondCorpusPath, corpus);
        const secondCommitment = signedCommitment(secondBytes);
        initializeCustodyLedger(secondLedgerPath);
        await expect(runAttendedFileRelease({ corpusPath: secondCorpusPath, candidate: evaluation.candidate, developmentReport: evaluation.report, developmentManifest: developmentManifest(), authorizedAdjudicator: human.authorizedAdjudicator, ledgerPath: secondLedgerPath, publicArtifactPath: secondPublicPath, commitment: secondCommitment, qualify: async () => { throw new Error("synthetic provider failure"); } })).rejects.toThrow(/synthetic provider failure/);
        expect(readCustodyLedger(secondLedgerPath).state).toBe("spent");
        await expect(runAttendedFileRelease({ corpusPath: secondCorpusPath, candidate: evaluation.candidate, developmentReport: evaluation.report, developmentManifest: developmentManifest(), authorizedAdjudicator: human.authorizedAdjudicator, ledgerPath: secondLedgerPath, publicArtifactPath: join(secondDirectory, "second-public.json"), commitment: secondCommitment, qualify: async (_input, _tokens, context) => publicAggregate(context) })).rejects.toThrow(/spent/);
      } finally {
        rmSync(secondDirectory, { recursive: true, force: true });
      }
      expect(bytes.length).toBeGreaterThan(0);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("checks public output collision before spending custody", async () => {
    const directory = root();
    try {
      const evaluation = developmentEvaluation();
      const human = humanCorpus(evaluation.candidate.manifestHash);
      const corpus = human.corpus;
      const output = await run({ directory, corpus, authorizedAdjudicator: human.authorizedAdjudicator, ...evaluation, publicExists: true }).catch((error) => error);
      expect(output).toBeInstanceOf(Error);
      expect((output as Error).message).toMatch(/artifact already exists/);
      expect(readCustodyLedger(join(directory, "ledger.json"))).toMatchObject({ schemaVersion: CUSTODY_LEDGER_SCHEMA_VERSION, state: "available" });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("rejects a public aggregate bound to a different raw corpus or custody number", async () => {
    const directory = root();
    try {
      const evaluation = developmentEvaluation();
      const human = humanCorpus(evaluation.candidate.manifestHash);
      const corpus = human.corpus;
      await expect(run({ directory, corpus, authorizedAdjudicator: human.authorizedAdjudicator, ...evaluation, boundAggregate: false })).rejects.toThrow(/not bound/);
      expect(readCustodyLedger(join(directory, "ledger.json")).state).toBe("spent");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("rejects missing or mismatched external adjudicator binding before qualification", async () => {
    const directory = root();
    try {
      const evaluation = developmentEvaluation();
      const human = humanCorpus(evaluation.candidate.manifestHash);
      const corpusPath = join(directory, "release.json");
      const ledgerPath = join(directory, "ledger.json");
      const publicPath = join(directory, "public.json");
      const bytes = writeCorpus(corpusPath, human.corpus);
      const commitment = signedCommitment(bytes);
      initializeCustodyLedger(ledgerPath);
      let calls = 0;
      await expect(runAttendedFileRelease({
        corpusPath,
        candidate: evaluation.candidate,
        developmentReport: evaluation.report,
        developmentManifest: developmentManifest(),
        authorizedAdjudicator: { ...authorizedAdjudicator(), adjudicatorID: human.authorizedAdjudicator.adjudicatorID },
        ledgerPath,
        publicArtifactPath: publicPath,
        commitment,
        qualify: async () => { calls += 1; return publicAggregate({ candidateManifestHash: evaluation.candidate.manifestHash, corpusDigest: "b".repeat(64), custodyNumber: 1 }); },
      })).rejects.toThrow(/not authorized/);
      expect(calls).toBe(0);
      expect(readCustodyLedger(ledgerPath).state).toBe("spent");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
