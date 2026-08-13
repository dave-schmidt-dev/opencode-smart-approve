import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  QUALIFICATION_MODEL,
  QUALIFICATION_VARIANT,
  REPEAT_COUNT,
  createDevelopmentCandidateReport,
  createFrozenCandidateManifest,
  evaluateCorpus,
  evaluateFaults,
  getCorpusReadCounters,
  hashQualificationRecord,
  loadDevelopmentCorpus,
  resetCorpusReadCounters,
  type Corpus,
  type Decision,
  type QualificationRecord,
} from "../../scripts/classifier-gate";
import {
  createTerminalAttestation,
  createTerminalCustodyManifest,
  createTerminalPreflight,
  main,
  validateTerminalAttestation,
  validateTerminalCustodyManifest,
  validateTerminalPreflight,
  verifyTerminal,
} from "../../scripts/qualification/verify-terminal";

function root(): string {
  return mkdtempSync(join(tmpdir(), "smart-approve-terminal-"));
}

function recordFor(fixture: Corpus["fixtures"][number], repeat: QualificationRecord["repeat"], invalid = false): QualificationRecord {
  const deterministic = fixture.errorPath === true || fixture.category === "secret" || fixture.category === "dangerous" || fixture.category === "obfuscated";
  const decision: Decision = fixture.category === "benign" ? "allow" : "manual";
  const base: Omit<QualificationRecord, "responseHash"> = {
    observationID: `obs_${fixture.id}_${repeat}`,
    fixtureID: fixture.id,
    category: fixture.category,
    repeat,
    expectedDecision: fixture.expectedDecision,
    decision,
    route: invalid ? "reviewer" : deterministic ? "deterministic" : "reviewer",
    providerAttempted: invalid ? true : !deterministic,
    reasonCodes: [invalid ? "uncertain" : deterministic ? "manual" : decision === "allow" ? "safe" : "ambiguous"],
    schemaValid: !invalid,
    metricEligible: !invalid,
    outcome: invalid ? "invalid_run" : "classifier",
    terminalKind: invalid ? "manual" : deterministic ? "manual" : "valid_model",
    latencyMs: 100 + repeat,
  };
  return { ...base, responseHash: hashQualificationRecord(base) };
}

function terminalFixture() {
  const { corpus } = loadDevelopmentCorpus();
  const records = corpus.fixtures.flatMap((fixture) => Array.from({ length: REPEAT_COUNT }, (_, index) => recordFor(fixture, (index + 1) as QualificationRecord["repeat"], fixture === corpus.fixtures[0] && index === 0)));
  const report = evaluateCorpus("development", corpus, records);
  const candidate = createFrozenCandidateManifest("2026-08-13T01:50:00.000Z");
  const development = createDevelopmentCandidateReport({ candidate, corpusReport: report, faults: evaluateFaults([]), terminal: "stop-disabled", failureCode: "invalid_run", generatedAt: "2026-08-13T01:51:00.000Z" });
  return { candidate, development };
}

describe("fixed-candidate terminal qualification", () => {
  test("writes and validates the no-corpus terminal branch without opening corpus bytes", async () => {
    const { candidate, development } = terminalFixture();
    const directory = root();
    const candidatePath = join(directory, "candidate.json");
    const reportPath = join(directory, "development.json");
    const preflightPath = join(directory, "preflight.json");
    const custodyPath = join(directory, "custody.json");
    const attestationPath = join(directory, "attestation.json");
    writeFileSync(candidatePath, `${JSON.stringify(candidate)}\n`);
    writeFileSync(reportPath, `${JSON.stringify(development)}\n`);
    resetCorpusReadCounters();
    try {
      const result = verifyTerminal({ candidatePath, developmentReportPath: reportPath, preflightPath, custodyPath, attestationPath });
      expect(validateTerminalPreflight(result.preflight, candidate, development)).toEqual(result.preflight);
      expect(validateTerminalCustodyManifest(result.custody, candidate, development)).toEqual(result.custody);
      expect(validateTerminalAttestation(result.attestation, candidate, development, result.custody)).toEqual(result.attestation);
      expect(result.attestation).toMatchObject({ decision: "release-disabled", providerCalls: 0, privateByteReads: 0, custodyTransition: "none", productionLock: false });
      expect(result.custody).toMatchObject({ status: "not_created", namedCorpusRoles: 0, ledgerState: "not_created" });
      expect(getCorpusReadCounters()).toEqual({ developmentReads: 0, combinedBundleReads: 0, privateHeldoutByteReads: 0 });
      for (const path of [preflightPath, custodyPath, attestationPath]) {
        expect(statSync(path).mode & 0o777).toBe(0o600);
        expect(readFileSync(path, "utf8")).not.toMatch(/records?|observations?|fixtureIDs?|commands?|prompts?|providerResponse|privateCorpus/i);
      }
      expect(await main(["--candidate", candidatePath, "--development-report", reportPath, "--preflight", preflightPath, "--custody", custodyPath, "--attestation", attestationPath])).toBe(0);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("A/B rejects a synthetic pass and tampered or colliding terminal inputs", () => {
    const { candidate, development } = terminalFixture();
    const directory = root();
    try {
      const pass = createDevelopmentCandidateReport({ candidate, corpusReport: { ...development.development, invalidRunCount: 0, classifierDenominator: development.development.invocations } as never, faults: evaluateFaults([]), terminal: "development-pass", generatedAt: development.generatedAt });
      expect(() => createTerminalPreflight(candidate, pass)).toThrow(/failed/);
      const tampered = { ...development, candidateManifestHash: "0".repeat(64) };
      writeFileSync(join(directory, "candidate.json"), `${JSON.stringify(candidate)}\n`);
      writeFileSync(join(directory, "development.json"), `${JSON.stringify(tampered)}\n`);
      expect(() => verifyTerminal({ candidatePath: join(directory, "candidate.json"), developmentReportPath: join(directory, "development.json"), preflightPath: join(directory, "preflight.json"), custodyPath: join(directory, "custody.json"), attestationPath: join(directory, "attestation.json") })).toThrow(/candidate|hash|digest|binding/);
      writeFileSync(join(directory, "development.json"), JSON.stringify(development));
      writeFileSync(join(directory, "custody.json"), JSON.stringify({ occupied: true }));
      expect(() => verifyTerminal({ candidatePath: join(directory, "candidate.json"), developmentReportPath: join(directory, "development.json"), preflightPath: join(directory, "preflight.json"), custodyPath: join(directory, "custody.json"), attestationPath: join(directory, "attestation.json") })).toThrow(/overwrite|different/);
      expect(existsSync(join(directory, "preflight.json"))).toBe(false);
      expect(main(["--candidate", join(directory, "candidate.json"), "--custody", join(directory, "custody.json"), "--attestation", join(directory, "attestation.json"), "--unknown", "x"])).resolves.toBe(1);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("constructors keep terminal artifacts aggregate-only and hash-bound", () => {
    const { candidate, development } = terminalFixture();
    const preflight = createTerminalPreflight(candidate, development);
    const custody = createTerminalCustodyManifest(candidate, development);
    const attestation = createTerminalAttestation(candidate, development, custody);
    const walk = (value: unknown): void => {
      if (Array.isArray(value)) throw new Error("array escaped terminal artifact");
      if (value && typeof value === "object") for (const entry of Object.values(value)) walk(entry);
    };
    walk({ preflight, custody, attestation });
    expect(preflight.preflightHash).toMatch(/^[0-9a-f]{64}$/);
    expect(custody.manifestHash).toMatch(/^[0-9a-f]{64}$/);
    expect(attestation.attestationHash).toMatch(/^[0-9a-f]{64}$/);
    expect(QUALIFICATION_MODEL).toContain("deepseek");
    expect(QUALIFICATION_VARIANT).toBeTruthy();
  });
});
