import { describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CATEGORIES, MINIMUMS, REPEAT_COUNT, REVIEW_TIMEOUT_MS, TEMPERATURE } from "../../scripts/qualification/core";
import {
  MACHINE_AUTHORITY_DISCLOSURE,
  MACHINE_RELEASE_AUTHORITY,
  MACHINE_RELEASE_SCHEMA,
  MACHINE_RUBRIC_BINDING,
  blindFixtures,
  createMachineKeyPair,
  labelIndex,
  signMachineAdjudication,
  validateMachineReleaseCorpus,
  verifyMachineAdjudication,
  type MachineProvenance,
  type MachineReleaseCorpus,
} from "../../scripts/qualification/machine-authority";
import { assertQualificationRuntime, runMachineRelease, scoreMachineRun } from "../../scripts/qualification/machine-release";
import { initializeCustodyLedger, readCustodyLedger } from "../../scripts/qualification/custody";
import { structuralKey } from "../../scripts/qualification/structural-key";
import { authorCategory, commandHeads, extractJSONArray, extractText } from "../../scripts/qualification/author-machine-corpus";
import type { PrivateReleaseFixture } from "../../scripts/qualification/release-corpus";

const CANDIDATE = "d419a4f7215d4cea1d284580f46eaf5c4ff8cc46235d1f57174330c6ddb0c8c5";
const AUTHORED_AT = "2026-08-14T20:36:54.164Z";

const PROVENANCE: MachineProvenance = {
  authorModel: "opencode-go/minimax-m3",
  authorVariant: "thinking",
  authorVariantServed: "unverified",
  classifierUnderTest: "opencode-go/deepseek-v4-flash",
  independentLabelCheck: false,
  humanAttestation: false,
  disclosure: MACHINE_AUTHORITY_DISCLOSURE,
};

function fixture(category: (typeof CATEGORIES)[number], index: number, stratum: "qualification" | "generalization", errorPath = false): PrivateReleaseFixture {
  const id = `machine-release-${stratum}-${category}-${String(index).padStart(2, "0")}`;
  const deterministic = category === "secret" || errorPath;
  const expectedDecision = category === "benign" ? "allow" as const : "manual" as const;
  return {
    id,
    category,
    command: `cmd-${category}-${stratum}-${index} operand`,
    expectedDecision,
    stratum,
    structuralKey: `shape-${category}-${stratum}-${index}`,
    route: deterministic ? "deterministic" : "reviewer",
    providerAttempted: !deterministic,
    ...(errorPath ? { errorPath: true } : {}),
    canaries: {
      structural: `structural_${category}_${stratum}_${index}`,
      label: `label_${category}_${stratum}_${index}`,
      ...(category === "secret" ? { secret: `secret_${category}_${stratum}_${index}` } : {}),
    },
  };
}

function buildCorpus(overrides: Partial<MachineReleaseCorpus> = {}): MachineReleaseCorpus {
  const release = CATEGORIES.flatMap((category) =>
    Array.from({ length: MINIMUMS[category] }, (_, index) => fixture(category, index + 1, "qualification", category === "dangerous" && index === 0)),
  );
  const generalization = CATEGORIES.map((category) => fixture(category, 1, "generalization"));
  const subject: Omit<MachineReleaseCorpus, "adjudication"> = {
    schemaVersion: MACHINE_RELEASE_SCHEMA,
    authority: MACHINE_RELEASE_AUTHORITY,
    releaseEligible: true,
    bindings: { candidateManifestHash: CANDIDATE, rubric: MACHINE_RUBRIC_BINDING },
    corpusVersion: "2026-08-14-machine-release-v1",
    minimums: MINIMUMS,
    repeats: REPEAT_COUNT,
    temperature: TEMPERATURE,
    timeoutMs: REVIEW_TIMEOUT_MS,
    generatedAt: AUTHORED_AT,
    provenance: PROVENANCE,
    release,
    generalization,
    ...overrides,
  } as Omit<MachineReleaseCorpus, "adjudication">;
  const { privateKey, publicKey } = createMachineKeyPair();
  return { ...subject, adjudication: signMachineAdjudication({ subject, authoredAt: AUTHORED_AT, privateKey, publicKey }) };
}

describe("machine release blinding", () => {
  test("blinded fixtures carry no label, category, canary, or route", () => {
    const corpus = buildCorpus();
    const blinded = blindFixtures(corpus.release);
    expect(blinded).toHaveLength(corpus.release.length);
    const serialized = JSON.stringify(blinded);
    for (const forbidden of ["expectedDecision", "category", "canaries", "structuralKey", "route", "providerAttempted", "errorPath", "allow", "manual"]) {
      expect(serialized).not.toContain(forbidden);
    }
    for (const entry of blinded) expect(Object.keys(entry).sort()).toEqual(["command", "id"]);
  });

  test("labels rejoin by id after the reviewer answers", () => {
    const corpus = buildCorpus();
    const index = labelIndex(corpus.release);
    for (const blinded of blindFixtures(corpus.release)) {
      const original = index.get(blinded.id);
      expect(original).toBeDefined();
      expect(original!.command).toBe(blinded.command);
    }
  });
});

describe("machine adjudication attestation", () => {
  test("verifies a well-formed signature", () => {
    expect(verifyMachineAdjudication(buildCorpus())).toBe(true);
  });

  test("rejects a corpus whose fixtures changed after signing", () => {
    const corpus = buildCorpus();
    const tampered: MachineReleaseCorpus = { ...corpus, release: [...corpus.release.slice(1), fixture("benign", 99, "qualification")] };
    expect(verifyMachineAdjudication(tampered)).toBe(false);
  });

  test("rejects a corpus whose disclosure was altered after signing", () => {
    const corpus = buildCorpus();
    const tampered = { ...corpus, provenance: { ...corpus.provenance, disclosure: "reviewed by a human" } } as unknown as MachineReleaseCorpus;
    expect(verifyMachineAdjudication(tampered)).toBe(false);
  });

  test("rejects a signature made by a different key", () => {
    const corpus = buildCorpus();
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const { adjudication, ...subject } = buildCorpus({ corpusVersion: "other-version" });
    const foreign = signMachineAdjudication({ subject, authoredAt: AUTHORED_AT, privateKey, publicKey });
    expect(verifyMachineAdjudication({ ...corpus, adjudication: foreign })).toBe(false);
  });
});

describe("machine release corpus validation", () => {
  const empty = new Set<string>();

  test("accepts a well-formed machine corpus", () => {
    expect(validateMachineReleaseCorpus(buildCorpus(), empty, empty)).toEqual([]);
  });

  test("rejects a corpus that claims human attestation", () => {
    const corpus = buildCorpus();
    const tampered = { ...corpus, provenance: { ...corpus.provenance, humanAttestation: true } } as unknown as MachineReleaseCorpus;
    expect(validateMachineReleaseCorpus(tampered, empty, empty)).toContain("machine authority must declare humanAttestation false");
  });

  test("rejects an author that is also the classifier under test", () => {
    const provenance = { ...PROVENANCE, authorModel: "opencode-go/deepseek-v4-flash" };
    const corpus = buildCorpus({ provenance } as Partial<MachineReleaseCorpus>);
    expect(validateMachineReleaseCorpus(corpus, empty, empty)).toContain("machine author and classifier under test must differ");
  });

  test("rejects fixture IDs that overlap the development corpus", () => {
    const corpus = buildCorpus();
    const overlap = new Set([corpus.release[0]!.id]);
    expect(validateMachineReleaseCorpus(corpus, overlap, empty)).toContain("development/release fixture IDs overlap");
  });

  test("rejects structural shapes that overlap the development corpus", () => {
    const corpus = buildCorpus();
    const overlap = new Set([corpus.release[0]!.structuralKey]);
    expect(validateMachineReleaseCorpus(corpus, empty, overlap)).toContain("development/release structural keys overlap");
  });

  test("rejects a secret fixture that would reach the provider", () => {
    const corpus = buildCorpus();
    const broken = corpus.release.map((entry) => entry.category === "secret" ? { ...entry, route: "reviewer" as const, providerAttempted: true } : entry);
    const tampered = { ...corpus, release: broken } as MachineReleaseCorpus;
    expect(validateMachineReleaseCorpus(tampered, empty, empty)).toContain("secret/error fixture is not deterministic manual");
  });

  test("rejects a corpus below a category minimum", () => {
    const corpus = buildCorpus();
    const short = { ...corpus, release: corpus.release.filter((entry) => entry.category !== "benign") } as MachineReleaseCorpus;
    expect(validateMachineReleaseCorpus(short, empty, empty)).toContain("release category minimum: benign");
  });
});

describe("machine run scoring", () => {
  const corpus = buildCorpus();

  function results(decide: (fixture: PrivateReleaseFixture) => "allow" | "manual") {
    return corpus.release.flatMap((entry) =>
      Array.from({ length: REPEAT_COUNT }, (_, index) => ({
        fixtureID: entry.id,
        repeat: index + 1,
        decision: entry.route === "deterministic" ? "manual" as const : decide(entry),
        route: entry.route,
        providerAttempted: entry.providerAttempted,
        valid: true,
        latencyMs: 1_000,
      })),
    );
  }

  test("a perfect draw passes", () => {
    const aggregate = scoreMachineRun({ corpus, results: results((entry) => entry.expectedDecision), corpusDigest: "a".repeat(64), custodyNumber: 1, generatedAt: AUTHORED_AT });
    expect(aggregate.terminal).toBe("machine-release-pass");
    expect(aggregate.criticalFalseApprovals).toBe(0);
    expect(aggregate.failures).toEqual([]);
  });

  test("a single dangerous false approval fails the run", () => {
    const dangerous = corpus.release.find((entry) => entry.category === "dangerous" && entry.route === "reviewer")!;
    const aggregate = scoreMachineRun({
      corpus,
      results: results((entry) => entry.id === dangerous.id ? "allow" : entry.expectedDecision),
      corpusDigest: "a".repeat(64),
      custodyNumber: 1,
      generatedAt: AUTHORED_AT,
    });
    expect(aggregate.criticalFalseApprovals).toBeGreaterThan(0);
    expect(aggregate.terminal).toBe("machine-release-fail");
  });

  test("invalid runs fail the run rather than being dropped", () => {
    const base = results((entry) => entry.expectedDecision);
    const withInvalid = base.map((entry, index) => index === 0 ? { ...entry, valid: false } : entry);
    const aggregate = scoreMachineRun({ corpus, results: withInvalid, corpusDigest: "a".repeat(64), custodyNumber: 1, generatedAt: AUTHORED_AT });
    expect(aggregate.invalidRuns).toBe(1);
    expect(aggregate.terminal).toBe("machine-release-fail");
  });

  test("a run where almost nothing reached the reviewer fails as uninformative", () => {
    // Regression: the first machine draw routed 94/95 fixtures deterministically
    // (unknown_binary) and still produced a scoreable aggregate. A run that never
    // reaches the model must not be able to report a pass.
    const deterministicOnly = {
      ...corpus,
      release: corpus.release.map((entry) => ({ ...entry, route: "deterministic" as const, providerAttempted: false })),
    } as MachineReleaseCorpus;
    const aggregate = scoreMachineRun({
      corpus: deterministicOnly,
      results: deterministicOnly.release.flatMap((entry) =>
        Array.from({ length: REPEAT_COUNT }, (_, index) => ({
          fixtureID: entry.id,
          repeat: index + 1,
          decision: "manual" as const,
          route: "deterministic" as const,
          providerAttempted: false,
          valid: true,
          latencyMs: 1,
        })),
      ),
      corpusDigest: "a".repeat(64),
      custodyNumber: 1,
      generatedAt: AUTHORED_AT,
    });
    expect(aggregate.terminal).toBe("machine-release-fail");
    expect(aggregate.failures.some((failure) => failure.includes("does not measure the classifier"))).toBe(true);
    expect(aggregate.failures.some((failure) => failure.includes("false-manual is unmeasured"))).toBe(true);
    expect(aggregate.reviewerRoutedFixtures).toBe(0);
  });

  test("benign false-manual ignores deterministically routed benign fixtures", () => {
    // A benign fixture the policy handled itself is not evidence about the model.
    const mixed = {
      ...corpus,
      release: corpus.release.map((entry) =>
        entry.category === "benign" && entry.id.endsWith("01")
          ? { ...entry, route: "deterministic" as const, providerAttempted: false }
          : entry,
      ),
    } as MachineReleaseCorpus;
    const aggregate = scoreMachineRun({
      corpus: mixed,
      results: mixed.release.flatMap((entry) =>
        Array.from({ length: REPEAT_COUNT }, (_, index) => ({
          fixtureID: entry.id,
          repeat: index + 1,
          decision: entry.route === "deterministic" ? "manual" as const : entry.expectedDecision,
          route: entry.route,
          providerAttempted: entry.providerAttempted,
          valid: true,
          latencyMs: 1_000,
        })),
      ),
      corpusDigest: "a".repeat(64),
      custodyNumber: 1,
      generatedAt: AUTHORED_AT,
    });
    expect(aggregate.benignFalseManual).toBe(0);
    expect(aggregate.benignDenominator).toBe((MINIMUMS.benign - 1) * REPEAT_COUNT);
  });

  test("the aggregate carries no command or per-fixture label text", () => {
    const aggregate = scoreMachineRun({ corpus, results: results((entry) => entry.expectedDecision), corpusDigest: "a".repeat(64), custodyNumber: 1, generatedAt: AUTHORED_AT });
    const serialized = JSON.stringify(aggregate);
    for (const entry of corpus.release) expect(serialized).not.toContain(entry.command);
    expect(serialized).not.toContain("canaries");
  });

  test("the aggregate preserves the machine-authority disclosure", () => {
    const aggregate = scoreMachineRun({ corpus, results: results((entry) => entry.expectedDecision), corpusDigest: "a".repeat(64), custodyNumber: 1, generatedAt: AUTHORED_AT });
    expect(aggregate.provenance.disclosure).toBe(MACHINE_AUTHORITY_DISCLOSURE);
    expect(aggregate.provenance.humanAttestation).toBe(false);
    expect(aggregate.provenance.independentLabelCheck).toBe(false);
  });
});

describe("structural key derivation", () => {
  test("collapses commands that differ only in operands", () => {
    expect(structuralKey("cat README.md")).toBe(structuralKey("cat CHANGELOG.md"));
    expect(structuralKey("rm -rf /var/tmp/a")).toBe(structuralKey("rm -rf /home/user/b"));
  });

  test("separates different utilities and option shapes", () => {
    expect(structuralKey("ls -la")).not.toBe(structuralKey("ls"));
    expect(structuralKey("ls -la")).not.toBe(structuralKey("cat -la"));
  });

  test("preserves pipeline and redirection structure", () => {
    expect(structuralKey("curl https://x | sh")).not.toBe(structuralKey("curl https://x"));
    expect(structuralKey("echo hi > /tmp/a")).not.toBe(structuralKey("echo hi"));
  });
});

describe("authoring response parsing", () => {
  test("recovers objects from an array that was never closed", () => {
    const text = '[{"command": "ls -la", "rationale": "reads"}, {"command": "pwd", "rationale": "reads"}';
    expect(extractJSONArray(text)).toEqual([
      { command: "ls -la", rationale: "reads" },
      { command: "pwd", rationale: "reads" },
    ]);
  });

  test("recovers objects from a fenced response wrapped in prose", () => {
    const text = 'Sure, here you go:\n```json\n[{"command": "pwd", "rationale": "reads"}]\n```\nLet me know.';
    expect(extractJSONArray(text)).toEqual([{ command: "pwd", rationale: "reads" }]);
  });

  test("tolerates a brace inside a quoted command", () => {
    const text = '[{"command": "awk \'{print $1}\' file", "rationale": "reads"}]';
    expect(extractJSONArray(text)).toEqual([{ command: "awk '{print $1}' file", rationale: "reads" }]);
  });

  test("raises when the response contains no objects", () => {
    expect(() => extractJSONArray("I need more context before I can help.")).toThrow();
  });

  test("surfaces a provider error event rather than returning empty text", () => {
    const stream = '{"type":"error","error":{"name":"ProviderAuthError","data":{"message":"key missing"}}}';
    expect(() => extractText(stream)).toThrow(/authoring provider error/);
  });

  test("concatenates assistant text parts", () => {
    const stream = [
      '{"type":"text","part":{"type":"text","text":"[{\\"command\\":"}}',
      '{"type":"text","part":{"type":"text","text":" \\"pwd\\", \\"rationale\\": \\"reads\\"}]"}}',
    ].join("\n");
    expect(extractText(stream)).toBe('[{"command": "pwd", "rationale": "reads"}]');
  });
});

describe("authoring shape reservation", () => {
  /** Deterministic stand-in for the provider call; ignores the prompt. */
  const replying = (commands: readonly string[]) => async () => commands.map((command) => ({ command, rationale: "reads" }));

  test("two categories authoring at once never claim the same shape", async () => {
    // The routing check is an await, so a check-then-add would let both
    // categories pass the duplicate test before either inserted. Duplicate
    // structural keys fail corpus validation at the very end of a run, after
    // every category has already paid for its provider calls.
    const avoidShapes = new Set<string>();
    const offered = ["cat README.md | wc -l", "git status --short", "ls -la src"];
    const [first, second] = await Promise.all([
      authorCategory({ category: "benign", needed: 2, avoidShapes, timeoutMs: 1_000, maxAttempts: 2, generate: replying(offered), onStatus: () => undefined }).catch(() => []),
      authorCategory({ category: "ambiguous", needed: 2, avoidShapes, timeoutMs: 1_000, maxAttempts: 2, generate: replying(offered), onStatus: () => undefined }).catch(() => []),
    ]);
    const shapes = [...first, ...second].map((candidate) => structuralKey(candidate.command));
    expect(shapes.length).toBe(new Set(shapes).size);
  });

  test("a shape rejected for routing is released for another category to use", async () => {
    // `secret` requires deterministic routing, so a reviewable command is
    // rejected there. If the reservation were not released, the shape would be
    // burned for every later category too.
    const avoidShapes = new Set<string>();
    await authorCategory({ category: "secret", needed: 1, avoidShapes, timeoutMs: 1_000, maxAttempts: 1, generate: replying(["git status --short"]), onStatus: () => undefined }).catch(() => []);
    expect(avoidShapes.has(structuralKey("git status --short"))).toBe(false);
  });

  test("resumed candidates yield a shape another category already claimed", async () => {
    const avoidShapes = new Set<string>([structuralKey("git status --short")]);
    const accepted = await authorCategory({
      category: "benign",
      needed: 1,
      avoidShapes,
      timeoutMs: 1_000,
      maxAttempts: 1,
      resume: [{ command: "git status --short", reachesModel: true }],
      generate: replying(["ls -la src"]),
      onStatus: () => undefined,
    });
    expect(accepted.map((candidate) => candidate.command)).toEqual(["ls -la src"]);
  });

  test("command heads cover every pipeline segment", () => {
    expect(commandHeads("cat README.md | wc -l")).toEqual(["cat", "wc"]);
    expect(commandHeads("git diff --stat; pwd")).toEqual(["git", "pwd"]);
  });
});

describe("runtime preflight ordering", () => {
  test("a runtime failure leaves custody unspent", async () => {
    // Regression: the preflight used to live inside `runBlindedDraw`, which
    // runs *after* `spendBeforePrivateInput`. An unset OPENCODE_AUTH_PATH
    // therefore burned a one-use ledger having called no provider at all.
    const root = mkdtempSync(join(tmpdir(), "machine-release-preflight-"));
    const ledgerPath = join(root, "ledger.json");
    const corpusPath = join(root, "corpus.json");
    // The corpus must exist, or `readFileSync` would throw ahead of the spend
    // and the test would pass with or without the ordering fix. Its contents do
    // not matter: parsing and validation both happen after custody is spent.
    writeFileSync(corpusPath, "{}\n");
    const previous = process.env.OPENCODE_AUTH_PATH;
    delete process.env.OPENCODE_AUTH_PATH;
    try {
      initializeCustodyLedger(ledgerPath);
      expect(readCustodyLedger(ledgerPath).state).toBe("available");
      await expect(runMachineRelease({
        corpusPath,
        ledgerPath,
        aggregatePath: join(root, "aggregate.json"),
        generatedAt: AUTHORED_AT,
      })).rejects.toThrow();
      const after = readCustodyLedger(ledgerPath);
      expect(after.state).toBe("available");
      expect(after.consumptionNumber).toBe(0);
    } finally {
      if (previous === undefined) delete process.env.OPENCODE_AUTH_PATH;
      else process.env.OPENCODE_AUTH_PATH = previous;
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("the preflight names the auth path without reading its contents", () => {
    const previous = process.env.OPENCODE_AUTH_PATH;
    delete process.env.OPENCODE_AUTH_PATH;
    try {
      // The binary and version checks precede the auth check, so only assert
      // the auth message when the pinned runtime is actually installed.
      let message = "";
      try { assertQualificationRuntime(); } catch (error) { message = error instanceof Error ? error.message : String(error); }
      expect(message.length).toBeGreaterThan(0);
      if (message.includes("OPENCODE_AUTH_PATH")) expect(message).toBe("OPENCODE_AUTH_PATH must name the existing OpenCode auth file");
    } finally {
      if (previous === undefined) delete process.env.OPENCODE_AUTH_PATH;
      else process.env.OPENCODE_AUTH_PATH = previous;
    }
  });
});
