import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { archiveArtifactGroup, archiveDirectoryFor, archiveExistingArtifact, identifyArtifact } from "../../scripts/qualification/artifact-archive";
import { createMachineCorpusDigestCompanion, writeMachineCorpusGeneration } from "../../scripts/qualification/author-machine-corpus";
import {
  createDevelopmentCandidateReport,
  createFrozenCandidateManifest,
  evaluateCorpus,
  evaluateFaults,
  hashQualificationRecord,
  loadDevelopmentCorpus,
  main,
  writeDevelopmentCandidateReport,
  type QualificationRecord,
} from "../../scripts/classifier-gate";
import { REPEAT_COUNT } from "../../scripts/qualification/core";
import { buildRehearsalCorpus } from "../../scripts/qualification/rehearsal";
import { assertDevelopmentGate, scoreMachineRun, writeMachineReleaseAggregate, type MachineAggregate } from "../../scripts/qualification/machine-release";

const AUTHORED_AT = "2026-08-26T14:40:00.000Z";
const LATER_AT = "2026-08-27T09:15:00.000Z";

/**
 * A passing development receipt bound to a candidate frozen at `generatedAt`.
 * Mirrors the fixture in machine-release.test.ts; kept local so this file does
 * not depend on that suite's internals.
 */
function receiptFixture(generatedAt: string) {
  const candidate = createFrozenCandidateManifest(generatedAt);
  const { corpus } = loadDevelopmentCorpus();
  const records = corpus.fixtures.flatMap((entry) => Array.from({ length: REPEAT_COUNT }, (_, index) => {
    const deterministic = entry.errorPath === true || entry.category === "secret" || entry.category === "dangerous" || entry.category === "obfuscated";
    const decision = entry.category === "benign" ? "allow" : "manual";
    const base = {
      observationID: `artifact-archive-${entry.id}-${index + 1}`,
      fixtureID: entry.id,
      category: entry.category,
      repeat: index + 1,
      expectedDecision: entry.expectedDecision,
      decision,
      route: deterministic ? "deterministic" : "reviewer",
      providerAttempted: !deterministic,
      reasonCodes: [deterministic ? "manual" : decision === "allow" ? "safe" : "ambiguous"],
      schemaValid: true,
      metricEligible: true,
      outcome: "classifier",
      terminalKind: deterministic ? "manual" : "valid_model",
      latencyMs: 100 + index,
    } as Omit<QualificationRecord, "responseHash">;
    return { ...base, responseHash: hashQualificationRecord(base) };
  }));
  return {
    candidate,
    report: createDevelopmentCandidateReport({
      candidate,
      corpusReport: evaluateCorpus("development", corpus, records),
      faults: evaluateFaults([]),
      terminal: "development-pass",
      generatedAt,
    }),
  };
}

function withTempRoot(body: (root: string) => void): void {
  const root = mkdtempSync(join(tmpdir(), "artifact-archive-"));
  try {
    body(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

async function aggregateFixture(generatedAt: string, fail = false): Promise<MachineAggregate> {
  const candidate = createFrozenCandidateManifest(AUTHORED_AT);
  const corpus = await buildRehearsalCorpus({
    candidateManifestHash: candidate.manifestHash,
    classifierModel: candidate.candidate.modelProfile.model,
    authoredAt: AUTHORED_AT,
  });
  const results = corpus.release.flatMap((fixture) => Array.from({ length: REPEAT_COUNT }, (_, index) => ({
    fixtureID: fixture.id,
    repeat: index + 1,
    decision: fail && fixture.category === "dangerous" && fixture.route === "reviewer" ? "allow" : fixture.expectedDecision,
    route: fixture.route,
    providerAttempted: fixture.route === "reviewer",
    terminalKind: fixture.route === "reviewer" ? "valid_model" as const : "manual" as const,
    valid: true,
    latencyMs: 1,
  })));
  return scoreMachineRun({ corpus, results, corpusDigest: "c".repeat(64), custodyNumber: 1, generatedAt, executionMode: "live" });
}

describe("artifact archive", () => {
  test("an absent artifact archives nothing", () => {
    withTempRoot((root) => {
      expect(archiveExistingArtifact(join(root, "missing.json"))).toBeUndefined();
      expect(existsSync(archiveDirectoryFor(join(root, "missing.json")))).toBe(false);
    });
  });

  test("a predecessor is preserved under its own identity, not the successor's", () => {
    withTempRoot((root) => {
      const path = join(root, "development-candidate-report.json");
      const first = receiptFixture(AUTHORED_AT);
      writeDevelopmentCandidateReport(path, first.report);

      const second = receiptFixture(LATER_AT);
      writeDevelopmentCandidateReport(path, second.report);

      const archives = readdirSync(archiveDirectoryFor(path));
      expect(archives).toHaveLength(1);
      // The name carries the archived receipt's own timestamp and the candidate
      // it was bound to, which is what makes an orphaned receipt identifiable.
      expect(archives[0]).toBe(`development-candidate-report-20260826T144000Z-${first.report.candidateManifestHash.slice(0, 12)}.json`);

      const preserved = JSON.parse(readFileSync(join(archiveDirectoryFor(path), archives[0] ?? ""), "utf8")) as { generatedAt: string };
      expect(preserved.generatedAt).toBe(AUTHORED_AT);
    });
  });

  test("readers still resolve the canonical path after an archive", () => {
    withTempRoot((root) => {
      const path = join(root, "development-candidate-report.json");
      const first = receiptFixture(AUTHORED_AT);
      const second = receiptFixture(LATER_AT);
      writeDevelopmentCandidateReport(path, first.report);
      writeDevelopmentCandidateReport(path, second.report);

      // This is the defect that actually cost evidence on 2026-08-16: the
      // receipt was overwritten and every reader kept working, so nothing
      // surfaced. The canonical path must now hold the successor, and the
      // archive directory's presence must not disturb the read.
      expect(() => assertDevelopmentGate(second.candidate, path)).not.toThrow();
      expect(() => assertDevelopmentGate(first.candidate, path)).toThrow();
      expect((JSON.parse(readFileSync(path, "utf8")) as { generatedAt: string }).generatedAt).toBe(LATER_AT);
    });
  });

  test("an unparseable predecessor is archived under a content hash", () => {
    withTempRoot((root) => {
      const path = join(root, "development-candidate-report.json");
      writeFileSync(path, "{ truncated");
      const archived = archiveExistingArtifact(path);
      expect(archived).toBeDefined();
      expect(archived).toMatch(/development-candidate-report-unidentified-[0-9a-f]{16}\.json$/);
      expect(readFileSync(archived ?? "", "utf8")).toBe("{ truncated");
    });
  });

  test("a valid artifact with no recognizable identity still survives", () => {
    withTempRoot((root) => {
      const path = join(root, "frozen-candidate-manifest.json");
      writeFileSync(path, JSON.stringify({ generatedAt: AUTHORED_AT, manifestHash: "not-a-sha" }));
      expect(identifyArtifact({ generatedAt: AUTHORED_AT, manifestHash: "not-a-sha" })).toBeUndefined();
      expect(archiveExistingArtifact(path)).toMatch(/frozen-candidate-manifest-unidentified-[0-9a-f]{16}\.json$/);
    });
  });

  test("two artifacts sharing an identity are both kept", () => {
    withTempRoot((root) => {
      const path = join(root, "report.json");
      const hash = "a".repeat(64);
      writeFileSync(path, JSON.stringify({ generatedAt: AUTHORED_AT, candidateManifestHash: hash, body: "first" }));
      archiveExistingArtifact(path);
      // Same timestamp and same candidate, different content: the archive must
      // not reintroduce the defect it exists to prevent.
      writeFileSync(path, JSON.stringify({ generatedAt: AUTHORED_AT, candidateManifestHash: hash, body: "second" }));
      archiveExistingArtifact(path);
      expect(readdirSync(archiveDirectoryFor(path))).toHaveLength(2);
    });
  });

  test("re-archiving identical bytes is idempotent", () => {
    withTempRoot((root) => {
      const path = join(root, "report.json");
      writeFileSync(path, JSON.stringify({ generatedAt: AUTHORED_AT, candidateManifestHash: "b".repeat(64) }));
      archiveExistingArtifact(path);
      archiveExistingArtifact(path);
      expect(readdirSync(archiveDirectoryFor(path))).toHaveLength(1);
    });
  });

  test("a re-freeze preserves the manifest an existing receipt names", () => {
    withTempRoot((root) => {
      const path = join(root, "frozen-candidate-manifest.json");
      const outgoing = createFrozenCandidateManifest(AUTHORED_AT);
      writeFileSync(path, `${JSON.stringify(outgoing, null, 2)}\n`, { mode: 0o600 });
      const archived = archiveExistingArtifact(path);
      expect(archived).toBe(join(archiveDirectoryFor(path), `frozen-candidate-manifest-20260826T144000Z-${outgoing.manifestHash.slice(0, 12)}.json`));
      writeFileSync(path, `${JSON.stringify(createFrozenCandidateManifest(LATER_AT), null, 2)}\n`, { mode: 0o600 });
      expect((JSON.parse(readFileSync(archived ?? "", "utf8")) as { manifestHash: string }).manifestHash).toBe(outgoing.manifestHash);
    });
  });

  test("the freeze command archives the manifest it replaces", async () => {
    const root = mkdtempSync(join(tmpdir(), "artifact-archive-freeze-"));
    try {
      const path = join(root, "frozen-candidate-manifest.json");
      // Drive the CLI entry point rather than the helper: this is the only test
      // that fails if the archive call is removed from the --freeze-candidate
      // branch. The freeze mode returns before any runtime or provider work, so
      // it is hermetic.
      expect(await main(["--freeze-candidate", path])).toBe(0);
      expect(existsSync(archiveDirectoryFor(path))).toBe(false);

      const outgoing = JSON.parse(readFileSync(path, "utf8")) as { manifestHash: string };
      expect(await main(["--freeze-candidate", path])).toBe(0);

      const archives = readdirSync(archiveDirectoryFor(path));
      expect(archives).toHaveLength(1);
      expect(archives[0]).toContain(outgoing.manifestHash.slice(0, 12));
      expect((JSON.parse(readFileSync(join(archiveDirectoryFor(path), archives[0] ?? ""), "utf8")) as { manifestHash: string }).manifestHash).toBe(outgoing.manifestHash);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("a release aggregate is preserved before a later draw reuses its path", async () => {
    const root = mkdtempSync(join(tmpdir(), "artifact-archive-aggregate-"));
    try {
      const path = join(root, "machine-release-aggregate.json");
      // The corpus a release draw consumes is one-use, so the aggregate is the
      // only evidence that draw will ever produce. Overwriting it is
      // unrecoverable in a way an ordinary report is not.
      const first = await aggregateFixture(AUTHORED_AT, true);
      const second = await aggregateFixture(LATER_AT);
      expect(first.candidateManifestHash).toBe(second.candidateManifestHash);
      await writeMachineReleaseAggregate(path, first);
      const predecessorBytes = readFileSync(path, "utf8");
      expect(existsSync(archiveDirectoryFor(path))).toBe(false);
      await expect(writeMachineReleaseAggregate(path, { generatedAt: AUTHORED_AT, candidateManifestHash: first.candidateManifestHash, terminal: "machine-release-fail" }))
        .rejects.toThrow(/schema version/);
      expect(readFileSync(path, "utf8")).toBe(predecessorBytes);
      expect(existsSync(archiveDirectoryFor(path))).toBe(false);
      await writeMachineReleaseAggregate(path, second);

      const archives = readdirSync(archiveDirectoryFor(path));
      expect(archives).toEqual([`machine-release-aggregate-20260826T144000Z-${first.candidateManifestHash.slice(0, 12)}.json`]);
      expect((JSON.parse(readFileSync(join(archiveDirectoryFor(path), archives[0] ?? ""), "utf8")) as MachineAggregate).terminal).toBe("machine-release-fail");
      expect((JSON.parse(readFileSync(path, "utf8")) as MachineAggregate).terminal).toBe("machine-release-pass");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("identity reads the corpus binding, which is nested rather than top level", () => {
    const hash = "d".repeat(64);
    expect(identifyArtifact({ generatedAt: AUTHORED_AT, bindings: { candidateManifestHash: hash } })).toEqual({ stamp: "20260826T144000Z", hash: hash.slice(0, 12) });
    // A top-level hash still wins, so nothing that already resolved changes.
    expect(identifyArtifact({ generatedAt: AUTHORED_AT, candidateManifestHash: "e".repeat(64), bindings: { candidateManifestHash: hash } })?.hash).toBe("e".repeat(12));
  });

  test("a corpus generation is archived as one identity, not two", () => {
    withTempRoot((root) => {
      const corpusPath = join(root, "machine-release-corpus.json");
      const digestPath = join(root, "machine-release-corpus.digest.json");
      const hash = "f".repeat(64);
      const generation = (generatedAt: string, marker: string) => {
        const corpusBytes = `${JSON.stringify({ generatedAt, corpusVersion: marker, bindings: { candidateManifestHash: hash } }, null, 2)}\n`;
        writeMachineCorpusGeneration({ corpusPath, digestPath, corpusBytes, digestCompanion: createMachineCorpusDigestCompanion({ candidateManifestHash: hash, corpusBytes }) });
      };
      generation(AUTHORED_AT, "gen-1");
      generation(LATER_AT, "gen-2");

      const archives = readdirSync(archiveDirectoryFor(corpusPath)).sort();
      expect(archives).toHaveLength(2);
      // The digest companion carries no timestamp of its own. Archived on its
      // own it would be named from its bytes and nothing would tie it to the
      // corpus it attests, which is the mispairing the group exists to prevent.
      const stem = `-20260826T144000Z-${hash.slice(0, 12)}`;
      expect(archives.every((name) => name.includes(stem))).toBe(true);
      expect((JSON.parse(readFileSync(join(archiveDirectoryFor(corpusPath), archives.find((name) => !name.includes("digest")) ?? ""), "utf8")) as { corpusVersion: string }).corpusVersion).toBe("gen-1");
    });
  });

  test("a group with no identifiable member is still kept together", () => {
    withTempRoot((root) => {
      const first = join(root, "a.json");
      const second = join(root, "b.json");
      writeFileSync(first, "{ truncated");
      writeFileSync(second, JSON.stringify({ unrelated: true }));
      const archived = archiveArtifactGroup([first, second]);
      expect(archived).toHaveLength(2);
      const stems = archived.map((path) => path.replace(/.*\/[ab]-/, ""));
      expect(stems[0]).toBe(stems[1]);
      expect(stems[0]).toMatch(/^undated-[0-9a-f]{12}\.json$/);
    });
  });

  test("a group archives nothing when no member exists", () => {
    withTempRoot((root) => {
      expect(archiveArtifactGroup([join(root, "x.json"), join(root, "y.json")])).toEqual([]);
      expect(existsSync(archiveDirectoryFor(join(root, "x.json")))).toBe(false);
    });
  });
});
