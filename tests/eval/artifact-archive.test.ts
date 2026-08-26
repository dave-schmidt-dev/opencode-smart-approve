import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { archiveDirectoryFor, archiveExistingArtifact, identifyArtifact } from "../../scripts/qualification/artifact-archive";
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
import { assertDevelopmentGate } from "../../scripts/qualification/machine-release";

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
});
