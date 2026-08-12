import { readFile } from "node:fs/promises";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { runABTrial, validateABReceipt } from "../../scripts/deny-replan-ab-trial";

describe("deny/replan paired A/B trial harness", () => {
  test("fake paired run produces two bounded arms per repetition", async () => {
    const root = await mkdtemp(join(tmpdir(), "deny-replan-ab-test-"));
    try {
      const result = await runABTrial({ fake: true, outputDirectory: root, repeats: 2, order: "alternate" });
      expect(result.runs).toHaveLength(4);
      expect(result.arms.control.runs).toBe(2);
      expect(result.arms.treatment.runs).toBe(2);
      expect(result.all_global_config_hashes_equal).toBe(true);
      expect(result.owner_opt_in).toBe(false);
      expect(result.model_approval_qualified).toBe(false);
      for (const arm of [result.arms.control, result.arms.treatment]) {
        expect(arm.totals.target_attempts).toBe(14);
        expect(arm.totals.target_blocks).toBe(14);
        expect(arm.totals.target_recoveries).toBe(12);
        expect(arm.totals.target_repeated_calls).toBe(6);
        expect(arm.totals.pipeline_attempts).toBe(4);
        expect(arm.totals.pipeline_blocks).toBe(4);
        expect(arm.totals.pipeline_recoveries).toBe(4);
      }
      expect(result.treatment_minus_control.target_attempts).toBe(0);
      expect(result.treatment_minus_control.pipeline_recoveries).toBe(0);
      expect(validateABReceipt(JSON.parse(await readFile(join(root, "ab-summary.json"), "utf8")))).toEqual(result);
      const serialized = await readFile(join(root, "ab-summary.json"), "utf8");
      expect(serialized).not.toMatch(/(?:command|prompt|provider|environment|credential|secret|raw|output)\s*:/i);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("real paired mode fails closed without explicit confirmation", () => {
    const result = Bun.spawnSync(["bun", "run", "scripts/deny-replan-ab-trial.ts"], { cwd: process.cwd(), stdout: "pipe", stderr: "pipe" });
    expect(result.exitCode).not.toBe(0);
    expect(new TextDecoder().decode(result.stderr)).toContain("--confirm");
  });

  test("receipt integrity rejects variant-hash, arm-mapping, and global-hash tampering", async () => {
    const root = await mkdtemp(join(tmpdir(), "deny-replan-ab-tamper-test-"));
    try {
      const result = await runABTrial({ fake: true, outputDirectory: root, repeats: 1 });
      const hashTamper = structuredClone(result) as any;
      hashTamper.feedback_variant_hashes.catalog = "0".repeat(64);
      expect(() => validateABReceipt(hashTamper)).toThrow();
      const mappingTamper = structuredClone(result) as any;
      mappingTamper.runs[0].feedback_arm = "treatment";
      expect(() => validateABReceipt(mappingTamper)).toThrow();
      const hashAssignmentTamper = structuredClone(result) as any;
      hashAssignmentTamper.runs[0].feedback_variant_hash = hashAssignmentTamper.feedback_variant_hashes.catalog;
      expect(() => validateABReceipt(hashAssignmentTamper)).toThrow();
      const globalTamper = structuredClone(result) as any;
      globalTamper.runs[1].global_config_hash = "f".repeat(64);
      expect(() => validateABReceipt(globalTamper)).toThrow();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("bare-microplan-vs-enriched-catalog comparison keeps distinct feedback mappings", async () => {
    const root = await mkdtemp(join(tmpdir(), "deny-replan-ab-bare-test-"));
    try {
      const result = await runABTrial({ fake: true, outputDirectory: root, repeats: 1, comparison: "bare-microplan-vs-enriched-catalog" });
      expect(result.comparison).toBe("bare-microplan-vs-enriched-catalog");
      expect(result.runs[0]?.feedback_arm).toBe("historical_bare");
      expect(result.runs[1]?.feedback_arm).toBe("treatment");
      expect(validateABReceipt(JSON.parse(await readFile(join(root, "ab-summary.json"), "utf8")))).toEqual(result);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("enriched-catalog-vs-compact-catalog comparison maps production control and candidate treatment", async () => {
    const root = await mkdtemp(join(tmpdir(), "deny-replan-ab-compact-test-"));
    try {
      const result = await runABTrial({ fake: true, outputDirectory: root, repeats: 1, comparison: "enriched-catalog-vs-compact-catalog" });
      expect(result.comparison).toBe("enriched-catalog-vs-compact-catalog");
      expect(result.runs[0]?.feedback_arm).toBe("treatment");
      expect(result.runs[1]?.feedback_arm).toBe("compact_catalog");
      expect(validateABReceipt(JSON.parse(await readFile(join(root, "ab-summary.json"), "utf8")))).toEqual(result);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("v4 bare/enriched receipts remain readable while v5 compact receipts stay strict", async () => {
    const root = await mkdtemp(join(tmpdir(), "deny-replan-ab-v4-compat-test-"));
    try {
      const result = await runABTrial({ fake: true, outputDirectory: root, repeats: 1, comparison: "bare-microplan-vs-enriched-catalog" });
      const v4 = structuredClone(result) as any;
      v4.schema_version = "deny-replan-ab/v4";
      delete v4.feedback_variant_hashes.compact_catalog;
      expect(validateABReceipt(v4).schema_version).toBe("deny-replan-ab/v4");
      const invalidV5 = structuredClone(result) as any;
      invalidV5.schema_version = "deny-replan-ab/v5";
      delete invalidV5.feedback_variant_hashes.compact_catalog;
      expect(() => validateABReceipt(invalidV5)).toThrow();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("paired output collision requires explicit overwrite", async () => {
    const root = await mkdtemp(join(tmpdir(), "deny-replan-ab-collision-"));
    try {
      await runABTrial({ fake: true, outputDirectory: root, repeats: 1 });
      await expect(runABTrial({ fake: true, outputDirectory: root, repeats: 1 })).rejects.toThrow("receipt already exists");
      await expect(runABTrial({ fake: true, outputDirectory: root, repeats: 1, overwrite: true })).resolves.toBeDefined();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
