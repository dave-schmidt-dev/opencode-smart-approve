import { mkdtemp, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { createAuditWriter } from "../../src/audit/writer";

describe("privacy-preserving audit", () => {
  test("is disabled by default and drops raw command/prompt/output/env values", async () => {
    const directory = await mkdtemp(join(tmpdir(), "smart-approve-audit-"));
    const disabled = createAuditWriter({ directory });
    await disabled.append({ requestID: "disabled", command: "CANARY_SECRET", decision: "allow" });
    expect(await readdir(directory)).toEqual([]);

    const writer = createAuditWriter({ enabled: true, directory, maxBytes: 100_000 });
    await writer.append({
      requestID: "request-1",
      command: "printf CANARY_SECRET",
      prompt: "CANARY_PROMPT",
      output: "CANARY_OUTPUT",
      environment: { SECRET: "CANARY_ENV" },
      decision: "manual",
      reasonCodes: ["policy.manual"],
      policyID: "policy-v1",
      promptID: "prompt-v1",
      modelID: "model-v1",
      latencyMs: 123,
      raceState: "none",
    });
    await writer.flush();
    const text = await readFile(join(directory, "smart-approve-audit.jsonl"), "utf8");
    expect(text).not.toContain("CANARY_");
    expect(text).not.toContain("printf");
    expect(JSON.parse(text)).toMatchObject({ decision: "manual", latencyMs: 123, raceState: "none" });
  });

  test("rotates bounded JSONL without rejecting writes", async () => {
    const directory = await mkdtemp(join(tmpdir(), "smart-approve-rotate-"));
    const path = join(directory, "audit.jsonl");
    await writeFile(path, "x".repeat(120), "utf8");
    const writer = createAuditWriter({ enabled: true, filePath: path, maxBytes: 100, maxFiles: 2 });
    await writer.append({ requestID: "rotate", command: "echo safe", decision: "complete" });
    await writer.flush();
    expect((await stat(`${path}.1`)).size).toBe(120);
    expect((await stat(path)).size).toBeLessThanOrEqual(500);
  });
});
