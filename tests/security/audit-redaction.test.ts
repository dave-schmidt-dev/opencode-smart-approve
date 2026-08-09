import * as fs from "node:fs/promises";
import { mkdtemp, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, mock, test } from "bun:test";
import { createAuditRecord, parseAuditRecord } from "../../src/audit/schema";
import { createAuditWriter, type AuditFileSystem } from "../../src/audit/writer";
import { validateConfig } from "../../src/config/schema";
import { createSmartApproveHooks } from "../../src/plugin";

const APPROVED_FIELDS = [
  "commandShapeHash",
  "decision",
  "latencyMs",
  "modelID",
  "policyID",
  "promptID",
  "raceState",
  "reasonCodes",
  "requestHash",
  "timestamp",
] as const;

const permissionEvent = (id: string, command: string) => ({
  type: "permission.asked",
  properties: { id, sessionID: "parent", permission: "bash", metadata: { command } },
});

async function waitFor(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (predicate()) return;
    await Bun.sleep(1);
  }
  throw new Error("timed out waiting for detached permission handling");
}

describe("privacy-preserving audit", () => {
  test("production hooks keep audit off by default and write one strict record only after opt-in flush", async () => {
    const disabledDirectory = await mkdtemp(join(tmpdir(), "smart-approve-production-disabled-"));
    const disabledReview = mock(async ({ requestID }: { requestID: string }) => ({
      decision: "manual" as const,
      reasonCodes: ["manual" as const],
      requestID,
      sessionID: "child-disabled",
      toolCounters: { executable: 0, dataAccess: 0, mcp: 0, web: 0, task: 0 },
    }));
    const disabled = createSmartApproveHooks({
      directory: disabledDirectory,
      reviewer: { review: disabledReview },
      shellCompatible: true,
      policy: async () => ({ status: "model_review", decision: "model_review", reasonCodes: [], parse: undefined, privacy: undefined }),
    });
    await disabled.event({ event: permissionEvent("disabled-production", "printf disabled") });
    await waitFor(() => disabled.state("disabled-production") === "manual");
    await disabled.flushDiagnostics();
    await expect(readdir(join(disabledDirectory, ".logs"))).rejects.toMatchObject({ code: "ENOENT" });

    const enabledDirectory = await mkdtemp(join(tmpdir(), "smart-approve-production-enabled-"));
    const canary = "CANARY_PRODUCTION_AUDIT_SECRET";
    const review = mock(async ({ requestID }: { requestID: string }) => ({
      decision: "allow" as const,
      reasonCodes: ["safe" as const],
      requestID,
      sessionID: "child-enabled",
      toolCounters: { executable: 0, dataAccess: 0, mcp: 0, web: 0, task: 0 },
    }));
    const approve = mock(async () => undefined);
    const enabled = createSmartApproveHooks({
      config: validateConfig({ model: { enabled: true }, audit: { enabled: true, directory: enabledDirectory } }),
      reviewer: { review },
      approve,
      shellCompatible: true,
      policy: async () => ({ status: "model_review", decision: "model_review", reasonCodes: [], parse: undefined, privacy: undefined }),
    });
    await enabled.event({ event: permissionEvent("enabled-production", `printf ${canary}`) });
    await waitFor(() => enabled.state("enabled-production") === "manual");
    await enabled.flushDiagnostics();

    const text = await readFile(join(enabledDirectory, "smart-approve-audit.jsonl"), "utf8");
    const lines = text.trim().split("\n");
    expect(lines).toHaveLength(1);
    expect(text).not.toContain(canary);
    const record = JSON.parse(lines[0]!) as Record<string, unknown>;
    expect(Object.keys(record).sort()).toEqual([...APPROVED_FIELDS].sort());
    expect(parseAuditRecord(record).decision).toBe("manual");
    expect(review).not.toHaveBeenCalled();
    expect(approve).not.toHaveBeenCalled();
    expect(enabled.metricsSnapshot()).toMatchObject({ reviewCount: 0, completedCount: 0 });
  });

  test("production model kill switch audits manual without provider or permission reply", async () => {
    const directory = await mkdtemp(join(tmpdir(), "smart-approve-production-kill-switch-"));
    const review = mock(async () => { throw new Error("provider must not be called"); });
    const approve = mock(async () => undefined);
    const hooks = createSmartApproveHooks({
      config: validateConfig({ model: { enabled: false }, audit: { enabled: true, directory } }),
      reviewer: { review },
      approve,
      shellCompatible: true,
    });
    await hooks.event({ event: permissionEvent("kill-switch", "printf safe") });
    await waitFor(() => hooks.state("kill-switch") === "manual");
    await hooks.flushDiagnostics();

    expect(review).not.toHaveBeenCalled();
    expect(approve).not.toHaveBeenCalled();
    const record = parseAuditRecord(JSON.parse(await readFile(join(directory, "smart-approve-audit.jsonl"), "utf8")));
    expect(record).toMatchObject({ decision: "manual", reasonCodes: ["model_disabled"], promptID: "none", raceState: "none" });
  });

  test("is disabled by default", async () => {
    const directory = await mkdtemp(join(tmpdir(), "smart-approve-audit-disabled-"));
    const writer = createAuditWriter({ directory });
    await writer.append({ requestID: "disabled", command: "CANARY_SECRET", decision: "allow" });
    await writer.flush();
    expect(await readdir(directory)).toEqual([]);
  });

  test("persists exactly approved fields and zero raw or canary bytes", async () => {
    const directory = await mkdtemp(join(tmpdir(), "smart-approve-audit-fields-"));
    const canary = "CANARY_API_KEY_7f3319";
    const writer = createAuditWriter({ enabled: true, directory, maxBytes: 100_000 });
    await writer.append({
      requestID: "request-1",
      command: `printf ${canary}`,
      commandShape: "command word",
      prompt: `review prompt ${canary}`,
      output: `model prose ${canary}`,
      environment: { API_KEY: canary },
      decision: "manual",
      reasonCodes: ["policy.manual"],
      policyID: "policy-v1",
      promptID: "prompt-v1",
      modelID: "model-v1",
      latencyMs: 123,
      raceState: "none",
      rawCommand: `printf ${canary}`,
      unknown: canary,
    } as Parameters<typeof writer.append>[0] & Record<string, unknown>);
    await writer.flush();

    const text = await readFile(join(directory, "smart-approve-audit.jsonl"), "utf8");
    expect(text).not.toContain(canary);
    expect(text).not.toContain("printf");
    expect(text).not.toContain("review prompt");
    expect(text).not.toContain("model prose");
    expect(text).not.toContain("API_KEY");
    const record = JSON.parse(text) as Record<string, unknown>;
    expect(Object.keys(record).sort()).toEqual([...APPROVED_FIELDS].sort());
    expect(parseAuditRecord(record)).toMatchObject({
      decision: "manual",
      latencyMs: 123,
      raceState: "none",
      reasonCodes: ["policy.manual"],
    });
  });

  test("never derives command-shape hashes from raw command bytes", () => {
    const first = createAuditRecord({ command: "first raw secret", decision: "manual" });
    const second = createAuditRecord({ command: "different raw secret", decision: "manual" });
    expect(first.commandShapeHash).toBe(second.commandShapeHash);
  });

  test("captures a sanitized snapshot before asynchronous persistence", async () => {
    const directory = await mkdtemp(join(tmpdir(), "smart-approve-audit-snapshot-"));
    const input = { requestID: "before", commandShape: "word", decision: "manual" };
    const expectedHash = createAuditRecord(input).requestHash;
    const writer = createAuditWriter({ enabled: true, directory });
    await writer.append(input);
    input.requestID = "CANARY_MUTATED_AFTER_APPEND";
    await writer.flush();

    const text = await readFile(join(directory, "smart-approve-audit.jsonl"), "utf8");
    expect(text).not.toContain("CANARY_MUTATED_AFTER_APPEND");
    expect(JSON.parse(text).requestHash).toBe(expectedHash);
  });

  test("rotates before crossing the configured boundary and enforces retention", async () => {
    const directory = await mkdtemp(join(tmpdir(), "smart-approve-rotate-"));
    const path = join(directory, "audit.jsonl");
    const sample = `${JSON.stringify(createAuditRecord({ requestID: "sample", commandShape: "word", decision: "complete" }))}\n`;
    const maxBytes = Buffer.byteLength(sample, "utf8") + 8;
    const writer = createAuditWriter({ enabled: true, filePath: path, maxBytes, maxFiles: 3 });
    for (let index = 0; index < 5; index += 1) {
      await writer.append({ requestID: `rotate-${index}`, commandShape: "word", decision: "complete" });
    }
    await writer.flush();

    const files = (await readdir(directory)).sort();
    expect(files).toEqual(["audit.jsonl", "audit.jsonl.1", "audit.jsonl.2"]);
    for (const file of files) {
      const bytes = Buffer.byteLength(await readFile(join(directory, file), "utf8"), "utf8");
      expect(bytes).toBeLessThanOrEqual(maxBytes);
    }
  });

  test("drops an individual line that cannot fit the configured size bound", async () => {
    const directory = await mkdtemp(join(tmpdir(), "smart-approve-oversize-"));
    const writer = createAuditWriter({ enabled: true, directory, maxBytes: 1 });
    await writer.append({ requestID: "oversize", commandShape: "word", decision: "manual" });
    await writer.flush();
    expect(await readdir(directory)).toEqual([]);
  });

  test("append returns before slow audit I/O and flush remains the explicit wait", async () => {
    const directory = await mkdtemp(join(tmpdir(), "smart-approve-nonblocking-"));
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let enteredWrite = false;
    const fileSystem: AuditFileSystem = {
      appendFile: (async (...args: Parameters<typeof fs.appendFile>) => {
        enteredWrite = true;
        await gate;
        return fs.appendFile(...args);
      }) as typeof fs.appendFile,
      mkdir: fs.mkdir,
      rename: fs.rename,
      stat: fs.stat,
      unlink: fs.unlink,
    };
    const writer = createAuditWriter({ enabled: true, directory, fileSystem });
    let decisionContinued = false;
    await writer.append({ requestID: "slow-write", commandShape: "word", decision: "allow" });
    decisionContinued = true;

    expect(decisionContinued).toBe(true);
    while (!enteredWrite) await Bun.sleep(0);
    expect(await readdir(directory)).toEqual([]);
    release();
    await writer.flush();
    expect(await readdir(directory)).toEqual(["smart-approve-audit.jsonl"]);
  });
});
