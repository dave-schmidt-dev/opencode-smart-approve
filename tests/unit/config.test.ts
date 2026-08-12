import { describe, expect, test } from "bun:test";
import { ConfigValidationError, validateConfig } from "../../src/config/schema";
import { loadGlobalConfig, parseGlobalConfig } from "../../src/config/load";

describe("global configuration", () => {
  test("keeps the unqualified model disabled with a 30-second timeout default", () => {
    const config = validateConfig({});
    expect(config.source).toBe("global");
    expect(config.model.enabled).toBe(false);
    expect(config.model.timeoutMs).toBe(30_000);
    expect(config.audit).toEqual({ enabled: false, maxBytes: 1_000_000, maxFiles: 2 });
    expect(config.replan).toEqual({ enabled: false, maxBlocksPerTurn: 3 });
  });

  test("keeps replan independent from model enablement and validates its strict budget", () => {
    expect(validateConfig({ model: { enabled: true } }).replan).toEqual({ enabled: false, maxBlocksPerTurn: 3 });
    expect(validateConfig({ replan: { enabled: true } }).replan).toEqual({ enabled: true, maxBlocksPerTurn: 3 });
    for (const value of [1, 3]) expect(validateConfig({ replan: { maxBlocksPerTurn: value } }).replan.maxBlocksPerTurn).toBe(value);
    for (const value of [0, 4, 5, 6, 1.5, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      expect(() => validateConfig({ replan: { maxBlocksPerTurn: value } })).toThrow(ConfigValidationError);
    }
    expect(() => validateConfig({ replan: { unknown: true } })).toThrow(ConfigValidationError);
    expect(() => validateConfig({ unknown: true })).toThrow(ConfigValidationError);
  });

  test("audit is opt-in with a strict directory and bounded rotation policy", () => {
    expect(validateConfig({ audit: { enabled: true, directory: "/tmp/audit", maxBytes: 4_096, maxFiles: 3 } }).audit)
      .toEqual({ enabled: true, directory: "/tmp/audit", maxBytes: 4_096, maxFiles: 3 });
    expect(() => validateConfig({ audit: { enabled: true, unknown: true } })).toThrow(ConfigValidationError);
    expect(() => validateConfig({ audit: { maxBytes: 1_023 } })).toThrow(ConfigValidationError);
    expect(() => validateConfig({ audit: { maxFiles: 9 } })).toThrow(ConfigValidationError);
  });

  test("rejects unknown keys, projects, and out-of-range timeouts", async () => {
    expect(() => validateConfig({ unknown: true })).toThrow(ConfigValidationError);
    expect(() => validateConfig({ source: "project" })).toThrow(ConfigValidationError);
    expect(() => validateConfig({ model: { timeoutMs: 9_999 } })).toThrow(ConfigValidationError);
    expect(() => validateConfig({ model: { timeoutMs: 60_001 } })).toThrow(ConfigValidationError);
    await expect(loadGlobalConfig({ projectPath: "/tmp/project/config.json" })).rejects.toThrow(/Project configuration/);
  });

  test("reads only the supplied global source and accepts model kill switch", async () => {
    let reads = 0;
    const config = await loadGlobalConfig({
      globalPath: "/tmp/global.json",
      readFile: async () => { reads += 1; return JSON.stringify({ model: { enabled: false } }); },
    });
    expect(reads).toBe(1);
    expect(config.model.enabled).toBe(false);
    expect(parseGlobalConfig(JSON.stringify({ policy: { rules: [{ pattern: "echo", action: "manual" }] } })).policy.rules[0]?.action).toBe("manual");
  });

  test("treats a missing global file as defaults but fails startup on malformed content", async () => {
    const missing = await loadGlobalConfig({
      globalPath: "/tmp/missing-global.json",
      readFile: async () => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); },
    });
    expect(missing.source).toBe("global");
    expect(missing.model.enabled).toBe(false);
    expect(missing.replan).toEqual({ enabled: false, maxBlocksPerTurn: 3 });

    await expect(loadGlobalConfig({
      globalPath: "/tmp/bad-global.json",
      readFile: async () => "{\"model\": {\"enabled\": false}, \"unknown\": true}",
    })).rejects.toThrow(ConfigValidationError);
  });

  test("configuration is read on restart and the kill switch routes all requests manual", async () => {
    let document = JSON.stringify({ model: { enabled: true } });
    const readFile = async () => document;
    expect((await loadGlobalConfig({ globalPath: "/tmp/restart.json", readFile })).model.enabled).toBe(true);
    document = JSON.stringify({ model: { enabled: false } });
    expect((await loadGlobalConfig({ globalPath: "/tmp/restart.json", readFile })).model.enabled).toBe(false);
  });
});
