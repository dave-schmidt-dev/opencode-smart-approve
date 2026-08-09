import { describe, expect, test } from "bun:test";
import { DEFAULT_CONFIG, ConfigValidationError, validateConfig } from "../../src/config/schema";
import { loadGlobalConfig, parseGlobalConfig } from "../../src/config/load";

describe("global configuration", () => {
  test("supplies the enabled model and 30-second timeout defaults", () => {
    const config = validateConfig({});
    expect(config.source).toBe("global");
    expect(config.model.enabled).toBe(true);
    expect(config.model.timeoutMs).toBe(30_000);
    expect(DEFAULT_CONFIG.model.timeoutMs).toBe(30_000);
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
});
