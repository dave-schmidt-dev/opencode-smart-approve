import { readFileSync } from "node:fs";
import { describe, expect, test } from "bun:test";

type PackageJson = {
  main?: string;
  exports?: Record<string, string>;
  files?: string[];
  grammar?: { name?: string; source?: string; license?: string; wasm?: string; checksum?: string; checksumAlgorithm?: string };
  scripts?: Record<string, string>;
};

const packageJson = (): PackageJson => JSON.parse(readFileSync("package.json", "utf8")) as PackageJson;

function packedFiles(): string[] {
  const result = Bun.spawnSync(["npm", "pack", "--dry-run", "--json"], {
    cwd: process.cwd(),
    env: { ...process.env, TMPDIR: "/private/tmp", npm_config_cache: "/private/tmp/smart-approve-npm-cache" },
    stdout: "pipe",
    stderr: "pipe",
  });
  expect(result.exitCode).toBe(0);
  const output = new TextDecoder().decode(result.stdout);
  return Array.from(output.matchAll(/"path"\s*:\s*"([^"]+)"/g), (match) => match[1]);
}

describe("package recovery and allowlist", () => {
  test("package smoke exposes entrypoint, provenance, and runtime grammar assets", () => {
    const manifest = packageJson();
    expect(manifest.main).toBe("./src/plugin.ts");
    expect(manifest.exports?.["."]).toBe("./src/plugin.ts");
    expect(manifest.files).toEqual(expect.arrayContaining(["src", "README.md", "LICENSE"]));
    expect(manifest.grammar).toEqual(expect.objectContaining({
      name: "tree-sitter-bash",
      source: expect.stringContaining("tree-sitter/tree-sitter-bash"),
      license: "MIT",
      wasm: "src/assets/tree-sitter-bash.wasm",
      checksum: "src/assets/tree-sitter-bash.sha256",
      checksumAlgorithm: "sha256",
    }));
    const files = packedFiles();
    expect(files).toContain("src/assets/tree-sitter-bash.wasm");
    expect(files).toContain("src/assets/tree-sitter-bash.sha256");
    expect(files).toContain("src/plugin.ts");
  }, 120_000);

  test("package smoke excludes tests, fixtures, logs, credentials, and local config", () => {
    for (const file of packedFiles()) {
      expect(file).not.toMatch(/^(tests?|fixtures|logs?|credentials?|config|eval-results)(\/|$)/i);
      expect(file).not.toMatch(/(^|\/)(\.env(?:\.|$)|.*\.log$)/i);
    }
  }, 120_000);

  test("check stays offline and does not invoke the attended E2E script", () => {
    const scripts = packageJson().scripts ?? {};
    expect(scripts.check).toContain("test:offline");
    expect(scripts.check).toContain("test:package");
    expect(scripts.check).not.toContain("test:e2e");
    expect(scripts["test:offline"]).not.toContain("opencode");
    expect(scripts["test:offline"]).not.toContain("provider");
    expect(scripts["test:e2e"]).toContain("test:e2e:integration");
    expect(scripts["test:e2e"]).toContain("test:e2e:canary");
    expect(scripts["test:e2e:integration"]).toContain("--max-concurrency=1");
    expect(scripts["test:e2e:canary"]).toContain("--max-concurrency=1");
  });
});
