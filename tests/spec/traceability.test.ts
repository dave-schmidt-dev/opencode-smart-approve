import { copyFileSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { validateTraceability } from "../../scripts/spec-guard";

const fixture = (unmapped = false): string => {
  const root = mkdtempSync(join(tmpdir(), "smart-approve-trace-"));
  mkdirSync(join(root, "tests/spec"), { recursive: true });
  writeFileSync(join(root, "SPEC.md"), "### REQ-001\n### REQ-002\n");
  writeFileSync(
    join(root, "TASKS.md"),
    `- [ ] TASK-001: scaffold\n  - spec: REQ-001${unmapped ? "" : ", REQ-002"}\n  - test: tests/spec/traceability.test.ts\n`,
  );
  writeFileSync(join(root, "INVARIANTS.md"), "### INV-1\ngate_test: tests/spec/traceability.test.ts\n");
  writeFileSync(join(root, "tests/spec/traceability.test.ts"), "fixture");
  return root;
};

describe("spec traceability", () => {
  test("accepts a complete requirement/task/test/invariant mapping", () => {
    const root = fixture();
    try {
      expect(validateTraceability(root).errors).toEqual([]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("rejects an unmapped requirement", () => {
    const root = fixture(true);
    try {
      expect(validateTraceability(root).errors).toContain("REQ-002 is not mapped to a TASK-###");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("repository installs from the frozen Bun lockfile", () => {
    const root = mkdtempSync(join(tmpdir(), "smart-approve-install-"));
    copyFileSync(join(process.cwd(), "package.json"), join(root, "package.json"));
    copyFileSync(join(process.cwd(), "bun.lock"), join(root, "bun.lock"));
    const result = Bun.spawnSync(["bun", "install", "--frozen-lockfile", "--ignore-scripts"], {
      cwd: root,
      stdout: "ignore",
      stderr: "pipe",
      env: { ...process.env, TMPDIR: "/private/tmp" },
    });
    try {
      expect(result.exitCode).toBe(0);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 120_000);

  test("npm pack dry-run excludes local configuration, logs, credentials, and eval results", () => {
    const result = Bun.spawnSync(["npm", "pack", "--dry-run", "--json"], {
      cwd: process.cwd(),
      stdout: "pipe",
      stderr: "pipe",
      env: { ...process.env, TMPDIR: "/private/tmp", npm_config_cache: "/private/tmp/npm-cache" },
    });
    expect(result.exitCode).toBe(0);
    const output = new TextDecoder().decode(result.stdout);
    const files = Array.from(output.matchAll(/"path"\s*:\s*"([^"]+)"/g), (match) => match[1]);
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      expect(file).not.toMatch(/^(config|credentials|eval-results|\.logs)(\/|$)/);
      expect(file).not.toMatch(/(^|\/)(\.env|.*\.log$)/);
    }
  }, 120_000);
});
