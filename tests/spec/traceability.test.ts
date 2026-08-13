import { copyFileSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { validateTraceability } from "../../scripts/spec-guard";
import { REPLAN_EXECUTABLES } from "../../src/policy/executable-identity";
import { evaluateDeterministicPolicy } from "../../src/policy/deterministic";

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

const replanTraceErrors = (root: string): string[] => {
  const spec = readFileSync(join(root, "SPEC.md"), "utf8");
  const invariants = readFileSync(join(root, "INVARIANTS.md"), "utf8");
  const traceability = readFileSync(join(root, "TRACEABILITY.md"), "utf8");
  const errors: string[] = [];
  if (!spec.includes("### REQ-014: Opt-in pre-execution replan")) errors.push("REQ-014 is missing");
  if (!/^### INV-8[^\n]*\n(?:[^\n]*\n)*?gate_test:\s*tests\/integration\/replan-guard\.test\.ts$/m.test(invariants)) {
    errors.push("INV-8 must name tests/integration/replan-guard.test.ts");
  }
  const replanMapping = traceability.match(/^\|\s*TASK-011\s*\|\s*REQ-014\s*\|(.+)\|$/m)?.[1] ?? "";
  if (!replanMapping) errors.push("REQ-014 is not mapped to TASK-011");
  if (/permission[-_/ ]reply/i.test(replanMapping)) errors.push("REQ-014 must not map to a permission-reply path");
  return errors;
};

const replanFixture = (options: { readonly omitGate?: boolean; readonly permissionReply?: boolean } = {}): string => {
  const root = mkdtempSync(join(tmpdir(), "smart-approve-replan-trace-"));
  writeFileSync(join(root, "SPEC.md"), "### REQ-014: Opt-in pre-execution replan\n", "utf8");
  writeFileSync(
    join(root, "INVARIANTS.md"),
    options.omitGate
      ? "### INV-8\nthreshold: 3\n"
      : "### INV-8\ngate_test: tests/integration/replan-guard.test.ts\nthreshold: 3\n",
    "utf8",
  );
  writeFileSync(
    join(root, "TRACEABILITY.md"),
    `| TASK-011 | REQ-014 | tests/integration/${options.permissionReply ? "permission-reply" : "replan-guard"}.test.ts |\n`,
    "utf8",
  );
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

  test("rejects a replan fixture that omits the INV-8 gate", () => {
    const root = replanFixture({ omitGate: true });
    try {
      expect(replanTraceErrors(root)).toContain("INV-8 must name tests/integration/replan-guard.test.ts");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("rejects a replan fixture mapped to a permission-reply path", () => {
    const root = replanFixture({ permissionReply: true });
    try {
      expect(replanTraceErrors(root)).toContain("REQ-014 must not map to a permission-reply path");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("maps the repository replan contract to INV-8 without a permission reply", () => {
    expect(replanTraceErrors(process.cwd())).toEqual([]);
  });

  test("keeps the six-executable rubric boundary and preserves other routing", async () => {
    const spec = readFileSync(join(process.cwd(), "SPEC.md"), "utf8");
    const rubric = readFileSync(join(process.cwd(), "fixtures/eval/authoring-rubric.md"), "utf8");
    const accepted = await Promise.all(REPLAN_EXECUTABLES.map((executable) => evaluateDeterministicPolicy(executable, { config: { model: { enabled: true } } })));
    expect([...REPLAN_EXECUTABLES]).toEqual(["awk", "xargs", "find", "env", "command", "cmp"]);
    expect(accepted).toHaveLength(6);
    expect(accepted.every((result) => result.status === "manual" && result.reasonCodes.includes("manual_executable"))).toBe(true);
    expect(spec).toMatch(/accepts exactly `awk`,\s*`xargs`,\s*`find`,\s*`env`,\s*`command`,\s*and `cmp` as deterministic-manual identities/);
    expect(rubric).toContain("exactly the six owner-accepted deterministic-manual");

    const ordinary = await Promise.all(["echo hello", "cat README.md", "printf hello", "git status", "ls", "sed -n 1p README.md", "sort README.md", "true", "wc -c README.md"].map((command) => evaluateDeterministicPolicy(command, { config: { model: { enabled: true } } })));
    expect(ordinary.every((result) => !result.reasonCodes.includes("manual_executable"))).toBe(true);
  });

  test("binds REQ-011 selectors and the INV-7 offline runner exactly once", () => {
    const root = process.cwd();
    const spec = readFileSync(join(root, "SPEC.md"), "utf8");
    const traceability = readFileSync(join(root, "TRACEABILITY.md"), "utf8");
    const invariants = readFileSync(join(root, "INVARIANTS.md"), "utf8");
    const packageJson = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { scripts: { "test:offline": string } };
    expect(spec).toMatch(/immutableModelRevisionAttested` is explicitly\s+`false`/);
    expect(spec).toContain("servedVariantAttested` is explicitly `false`");
    expect(spec).toContain("not_independently_recomputable");
    expect((traceability.match(/^- Observed safety-routing selector \(100% manual\):/gm) ?? [])).toHaveLength(1);
    expect((traceability.match(/^- Mandatory mechanical-fault selector:/gm) ?? [])).toHaveLength(1);
    expect((invariants.match(/^\s*gate_test:\s*tests\/eval\/classifier-gate\.test\.ts$/gm) ?? [])).toHaveLength(1);
    expect((packageJson.scripts["test:offline"].match(/tests\/eval\/classifier-gate\.test\.ts/g) ?? [])).toHaveLength(1);
  });

  test("rejects an empty or stale repository task queue", () => {
    const report = validateTraceability(process.cwd());
    expect(report.errors).toEqual([]);
    expect(report.tasks).toEqual([
      "TASK-001",
      "TASK-002",
      "TASK-003",
      "TASK-004",
      "TASK-005",
      "TASK-006",
      "TASK-007",
      "TASK-008",
      "TASK-009",
      "TASK-010",
      "TASK-011",
    ]);
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
