import { existsSync, readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { COMPACT_CATALOG_FEEDBACK, CONTROL_FEEDBACK, FEEDBACK_VARIANT_HASHES, HISTORICAL_BARE_MICROPLAN_FEEDBACK, runTrial, summarizeScenarioMessages, validateTrialReceipt } from "../../scripts/deny-replan-usefulness-trial";

describe("deny/replan usefulness trial harness", () => {
  test("the A/B control text stays the historical one-line feedback", () => {
    expect(CONTROL_FEEDBACK).toBe("SMART_APPROVE_REPLAN: blocked shell approach; use native tools or a different command");
  });

  test("test catalog hash derives from the current production catalog", () => {
    expect(FEEDBACK_VARIANT_HASHES.catalog).toMatch(/^[a-f0-9]{64}$/);
    expect(FEEDBACK_VARIANT_HASHES.catalog).not.toBe(FEEDBACK_VARIANT_HASHES.control);
  });

  test("historical bare micro-plan baseline is explicit and separate from production treatment", () => {
    expect(Object.keys(HISTORICAL_BARE_MICROPLAN_FEEDBACK).sort()).toEqual(["awk", "cmp", "command", "env", "find", "xargs"]);
    expect(FEEDBACK_VARIANT_HASHES.historical_bare).not.toBe(FEEDBACK_VARIANT_HASHES.catalog);
  });

  test("compact catalog candidate is six-entry, directive-complete, and distinct", () => {
    expect(Object.keys(COMPACT_CATALOG_FEEDBACK).sort()).toEqual(["awk", "cmp", "command", "env", "find", "xargs"]);
    for (const feedback of Object.values(COMPACT_CATALOG_FEEDBACK)) expect(feedback).toContain("Your next action MUST be a native tool call, not prose");
    expect(FEEDBACK_VARIANT_HASHES.compact_catalog).not.toBe(FEEDBACK_VARIANT_HASHES.catalog);
  });

  test("fake provider path writes a bounded seven-scenario receipt", async () => {
    const root = await mkdtemp(join(tmpdir(), "deny-replan-trial-test-"));
    const output = join(root, "receipt.json");
    try {
      const receipt = await runTrial({ fake: true, output });
      expect(receipt.scenario_count).toBe(7);
      expect(receipt.terminal_outcome_count).toBe(7);
      expect(receipt.scenarios.filter((scenario) => scenario.kind === "eligible_identity")).toHaveLength(6);
      expect(receipt.scenarios.filter((scenario) => scenario.kind === "stubborn_exhaustion")).toHaveLength(1);
      expect(receipt.global_config_before_hash).toBe(receipt.global_config_after_hash);
      expect(receipt.owner_opt_in).toBe(false);
      expect(receipt.model_approval_qualified).toBe(false);
      expect(receipt.scenarios.every((scenario) => scenario.bash_call_count >= 1)).toBe(true);
      expect(receipt.scenarios.filter((scenario) => scenario.target_repeated_after_first)).toHaveLength(1);
      expect(receipt.scenarios.filter((scenario) => scenario.first_bash_matches_expected)).toHaveLength(7);
      expect(receipt.scenarios.filter((scenario) => scenario.first_bash_pipeline)).toHaveLength(2);
      expect(receipt.scenarios.filter((scenario) => scenario.replan_block_observed)).toHaveLength(7);
      expect(validateTrialReceipt(JSON.parse(readFileSync(output, "utf8")))).toEqual(receipt);
      expect(readFileSync(output, "utf8")).not.toMatch(/"(?:command|prompt|provider|environment|credential|secret)"\s*:/i);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("fake receipt records the selected feedback variant hash", async () => {
    const root = await mkdtemp(join(tmpdir(), "deny-replan-trial-hash-test-"));
    try {
      const receipt = await runTrial({ fake: true, feedbackArm: "treatment", output: join(root, "receipt.json") });
      expect(receipt.feedback_variant_hash).toBe(FEEDBACK_VARIANT_HASHES.catalog);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("summarizes first Bash identity and pipeline without returning raw command data", () => {
    const telemetry = summarizeScenarioMessages([
      { type: "tool", tool: "bash", state: { input: { command: "awk '{print $1}' input.txt | cmp - output.txt" } } },
      { type: "tool", tool: "read", state: { input: { path: "README.md" } } },
      { type: "tool", tool: "grep", state: { input: { pattern: "safe" } } },
    ], "awk");
    expect(telemetry).toEqual({
      bash_call_count: 1,
      bash_target_call_count: 1,
      target_repeated_after_first: false,
      native_tool_call_count: 2,
      first_bash_identity: "awk",
      first_bash_pipeline: true,
      first_bash_matches_expected: true,
      first_tool_after_target: "read",
    });
    expect(JSON.stringify(telemetry)).not.toContain("awk '{print");
  });

  test("missing or non-eligible first Bash identity is explicit and fails the expected-match flag", () => {
    expect(summarizeScenarioMessages([{ type: "tool", tool: "bash", state: { input: {} } }], "awk")).toEqual({
      bash_call_count: 1,
      bash_target_call_count: 0,
      target_repeated_after_first: false,
      native_tool_call_count: 0,
      first_bash_identity: "none",
      first_bash_pipeline: false,
      first_bash_matches_expected: false,
      first_tool_after_target: "none",
    });
    expect(summarizeScenarioMessages([{ type: "tool", tool: "bash", args: { command: "printf safe" } }], "awk")).toEqual({
      bash_call_count: 1,
      bash_target_call_count: 0,
      target_repeated_after_first: false,
      native_tool_call_count: 0,
      first_bash_identity: "other",
      first_bash_pipeline: false,
      first_bash_matches_expected: false,
      first_tool_after_target: "none",
    });
  });

  test("reports immediate native, Bash, or absent sequencing after the first target", () => {
    expect(summarizeScenarioMessages([
      { type: "tool", tool: "bash", state: { input: { command: "awk '{print 1}' file" } } },
      { type: "tool", tool: "read" },
    ], "awk").first_tool_after_target).toBe("read");
    expect(summarizeScenarioMessages([
      { type: "tool", tool: "bash", state: { input: { command: "awk '{print 1}' file" } } },
      { type: "tool", tool: "bash", state: { input: { command: "awk '{print 2}' file" } } },
    ], "awk").first_tool_after_target).toBe("bash");
    expect(summarizeScenarioMessages([
      { type: "tool", tool: "bash", state: { input: { command: "awk '{print 1}' file" } } },
    ], "awk").first_tool_after_target).toBe("none");
  });

  test("fake mode requires an explicit output and refuses a collision", async () => {
    const root = await mkdtemp(join(tmpdir(), "deny-replan-trial-collision-"));
    const output = join(root, "receipt.json");
    try {
      await expect(runTrial({ fake: true })).rejects.toThrow("explicit --output");
      await runTrial({ fake: true, output });
      await expect(runTrial({ fake: true, output })).rejects.toThrow("receipt already exists");
      expect(existsSync(output)).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("real mode fails closed without explicit confirmation", async () => {
    const result = Bun.spawnSync(["bun", "run", "scripts/deny-replan-usefulness-trial.ts"], { cwd: process.cwd(), stdout: "pipe", stderr: "pipe" });
    expect(result.exitCode).not.toBe(0);
    expect(new TextDecoder().decode(result.stderr)).toContain("--confirm");
  });

  test("malformed options fail before a runtime starts", async () => {
    const result = Bun.spawnSync(["bun", "run", "scripts/deny-replan-usefulness-trial.ts", "--definitely-not-an-option"], { cwd: process.cwd(), stdout: "pipe", stderr: "pipe" });
    expect(result.exitCode).not.toBe(0);
    expect(new TextDecoder().decode(result.stderr)).toContain("unknown option");
  });
});
