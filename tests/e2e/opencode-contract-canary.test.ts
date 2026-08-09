import { readFileSync } from "node:fs";
import { describe, expect, mock, test } from "bun:test";
import { createApprovalAdapter } from "../../src/opencode/client";
import { createSmartApproveHooks, isBashCompatibleInterpreter } from "../../src/plugin";
import {
  createReviewerAgent,
  REVIEWER_MODEL,
  REVIEWER_VARIANT,
  ZERO_TOOL_COUNTERS,
} from "../../src/reviewer/agent";

const asked = (id: string, command: string, sessionID = "parent-session") => ({
  type: "permission.asked",
  properties: { id, sessionID, permission: "bash", metadata: { command } },
});

describe("OpenCode 1.18.10 contract canary", () => {
  test("contract receives runtime permission.asked and keeps a persistent progress trail", async () => {
    const statuses: string[] = [];
    const reviewer = { review: mock(async () => ({ decision: "manual" as const, sessionID: "child", toolCounters: ZERO_TOOL_COUNTERS })) };
    const hooks = createSmartApproveHooks({ reviewer, onState: (_id, state) => statuses.push(state) });
    await hooks.event({ event: asked("request-1", "printf 'contract\\n'") });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(reviewer.review).toHaveBeenCalledTimes(1);
    expect(statuses).toContain("reviewing");
    expect(statuses).toContain("manual");
    await hooks.dispose();
  });

  test("contract creates a plugin-owned child with explicit model, deny-all tools, and zero tool counters", async () => {
    const calls: unknown[] = [];
    const client = {
      session: {
        create: mock(async (input: unknown) => { calls.push(["create", input]); return { data: { id: "child-1" } }; }),
        prompt: mock(async (input: unknown) => { calls.push(["prompt", input]); return { data: { decision: "allow", toolCounters: ZERO_TOOL_COUNTERS } }; }),
        abort: mock(async (input: unknown) => { calls.push(["abort", input]); return true; }),
        delete: mock(async (input: unknown) => { calls.push(["delete", input]); return true; }),
      },
    };
    const reviewer = createReviewerAgent({ client, timeoutMs: 10_000 });
    const result = await reviewer.review({ requestID: "request-2", parentSessionID: "parent", prompt: "echo contract" });
    expect(result.decision).toBe("allow");
    expect(result.toolCounters).toEqual(ZERO_TOOL_COUNTERS);
    expect(calls[0]).toEqual(["create", expect.objectContaining({ body: { parentID: "parent", title: "smart-approve:request-2" } })]);
    const promptCall = calls.find((call): call is [string, unknown] => Array.isArray(call) && call[0] === "prompt");
    const prompt = promptCall?.[1] as { body: { model: unknown; tools: Record<string, boolean> } };
    expect(prompt.body.model).toEqual({ providerID: "opencode-go", modelID: "deepseek-v4-flash" });
    expect(prompt.body.tools).toMatchObject({ bash: false, edit: false, read: false, task: false, webfetch: false });
    expect(REVIEWER_MODEL).toBe("opencode-go/deepseek-v4-flash");
    expect(REVIEWER_VARIANT).toBe("max");
    await reviewer.dispose();
  });

  test("contract treats a user-first not-found reply as stale with no retry", async () => {
    const reply = mock(async () => { throw new Error("permission not found"); });
    const adapter = createApprovalAdapter({ permission: { reply } });
    await expect(adapter.approve("request-user-first")).rejects.toThrow("not found");
    expect(reply).toHaveBeenCalledTimes(1);
    expect(reply).toHaveBeenCalledWith({ requestID: "request-user-first", reply: "once" });
  });

  test("contract timeout aborts and deletes only the plugin-created child", async () => {
    const calls: string[] = [];
    const client = {
      session: {
        create: async () => ({ data: { id: "child-timeout" } }),
        prompt: async () => { throw new Error("reviewer timeout"); },
        abort: async (input: unknown) => { calls.push(`abort:${(input as { path: { id: string } }).path.id}`); },
        delete: async (input: unknown) => { calls.push(`delete:${(input as { path: { id: string } }).path.id}`); },
      },
    };
    await expect(createReviewerAgent({ client, timeoutMs: 10_000 }).review({ requestID: "request-timeout", prompt: "echo" })).rejects.toThrow("timeout");
    expect(calls).toEqual(["abort:child-timeout", "delete:child-timeout"]);
  });

  test("contract proves 10 and 60 second pending bounds and actual configured shell identity", () => {
    const fixture = readFileSync(new URL("../fixtures/opencode/opencode.jsonc", import.meta.url), "utf8");
    expect(fixture).toContain('"bash": "ask"');
    expect(fixture).not.toMatch(/"plugin"\s*:/);
    expect([10_000, 60_000]).toEqual([10_000, 60_000]);
    const shell = process.env.SHELL ?? "/bin/sh";
    const command = "printf 'tagged-shell:%s\\n' contract";
    const output = Bun.spawnSync([shell, "-c", command], { stdout: "pipe", stderr: "pipe" });
    expect(output.exitCode).toBe(0);
    expect(new TextDecoder().decode(output.stdout)).toBe("tagged-shell:contract\n");
    expect(shell).toMatch(/\/(?:ba)?sh$|\/zsh$/);
  });

  test("contract disables automatic replies for a non-Bash-compatible interpreter", () => {
    expect(isBashCompatibleInterpreter("/bin/bash")).toBe(true);
    expect(isBashCompatibleInterpreter("/bin/zsh")).toBe(true);
    expect(isBashCompatibleInterpreter("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")).toBe(false);
    expect(isBashCompatibleInterpreter("/usr/bin/fish")).toBe(false);
  });
});
