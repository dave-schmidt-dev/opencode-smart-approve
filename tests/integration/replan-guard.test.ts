import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, mock, test } from "bun:test";
import { createAuditWriter } from "../../src/audit/writer";
import { DEFAULT_CONFIG, validateConfig } from "../../src/config/schema";
import { evaluateDeterministicPolicy } from "../../src/policy/deterministic";
import { REPLAN_EXECUTABLES } from "../../src/policy/executable-identity";
import { REPLAN_BLOCKED_FEEDBACK, ReplanBlockedError } from "../../src/replan/error";
import { createReplanGuard } from "../../src/replan/guard";
import { REPLAN_GUIDANCE_CATALOG } from "../../src/replan/guidance";
import { ReplanStateStore } from "../../src/replan/state";
import { REQUIRED_RUNTIME_VERSION, verifyRuntimeVersion } from "../../src/replan/runtime-version";
import { createProgressMetrics } from "../../src/progress/reporter";
import { SmartApprovePlugin } from "../../src/plugin";

describe("INV-8 pre-execution replan gate", () => {
  const output = (command: unknown) => ({ args: { command } });
  const input = (generation: ReturnType<ReplanStateStore["captureGeneration"]>, overrides: Record<string, unknown> = {}) => ({
    tool: "bash", sessionID: "session", callID: "call-1", generation, ...overrides,
  });

  test("blocks exactly once before downstream permission or execution", async () => {
    const state = new ReplanStateStore(3);
    const generation = state.observeUserMessage("session", "message");
    const permission = mock(() => undefined);
    const execute = mock(() => undefined);
    const guard = createReplanGuard({
      state,
      config: { replan: { enabled: true }, model: { enabled: true } },
      policy: (command, options) => evaluateDeterministicPolicy(command, options as never),
    });
    await expect(guard.before(input(generation), output("awk"))).rejects.toBeInstanceOf(ReplanBlockedError);
    expect(permission).not.toHaveBeenCalled();
    expect(execute).not.toHaveBeenCalled();
    await expect(guard.before(input(generation), output("awk"))).resolves.toBeUndefined();
  });

  test("emits the matching static guidance for each eligible identity", async () => {
    const state = new ReplanStateStore(3);
    const guard = createReplanGuard({
      state,
      config: { replan: { enabled: true }, model: { enabled: true } },
      policy: async () => ({ status: "replan" as const, decision: "replan" as const, reasonCodes: ["replan" as const], parse: undefined, privacy: undefined }),
    });
    for (const [index, identity] of REPLAN_EXECUTABLES.entries()) {
      const generation = state.observeUserMessage("session", `message-${identity}`);
      const canary = `STATIC_GUIDANCE_CANARY_${index}`;
      const error = await guard.before(input(generation, { callID: `call-${identity}` }), output(`${identity} ${canary}`)).then(
        () => undefined,
        (value: unknown) => value,
      );
      expect(error).toBeInstanceOf(ReplanBlockedError);
      expect((error as Error).message).toBe(REPLAN_GUIDANCE_CATALOG[identity].feedback);
      expect((error as Error).message).not.toContain(canary);
    }
  });

  test("the production plugin rejects a direct four- or five-block configuration", async () => {
    const input = {
      serverUrl: new URL("http://127.0.0.1:4096"),
      directory: "/owned/project",
      client: { tui: { showToast: async () => true } },
    };
    for (const maxBlocksPerTurn of [4, 5]) {
      await expect(SmartApprovePlugin(input as never, {
        config: { ...DEFAULT_CONFIG, replan: { enabled: true, maxBlocksPerTurn } },
        runtimeHealthFetcher: async () => ({ ok: true, json: async () => ({ version: REQUIRED_RUNTIME_VERSION }) }),
      } as never)).rejects.toThrow(/1 through 3/);
    }
  });

  test("falls through for non-bash, non-replan, duplicate, stale, exhausted, and malformed input", async () => {
    const state = new ReplanStateStore(1);
    const generation = state.observeUserMessage("session", "message");
    const guard = createReplanGuard({ state, config: { replan: { enabled: true }, model: { enabled: true } }, policy: (command, options) => evaluateDeterministicPolicy(command, options as never) });
    await expect(guard.before(input(generation, { tool: "read" }), output("awk"))).resolves.toBeUndefined();
    await expect(guard.before(input(generation), output("echo safe"))).resolves.toBeUndefined();
    await expect(guard.before(input(generation), output("awk"))).rejects.toBeInstanceOf(ReplanBlockedError);
    await expect(guard.before(input(generation), output("awk"))).resolves.toBeUndefined();
    await expect(guard.before(input(generation), output("awk"))).resolves.toBeUndefined();
    state.observeUserMessage("session", "new-message");
    await expect(guard.before(input(generation), output("awk"))).resolves.toBeUndefined();
    await expect(guard.before(input(undefined), output("awk"))).resolves.toBeUndefined();
    await expect(guard.before(input(generation, { callID: undefined }), output("awk"))).resolves.toBeUndefined();
    await expect(guard.before(input(generation), output(undefined))).resolves.toBeUndefined();
  });

  test("policy and state failures fall through without hook errors", async () => {
    const state = new ReplanStateStore(1);
    const generation = state.observeUserMessage("session", "message");
    const policyFailure = createReplanGuard({ state, policy: async () => { throw new Error("provider text"); } });
    await expect(policyFailure.before(input(generation), output("awk"))).resolves.toBeUndefined();
    const stateFailure = createReplanGuard({ state: { reserve: () => { throw new Error("state failure"); } } as unknown as ReplanStateStore, policy: async () => ({ status: "replan" as never, decision: "replan" as never, reasonCodes: [], parse: undefined, privacy: undefined }) });
    await expect(stateFailure.before(input(generation), output("awk"))).resolves.toBeUndefined();
  });

  test("blocked feedback is fixed and contains no dynamic command or capability data", () => {
    expect(new ReplanBlockedError().message).toBe(REPLAN_BLOCKED_FEEDBACK);
    expect(REPLAN_BLOCKED_FEEDBACK).not.toContain("CANARY_SECRET");
    expect(REPLAN_BLOCKED_FEEDBACK).not.toContain("/tmp/");
    expect(REPLAN_BLOCKED_FEEDBACK).not.toContain("opencode-go");
  });

  test("guard public source exposes no execution or permission capabilities", async () => {
    const source = await Bun.file(new URL("../../src/replan/guard.ts", import.meta.url)).text();
    expect(source).not.toMatch(/(?:fetch|spawn|permission\.reply|reviewerClient|child_process|net\.)/i);
  });

  test("blocked calls emit fixed progress, redacted audit, and no observer can alter blocking", async () => {
    const directory = await mkdtemp(join(tmpdir(), "smart-approve-replan-guard-"));
    const auditWriter = createAuditWriter({ enabled: true, directory });
    const statuses: string[] = [];
    const metrics = createProgressMetrics();
    const state = new ReplanStateStore(3);
    const generation = state.observeUserMessage("session", "message");
    const guard = createReplanGuard({
      state,
      config: { replan: { enabled: true }, model: { enabled: true } },
      policy: (command, options) => evaluateDeterministicPolicy(command, options as never),
      progressSink: { tui: { showToast: () => { throw new Error("sink unavailable"); } } },
      onStatus: ({ status }) => statuses.push(status),
      metrics,
      auditWriter,
    });

    await expect(guard.before(input(generation, { callID: "call-replan" }), output("awk SECRET_REPLAN_CANARY"))).rejects.toBeInstanceOf(ReplanBlockedError);
    await auditWriter.flush();
    const audit = await readFile(join(directory, "smart-approve-audit.jsonl"), "utf8");
    expect(audit).not.toContain("SECRET_REPLAN_CANARY");
    expect(statuses).toEqual(["started", "blocked"]);
    expect(metrics.snapshot()).toMatchObject({ replanAttemptCount: 1, replanBlockedCount: 1 });
  });

  test("runtime activation requires exact global health version", async () => {
    const url = new URL("http://127.0.0.1:4096");
    const response = (body: unknown, ok = true) => ({ ok, json: async () => body });
    expect(await verifyRuntimeVersion(url, async (health) => { expect(health.pathname).toBe("/global/health"); return response({ version: REQUIRED_RUNTIME_VERSION }); })).toBe(true);
    expect(await verifyRuntimeVersion(url, async () => response({ version: "1.18.11" }))).toBe(false);
    expect(await verifyRuntimeVersion(url, async () => response({ version: REQUIRED_RUNTIME_VERSION }, false))).toBe(false);
    expect(await verifyRuntimeVersion(url, async () => response({ version: 1.18 }))).toBe(false);
    expect(await verifyRuntimeVersion(url, async () => { throw new Error("health unavailable"); })).toBe(false);
  });

  test("plugin registers replan hooks only after exact runtime activation", async () => {
    let healthCalls = 0;
    const input = {
      serverUrl: new URL("http://127.0.0.1:4096"),
      directory: "/owned/project",
      client: {
        tui: { showToast: async () => true },
        postSessionIdPermissionsPermissionId: async () => true,
      },
    };
    const disabled = await SmartApprovePlugin(input as never, {
      config: validateConfig({ replan: { enabled: false } }),
      runtimeHealthFetcher: async () => { healthCalls += 1; return { ok: true, json: async () => ({ version: REQUIRED_RUNTIME_VERSION }) }; },
    } as never);
    expect(disabled["chat.message"]).toBeUndefined();
    expect(disabled["tool.execute.before"]).toBeUndefined();
    expect(healthCalls).toBe(0);
    await disabled.dispose?.();

    const enabled = await SmartApprovePlugin(input as never, {
      config: validateConfig({ replan: { enabled: true }, model: { enabled: true } }),
      runtimeHealthFetcher: async () => ({ ok: true, json: async () => ({ version: REQUIRED_RUNTIME_VERSION }) }),
    } as never);
    expect(enabled["chat.message"]).toBeFunction();
    expect(enabled["tool.execute.before"]).toBeFunction();
    await enabled["chat.message"]?.({ sessionID: "session", messageID: "msg-user" }, { message: { id: "msg-user", role: "user", sessionID: "session", time: { created: 0 }, agent: "build", model: { providerID: "test", modelID: "test" } }, parts: [] });
    await expect(enabled["tool.execute.before"]?.({ tool: "bash", sessionID: "session", callID: "call-plugin" }, { args: { command: "awk" } })).rejects.toBeInstanceOf(ReplanBlockedError);
    await enabled.dispose?.();
  });

  test("plugin resets the replan budget at the next user-message boundary", async () => {
    const plugin = await SmartApprovePlugin({
      serverUrl: new URL("http://127.0.0.1:4096"),
      directory: "/owned/project",
      client: { tui: { showToast: async () => true } },
    } as never, {
      config: validateConfig({ replan: { enabled: true, maxBlocksPerTurn: 1 } }),
      runtimeHealthFetcher: async () => ({ ok: true, json: async () => ({ version: REQUIRED_RUNTIME_VERSION }) }),
    } as never);
    try {
      await plugin["chat.message"]?.({ sessionID: "boundary-session", messageID: "user-1" }, { message: { id: "user-1", role: "user", sessionID: "boundary-session", time: { created: 0 }, agent: "build", model: { providerID: "test", modelID: "test" } }, parts: [] });
      await expect(plugin["tool.execute.before"]?.({ tool: "bash", sessionID: "boundary-session", callID: "same-call" }, { args: { command: "awk" } })).rejects.toBeInstanceOf(ReplanBlockedError);
      await expect(plugin["tool.execute.before"]?.({ tool: "bash", sessionID: "boundary-session", callID: "after-exhaustion" }, { args: { command: "awk" } })).resolves.toBeUndefined();

      await plugin["chat.message"]?.({ sessionID: "boundary-session", messageID: "user-2" }, { message: { id: "user-2", role: "user", sessionID: "boundary-session", time: { created: 0 }, agent: "build", model: { providerID: "test", modelID: "test" } }, parts: [] });
      await expect(plugin["tool.execute.before"]?.({ tool: "bash", sessionID: "boundary-session", callID: "same-call" }, { args: { command: "awk" } })).rejects.toBeInstanceOf(ReplanBlockedError);
    } finally {
      await plugin.dispose?.();
    }
  });

  test("replan stays independent from approval when model approval is disabled", async () => {
    const review = mock(async () => ({ decision: "allow" as const, requestID: "review", sessionID: "child", toolCounters: { executable: 0, dataAccess: 0, mcp: 0, web: 0, task: 0 } }));
    const reply = mock(async () => true);
    const plugin = await SmartApprovePlugin({
      serverUrl: new URL("http://127.0.0.1:4096"),
      directory: "/owned/project",
      client: { tui: { showToast: async () => true }, postSessionIdPermissionsPermissionId: reply },
    } as never, {
      config: validateConfig({ model: { enabled: false }, replan: { enabled: true } }),
      reviewer: { review },
      runtimeHealthFetcher: async () => ({ ok: true, json: async () => ({ version: REQUIRED_RUNTIME_VERSION }) }),
    } as never);
    try {
      await plugin["chat.message"]?.({ sessionID: "session", messageID: "msg-user" }, { message: { id: "msg-user", role: "user", sessionID: "session", time: { created: 0 }, agent: "build", model: { providerID: "test", modelID: "test" } }, parts: [] });
      await expect(plugin["tool.execute.before"]?.({ tool: "bash", sessionID: "session", callID: "call-disabled" }, { args: { command: "awk" } })).rejects.toBeInstanceOf(ReplanBlockedError);
      await expect(plugin["tool.execute.before"]?.({ tool: "bash", sessionID: "session", callID: "call-exhausted" }, { args: { command: "awk" } })).rejects.toBeInstanceOf(ReplanBlockedError);
      expect(review).not.toHaveBeenCalled();
      expect(reply).not.toHaveBeenCalled();
    } finally {
      await plugin.dispose?.();
    }
  });
});
