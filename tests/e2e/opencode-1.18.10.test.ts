import { readFileSync, statSync } from "node:fs";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, mock, spyOn, test } from "bun:test";
import { createSmartApproveHooks, SmartApprovePlugin } from "../../src/plugin";
import { DEFAULT_CONFIG } from "../../src/config/schema";
import { createReviewerAgent, ZERO_TOOL_COUNTERS } from "../../src/reviewer/agent";
import {
  createDisposableOpenCode,
  DEFAULT_OPENCODE_BINARY,
  REQUIRED_OPENCODE_VERSION,
  requireOpenCodeVersion,
  runOpenCodeVersion,
} from "../../scripts/e2e-opencode";

const fixturePath = new URL("../fixtures/opencode/opencode.jsonc", import.meta.url).pathname;
const asked = (id: string, command: string) => ({
  type: "permission.asked",
  properties: { id, sessionID: "parent", permission: "bash", metadata: { command } },
});
const tick = (ms = 25) => new Promise<void>((resolve) => setTimeout(resolve, ms));

const waitForHTTP = async (url: string): Promise<void> => {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    try { if ((await fetch(url)).ok) return; } catch { /* server still starting */ }
    await tick(25);
  }
  throw new Error("disposable OpenCode server did not become ready");
};

const stopChild = async (child: ReturnType<typeof Bun.spawn>): Promise<void> => {
  if (child.exitCode === null) child.kill("SIGTERM");
  const exited = await Promise.race([child.exited.then(() => true), tick(5_000).then(() => false)]);
  if (exited) return;
  child.kill("SIGKILL");
  await Promise.race([child.exited, tick(2_000)]);
};

const stopProvider = async (provider: ReturnType<typeof Bun.serve>): Promise<void> => {
  // Bun's close-active promise can wait on an in-flight model stream; bound the
  // observer teardown so a provider fixture cannot hold the E2E gate hostage.
  await Promise.race([provider.stop(true), tick(2_000)]);
};

const textCompletionSSE = (): Response => {
  const chunks = [
    { delta: { role: "assistant", content: "Live" }, finish_reason: null },
    { delta: {}, finish_reason: "stop" },
  ];
  const body = chunks.map((chunk) => `data: ${JSON.stringify({ id: "live-title", object: "chat.completion.chunk", choices: [{ index: 0, ...chunk }] })}\n\n`).join("") + "data: [DONE]\n\n";
  return new Response(body, { headers: { "content-type": "text/event-stream" } });
};

const toolCallSSE = (callID = "live-awk"): Response => {
  const chunks = [
    { delta: { role: "assistant", tool_calls: [{ index: 0, id: callID, type: "function", function: { name: "bash", arguments: "" } }] }, finish_reason: null },
    { delta: { tool_calls: [{ index: 0, function: { arguments: JSON.stringify({ command: "awk" }) } }] }, finish_reason: null },
    { delta: {}, finish_reason: "tool_calls" },
  ];
  const body = chunks.map((chunk) => `data: ${JSON.stringify({ id: "live", object: "chat.completion.chunk", choices: [{ index: 0, ...chunk }] })}\n\n`).join("") + "data: [DONE]\n\n";
  return new Response(body, { headers: { "content-type": "text/event-stream" } });
};

describe("OpenCode 1.18.10 disposable integration", () => {
  test.serial("live disposable server loads production plugin and blocks before permission", async () => {
    const fixturePath = new URL("../fixtures/opencode/opencode.jsonc", import.meta.url).pathname;
    const auditDirectory = join(tmpdir(), `smart-approve-live-audit-${Date.now()}`);
    const runtimeConfig = {
      ...DEFAULT_CONFIG,
      audit: { ...DEFAULT_CONFIG.audit, enabled: true, directory: auditDirectory },
      replan: { enabled: true, maxBlocksPerTurn: 3 },
    };
    const sandbox = await createDisposableOpenCode({
      fixturePath,
      loaderSource: `import plugin from ${JSON.stringify(pathToFileURL(join(process.cwd(), "src/plugin.ts")).href)}; export default async (input, options) => plugin(input, { ...options, config: ${JSON.stringify(runtimeConfig)} });\n`,
      pluginOptions: { config: runtimeConfig },
    });
    let providerCalls = 0;
    const provider = Bun.serve({ port: 0, fetch: async (request) => {
      const body = await request.text();
      if (body.includes("title generator")) return textCompletionSSE();
      providerCalls += 1;
      return toolCallSSE(`live-awk-${providerCalls}`);
    } });
    const portReservation = Bun.serve({ port: 0, fetch: () => new Response("reserved") });
    const port = portReservation.port;
    await portReservation.stop(true);
    if (!port) throw new Error("failed to reserve OpenCode port");
    const serverURL = `http://127.0.0.1:${port}`;
    const config = {
      "$schema": "https://opencode.ai/config.json",
      model: "local/test",
      permission: { bash: "ask" },
      provider: { local: { npm: "@ai-sdk/openai-compatible", name: "Local", options: { baseURL: `http://127.0.0.1:${provider.port}/v1`, apiKey: "test" }, models: { test: { name: "test", tool_call: true, limit: { context: 32_768, output: 4_096 } } } } },
      plugin: [[join(sandbox.root, "loader.mjs"), { config: runtimeConfig }]],
    };
    const child = Bun.spawn([DEFAULT_OPENCODE_BINARY, "serve", "--port", String(port), "--hostname", "127.0.0.1"], {
      env: { ...process.env, XDG_CONFIG_HOME: sandbox.configHome, XDG_DATA_HOME: sandbox.dataHome, XDG_STATE_HOME: sandbox.stateHome, XDG_CACHE_HOME: sandbox.cacheHome },
      stdout: "ignore", stderr: process.env.STALL_CANARY_DEBUG === "1" ? "inherit" : "ignore",
    });
    try {
      await writeFile(sandbox.configPath, JSON.stringify(config), "utf8");
      await waitForHTTP(`${serverURL}/global/health`);
      const sessionResponse = await fetch(`${serverURL}/session`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ title: "live replan" }) });
      const session = await sessionResponse.json() as { id: string };
      const messageAbort = new AbortController();
      const message = fetch(`${serverURL}/session/${session.id}/message`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ model: { providerID: "local", modelID: "test" }, agent: "build", parts: [{ type: "text", text: "use a shell" }] }), signal: messageAbort.signal }).catch(() => undefined);
      let pending: unknown[] = [];
      for (let attempt = 0; attempt < 20; attempt += 1) {
        const response = await fetch(`${serverURL}/permission`);
        pending = response.ok ? await response.json() as unknown[] : [];
        if (pending.length > 0) break;
        await tick(50);
      }
      expect(pending.length).toBe(1);
      expect(providerCalls).toBeGreaterThanOrEqual(2);
      const auditPath = join(auditDirectory, "smart-approve-audit.jsonl");
      let auditText = "";
      for (let attempt = 0; attempt < 40; attempt += 1) {
        auditText = await Bun.file(auditPath).text().catch(() => "");
        if ((auditText.match(/"decision":"replan_blocked"/g) ?? []).length >= 3) break;
        await tick(25);
      }
      expect(providerCalls).toBeGreaterThanOrEqual(4);
      expect((auditText.match(/"decision":"replan_blocked"/g) ?? []).length).toBe(3);
      expect((await fetch(`${serverURL}/permission`)).ok).toBe(true);
      await fetch(`${serverURL}/session/${session.id}/abort`, { method: "POST", signal: AbortSignal.timeout(5_000) }).catch(() => undefined);
      messageAbort.abort();
      await Promise.race([message, tick(2_000)]);
    } finally {
      await stopChild(child);
      await stopProvider(provider);
      await sandbox.cleanup();
      await rm(auditDirectory, { recursive: true, force: true });
    }
  }, { timeout: 120_000 });
  test.serial("live disposable server keeps disabled and mismatched production-plugin paths native", async () => {
    for (const mode of ["disabled", "mismatched"] as const) {
      const auditDirectory = join(tmpdir(), `smart-approve-live-${mode}-${Date.now()}`);
      const runtimeConfig = {
        ...DEFAULT_CONFIG,
        audit: { ...DEFAULT_CONFIG.audit, enabled: true, directory: auditDirectory },
        replan: { enabled: mode === "disabled" ? false : true, maxBlocksPerTurn: 3 },
      };
      const healthOverride = mode === "mismatched"
        ? `, runtimeHealthFetcher: async () => ({ ok: true, json: async () => ({ version: "1.18.11" }) })`
        : "";
      const sandbox = await createDisposableOpenCode({
        fixturePath,
        loaderSource: `import plugin from ${JSON.stringify(pathToFileURL(join(process.cwd(), "src/plugin.ts")).href)}; export default async (input, options) => plugin(input, { ...options, config: ${JSON.stringify(runtimeConfig)}${healthOverride} });\n`,
        pluginOptions: { config: runtimeConfig },
      });
      let providerCalls = 0;
      const provider = Bun.serve({ port: 0, fetch: async (request) => {
        const body = await request.text();
        if (body.includes("title generator")) return textCompletionSSE();
        providerCalls += 1;
        return toolCallSSE(`${mode}-awk-${providerCalls}`);
      } });
      const portReservation = Bun.serve({ port: 0, fetch: () => new Response("reserved") });
      const port = portReservation.port;
      await portReservation.stop(true);
      if (!port) throw new Error("failed to reserve OpenCode port");
      const serverURL = `http://127.0.0.1:${port}`;
      const config = {
        "$schema": "https://opencode.ai/config.json",
        model: "local/test",
        permission: { bash: "ask" },
        provider: { local: { npm: "@ai-sdk/openai-compatible", name: "Local", options: { baseURL: `http://127.0.0.1:${provider.port}/v1`, apiKey: "test" }, models: { test: { name: "test", tool_call: true, limit: { context: 32_768, output: 4_096 } } } } },
        plugin: [[join(sandbox.root, "loader.mjs"), { config: runtimeConfig }]],
      };
      const child = Bun.spawn([DEFAULT_OPENCODE_BINARY, "serve", "--port", String(port), "--hostname", "127.0.0.1"], {
        env: { ...process.env, XDG_CONFIG_HOME: sandbox.configHome, XDG_DATA_HOME: sandbox.dataHome, XDG_STATE_HOME: sandbox.stateHome, XDG_CACHE_HOME: sandbox.cacheHome },
        stdout: "ignore", stderr: process.env.STALL_CANARY_DEBUG === "1" ? "inherit" : "ignore",
      });
      try {
        await writeFile(sandbox.configPath, JSON.stringify(config), "utf8");
        await waitForHTTP(`${serverURL}/global/health`);
        const sessionResponse = await fetch(`${serverURL}/session`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ title: `live ${mode}` }) });
        const session = await sessionResponse.json() as { id: string };
        const messageAbort = new AbortController();
        const message = fetch(`${serverURL}/session/${session.id}/message`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ model: { providerID: "local", modelID: "test" }, agent: "build", parts: [{ type: "text", text: "use a shell" }] }), signal: messageAbort.signal }).catch(() => undefined);
        let pending: unknown[] = [];
        for (let attempt = 0; attempt < 20; attempt += 1) {
          const response = await fetch(`${serverURL}/permission`);
          pending = response.ok ? await response.json() as unknown[] : [];
          if (pending.length > 0) break;
          await tick(50);
        }
        expect(pending.length, mode).toBe(1);
        expect(providerCalls, mode).toBeGreaterThanOrEqual(1);
        const auditPath = join(auditDirectory, "smart-approve-audit.jsonl");
        const auditText = await Bun.file(auditPath).text().catch(() => "");
        expect(auditText, mode).not.toContain("replan_blocked");
        await fetch(`${serverURL}/session/${session.id}/abort`, { method: "POST", signal: AbortSignal.timeout(5_000) }).catch(() => undefined);
        messageAbort.abort();
        await Promise.race([message, tick(2_000)]);
      } finally {
        await stopChild(child);
        await stopProvider(provider);
        await sandbox.cleanup();
        await rm(auditDirectory, { recursive: true, force: true });
      }
    }
  }, { timeout: 120_000 });
  test("production plugin exact-runtime replan gate blocks three calls then preserves native fallthrough", async () => {
    const fetchSpy = spyOn(globalThis, "fetch").mockImplementation((async () => new Response(JSON.stringify({ version: "1.18.10" }), { status: 200 })) as unknown as typeof fetch);
    const plugin = await SmartApprovePlugin({ client: { tui: { showToast: async () => true } }, directory: "/owned/project", serverUrl: new URL("http://127.0.0.1:4096") } as never, {
      config: { ...DEFAULT_CONFIG, replan: { enabled: true, maxBlocksPerTurn: 3 } },
      policy: async () => ({ status: "replan" as never, decision: "replan" as never, reasonCodes: ["replan" as never], parse: undefined, privacy: undefined }),
      shellCompatible: true,
    });
    try {
      await plugin["chat.message"]?.({ sessionID: "main", messageID: "user-1" }, { message: { role: "user", id: "user-1" } } as never);
      for (let index = 0; index < 3; index += 1) {
        await expect(plugin["tool.execute.before"]?.({ tool: "bash", sessionID: "main", callID: `call-${index}` }, { args: { command: "awk" } })).rejects.toThrow();
      }
      await expect(plugin["tool.execute.before"]?.({ tool: "bash", sessionID: "main", callID: "call-4" }, { args: { command: "awk" } })).resolves.toBeUndefined();
    } finally {
      await plugin.dispose?.();
      fetchSpy.mockRestore();
    }
  });

  test("production plugin leaves replan hooks inactive for disabled and mismatched runtime", async () => {
    const fetchSpy = spyOn(globalThis, "fetch").mockImplementation((async () => new Response(JSON.stringify({ version: "1.18.11" }), { status: 200 })) as unknown as typeof fetch);
    const input = { client: { tui: { showToast: async () => true } }, directory: "/owned/project", serverUrl: new URL("http://127.0.0.1:4096") } as never;
    const disabled = await SmartApprovePlugin(input, { config: { ...DEFAULT_CONFIG, replan: { enabled: false, maxBlocksPerTurn: 3 } } });
    const mismatch = await SmartApprovePlugin(input, { config: { ...DEFAULT_CONFIG, replan: { enabled: true, maxBlocksPerTurn: 3 } } });
    expect(disabled["tool.execute.before"]).toBeUndefined();
    expect(mismatch["tool.execute.before"]).toBeUndefined();
    await disabled.dispose?.();
    await mismatch.dispose?.();
    fetchSpy.mockRestore();
  });
  test("smoke uses the installed binary and isolated XDG config/data/cache", async () => {
    const sandbox = await createDisposableOpenCode({ fixturePath });
    try {
      const result = runOpenCodeVersion(sandbox);
      expect(result.exitCode).toBe(0);
      expect(result.stdout.trim()).toBe("1.18.10");
      expect(readFileSync(sandbox.configPath, "utf8")).toContain('"plugin"');
      expect(readFileSync(sandbox.configPath, "utf8")).toContain('"bash": "ask"');
      expect(statSync(sandbox.cacheHome).isDirectory()).toBe(true);
      const sessionMarker = `${sandbox.dataHome}/session-marker`;
      await Bun.write(sessionMarker, "pending");
      await sandbox.removeLoader();
      expect(readFileSync(sandbox.configPath, "utf8")).not.toContain('"plugin"');
      expect(readFileSync(sessionMarker, "utf8")).toBe("pending");
      expect(statSync(sandbox.dataHome).isDirectory()).toBe(true);
    } finally {
      await sandbox.cleanup();
    }
  });

  test("version seam defaults locally and rejects mismatched, malformed, empty, and failed overrides", async () => {
    const sandbox = await createDisposableOpenCode({ fixturePath });
    const fakeBin = await mkdtemp(join(tmpdir(), "smart-approve-fake-opencode-"));
    try {
      const mismatchedBinary = join(fakeBin, "opencode");
      await writeFile(mismatchedBinary, "#!/bin/sh\nprintf '1.18.15\\n'\n", "utf8");
      await chmod(mismatchedBinary, 0o755);

      const exact = requireOpenCodeVersion(sandbox, { ...process.env, OPENCODE_BIN: undefined, PATH: fakeBin });
      expect(exact.stdout.trim()).toBe(REQUIRED_OPENCODE_VERSION);

      const mismatchedOverride = { ...process.env, OPENCODE_BIN: mismatchedBinary, PATH: fakeBin };
      expect(() => requireOpenCodeVersion(sandbox, mismatchedOverride)).toThrow("OpenCode 1.18.10 is required");

      for (const [name, body] of [
        ["malformed", "printf 'not-a-version\\n'\n"],
        ["empty", "exit 0\n"],
        ["failed", "exit 7\n"],
      ] as const) {
        const binary = join(fakeBin, name);
        await writeFile(binary, `#!/bin/sh\n${body}`, "utf8");
        await chmod(binary, 0o755);
        expect(() => requireOpenCodeVersion(sandbox, { ...process.env, OPENCODE_BIN: binary })).toThrow(
          "OpenCode 1.18.10 is required",
        );
      }
    } finally {
      await rm(fakeBin, { recursive: true, force: true });
      await sandbox.cleanup();
    }
  });

  test("version seam rejects missing and non-executable explicit overrides before spawning", async () => {
    const sandbox = await createDisposableOpenCode({ fixturePath });
    const fakeBin = await mkdtemp(join(tmpdir(), "smart-approve-non-executable-opencode-"));
    const nonExecutableBinary = join(fakeBin, "opencode");
    const spawn = spyOn(Bun, "spawnSync");
    try {
      await writeFile(nonExecutableBinary, "#!/bin/sh\nprintf '1.18.10\\n'\n", "utf8");
      await chmod(nonExecutableBinary, 0o644);

      expect(() => requireOpenCodeVersion(sandbox, { ...process.env, OPENCODE_BIN: join(fakeBin, "missing") })).toThrow(
        "OpenCode 1.18.10 is required",
      );
      expect(() => requireOpenCodeVersion(sandbox, { ...process.env, OPENCODE_BIN: fakeBin })).toThrow(
        "OpenCode 1.18.10 is required",
      );
      expect(() => requireOpenCodeVersion(sandbox, { ...process.env, OPENCODE_BIN: nonExecutableBinary })).toThrow(
        "OpenCode 1.18.10 is required",
      );
      expect(spawn).not.toHaveBeenCalled();
    } finally {
      spawn.mockRestore();
      await rm(fakeBin, { recursive: true, force: true });
      await sandbox.cleanup();
    }
  });

  test("plugin-load failure leaves the native shell request pending", async () => {
    const sandbox = await createDisposableOpenCode({ fixturePath });
    const pending = new Set(["load-failure"]);
    const hooks = createSmartApproveHooks({ approve: mock(async (id: string) => { pending.delete(id); }) });
    try {
      // The disposable loader throws before hooks can register. The native
      // request therefore remains pending and has no approval callback.
      expect(readFileSync(sandbox.configPath, "utf8")).toContain("loader.mjs");
      await hooks.event({ event: asked("load-failure", "printf native-prompt") });
      await tick();
      expect(pending.has("load-failure")).toBe(true);
    } finally {
      await hooks.dispose();
      await sandbox.cleanup();
    }
  });

  test("model approval remains disabled even for a matching allow result", async () => {
    const pending = new Set(["model-allow"]);
    const promptBodies: unknown[] = [];
    const reviewer = createReviewerAgent({
      client: {
        session: {
          create: async () => ({ data: { id: "review-model-allow" } }),
          prompt: async (input: unknown) => { promptBodies.push(input); return { data: { decision: "allow", reasonCodes: ["safe"] } }; },
          abort: async () => undefined,
          delete: async () => undefined,
        },
      },
    });
    const hooks = createSmartApproveHooks({ reviewer, approve: async (id) => { pending.delete(id); } });
    try {
      await hooks.event({ event: asked("model-allow", "printf safe") });
      await tick();
      expect(promptBodies).toHaveLength(0);
      expect(pending.has("model-allow")).toBe(true);
      expect(hooks.state("model-allow")).toBe("manual");
    } finally {
      await hooks.dispose();
    }
  });

  test("unsafe and disabled-model requests preserve the pending prompt", async () => {
    const pending = new Set(["unsafe", "timeout", "error"]);
    const review = mock(async () => { throw new Error("provider must not be called"); });
    const hooks = createSmartApproveHooks({
      reviewer: { review },
      approve: async (id) => { pending.delete(id); },
    });
    try {
      await hooks.event({ event: asked("unsafe", "rm -rf /tmp/not-safe") });
      await hooks.event({ event: asked("timeout", "printf waits") });
      await hooks.event({ event: asked("error", "printf fails") });
      await tick(40);
      expect(pending.has("unsafe")).toBe(true);
      expect(pending.has("timeout")).toBe(true);
      expect(pending.has("error")).toBe(true);
      expect(hooks.state("unsafe")).toBe("manual");
      expect(hooks.state("timeout")).toBe("manual");
      expect(hooks.state("error")).toBe("manual");
      expect(review).not.toHaveBeenCalled();
    } finally {
      await hooks.dispose();
    }
  });

  test("disabled model does not attempt a user-first reply race", async () => {
    const reply = mock(async () => { throw new Error("permission not found"); });
    const hooks = createSmartApproveHooks({
      reviewer: { review: async () => ({ decision: "allow" as const, requestID: "race", sessionID: "race-review", toolCounters: ZERO_TOOL_COUNTERS }) },
      approve: reply,
    });
    try {
      await hooks.event({ event: asked("race", "printf race") });
      await tick();
      expect(reply).not.toHaveBeenCalled();
      expect(hooks.state("race")).toBe("manual");
    } finally {
      await hooks.dispose();
    }
  });
});
