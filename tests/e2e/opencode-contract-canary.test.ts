import { readFileSync } from "node:fs";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, mock, test } from "bun:test";
import { createApprovalAdapter } from "../../src/opencode/client";
import { DEFAULT_CONFIG } from "../../src/config/schema";
import { configuredShellCompatible, createSmartApproveHooks, isBashCompatibleInterpreter } from "../../src/plugin";
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

const waitFor = async (predicate: () => boolean, timeoutMs = 10_000): Promise<void> => {
  const deadline = Date.now() + timeoutMs;
  while (!predicate() && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 10));
  if (!predicate()) throw new Error(`condition not met within ${timeoutMs}ms`);
};

const withDeadline = async <T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> => {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(message)), timeoutMs); }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
};

const waitForServer = async (baseURL: string, timeoutMs = 10_000): Promise<void> => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseURL}/session`);
      if (response.ok) return;
    } catch { /* the disposable server is still starting */ }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`OpenCode server did not start within ${timeoutMs}ms`);
};

interface RuntimePermissionAsked {
  readonly type: "permission.asked";
  readonly properties: {
    readonly id: string;
    readonly sessionID: string;
    readonly permission: string;
    readonly metadata: { readonly command?: string };
  };
}

const readRuntimePermissionAsked = async (baseURL: string, signal: AbortSignal): Promise<RuntimePermissionAsked> => {
  const response = await fetch(`${baseURL}/global/event`, { signal });
  if (!response.ok || !response.body) throw new Error(`event stream failed: ${response.status}`);
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    while (true) {
      const { done, value } = await withDeadline(reader.read(), 15_000, "permission.asked event deadline exceeded");
      if (done) throw new Error("event stream ended before permission.asked");
      buffer += decoder.decode(value, { stream: true });
      let boundary = buffer.indexOf("\n\n");
      while (boundary >= 0) {
        const frame = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        const data = frame.split("\n").filter((line) => line.startsWith("data:")).map((line) => line.slice(5).trim()).join("\n");
        if (data && data !== "[DONE]") {
          const envelope = JSON.parse(data) as { payload?: unknown };
          const event = (envelope.payload ?? envelope) as Partial<RuntimePermissionAsked>;
          if (event.type === "permission.asked") return event as RuntimePermissionAsked;
        }
        boundary = buffer.indexOf("\n\n");
      }
    }
  } finally {
    await withDeadline(reader.cancel().catch(() => undefined), 1_000, "event reader cancellation deadline exceeded").catch(() => undefined);
    reader.releaseLock();
  }
};

const reservePort = async (): Promise<number> => {
  const reservation = Bun.serve({ port: 0, fetch: () => new Response("reserved") });
  const port = reservation.port;
  await reservation.stop(true);
  if (port === undefined) throw new Error("failed to reserve a loopback port");
  return port;
};

const opencodeBinary = process.env.OPENCODE_BIN ?? "opencode";

const localCompletion = (title: boolean): Response => {
  const chunks = title
    ? [{ delta: { role: "assistant", content: "Canary" }, finish_reason: null }, { delta: {}, finish_reason: "stop" }]
    : [{ delta: { role: "assistant", tool_calls: [{ index: 0, id: "canary-call", type: "function", function: { name: "bash", arguments: "" } }] }, finish_reason: null }, { delta: { tool_calls: [{ index: 0, function: { arguments: JSON.stringify({ command: "printf canary" }) } }] }, finish_reason: null }, { delta: {}, finish_reason: "tool_calls" }];
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const [index, chunk] of chunks.entries()) controller.enqueue(new TextEncoder().encode(`data: ${JSON.stringify({ id: "canary", object: "chat.completion.chunk", choices: [{ index: 0, ...chunk }] })}\n\n`));
      controller.enqueue(new TextEncoder().encode("data: [DONE]\n\n"));
      controller.close();
    },
  });
  return new Response(stream, { headers: { "content-type": "text/event-stream" } });
};

describe("OpenCode 1.18.10 contract canary", () => {
  test("contract receives a real permission.asked and preserves it at 10s and 60s", async () => {
    const root = await mkdtemp(join(tmpdir(), "smart-approve-runtime-"));
    const configHome = join(root, "config");
    const dataHome = join(root, "data");
    const stateHome = join(root, "state");
    const configDir = join(configHome, "opencode");
    const provider = Bun.serve({
      port: 0,
      fetch: async (request) => localCompletion((await request.text()).includes("title generator")),
    });
    const port = await reservePort();
    const baseURL = `http://127.0.0.1:${port}`;
    const eventAbort = new AbortController();
    const messageAbort = new AbortController();
    let child: ReturnType<typeof Bun.spawn> | undefined;
    try {
      await mkdir(configDir, { recursive: true });
      await mkdir(dataHome, { recursive: true });
      await mkdir(stateHome, { recursive: true });
      const config = {
        "$schema": "https://opencode.ai/config.json",
        model: "local/test",
        permission: { bash: "ask" },
        provider: { local: { npm: "@ai-sdk/openai-compatible", name: "Local", options: { baseURL: `http://127.0.0.1:${provider.port}/v1`, apiKey: "test" }, models: { test: { name: "test", tool_call: true, limit: { context: 32_768, output: 4_096 } } } } },
      };
      await writeFile(join(configDir, "opencode.jsonc"), JSON.stringify(config));
      child = Bun.spawn([opencodeBinary, "serve", "--port", String(port), "--hostname", "127.0.0.1"], { env: { ...globalThis.process.env, XDG_CONFIG_HOME: configHome, XDG_DATA_HOME: dataHome, XDG_STATE_HOME: stateHome }, stdout: "ignore", stderr: "ignore" });
      await waitForServer(baseURL);
      const eventPromise = readRuntimePermissionAsked(baseURL, AbortSignal.any([eventAbort.signal, AbortSignal.timeout(15_000)]));
      await new Promise((resolve) => setTimeout(resolve, 100));
      const sessionResponse = await fetch(`${baseURL}/session`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ title: "smart-approve runtime canary" }), signal: AbortSignal.timeout(5_000) });
      expect(sessionResponse.ok).toBe(true);
      const session = await sessionResponse.json() as { id: string };
      let pendingSettled = false;
      const pending = fetch(`${baseURL}/session/${session.id}/message`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ model: { providerID: "local", modelID: "test" }, agent: "build", parts: [{ type: "text", text: "run printf canary" }] }), signal: messageAbort.signal }).finally(() => { pendingSettled = true; });
      const prematureMessage = pending.then(
        () => { throw new Error("message completed before permission.asked"); },
        (error) => { throw new Error(`message failed before permission.asked: ${error instanceof Error ? error.name : "unknown"}`); },
      );
      const event = await Promise.race([eventPromise, prematureMessage]);
      expect(event.properties.permission).toBe("bash");
      expect(event.properties.metadata.command).toBe("printf canary");
      expect(event.properties.id).toBeTruthy();
      expect(event.properties.sessionID).toBe(session.id);

      await new Promise((resolve) => setTimeout(resolve, 10_000));
      expect(pendingSettled).toBe(false);
      await new Promise((resolve) => setTimeout(resolve, 50_000));
      expect(pendingSettled).toBe(false);

      await fetch(`${baseURL}/session/${session.id}/abort`, { method: "POST", signal: AbortSignal.timeout(5_000) }).catch(() => undefined);
      messageAbort.abort();
      await Promise.race([pending.catch(() => undefined), new Promise((resolve) => setTimeout(resolve, 2_000))]);
    } finally {
      eventAbort.abort();
      messageAbort.abort();
      if (child) {
        child.kill();
        const exited = await Promise.race([child.exited.then(() => true), new Promise<false>((resolve) => setTimeout(() => resolve(false), 2_000))]);
        if (!exited) {
          child.kill("SIGKILL");
          await Promise.race([child.exited, new Promise((resolve) => setTimeout(resolve, 2_000))]);
        }
      }
      await withDeadline(provider.stop(true), 2_000, "provider shutdown deadline exceeded");
      await withDeadline(rm(root, { recursive: true, force: true }), 5_000, "sandbox cleanup deadline exceeded");
    }
  }, { timeout: 120_000 });

  test("contract keeps the unqualified reviewer disabled even when configuration requests it", async () => {
    const statuses: string[] = [];
    const reviewer = { review: mock(async () => ({ decision: "manual" as const, sessionID: "child", toolCounters: ZERO_TOOL_COUNTERS })) };
    const hooks = createSmartApproveHooks({ config: { ...DEFAULT_CONFIG, model: { ...DEFAULT_CONFIG.model, enabled: true } }, reviewer, policy: async () => ({ status: "model_review", decision: "model_review", reasonCodes: [], parse: undefined, privacy: undefined }), onState: (_id, state) => statuses.push(state) });
    await hooks.event({ event: asked("request-1", "printf 'contract\\n'") });
    await waitFor(() => statuses.includes("manual"));
    expect(reviewer.review).not.toHaveBeenCalled();
    expect(statuses).not.toContain("reviewing");
    expect(statuses).toContain("manual");
    await hooks.dispose();
  });

  test("contract creates a plugin-owned child with explicit model, deny-all tools, and zero tool counters", async () => {
    const calls: unknown[] = [];
    const client = {
      session: {
        create: mock(async (input: unknown) => { calls.push(["create", input]); return { data: { id: "child-1" } }; }),
        prompt: mock(async (input: unknown) => { calls.push(["prompt", input]); return { data: { decision: "allow", reasonCodes: ["safe"], toolCounters: ZERO_TOOL_COUNTERS } }; }),
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
    const result = await createReviewerAgent({ client, timeoutMs: 10_000 }).review({ requestID: "request-timeout", prompt: "echo" });
    expect(result.decision).toBe("manual");
    expect(result.reasonCodes).toContain("timeout");
    expect(calls).toEqual(["abort:child-timeout", "delete:child-timeout"]);
  });

  test("contract records actual configured shell identity and validates runtime bounds", () => {
    const fixture = readFileSync(new URL("../fixtures/opencode/opencode.jsonc", import.meta.url), "utf8");
    expect(fixture).toContain('"bash": "ask"');
    expect(fixture).not.toMatch(/"plugin"\s*:/);
    expect(process.env.SHELL).toBeTruthy();
    const shell = process.env.SHELL as string;
    const command = "printf 'tagged-shell:%s\\n' contract";
    const output = Bun.spawnSync([shell, "-c", command], { stdout: "pipe", stderr: "pipe" });
    expect(output.exitCode).toBe(0);
    expect(new TextDecoder().decode(output.stdout)).toBe("tagged-shell:contract\n");
    expect(shell).toMatch(/\/(?:ba)?sh$|\/zsh$/);
    expect(configuredShellCompatible({ SHELL: shell })).toBe(true);
  });

  test("contract disables automatic replies for a non-Bash-compatible interpreter", () => {
    expect(isBashCompatibleInterpreter("/bin/bash")).toBe(true);
    expect(isBashCompatibleInterpreter("/bin/zsh")).toBe(true);
    expect(isBashCompatibleInterpreter("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")).toBe(false);
    expect(isBashCompatibleInterpreter("/usr/bin/fish")).toBe(false);
  });
});
