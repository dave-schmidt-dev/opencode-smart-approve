import { readFileSync } from "node:fs";
import { appendFile, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { describe, expect, mock, test } from "bun:test";
import { createOpencodeClient } from "@opencode-ai/sdk/v2";
import { createApprovalAdapter } from "../../src/opencode/client";
import { DEFAULT_CONFIG } from "../../src/config/schema";
import { configuredShellCompatible, createSmartApproveHooks, isBashCompatibleInterpreter } from "../../src/plugin";
import {
  createReviewerAgent,
  REVIEWER_MODEL,
  REVIEWER_VARIANT,
  ZERO_TOOL_COUNTERS,
} from "../../src/reviewer/agent";
import { DEFAULT_OPENCODE_BINARY, requireOpenCodeVersion } from "../../scripts/e2e-opencode";

const asked = (id: string, command: string, sessionID = "parent-session") => ({
  type: "permission.asked",
  properties: { id, sessionID, permission: "bash", metadata: { command } },
});

const waitFor = async (predicate: () => boolean | Promise<boolean>, timeoutMs = 10_000): Promise<void> => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  if (!(await predicate())) throw new Error(`condition not met within ${timeoutMs}ms`);
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

const waitForServer = async (baseURL: string, timeoutMs = 10_000, exited: () => boolean = () => false): Promise<void> => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (exited()) throw new Error("OpenCode server exited before becoming ready");
    try {
      const remainingMs = deadline - Date.now();
      if (remainingMs <= 0) break;
      const response = await fetch(`${baseURL}/session`, { signal: AbortSignal.timeout(Math.min(1_000, remainingMs)) });
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

interface RuntimePermissionReplied {
  readonly type: "permission.replied";
  readonly properties: {
    readonly sessionID: string;
    readonly requestID: string;
    readonly reply: string;
  };
}

const readRuntimePermissionAsked = async (
  baseURL: string,
  signal: AbortSignal,
  onReady?: () => void,
): Promise<RuntimePermissionAsked> => {
  const response = await fetch(`${baseURL}/global/event`, { signal });
  if (!response.ok || !response.body) throw new Error(`event stream failed: ${response.status}`);
  onReady?.();
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

const readRuntimePermissionReplies = async (
  baseURL: string,
  requestIDs: readonly string[],
  signal: AbortSignal,
  onReady?: () => void,
): Promise<RuntimePermissionReplied[]> => {
  const response = await fetch(`${baseURL}/global/event`, { signal });
  if (!response.ok || !response.body) throw new Error(`event stream failed: ${response.status}`);
  onReady?.();
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const expected = new Set(requestIDs);
  const observed = new Map<string, RuntimePermissionReplied>();
  let buffer = "";
  try {
    while (observed.size < expected.size) {
      const { done, value } = await withDeadline(reader.read(), 10_000, "permission.replied event deadline exceeded");
      if (done) throw new Error("event stream ended before permission.replied");
      buffer += decoder.decode(value, { stream: true });
      let boundary = buffer.indexOf("\n\n");
      while (boundary >= 0) {
        const frame = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        const data = frame.split("\n").filter((line) => line.startsWith("data:")).map((line) => line.slice(5).trim()).join("\n");
        if (data && data !== "[DONE]") {
          const envelope = JSON.parse(data) as { payload?: unknown };
          const event = (envelope.payload ?? envelope) as Partial<RuntimePermissionReplied>;
          if (event.type === "permission.replied" && event.properties && expected.has(event.properties.requestID)) {
            observed.set(event.properties.requestID, event as RuntimePermissionReplied);
          }
        }
        boundary = buffer.indexOf("\n\n");
      }
    }
    return requestIDs.map((requestID) => observed.get(requestID)!).filter(Boolean);
  } finally {
    await withDeadline(reader.cancel().catch(() => undefined), 1_000, "event reader cancellation deadline exceeded").catch(() => undefined);
    reader.releaseLock();
  }
};

const beginRuntimeEventSubscription = <T>(
  start: (onReady: () => void) => Promise<T>,
): { readonly event: Promise<T>; readonly ready: Promise<void> } => {
  let markReady: () => void = () => undefined;
  const streamReady = new Promise<void>((resolve) => { markReady = resolve; });
  const event = start(markReady);
  const ready = withDeadline(
    Promise.race([streamReady, event.then(() => undefined)]),
    5_000,
    "event stream did not become ready",
  );
  return { event, ready };
};

const reservePort = async (): Promise<number> => {
  const reservation = Bun.serve({ port: 0, fetch: () => new Response("reserved") });
  const port = reservation.port;
  await reservation.stop(true);
  if (port === undefined) throw new Error("failed to reserve a loopback port");
  return port;
};

const configuredOpencodeBinary = process.env.OPENCODE_BIN ?? DEFAULT_OPENCODE_BINARY;
const opencodeBinary = isAbsolute(configuredOpencodeBinary) ? configuredOpencodeBinary : resolve(process.cwd(), configuredOpencodeBinary);
const SHORT_CANARY_TIMEOUT_MS = 90_000;

type PendingPermission = {
  readonly id: string;
  readonly sessionID: string;
};

type TerminalResult = "fulfilled" | "rejected" | "http_error" | "unsettled";
type Propagation = "assistant_continues" | "turn_fails" | "session_aborts";

const sleep = (milliseconds: number) => new Promise<void>((resolve) => setTimeout(resolve, milliseconds));

const debugCanaryStatus = (status: string): void => {
  if (process.env.STALL_CANARY_DEBUG === "1") process.stderr.write(`[bounded-stall-canary] ${status}\n`);
};

const waitWithStderrProgress = async (milliseconds: number, completedMinutes: number): Promise<void> => {
  process.stderr.write(`[bounded-stall-canary] pending-list wait starting (${milliseconds}ms)\n`);
  let elapsed = 0;
  while (elapsed < milliseconds) {
    const interval = Math.min(60_000, milliseconds - elapsed);
    await sleep(interval);
    elapsed += interval;
    process.stderr.write(`[bounded-stall-canary] pending-list ${completedMinutes + Math.ceil(elapsed / 60_000)}m (${elapsed}ms elapsed)\n`);
  }
};

const sanitizedBody = async (response: Response): Promise<"true" | "false" | "empty" | "other"> => {
  const body = (await response.clone().text()).trim();
  if (!body) return "empty";
  if (body === "true") return "true";
  if (body === "false") return "false";
  return "other";
};

const listPendingPermissions = async (baseURL: string): Promise<PendingPermission[]> => {
  const response = await fetch(`${baseURL}/permission`, { signal: AbortSignal.timeout(5_000) });
  if (!response.ok) throw new Error(`pending-permission query failed: ${response.status}`);
  const value = await response.json() as unknown;
  if (!Array.isArray(value)) throw new Error("pending-permission query did not return an array");
  return value.map((entry) => {
    const permission = entry as Partial<PendingPermission>;
    if (typeof permission.id !== "string" || typeof permission.sessionID !== "string") {
      throw new Error("pending-permission query returned an incomplete request");
    }
    return { id: permission.id, sessionID: permission.sessionID };
  });
};

const waitForPendingPermission = async (baseURL: string, sessionID: string, timeoutMs = 10_000): Promise<PendingPermission> => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const matching = (await listPendingPermissions(baseURL)).find((permission) => permission.sessionID === sessionID);
    if (matching) return matching;
    await sleep(25);
  }
  throw new Error("pending permission was not independently observable");
};

const settleTerminal = async (promise: Promise<Response>, timeoutMs = 10_000): Promise<TerminalResult> => {
  try {
    const response = await withDeadline(promise, timeoutMs, "message did not terminalize after reject");
    return response.ok ? "fulfilled" : "http_error";
  } catch (error) {
    return error instanceof Error && error.message === "message did not terminalize after reject" ? "unsettled" : "rejected";
  }
};

const writeRuntimeEvidence = async (observations: Record<string, unknown>): Promise<void> => {
  const evidencePath = join(process.cwd(), "eval-results/2026-08-10-bounded-stall-runtime-contract.jsonl");
  const bounded = Object.fromEntries(Object.entries(observations).slice(0, 64));
  const record = JSON.stringify({
    runtime: "local disposable OpenCode 1.18.10",
    capture: "bounded status, shape, count, and enum observations; no command, provider, or error bytes",
    observations: bounded,
  });
  if (record.length > 16_384) throw new Error("runtime evidence record exceeded bounded size");
  await mkdir(join(process.cwd(), "eval-results"), { recursive: true });
  await appendFile(evidencePath, `${record}\n`, { encoding: "utf8", flag: "a" });
};

interface RuntimeCanary {
  readonly baseURL: string;
  readonly provider: ReturnType<typeof Bun.serve>;
  readonly nonTitleProviderCalls: () => number;
  readonly createSession: (parentID?: string) => Promise<{ id: string; parentID?: string }>;
  readonly prompt: (sessionID: string, signal?: AbortSignal, text?: string, messageID?: string) => Promise<Response>;
  readonly promptAsync: (sessionID: string, text?: string, messageID?: string) => Promise<Response>;
  readonly listMessages: (sessionID: string) => Promise<readonly Record<string, unknown>[]>;
  readonly readPluginLog: () => Promise<readonly Record<string, unknown>[]>;
  readonly cleanup: () => Promise<void>;
}

type RuntimePluginMode = "none" | "exact" | "missing" | "malformed" | "different";

const runtimeContractPlugin = (logPath: string, mode: RuntimePluginMode): string => `

const expected = "1.18.10";
const mode = ${JSON.stringify(mode)};
const logPath = ${JSON.stringify(logPath)};
let writeTail = Promise.resolve();
const write = (entry) => {
  const current = writeTail.then(async () => {
  const bounded = Object.fromEntries(Object.entries(entry).slice(0, 8));
  const previous = await Bun.file(logPath).text().catch(() => "");
  await Bun.write(logPath, previous + JSON.stringify(bounded) + "\\n");
  });
  writeTail = current.catch(() => undefined);
  return current;
};
const shape = (value) => value === undefined ? "missing" : typeof value === "string" ? "string" : "other";
let active = false;
let hookErrors = 0;
const seenMessageIDs = new Set();
let lifecycleReady;
const lifecycle = async (serverUrl) => {
  if (lifecycleReady) return lifecycleReady;
  lifecycleReady = (async () => {
    let signal;
    try {
      const response = await fetch(new URL("/global/health", serverUrl));
      signal = response.ok ? await response.json() : undefined;
    } catch { signal = undefined; }
    const version = mode === "exact" ? signal?.version
      : mode === "missing" ? undefined
        : mode === "malformed" ? { version: expected }
          : mode === "different" ? "1.18.11" : undefined;
    active = typeof version === "string" && version === expected;
    await write({ kind: "lifecycle", shape: shape(version), exact: active, active });
    return active;
  })();
  return lifecycleReady;
};

export const RuntimeContractCanary = async (input) => {
  return ({
  "chat.message": async (hookInput, output) => {
    const enabled = await lifecycle(input.serverUrl);
    const role = output?.message?.role;
    const messageID = typeof hookInput.messageID === "string" && hookInput.messageID.length > 0
      ? hookInput.messageID
      : typeof output?.message?.id === "string" && output.message.id.length > 0
        ? output.message.id
        : undefined;
    const hasMessageID = messageID !== undefined;
    const duplicate = hasMessageID && seenMessageIDs.has(messageID);
    if (messageID) seenMessageIDs.add(messageID);
    await write({ kind: "generation", enabled, user: role === "user", messageID: hasMessageID, duplicate, newGeneration: hasMessageID && !duplicate });
  },
  "tool.execute.before": async (hookInput, output) => {
    const enabled = await lifecycle(input.serverUrl);
    const hasSessionID = typeof hookInput.sessionID === "string" && hookInput.sessionID.length > 0;
    const hasCallID = typeof hookInput.callID === "string" && hookInput.callID.length > 0;
    const isBash = hookInput.tool === "bash";
    await write({ kind: "before", enabled, bash: isBash, hasSessionID, hasCallID, argsObject: typeof output?.args === "object" && output.args !== null });
    if (enabled && isBash && hookErrors < 2) {
      hookErrors += 1;
      await write({ kind: "hook-error", count: hookErrors });
      throw new Error("SMART_APPROVE_REPLAN: blocked shell approach; use native tools or a different command");
    }
  },
  });
};

export default RuntimeContractCanary;
`;

type RuntimeProviderMode = "bash-then-final" | "bash-then-native" | "stubborn";

const startRuntimeCanary = async (options: { readonly pluginMode?: RuntimePluginMode; readonly providerMode?: RuntimeProviderMode } = {}): Promise<RuntimeCanary> => {
  const root = await mkdtemp(join(tmpdir(), "smart-approve-runtime-"));
  const configHome = join(root, "config");
  const dataHome = join(root, "data");
  const stateHome = join(root, "state");
  const cacheHome = join(root, "cache");
  const configDir = join(configHome, "opencode");
  const projectDir = join(root, "project");
  const pluginPath = join(root, "runtime-contract-canary.mjs");
  const pluginLogPath = join(root, "runtime-contract-canary.jsonl");
  let nonTitleProviderCalls = 0;
  const firstRequestFor = new Set<string>();
  const provider = Bun.serve({
    port: 0,
    fetch: async (request) => {
      const requestBody = await request.text();
      const title = requestBody.includes("title generator");
      if (!title) nonTitleProviderCalls += 1;
      const parallel = requestBody.includes("parallel-permission");
      const requestKey = parallel ? "parallel-permission"
        : requestBody.includes("main bash") ? "main bash"
          : requestBody.includes("subagent bash") ? "subagent bash"
            : requestBody.includes("async bash") ? "async bash"
              : requestBody.includes("stubborn fresh call IDs") ? "stubborn fresh call IDs"
                : requestBody.includes("duplicate delivery") ? "duplicate delivery"
                  : requestBody.includes("later delivery") ? "later delivery"
                    : "default";
      const firstForKey = !firstRequestFor.has(requestKey);
      firstRequestFor.add(requestKey);
      if (title) return localCompletion(true);
      if (options.providerMode === "stubborn") return localCompletion(false, parallel);
      if (options.providerMode === undefined) return localCompletion(false, parallel);
      if (firstForKey) return localCompletion(false, parallel);
      if (options.providerMode === "bash-then-native") return localCompletion(false, false, true);
      return localCompletion(true);
    },
  });
  let baseURL = "";
  let child: ReturnType<typeof Bun.spawn> | undefined;
  const stopChild = async (): Promise<void> => {
    const current = child;
    child = undefined;
    if (!current) return;
    if (current.exitCode === null) current.kill();
    const exited = await Promise.race([current.exited.then(() => true), sleep(2_000).then(() => false)]);
    if (!exited) {
      current.kill("SIGKILL");
      await Promise.race([current.exited, sleep(2_000)]);
    }
  };
  const cleanup = async (): Promise<void> => {
    await stopChild();
    await withDeadline(provider.stop(true), 2_000, "provider shutdown deadline exceeded");
    await withDeadline(rm(root, { recursive: true, force: true }), 5_000, "sandbox cleanup deadline exceeded");
  };
  try {
    await mkdir(configDir, { recursive: true });
    await mkdir(projectDir, { recursive: true });
    await mkdir(dataHome, { recursive: true });
    await mkdir(stateHome, { recursive: true });
    await mkdir(cacheHome, { recursive: true });
    const config = {
      "$schema": "https://opencode.ai/config.json",
      model: "local/test",
      permission: { bash: "ask" },
      provider: { local: { npm: "@ai-sdk/openai-compatible", name: "Local", options: { baseURL: `http://127.0.0.1:${provider.port}/v1`, apiKey: "test" }, models: { test: { name: "test", tool_call: true, limit: { context: 32_768, output: 4_096 } } } } },
    };
    if (options.pluginMode && options.pluginMode !== "none") {
      await writeFile(pluginPath, runtimeContractPlugin(pluginLogPath, options.pluginMode), "utf8");
      (config as { plugin?: string[] }).plugin = [`file://${pluginPath}`];
    }
    await writeFile(join(configDir, "opencode.jsonc"), JSON.stringify(config));
    requireOpenCodeVersion({ configHome, dataHome, stateHome, cacheHome });
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      const port = await reservePort();
      baseURL = `http://127.0.0.1:${port}`;
      child = Bun.spawn([opencodeBinary, "serve", ...(process.env.STALL_CANARY_DEBUG === "1" ? ["--print-logs", "--log-level", "DEBUG"] : []), "--port", String(port), "--hostname", "127.0.0.1"], {
        env: { ...globalThis.process.env, XDG_CONFIG_HOME: configHome, XDG_DATA_HOME: dataHome, XDG_STATE_HOME: stateHome, XDG_CACHE_HOME: cacheHome },
        cwd: projectDir,
        stdout: "ignore",
        stderr: process.env.STALL_CANARY_DEBUG === "1" ? "inherit" : "ignore",
      });
      try {
        await waitForServer(baseURL, 5_000, () => child?.exitCode !== null);
        break;
      } catch (error) {
        await stopChild();
        if (attempt === 3) throw error;
        process.stderr.write(`[bounded-stall-canary] runtime start retry ${attempt + 1}/3\n`);
      }
    }
    if (!child) throw new Error("OpenCode server did not start");
    return {
      baseURL,
      provider,
      nonTitleProviderCalls: () => nonTitleProviderCalls,
      createSession: async (parentID?: string) => {
        const response = await fetch(`${baseURL}/session`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ title: "smart-approve runtime canary", ...(parentID ? { parentID } : {}) }),
          signal: AbortSignal.timeout(5_000),
        });
        if (!response.ok) throw new Error(`session creation failed: ${response.status}`);
        return await response.json() as { id: string; parentID?: string };
      },
      prompt: (sessionID, signal, text = "run disposable canary", messageID) => fetch(`${baseURL}/session/${sessionID}/message`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: { providerID: "local", modelID: "test" }, agent: "build", ...(messageID ? { messageID } : {}), parts: [{ type: "text", text }] }),
        signal,
      }),
      promptAsync: (sessionID, text = "run disposable canary", messageID) => fetch(`${baseURL}/session/${sessionID}/prompt_async`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: { providerID: "local", modelID: "test" }, agent: "build", ...(messageID ? { messageID } : {}), parts: [{ type: "text", text }] }),
        signal: AbortSignal.timeout(5_000),
      }),
      listMessages: async (sessionID) => {
        const response = await fetch(`${baseURL}/session/${sessionID}/message`, { signal: AbortSignal.timeout(5_000) });
        if (!response.ok) throw new Error(`message list failed: ${response.status}`);
        return await response.json() as readonly Record<string, unknown>[];
      },
      readPluginLog: async () => {
        try {
          const text = await readFile(pluginLogPath, "utf8");
          return text.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line) as Record<string, unknown>);
        } catch { return []; }
      },
      cleanup,
    };
  } catch (error) {
    await cleanup().catch(() => undefined);
    throw error;
  }
};

const localCompletion = (title: boolean, twoToolCalls = false, nativeAlternative = false): Response => {
  const chunks = title
    ? [{ delta: { role: "assistant", content: "Canary" }, finish_reason: null }, { delta: {}, finish_reason: "stop" }]
    : nativeAlternative
      ? [{ delta: { role: "assistant", tool_calls: [{ index: 0, id: "canary-glob", type: "function", function: { name: "glob", arguments: "" } }] }, finish_reason: null }, { delta: { tool_calls: [{ index: 0, function: { arguments: JSON.stringify({ pattern: "README.md" }) } }] }, finish_reason: null }, { delta: {}, finish_reason: "tool_calls" }]
    : twoToolCalls
      ? [{ delta: { role: "assistant", tool_calls: [{ index: 0, id: "canary-call-one", type: "function", function: { name: "bash", arguments: "" } }, { index: 1, id: "canary-call-two", type: "function", function: { name: "bash", arguments: "" } }] }, finish_reason: null }, { delta: { tool_calls: [{ index: 0, function: { arguments: JSON.stringify({ command: "printf one" }) } }, { index: 1, function: { arguments: JSON.stringify({ command: "printf two" }) } }] }, finish_reason: null }, { delta: {}, finish_reason: "tool_calls" }]
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
    const cacheHome = join(root, "cache");
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
      await mkdir(cacheHome, { recursive: true });
      const config = {
        "$schema": "https://opencode.ai/config.json",
        model: "local/test",
        permission: { bash: "ask" },
        provider: { local: { npm: "@ai-sdk/openai-compatible", name: "Local", options: { baseURL: `http://127.0.0.1:${provider.port}/v1`, apiKey: "test" }, models: { test: { name: "test", tool_call: true, limit: { context: 32_768, output: 4_096 } } } } },
      };
      await writeFile(join(configDir, "opencode.jsonc"), JSON.stringify(config));
      requireOpenCodeVersion({ configHome, dataHome, stateHome, cacheHome }, { ...globalThis.process.env, OPENCODE_BIN: opencodeBinary });
      child = Bun.spawn([opencodeBinary, "serve", "--port", String(port), "--hostname", "127.0.0.1"], { env: { ...globalThis.process.env, OPENCODE_BIN: opencodeBinary, XDG_CONFIG_HOME: configHome, XDG_DATA_HOME: dataHome, XDG_STATE_HOME: stateHome, XDG_CACHE_HOME: cacheHome }, stdout: "ignore", stderr: "ignore" });
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

      await waitWithStderrProgress(10_000, 0);
      expect(pendingSettled).toBe(false);
      await waitWithStderrProgress(50_000, 0);
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

  test.serial("reject contract short captures exact reject HTTP/SDK shape and propagation", async () => {
    debugCanaryStatus("short propagation: starting runtime");
    const canary = await startRuntimeCanary();
    const parentAbort = new AbortController();
    try {
      debugCanaryStatus("short propagation: creating session");
      const parent = await canary.createSession();
      const parentSubscription = beginRuntimeEventSubscription((onReady) =>
        readRuntimePermissionAsked(canary.baseURL, AbortSignal.timeout(15_000), onReady));
      await parentSubscription.ready;
      const parentMessage = canary.prompt(parent.id, parentAbort.signal);
      void parentMessage.catch(() => undefined);
      debugCanaryStatus("short propagation: awaiting permission event");
      const askedParent = await parentSubscription.event;
      expect(askedParent.properties.sessionID).toBe(parent.id);
      expect(askedParent.properties.permission).toBe("bash");
      const parentPending = await waitForPendingPermission(canary.baseURL, parent.id);
      debugCanaryStatus("short propagation: permission independently listed");
      expect(parentPending.id).toBe(askedParent.properties.id);

      let capturedStatus: number | undefined;
      let capturedBody: "true" | "false" | "empty" | "other" | undefined;
      let capturedPath: string | undefined;
      const capturingFetch = Object.assign(async (request: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        capturedPath = new URL(typeof request === "string" ? request : request instanceof URL ? request.toString() : request.url).pathname;
        try {
          const response = await fetch(request, init);
          capturedStatus = response.status;
          capturedBody = await sanitizedBody(response);
          return response;
        } catch {
          throw new Error(`SDK permission reply was interrupted at ${capturedPath}`);
        }
      }, { preconnect: fetch.preconnect.bind(fetch) });
      const client = createOpencodeClient({
        baseUrl: canary.baseURL,
        fetch: capturingFetch,
      });
      const providerCallsBeforeReject = canary.nonTitleProviderCalls();
      expect(providerCallsBeforeReject).toBe(1);
      const sdkResult = await client.permission.reply({ requestID: parentPending.id, reply: "reject" }, { throwOnError: false });
      debugCanaryStatus("short propagation: reject returned");
      const sdkResultKeys = Object.keys(sdkResult).sort();
      expect(capturedStatus).toBe(200);
      expect(capturedBody).toBe("true");
      expect(sdkResult.response.status).toBe(200);
      expect(sdkResult.data).toBe(true);
      expect(sdkResult.error).toBeUndefined();
      expect(sdkResultKeys).toEqual(["data", "request", "response"]);

      const parentTerminal = await settleTerminal(parentMessage);
      debugCanaryStatus(`short propagation: message ${parentTerminal}`);
      expect(parentTerminal).not.toBe("unsettled");
      const sessionState = await fetch(`${canary.baseURL}/session/${parent.id}`, { signal: AbortSignal.timeout(5_000) });
      await sleep(250);
      const providerCallsAfterReject = canary.nonTitleProviderCalls();
      const sameTurnContinuation = providerCallsAfterReject > providerCallsBeforeReject;
      const propagation: Propagation = !sessionState.ok
        ? "session_aborts"
        : sameTurnContinuation
          ? "assistant_continues"
          : "turn_fails";
      // The pinned 1.18.10 runtime rejects the tool call and ends this turn;
      // continuation is only enabled by the explicit message-bearing path.
      expect(sessionState.ok).toBe(true);
      expect(sameTurnContinuation).toBe(false);
      expect(propagation).toBe("turn_fails");

      await writeRuntimeEvidence({
        exact_binary: "1.18.10",
        reject_http: { status: capturedStatus, body: capturedBody },
        sdk_nonthrowing_result: { keys: sdkResultKeys, data: "boolean:true", error_property: "absent", response_status: sdkResult.response.status },
        propagation,
        propagation_probe: { parent_terminal: parentTerminal, same_turn_provider_calls_before_reject: providerCallsBeforeReject, same_turn_provider_calls_after_reject: providerCallsAfterReject },
      });
      debugCanaryStatus("short propagation: evidence written");
    } finally {
      parentAbort.abort();
      debugCanaryStatus("short propagation: cleanup starting");
      await canary.cleanup();
      debugCanaryStatus("short propagation: cleanup complete");
    }
  }, { timeout: SHORT_CANARY_TIMEOUT_MS });

  test.serial("reject contract short probes same-session two-tool-call and concurrent-prompt reachability", async () => {
    const canary = await startRuntimeCanary();
    const multiToolAbort = new AbortController();
    const multiToolRepliesAbort = new AbortController();
    const cascadeAbort = new AbortController();
    const secondAbort = new AbortController();
    try {
      const multiToolSession = await canary.createSession();
      const multiToolSubscription = beginRuntimeEventSubscription((onReady) =>
        readRuntimePermissionAsked(canary.baseURL, AbortSignal.timeout(15_000), onReady));
      await multiToolSubscription.ready;
      const multiToolMessage = canary.prompt(multiToolSession.id, multiToolAbort.signal, "parallel-permission");
      void multiToolMessage.catch(() => undefined);
      await multiToolSubscription.event;
      await sleep(250);
      const multiToolPending = (await listPendingPermissions(canary.baseURL)).filter((permission) => permission.sessionID === multiToolSession.id);
      expect(multiToolPending.length).toBeGreaterThanOrEqual(2);
      const multiToolRequestIDs = multiToolPending.slice(0, 2).map((permission) => permission.id);
      const multiToolRepliedSubscription = beginRuntimeEventSubscription((onReady) =>
        readRuntimePermissionReplies(
          canary.baseURL,
          multiToolRequestIDs,
          AbortSignal.any([multiToolRepliesAbort.signal, AbortSignal.timeout(10_000)]),
          onReady,
        ));
      await multiToolRepliedSubscription.ready;
      const multiToolReject = await fetch(`${canary.baseURL}/permission/${multiToolPending[0]?.id}/reply`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ reply: "reject" }),
        signal: AbortSignal.timeout(5_000),
      });
      expect(multiToolReject.status).toBe(200);
      expect(await sanitizedBody(multiToolReject)).toBe("true");
      const multiToolReplies = await multiToolRepliedSubscription.event;
      expect(multiToolReplies.map((event) => event.properties.requestID).sort()).toEqual([...multiToolRequestIDs].sort());
      expect(multiToolReplies.map((event) => event.properties.reply)).toEqual(["reject", "reject"]);
      const afterMultiToolReject = await listPendingPermissions(canary.baseURL);
      expect(afterMultiToolReject.some((permission) => multiToolRequestIDs.includes(permission.id))).toBe(false);
      const multiToolTerminal = await settleTerminal(multiToolMessage);

      const cascadeParent = await canary.createSession();
      const cascadeFirstSubscription = beginRuntimeEventSubscription((onReady) =>
        readRuntimePermissionAsked(canary.baseURL, AbortSignal.timeout(15_000), onReady));
      await cascadeFirstSubscription.ready;
      const cascadeFirstMessage = canary.prompt(cascadeParent.id, cascadeAbort.signal);
      void cascadeFirstMessage.catch(() => undefined);
      await cascadeFirstSubscription.event;
      const cascadeFirstPending = await waitForPendingPermission(canary.baseURL, cascadeParent.id);
      const secondEventAbort = new AbortController();
      const secondSubscription = beginRuntimeEventSubscription((onReady) =>
        readRuntimePermissionAsked(canary.baseURL, secondEventAbort.signal, onReady));
      await secondSubscription.ready;
      const secondMessage = canary.prompt(cascadeParent.id, secondAbort.signal);
      void secondMessage.catch(() => undefined);
      const askedSecond = await Promise.race([secondSubscription.event.catch(() => undefined), sleep(3_000).then(() => undefined)]);
      secondEventAbort.abort();
      const pendingBeforeReject = await listPendingPermissions(canary.baseURL);
      const sameSession = pendingBeforeReject.filter((permission) => permission.sessionID === cascadeParent.id);
      const secondReachable = askedSecond !== undefined && sameSession.length >= 2;
      let cascadeFirstTerminal: TerminalResult = "unsettled";
      let secondTerminal: TerminalResult = "unsettled";
      let cascadeFirstReply: "reject" | "not_observed" = "not_observed";
      let secondReply: "inferred_reject_cascade" | "not_observed" = "not_observed";
      if (secondReachable) {
        const cascadeReject = await fetch(`${canary.baseURL}/permission/${cascadeFirstPending.id}/reply`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ reply: "reject" }),
          signal: AbortSignal.timeout(5_000),
        });
        expect(cascadeReject.status).toBe(200);
        expect(await sanitizedBody(cascadeReject)).toBe("true");
        cascadeFirstReply = "reject";
        secondReply = "inferred_reject_cascade";
        cascadeFirstTerminal = await settleTerminal(cascadeFirstMessage);
        secondTerminal = await settleTerminal(secondMessage);
      } else {
        secondAbort.abort();
        secondTerminal = await settleTerminal(secondMessage, 1_000);
        const firstReject = await fetch(`${canary.baseURL}/permission/${cascadeFirstPending.id}/reply`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ reply: "reject" }),
          signal: AbortSignal.timeout(5_000),
        });
        expect(firstReject.status).toBe(200);
        expect(await sanitizedBody(firstReject)).toBe("true");
        cascadeFirstReply = "reject";
        cascadeFirstTerminal = await settleTerminal(cascadeFirstMessage);
      }

      await writeRuntimeEvidence({
        exact_binary: "1.18.10",
        same_session_pending: {
          reachable: true,
          attempts: {
            two_tool_calls: {
              mechanism: "one assistant response with two Bash tool calls",
              reachable: true,
              requests: [
                { id: multiToolReplies[0]?.properties.requestID, observed_reply: multiToolReplies[0]?.properties.reply, terminal: "removed_from_pending_list" },
                { id: multiToolReplies[1]?.properties.requestID, observed_reply: multiToolReplies[1]?.properties.reply, terminal: "removed_from_pending_list" },
              ],
              message_terminal: multiToolTerminal,
            },
            concurrent_prompts: {
              mechanism: "two concurrent user prompts",
              reachable: secondReachable,
              requests: [
                { id: cascadeFirstPending.id, observed_reply: cascadeFirstReply, terminal: cascadeFirstTerminal },
                { id: askedSecond?.properties.id, inferred_reply: secondReply, terminal: secondTerminal },
              ],
            },
          },
        },
      });
    } finally {
      multiToolAbort.abort();
      multiToolRepliesAbort.abort();
      cascadeAbort.abort();
      secondAbort.abort();
      await canary.cleanup();
    }
  }, { timeout: SHORT_CANARY_TIMEOUT_MS });

  test.serial("reject contract short verifies reviewer-child isolation", async () => {
    const canary = await startRuntimeCanary();
    const parentAbort = new AbortController();
    const childAbort = new AbortController();
    try {
      const isolationParent = await canary.createSession();
      const isolationParentSubscription = beginRuntimeEventSubscription((onReady) =>
        readRuntimePermissionAsked(canary.baseURL, AbortSignal.timeout(15_000), onReady));
      await isolationParentSubscription.ready;
      const isolationParentMessage = canary.prompt(isolationParent.id, parentAbort.signal);
      void isolationParentMessage.catch(() => undefined);
      await isolationParentSubscription.event;
      const isolationParentPending = await waitForPendingPermission(canary.baseURL, isolationParent.id);
      const reviewerChild = await canary.createSession(isolationParent.id);
      expect(reviewerChild.parentID).toBe(isolationParent.id);
      const childSubscription = beginRuntimeEventSubscription((onReady) =>
        readRuntimePermissionAsked(canary.baseURL, AbortSignal.timeout(15_000), onReady));
      await childSubscription.ready;
      const childMessage = canary.prompt(reviewerChild.id, childAbort.signal);
      const askedChild = await childSubscription.event;
      expect(askedChild.properties.sessionID).toBe(reviewerChild.id);
      const childPending = await waitForPendingPermission(canary.baseURL, reviewerChild.id);
      const childReject = await fetch(`${canary.baseURL}/permission/${childPending.id}/reply`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ reply: "reject" }),
        signal: AbortSignal.timeout(5_000),
      });
      expect(childReject.status).toBe(200);
      expect(await sanitizedBody(childReject)).toBe("true");
      expect(await settleTerminal(childMessage)).not.toBe("unsettled");
      const afterChildReject = await listPendingPermissions(canary.baseURL);
      expect(afterChildReject.some((permission) => permission.id === isolationParentPending.id)).toBe(true);

      await writeRuntimeEvidence({
        exact_binary: "1.18.10",
        reviewer_child_isolation: { child_reject_status: childReject.status, parent_remained_pending: true },
      });

      await fetch(`${canary.baseURL}/session/${isolationParent.id}/abort`, { method: "POST", signal: AbortSignal.timeout(5_000) }).catch(() => undefined);
      await Promise.race([isolationParentMessage.catch(() => undefined), sleep(2_000)]);
    } finally {
      parentAbort.abort();
      childAbort.abort();
      await canary.cleanup();
    }
  }, { timeout: SHORT_CANARY_TIMEOUT_MS });

  test.serial("production tool hook contract binds lifecycle, generations, and call identity", async () => {
    const canary = await startRuntimeCanary({ pluginMode: "exact", providerMode: "bash-then-final" });
    const parentAbort = new AbortController();
    const childAbort = new AbortController();
    try {
      const parent = await canary.createSession();
      const parentMessage = await canary.prompt(parent.id, parentAbort.signal, "run main bash");
      expect(parentMessage.status).toBe(200);

      const child = await canary.createSession(parent.id);
      const childMessage = await canary.prompt(child.id, childAbort.signal, "run subagent bash");
      expect(childMessage.status).toBe(200);

      const asyncSession = await canary.createSession();
      expect((await canary.promptAsync(asyncSession.id, "run async bash")).status).toBe(204);
      await waitFor(async () => (await canary.readPluginLog()).filter((entry) => entry.kind === "before").length >= 3, 15_000);

      const records = await canary.readPluginLog();
      const lifecycle = records.filter((entry) => entry.kind === "lifecycle");
      const generations = records.filter((entry) => entry.kind === "generation");
      const before = records.filter((entry) => entry.kind === "before" && entry.bash === true);
      const errors = records.filter((entry) => entry.kind === "hook-error");
      expect(lifecycle).toContainEqual(expect.objectContaining({ shape: "string", exact: true, active: true }));
      expect(generations.length).toBe(3);
      expect(generations.every((entry) => entry.user === true && entry.messageID === true)).toBe(true);
      expect(generations.filter((entry) => entry.duplicate === true)).toHaveLength(0);
      expect(before.length).toBeGreaterThanOrEqual(3);
      expect(before.every((entry) => entry.enabled === true && entry.hasSessionID === true && entry.hasCallID === true)).toBe(true);
      expect(errors.length).toBe(2);
    } finally {
      parentAbort.abort();
      childAbort.abort();
      await canary.cleanup();
    }
  }, { timeout: SHORT_CANARY_TIMEOUT_MS });

  test.serial("production tool hook contract deduplicates a message ID and starts a later generation", async () => {
    const canary = await startRuntimeCanary({ pluginMode: "exact", providerMode: "bash-then-final" });
    try {
      const session = await canary.createSession();
      expect((await canary.promptAsync(session.id, "duplicate delivery")).status).toBe(204);
      await waitFor(async () => (await canary.listMessages(session.id)).length > 0, 15_000);
      const first = await canary.listMessages(session.id);
      const fixedID = ((first[0]?.info as Record<string, unknown> | undefined)?.id as string | undefined);
      expect(fixedID).toBeTruthy();
      await sleep(200);
      expect((await canary.promptAsync(session.id, "duplicate delivery", fixedID)).status).toBe(204);
      await sleep(200);
      expect((await canary.promptAsync(session.id, "later delivery")).status).toBe(204);
      await sleep(500);
      const generations = (await canary.readPluginLog()).filter((entry) => entry.kind === "generation");
      expect(generations.length).toBeGreaterThanOrEqual(2);
      expect(generations.filter((entry) => entry.newGeneration === true)).toHaveLength(2);
      expect(generations.filter((entry) => entry.duplicate === true)).toHaveLength(1);
    } finally {
      await canary.cleanup();
    }
  }, { timeout: SHORT_CANARY_TIMEOUT_MS });

  test.serial("production tool hook contract bounds stubborn fresh-call-ID retries before native Bash ask", async () => {
    const canary = await startRuntimeCanary({ pluginMode: "exact", providerMode: "stubborn" });
    const abort = new AbortController();
    try {
      const session = await canary.createSession();
      const message = canary.prompt(session.id, abort.signal, "stubborn fresh call IDs");
      void message.catch(() => undefined);
      const pending = await waitForPendingPermission(canary.baseURL, session.id, 15_000);
      expect(pending.id).toBeTruthy();
      const records = await canary.readPluginLog();
      expect(records.filter((entry) => entry.kind === "hook-error")).toHaveLength(2);
      expect(records.filter((entry) => entry.kind === "before" && entry.bash === true).length).toBeGreaterThanOrEqual(3);
      expect(records.filter((entry) => entry.kind === "before" && entry.enabled === true).every((entry) => entry.hasCallID === true)).toBe(true);
      await fetch(`${canary.baseURL}/session/${session.id}/abort`, { method: "POST", signal: AbortSignal.timeout(5_000) }).catch(() => undefined);
      abort.abort();
    } finally {
      abort.abort();
      await canary.cleanup();
    }
  }, { timeout: SHORT_CANARY_TIMEOUT_MS });

  test.serial("production tool hook contract stays inactive for missing, malformed, or different lifecycle evidence", async () => {
    for (const pluginMode of ["missing", "malformed", "different"] as const) {
      const canary = await startRuntimeCanary({ pluginMode, providerMode: "bash-then-final" });
      const abort = new AbortController();
      try {
        const session = await canary.createSession();
        const message = canary.prompt(session.id, abort.signal, `inactive ${pluginMode}`);
        void message.catch(() => undefined);
        await waitForPendingPermission(canary.baseURL, session.id, 15_000);
        const records = await canary.readPluginLog();
        expect(records).toContainEqual(expect.objectContaining({ kind: "lifecycle", exact: false, active: false }));
        expect(records.filter((entry) => entry.kind === "hook-error")).toHaveLength(0);
        expect(records.filter((entry) => entry.kind === "before").every((entry) => entry.enabled === false)).toBe(true);
        await fetch(`${canary.baseURL}/session/${session.id}/abort`, { method: "POST", signal: AbortSignal.timeout(5_000) }).catch(() => undefined);
      } finally {
        abort.abort();
        await canary.cleanup();
      }
    }
  }, { timeout: SHORT_CANARY_TIMEOUT_MS * 3 });

  test.if(process.env.RUN_LONG_STALL_CANARY === "1")("contract independently lists a held permission at 5 and 60 minutes", async () => {
    const canary = await startRuntimeCanary();
    try {
      const session = await canary.createSession();
      const subscription = beginRuntimeEventSubscription((onReady) =>
        readRuntimePermissionAsked(canary.baseURL, AbortSignal.timeout(15_000), onReady));
      await subscription.ready;
      const promptAccepted = await canary.promptAsync(session.id);
      expect(promptAccepted.status).toBe(204);
      await subscription.event;
      const permission = await waitForPendingPermission(canary.baseURL, session.id);
      process.stderr.write("[bounded-stall-canary] pending-list observation started\n");
      await waitWithStderrProgress(300_000, 0);
      const atFiveMinutes = await listPendingPermissions(canary.baseURL);
      expect(atFiveMinutes.some((entry) => entry.id === permission.id)).toBe(true);
      process.stderr.write("[bounded-stall-canary] pending-list 5-minute observation passed\n");
      await waitWithStderrProgress(3_300_000, 5);
      const atSixtyMinutes = await listPendingPermissions(canary.baseURL);
      expect(atSixtyMinutes.some((entry) => entry.id === permission.id)).toBe(true);
      process.stderr.write("[bounded-stall-canary] pending-list 60-minute observation passed\n");
      await writeRuntimeEvidence({
        exact_binary: "1.18.10",
        pending_list_lifetime: { at_5_minutes: "pending", at_60_minutes: "pending", oracle: "independent GET /permission" },
      });
      await fetch(`${canary.baseURL}/session/${session.id}/abort`, { method: "POST", signal: AbortSignal.timeout(5_000) }).catch(() => undefined);
    } finally {
      await canary.cleanup();
    }
  }, { timeout: 3_900_000 });

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
    const prompt = promptCall?.[1] as { body: { model: unknown; variant: unknown; tools: Record<string, boolean> } };
    expect(prompt.body.model).toEqual({ providerID: "opencode-go", modelID: "deepseek-v4-flash" });
    expect(prompt.body.variant).toBe("low");
    expect(prompt.body.tools).toMatchObject({ bash: false, edit: false, read: false, task: false, webfetch: false });
    expect(REVIEWER_MODEL).toBe("opencode-go/deepseek-v4-flash");
    expect(REVIEWER_VARIANT).toBe("low");
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
