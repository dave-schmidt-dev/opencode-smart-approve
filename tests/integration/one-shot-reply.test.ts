import { readFileSync } from "node:fs";
import { describe, expect, mock, test } from "bun:test";
import { createApprovalAdapter } from "../../src/opencode/client";
import { createPermissionEventHandler } from "../../src/opencode/permission-event";
import { DEFAULT_CONFIG } from "../../src/config/schema";
import { MODEL_APPROVAL_QUALIFIED, SmartApprovePlugin } from "../../src/plugin";

const waitFor = async (predicate: () => boolean): Promise<void> => {
  for (let index = 0; index < 100; index += 1) {
    if (predicate()) return;
    await Bun.sleep(2);
  }
  throw new Error("timed out waiting for detached plugin work");
};

describe("one-shot OpenCode permission reply", () => {
  test("production entry point keeps model approval disabled until qualification", async () => {
    const rootReply = mock(async (_input: unknown) => true);
    const legacyPermission = new Proxy({}, { get: () => { throw new Error("nonexistent client.permission must not be read"); } });
    const showToast = mock(async (_input: unknown) => true);
    const client = {
      postSessionIdPermissionsPermissionId: rootReply,
      permission: legacyPermission,
      tui: { showToast },
    };
    const review = mock(async ({ requestID }: { requestID: string }) => ({ decision: "allow" as const, requestID, sessionID: "review-child", toolCounters: { executable: 0, dataAccess: 0, mcp: 0, web: 0, task: 0 } }));
    const hooks = await SmartApprovePlugin({ client, directory: "/owned/project" } as never, {
      config: { ...DEFAULT_CONFIG, model: { ...DEFAULT_CONFIG.model, enabled: true } },
      shellCompatible: true,
      reviewer: { review },
      policy: async () => ({ status: "model_review", decision: "model_review", reasonCodes: [], parse: undefined, privacy: undefined }),
    });
    await hooks.event?.({ event: {
      type: "permission.asked",
      properties: { id: "permission-42", sessionID: "session-17", permission: "bash", metadata: { command: "printf canary" } },
    } as never });
    await Bun.sleep(5);
    expect(MODEL_APPROVAL_QUALIFIED).toBe(false);
    expect(review).not.toHaveBeenCalled();
    expect(rootReply).not.toHaveBeenCalled();
    expect(showToast).not.toHaveBeenCalled();
    const runtimeConfig: Record<string, unknown> = {};
    await hooks.config?.(runtimeConfig as never);
    expect(runtimeConfig).toMatchObject({
      agent: {
        "smart-approve-reviewer": {
          mode: "subagent",
          model: "opencode-go/mimo-v2.5",
          temperature: 0,
          permission: { bash: "deny", edit: "deny", webfetch: "deny", external_directory: "deny" },
          tools: { "*": false, bash: false, read: false, write: false, mcp: false, task: false },
        },
      },
    });
    expect((runtimeConfig.agent as Record<string, Record<string, unknown>>)["smart-approve-reviewer"].variant).toBeUndefined();
    await hooks.dispose?.();
  });

  test("production global model kill switch cannot be overridden by modelEnabled", async () => {
    const rootReply = mock(async () => true);
    const review = mock(async ({ requestID }: { requestID: string }) => ({ decision: "allow" as const, requestID, sessionID: "child", toolCounters: { executable: 0, dataAccess: 0, mcp: 0, web: 0, task: 0 } }));
    const hooks = await SmartApprovePlugin({ client: { postSessionIdPermissionsPermissionId: rootReply, tui: { showToast: async () => true } }, directory: "/owned/project" } as never, {
      config: { ...DEFAULT_CONFIG, model: { ...DEFAULT_CONFIG.model, enabled: false } },
      modelEnabled: true,
      shellCompatible: true,
      reviewer: { review },
      policy: async () => ({ status: "model_review", decision: "model_review", reasonCodes: [], parse: undefined, privacy: undefined }),
    });
    await hooks.event?.({ event: { type: "permission.asked", properties: { id: "disabled", sessionID: "session", permission: "bash", metadata: { command: "echo safe" } } } as never });
    await Bun.sleep(5);
    expect(review).not.toHaveBeenCalled();
    expect(rootReply).not.toHaveBeenCalled();
    await hooks.dispose?.();
  });

  test("forwards the tagged metadata command unchanged to the real shell", async () => {
    const expectedCommand = "printf 'tagged-runtime:%s\\n' \"$SHELL_TAG\"  ";
    const classifiedCommands: string[] = [];
    const reply = mock(async (_input: unknown) => true);
    const classify = mock(async (command: string) => {
      classifiedCommands.push(command);
      return "allow" as const;
    });
    const handle = createPermissionEventHandler({
      classify,
      approve: createApprovalAdapter({ permission: { reply } }).approve,
    });

    await handle({
      type: "permission.asked",
      properties: {
        id: "tagged-runtime-request",
        permission: "bash",
        metadata: { command: expectedCommand },
      },
    });

    expect(classifiedCommands).toEqual([expectedCommand]);
    const shell = Bun.spawnSync(["/bin/bash", "-c", classifiedCommands[0]!], {
      env: { ...process.env, SHELL_TAG: "observed" },
      stdout: "pipe",
      stderr: "pipe",
    });
    expect(shell.exitCode).toBe(0);
    expect(new TextDecoder().decode(shell.stdout)).toBe("tagged-runtime:observed\n");
    expect(reply).toHaveBeenCalledWith({ requestID: "tagged-runtime-request", reply: "once" });
  });

  test("approves only the exact request ID with the one-shot payload", async () => {
    const replies: unknown[] = [];
    const client = {
      permission: {
        reply: mock(async (input: unknown) => {
          replies.push(input);
          return true;
        }),
      },
    };
    const adapter = createApprovalAdapter(client);
    const classify = mock(async (_command: string) => "allow" as const);
    const handle = createPermissionEventHandler({ classify, approve: adapter.approve });
    const command = "printf 'tagged-shell-command\\n'";

    await handle({
      type: "permission.asked",
      properties: {
        id: "exact-request-id",
        sessionID: "parent-session",
        permission: "bash",
        metadata: { command },
      },
    });

    expect(classify).toHaveBeenCalledWith(command);
    expect(replies).toEqual([{ requestID: "exact-request-id", reply: "once" }]);
    expect(client.permission.reply).toHaveBeenCalledTimes(1);
  });

  test("does not reply when the classifier remains manual", async () => {
    const reply = mock(async (_input: unknown) => true);
    const handle = createPermissionEventHandler({
      classify: async (_command: string) => "manual" as const,
      approve: createApprovalAdapter({ permission: { reply } }).approve,
    });

    await handle({
      type: "permission.asked",
      properties: { id: "manual-request", permission: "bash", metadata: { command: "echo manual" } },
    });

    expect(reply).not.toHaveBeenCalled();
  });

  test("keeps persistent and rejection reply modes out of the approval adapter", () => {
    const source = readFileSync(new URL("../../src/opencode/client.ts", import.meta.url), "utf8");
    expect(source).not.toMatch(/reply\s*:\s*["'](?:always|reject)["']/);
    expect(source).toMatch(/reply\s*:\s*["']once["']/);
  });
});
