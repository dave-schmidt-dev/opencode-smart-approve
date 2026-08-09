import { readFileSync } from "node:fs";
import { describe, expect, mock, test } from "bun:test";
import { createApprovalAdapter } from "../../src/opencode/client";
import { createPermissionEventHandler } from "../../src/opencode/permission-event";

describe("one-shot OpenCode permission reply", () => {
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
