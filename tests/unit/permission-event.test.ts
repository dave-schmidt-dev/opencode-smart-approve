import { describe, expect, mock, test } from "bun:test";
import {
  createPermissionEventHandler,
  parsePermissionAskedEvent,
} from "../../src/opencode/permission-event";

const asked = (properties: Record<string, unknown>) => ({
  type: "permission.asked",
  properties,
});

describe("permission.asked runtime adapter", () => {
  test("accepts bash and extracts metadata.command without rewriting it", () => {
    const command = "printf 'tagged-source:%s\\n' \"$SHELL_TAG\"  ";
    const request = parsePermissionAskedEvent(
      asked({ id: "request-1", sessionID: "session-1", permission: "bash", metadata: { command } }),
    );

    expect(request).toEqual({
      requestID: "request-1",
      sessionID: "session-1",
      permission: "bash",
      command,
    });
  });

  test("accepts the generated SDK data envelope as well as the plugin properties envelope", () => {
    expect(
      parsePermissionAskedEvent({
        type: "permission.asked",
        data: { id: "request-2", permission: "bash", metadata: { command: "echo fixture" } },
      })?.command,
    ).toBe("echo fixture");
  });

  test.each([
    undefined,
    null,
    {},
    { type: "permission.replied", properties: {} },
    asked({ id: "request-3", permission: "read", metadata: { command: "echo no" } }),
    asked({ id: "request-4", permission: "bash", metadata: {} }),
    asked({ id: "request-5", permission: "bash", metadata: { command: 42 } }),
    asked({ id: "request-6", permission: "bash", metadata: { command: "" } }),
  ])("ignores malformed, non-bash, and missing-command events (%p)", (event) => {
    expect(parsePermissionAskedEvent(event)).toBeUndefined();
  });

  test("invalid events produce no classifier call or reply", async () => {
    const classify = mock(async (_command: string) => true);
    const approve = mock(async (_requestID: string) => undefined);
    const handle = createPermissionEventHandler({ classify, approve });

    await handle(asked({ id: "request-7", permission: "file", metadata: { command: "echo no" } }));
    await handle(asked({ id: "request-8", permission: "bash", metadata: { command: 42 } }));
    await handle({ type: "permission.asked", properties: { id: "request-9", permission: "bash" } });

    expect(classify).not.toHaveBeenCalled();
    expect(approve).not.toHaveBeenCalled();
  });
});
