import { describe, expect, mock, test } from "bun:test";
import { createReviewerAgent } from "../../src/reviewer/agent";

describe("reviewer isolation", () => {
  test("sends redacted data-only input with every tool disabled", async () => {
    let promptInput: any;
    const client = {
      session: {
        create: async () => ({ data: { id: "child" } }),
        prompt: async (input: unknown) => { promptInput = input; return { data: { decision: "manual", reasonCodes: ["ambiguous"] } }; },
        abort: async () => true,
        delete: async () => true,
      },
    };
    await createReviewerAgent({ client }).review({ requestID: "r", prompt: "echo CANARY_SECRET_VALUE" });
    expect(JSON.stringify(promptInput)).not.toContain("CANARY_SECRET_VALUE");
    expect(Object.values(promptInput.body.tools).every((value: unknown) => value === false)).toBe(true);
  });

  test("rejects reviewer-owned permission requests and never approves the parent", async () => {
    const reject = mock(async () => true);
    let release!: (value: unknown) => void;
    const client = {
      permission: { reply: reject },
      session: {
        create: async () => ({ data: { id: "child" } }),
        prompt: async () => new Promise((resolve) => { release = resolve; }),
        abort: async () => true,
        delete: async () => true,
      },
    };
    const reviewer = createReviewerAgent({ client, timeoutMs: 1_000 });
    const pending = reviewer.review({ requestID: "parent", prompt: "echo hello" });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(await reviewer.handlePermission({ requestID: "nested", sessionID: "child" })).toBe(true);
    expect(reject).toHaveBeenCalledWith({ requestID: "nested", reply: "reject" });
    release({ data: { decision: "manual", reasonCodes: ["tool_violation"] } });
    expect((await pending).decision).toBe("manual");
  });

  test("does not allow a response that reports tool use", async () => {
    const client = {
      session: {
        create: async () => ({ data: { id: "child" } }),
        prompt: async () => ({ data: { decision: "allow", reasonCodes: ["safe"], toolCounters: { executable: 1 } } }),
        abort: async () => true,
        delete: async () => true,
      },
    };
    const result = await createReviewerAgent({ client }).review({ requestID: "r-tools", prompt: "echo hello" });
    expect(result.decision).toBe("manual");
    expect(result.reasonCodes).toEqual(["tool_violation"]);
  });
});
