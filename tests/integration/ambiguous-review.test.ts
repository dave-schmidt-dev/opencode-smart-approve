import { describe, expect, test } from "bun:test";
import { createReviewerAgent } from "../../src/reviewer/agent";

function client(response: unknown, calls: string[] = []) {
  return {
    session: {
      create: async () => ({ data: { id: "review-child" } }),
      prompt: async () => response,
      abort: async () => { calls.push("abort:review-child"); },
      delete: async () => { calls.push("delete:review-child"); },
    },
  };
}

describe("isolated reviewer decisions", () => {
  test("allows only a matching valid JSON result", async () => {
    const result = await createReviewerAgent({ client: client({ data: { decision: "allow", reasonCodes: ["safe"] } }) }).review({ requestID: "r1", prompt: "echo hello" });
    expect(result.decision).toBe("allow");
  });

  test.each([undefined, { data: { decision: "maybe" } }, { data: { decision: "allow", reasonCodes: ["unknown"] } }])(
    "fails closed for malformed or uncertain output (%j)", async (response) => {
      const result = await createReviewerAgent({ client: client(response) }).review({ requestID: "r2", prompt: "echo hello" });
      expect(result.decision).toBe("manual");
    },
  );

  test("fails closed when response parts disagree", async () => {
    const result = await createReviewerAgent({ client: client({ data: {
      parts: [
        { type: "text", text: '{"decision":"allow","reasonCodes":["safe"]}' },
        { type: "text", text: '{"decision":"manual","reasonCodes":["ambiguous"]}' },
      ],
    } }) }).review({ requestID: "r-inconsistent", prompt: "echo hello" });
    expect(result.decision).toBe("manual");
  });

  test("provider errors and timeout are manual and clean up the exact child", async () => {
    const calls: string[] = [];
    const pending = client(undefined, calls);
    pending.session.prompt = () => new Promise(() => undefined);
    const result = await createReviewerAgent({ client: pending, timeoutMs: 10 }).review({ requestID: "r3", prompt: "echo hello" });
    expect(result.decision).toBe("manual");
    expect(calls).toEqual(["abort:review-child", "delete:review-child"]);
  });
});
