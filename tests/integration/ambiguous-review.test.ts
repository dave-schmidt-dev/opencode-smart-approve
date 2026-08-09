import { describe, expect, test } from "bun:test";
import { createReviewerAgent } from "../../src/reviewer/agent";

type Call = { readonly method: string; readonly input: unknown };

function client(response: unknown, calls: Call[] = [], childID = "review-child") {
  return {
    session: {
      create: async (input: unknown) => {
        calls.push({ method: "create", input });
        return { data: { id: childID } };
      },
      prompt: async (input: unknown) => {
        calls.push({ method: "prompt", input });
        return response;
      },
      abort: async (input: unknown) => { calls.push({ method: "abort", input }); },
      delete: async (input: unknown) => { calls.push({ method: "delete", input }); },
    },
  };
}

const allowMessage = {
  data: {
    info: { id: "assistant-message", role: "assistant" },
    parts: [{ type: "text", text: '{"decision":"allow","reasonCodes":["safe"]}' }],
  },
};

describe("isolated reviewer decisions", () => {
  test("each eligible request needs exactly one matching schema-valid reviewer result", async () => {
    for (const [index, prompt] of ["echo hello", "printf --version"].entries()) {
      const requestID = `eligible-${index}`;
      const calls: Call[] = [];
      const result = await createReviewerAgent({ client: client(allowMessage, calls) }).review({ requestID, prompt });

      expect(result.decision).toBe("allow");
      expect(result.requestID).toBe(requestID);
      expect(calls.filter((call) => call.method === "create")).toHaveLength(1);
      expect(calls.filter((call) => call.method === "prompt")).toHaveLength(1);
      expect(calls.find((call) => call.method === "create")?.input).toMatchObject({
        body: { title: `smart-approve:${requestID}` },
      });
      expect(Object.keys((calls.find((call) => call.method === "create")?.input as { body: object }).body)).toEqual(["title"]);
      expect(calls.map((call) => call.method)).toEqual(["create", "prompt", "abort", "delete"]);
    }
  });

  test.each([
    ["empty", undefined, "empty"],
    ["malformed", { data: { parts: [{ type: "text", text: "not-json" }] } }, "malformed"],
    ["uncertain", { data: { decision: "maybe", reasonCodes: ["uncertain"] } }, "uncertain"],
    ["unknown reason", { data: { decision: "allow", reasonCodes: ["unknown"] } }, "uncertain"],
    ["allow without enumerated safe reason", { data: { decision: "allow" } }, "uncertain"],
    ["truncated", { data: { parts: [{ type: "text", text: '{"decision":"allow"' }] } }, "truncated"],
  ] as const)("%s output returns manual", async (_label, response, reasonCode) => {
    const result = await createReviewerAgent({ client: client(response) }).review({ requestID: `case-${reasonCode}`, prompt: "echo hello" });
    expect(result.decision).toBe("manual");
    expect(result.reasonCodes).toEqual([reasonCode]);
  });

  test("inconsistent valid response parts return manual", async () => {
    const result = await createReviewerAgent({ client: client({ data: {
      parts: [
        { type: "text", text: '{"decision":"allow","reasonCodes":["safe"]}' },
        { type: "text", text: '{"decision":"manual","reasonCodes":["ambiguous"]}' },
      ],
    } }) }).review({ requestID: "case-inconsistent", prompt: "echo hello" });
    expect(result.decision).toBe("manual");
    expect(result.reasonCodes).toEqual(["inconsistent"]);
  });

  test("accepts an exact fenced JSON object but rejects fenced prose", async () => {
    const accepted = await createReviewerAgent({ client: client({ data: { parts: [{ type: "text", text: '```json\n{"decision":"allow","reasonCodes":["safe"]}\n```' }] } }) }).review({ requestID: "fenced-json", prompt: "echo hello" });
    expect(accepted.decision).toBe("allow");
    const rejected = await createReviewerAgent({ client: client({ data: { parts: [{ type: "text", text: 'result:\n```json\n{"decision":"allow","reasonCodes":["safe"]}\n```' }] } }) }).review({ requestID: "fenced-prose", prompt: "echo hello" });
    expect(rejected.decision).toBe("manual");
  });

  test("accepts the OpenCode structured assistant field", async () => {
    const result = await createReviewerAgent({ client: client({ data: { info: { role: "assistant", structured: { decision: "allow", reasonCodes: ["safe"] } }, parts: [] } }) }).review({ requestID: "structured-output", prompt: "echo hello" });
    expect(result.decision).toBe("allow");
  });

  test("provider errors return manual without exposing provider text", async () => {
    const calls: Call[] = [];
    const failing = client(undefined, calls);
    failing.session.prompt = async () => { throw new Error("CANARY_SECRET_VALUE provider failure"); };
    const result = await createReviewerAgent({ client: failing }).review({ requestID: "provider-error", prompt: "echo hello" });
    expect(result.decision).toBe("manual");
    expect(result.reasonCodes).toEqual(["provider_error"]);
    expect(JSON.stringify(result)).not.toContain("CANARY_SECRET_VALUE");
  });

  test("timeout aborts and deletes only the exact child before returning manual", async () => {
    const calls: Call[] = [];
    const pending = client(undefined, calls, "exact-timeout-child");
    pending.session.prompt = () => new Promise(() => undefined);
    const result = await createReviewerAgent({ client: pending, timeoutMs: 5, directory: "/project" }).review({ requestID: "timeout-request", prompt: "echo hello" });

    expect(result.decision).toBe("manual");
    expect(result.reasonCodes).toEqual(["timeout"]);
    expect(calls.filter((call) => call.method === "abort").map((call) => call.input)).toEqual([
      { path: { id: "exact-timeout-child" }, query: { directory: "/project" } },
    ]);
    expect(calls.filter((call) => call.method === "delete").map((call) => call.input)).toEqual([
      { path: { id: "exact-timeout-child" }, query: { directory: "/project" } },
    ]);
  });
});
