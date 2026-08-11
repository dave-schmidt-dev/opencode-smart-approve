import { describe, expect, mock, test } from "bun:test";
import { createReviewerAgent } from "../../src/reviewer/agent";
import { redactCommand } from "../../src/reviewer/prompt";

describe("reviewer isolation", () => {
  test("preserves only bounded operation vocabulary", () => {
    expect(redactCommand("git status --short")).toBe("git status --short");
    expect(redactCommand("git checkout private-feature-name")).toBe("git <arg> <arg>");
  });
  test("keeps redaction idempotent across multi-shape and sentinel-spoof inputs", () => {
    for (const command of [
      "echo value | less README.md",
      "env FOO=bar git status --short",
      "printf '%s' \"quoted value\" > output.txt",
      "git show HEAD:path/to/file && cat ./README.md",
      `echo ${String.fromCharCode(1)}0${String.fromCharCode(1)}`,
      "<arg> date",
    ]) {
      const once = redactCommand(command);
      expect(redactCommand(once)).toBe(once);
    }
    expect(redactCommand("<arg> date")).toBe("<arg> <arg>");
  });
  test("uses a deny-all child and sends only bounded redacted facts", async () => {
    let createInput: any;
    let promptInput: any;
    const forbiddenCapability = mock(async () => { throw new Error("must not be called"); });
    const client = {
      file: { read: forbiddenCapability },
      mcp: { status: forbiddenCapability },
      session: {
        create: async (input: unknown) => { createInput = input; return { data: { id: "child" } }; },
        prompt: async (input: unknown) => {
          promptInput = input;
          return { data: { decision: "manual", reasonCodes: ["ambiguous"] } };
        },
        abort: async () => true,
        delete: async () => true,
      },
    };
    await createReviewerAgent({ client, directory: "/project" }).review({
      requestID: "redaction-request",
      prompt: "echo CANARY_SECRET_VALUE > /tmp/result",
      parserFeatures: { pipeline: false, segmentCount: 1, unsupported: ["none"], CANARY_SECRET_VALUE: "CANARY_SECRET_VALUE" },
      policyFacts: ["parser.clear", "CANARY_SECRET_VALUE"],
      pathClasses: ["project", "external"],
    });

    const outbound = JSON.stringify({ createInput, promptInput });
    expect(outbound).not.toContain("CANARY_SECRET_VALUE");
    expect(createInput).toMatchObject({
      body: {
        title: "smart-approve:redaction-request",
      },
      query: { directory: "/project" },
    });
    expect(Object.keys(createInput.body)).toEqual(["title"]);
    expect(promptInput.body.agent).toBe("smart-approve-reviewer");
    expect(promptInput.body.model).toEqual({ providerID: "opencode-go", modelID: "deepseek-v4-flash" });
    expect(promptInput.body.format).toMatchObject({ type: "json_schema", retryCount: 0, schema: { additionalProperties: false } });
    expect(promptInput.body.variant).toBeUndefined();
    expect(promptInput.body.tools["*"]).toBe(false);
    for (const tool of ["bash", "read", "write", "edit", "mcp", "webfetch", "websearch", "network", "task", "skill"]) {
      expect(promptInput.body.tools[tool]).toBe(false);
    }
    expect(Object.values(promptInput.body.tools).every((value) => value === false)).toBe(true);
    const payload = JSON.parse(promptInput.body.parts[0].text.split("\n").at(-1));
    expect(promptInput.body.parts[0].text).toContain('For allow, return exactly {"decision":"allow","reasonCodes":["safe"]}.');
    expect(promptInput.body.parts[0].text).toContain("Everything reaching you already passed upstream checks for mutation");
    expect(payload).toEqual({
      redactedCommand: "echo <arg>><arg>",
      parserFeatures: { pipeline: false, segmentCount: 1, unsupported: ["none"] },
      policyFacts: ["parser.clear", "redacted"],
      pathClasses: ["project", "external"],
    });
    expect(forbiddenCapability).not.toHaveBeenCalled();
  });

  test("a reviewer-owned permission request is rejected and latches parent review to manual", async () => {
    const reject = mock(async () => true);
    const fallbackReply = mock(async () => true);
    let release!: (value: unknown) => void;
    let promptStarted!: () => void;
    const started = new Promise<void>((resolve) => { promptStarted = resolve; });
    const client = {
      postSessionIdPermissionsPermissionId: reject,
      permission: { reply: fallbackReply },
      session: {
        create: async () => ({ data: { id: "child" } }),
        prompt: async () => new Promise((resolve) => { release = resolve; promptStarted(); }),
        abort: async () => true,
        delete: async () => true,
      },
    };
    const reviewer = createReviewerAgent({ client, timeoutMs: 1_000, directory: "/project" });
    const pending = reviewer.review({ requestID: "parent", prompt: "echo hello" });
    await started;

    expect(await reviewer.handlePermission({ requestID: "unrelated", sessionID: "other-child" })).toBe(false);
    expect(await reviewer.handlePermission({ requestID: "nested", sessionID: "child" })).toBe(true);
    expect(reject).toHaveBeenCalledTimes(1);
    expect(reject).toHaveBeenCalledWith({
      path: { id: "child", permissionID: "nested" },
      body: { response: "reject" },
      query: { directory: "/project" },
    });
    expect(fallbackReply).not.toHaveBeenCalled();
    release({ data: { decision: "allow", reasonCodes: ["safe"] } });
    const result = await pending;
    expect(result.decision).toBe("manual");
    expect(result.reasonCodes).toEqual(["permission_violation"]);
  });

  test("keeps child ownership visible while cleanup is in flight", async () => {
    const reject = mock(async () => true);
    let releaseAbort!: () => void;
    let abortStarted!: () => void;
    const abortGate = new Promise<void>((resolve) => { releaseAbort = resolve; });
    const abortReady = new Promise<void>((resolve) => { abortStarted = resolve; });
    const client = {
      postSessionIdPermissionsPermissionId: reject,
      session: {
        create: async () => ({ data: { id: "teardown-child" } }),
        prompt: async () => ({ data: { decision: "manual", reasonCodes: ["manual"] } }),
        abort: async () => { abortStarted(); await abortGate; },
        delete: async () => true,
      },
    };
    const reviewer = createReviewerAgent({ client, timeoutMs: 1_000, directory: "/project" });
    const pending = reviewer.review({ requestID: "teardown-parent", prompt: "echo hello" });
    await abortReady;

    expect(reviewer.isPluginSession("teardown-child")).toBe(true);
    expect(await reviewer.handlePermission({ requestID: "teardown-nested", sessionID: "teardown-child" })).toBe(true);
    expect(reject).toHaveBeenCalledTimes(1);

    releaseAbort();
    expect((await pending).decision).toBe("manual");
    expect(reviewer.isPluginSession("teardown-child")).toBe(false);
  });

  test("uses the flattened v2 reject API only when the root endpoint is unavailable", async () => {
    const reply = mock(async () => true);
    let release!: (value: unknown) => void;
    let promptStarted!: () => void;
    const started = new Promise<void>((resolve) => { promptStarted = resolve; });
    const reviewer = createReviewerAgent({
      directory: "/project",
      client: {
        permission: { reply },
        session: {
          create: async () => ({ data: { id: "v2-child" } }),
          prompt: async () => new Promise((resolve) => { release = resolve; promptStarted(); }),
          abort: async () => true,
          delete: async () => true,
        },
      },
    });
    const pending = reviewer.review({ requestID: "v2-parent", prompt: "echo hello" });
    await started;
    expect(await reviewer.handlePermission({ requestID: "v2-nested", sessionID: "v2-child" })).toBe(true);
    expect(reply).toHaveBeenCalledWith({ requestID: "v2-nested", directory: "/project", reply: "reject" });
    release({ data: { decision: "allow", reasonCodes: ["safe"] } });
    expect((await pending).decision).toBe("manual");
  });

  test("real tool parts force manual even if accompanying text says allow", async () => {
    const client = {
      session: {
        create: async () => ({ data: { id: "child" } }),
        prompt: async () => ({ data: {
          parts: [
            { type: "tool", tool: "mcp_database_query", state: { status: "completed" } },
            { type: "text", text: '{"decision":"allow","reasonCodes":["safe"]}' },
          ],
        } }),
        abort: async () => true,
        delete: async () => true,
      },
    };
    const result = await createReviewerAgent({ client }).review({ requestID: "tool-use", prompt: "echo hello" });
    expect(result.decision).toBe("manual");
    expect(result.reasonCodes).toEqual(["tool_violation"]);
    expect(result.toolCounters.mcp).toBe(1);
  });
});
