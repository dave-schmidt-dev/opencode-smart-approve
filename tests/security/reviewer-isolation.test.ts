import { describe, expect, mock, test } from "bun:test";
import { readFileSync } from "node:fs";
import { createReviewerAgent } from "../../src/reviewer/agent";
import { buildReviewerPrompt, redactCommand } from "../../src/reviewer/prompt";
import { evaluateDeterministicPolicy } from "../../src/policy/deterministic";

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
    expect(promptInput.body.variant).toBe("low");
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

/**
 * The reviewer's vocabulary lives in three places -- `SAFE_EXECUTABLES` in the
 * redactor, the allow sentence, and the manual sentence -- and a name present in
 * the first but absent from the other two falls to the "does not clearly match
 * the allow list above" catch-all. That is always a false manual and never a
 * false approval, so it fails quietly: the gate reports a number, not a defect.
 *
 * It has now happened twice, both times because something upstream improved.
 * `cut`/`join`/`readlink`/`sort`/`tr`/`uniq` were forwardable but unnamed; then
 * on the 2026-08-27 v3 draw `jq`, `nl`, `shasum`, `grep`, `sed` and `cd` reached
 * the reviewer for the first time because the deterministic layer stopped
 * intercepting them, against a prompt nobody had extended to meet them. That
 * cost 37 of the draw's 42 benign false manuals and blocked the release.
 *
 * These tests read the corpus rather than restating a list, so the check tracks
 * what actually routes to the reviewer instead of what someone believed routed
 * there when they last edited a constant.
 */
describe("reviewer vocabulary gaps", () => {
  const prompt = buildReviewerPrompt({ redactedCommand: "pwd" }).split("\n");
  const allowSentence = prompt.find((line) => line.startsWith("Allow a plain")) ?? "";
  const manualSentence = prompt.find((line) => line.startsWith("Return manual for")) ?? "";

  /** Leading executable, skipping the wrappers the redactor also skips. */
  const leadingExecutable = (command: string): string => {
    const words = command.trim().split(/[;|&()<>\s]+/);
    let index = 0;
    while (index < words.length - 1 && (words[index] === "command" || words[index] === "env")) index += 1;
    return (words[index] ?? "").split("/").at(-1)?.toLowerCase() ?? "";
  };

  test("names every executable the corpus expects allowed and the policy routes to the reviewer", async () => {
    const corpus = JSON.parse(readFileSync("fixtures/eval/development.json", "utf8")) as {
      corpus: { fixtures: readonly { id: string; category: string; command: string; expectedDecision: string }[] };
    };
    const unnamed: string[] = [];
    for (const fixture of corpus.corpus.fixtures) {
      if (fixture.category !== "benign" || fixture.expectedDecision !== "allow") continue;
      const routed = await evaluateDeterministicPolicy(fixture.command);
      if (routed.decision !== "model_review") continue;
      const executable = leadingExecutable(fixture.command);
      // A bare name can appear inside a longer word, so match on a boundary.
      const named = new RegExp(`(?:^|[\\s:,])${executable}(?=[\\s,./]|$)`).test(allowSentence);
      if (!named) unnamed.push(`${fixture.id} (${executable})`);
    }
    expect(unnamed).toEqual([]);
  });

  test("forwards read-only tools under their own name rather than the refused marker", () => {
    // `<command>` is the first thing the manual sentence refuses, so a redacted
    // name is not a degraded hint -- it is a decided outcome.
    expect(manualSentence).toContain("<command>");
    for (const command of ["jq <arg>", "nl README.md", "shasum -a 256 README.md", "grep -n TODO README.md", "cd src"]) {
      expect(redactCommand(command)).not.toContain("<command>");
    }
  });

  test("shows the reviewer sed's in-place flag whatever suffix it carries", () => {
    // `-i.bak` fails the flag-shape test on the dot and used to render as a
    // generic <arg>, hiding the write form from the rule written to refuse it.
    expect(redactCommand("sed -i.bak 's/a/b/' README.md")).toBe("sed -i <arg> <arg>");
    expect(redactCommand("sed --in-place=.bak 's/a/b/' README.md")).toBe("sed --in-place <arg> <arg>");
    expect(manualSentence).toContain("sed -i");
  });

  test("states the compound-command safety rule and preserves every segment", () => {
    const compoundRule = prompt.find((line) => line.startsWith("Allow a pipeline, && chain")) ?? "";
    const examples = prompt.find((line) => line.startsWith("Required allow examples")) ?? "";
    expect(compoundRule).toContain("every segment independently matches");
    expect(compoundRule).toContain("otherwise manual segment");
    expect(compoundRule).toContain("semicolon-separated");
    expect(examples).toContain("git status --short && git diff --stat");
    expect(examples).toContain("rg --files | sort");
    expect(examples).toContain("pwd; git status --short");
    expect(examples).toContain("<arg>");
    expect(examples).toContain("not missing evidence");
    expect(manualSentence).toContain("any || or background & operator");
    expect(redactCommand("git status && git diff --stat")).toBe("git status&&git diff --stat");
    expect(redactCommand("sed -n '1,5p' README.md | nl")).toBe("sed -n <arg> <arg>|nl");
    expect(redactCommand("printf x | tee README.md")).toBe("printf <arg>|tee <arg>");
    expect(allowSentence).not.toMatch(/(?:^|[\s:,])tee(?=[\s,./]|$)/);
    expect(manualSentence).toContain("does not clearly match the allow list");
  });
});
