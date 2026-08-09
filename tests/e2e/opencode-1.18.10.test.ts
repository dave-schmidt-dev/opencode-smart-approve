import { readFileSync, statSync } from "node:fs";
import { describe, expect, mock, test } from "bun:test";
import { createSmartApproveHooks } from "../../src/plugin";
import { createReviewerAgent, ZERO_TOOL_COUNTERS } from "../../src/reviewer/agent";
import { createDisposableOpenCode, runOpenCodeVersion } from "../../scripts/e2e-opencode";

const fixturePath = new URL("../fixtures/opencode/opencode.jsonc", import.meta.url).pathname;
const asked = (id: string, command: string) => ({
  type: "permission.asked",
  properties: { id, sessionID: "parent", permission: "bash", metadata: { command } },
});
const tick = (ms = 25) => new Promise<void>((resolve) => setTimeout(resolve, ms));

describe("OpenCode 1.18.10 disposable integration", () => {
  test("smoke uses the installed binary and isolated XDG config/data", async () => {
    const sandbox = await createDisposableOpenCode({ fixturePath });
    try {
      const result = runOpenCodeVersion(sandbox);
      expect(result.exitCode).toBe(0);
      expect(result.stdout.trim()).toBe("1.18.10");
      expect(readFileSync(sandbox.configPath, "utf8")).toContain('"plugin"');
      expect(readFileSync(sandbox.configPath, "utf8")).toContain('"bash": "ask"');
      const sessionMarker = `${sandbox.dataHome}/session-marker`;
      await Bun.write(sessionMarker, "pending");
      await sandbox.removeLoader();
      expect(readFileSync(sandbox.configPath, "utf8")).not.toContain('"plugin"');
      expect(readFileSync(sessionMarker, "utf8")).toBe("pending");
      expect(statSync(sandbox.dataHome).isDirectory()).toBe(true);
    } finally {
      await sandbox.cleanup();
    }
  });

  test("plugin-load failure leaves the native shell request pending", async () => {
    const sandbox = await createDisposableOpenCode({ fixturePath });
    const pending = new Set(["load-failure"]);
    const hooks = createSmartApproveHooks({ approve: mock(async (id: string) => { pending.delete(id); }) });
    try {
      // The disposable loader throws before hooks can register. The native
      // request therefore remains pending and has no approval callback.
      expect(readFileSync(sandbox.configPath, "utf8")).toContain("loader.mjs");
      await hooks.event({ event: asked("load-failure", "printf native-prompt") });
      await tick();
      expect(pending.has("load-failure")).toBe(true);
    } finally {
      await hooks.dispose();
      await sandbox.cleanup();
    }
  });

  test("model approval remains disabled even for a matching allow result", async () => {
    const pending = new Set(["model-allow"]);
    const promptBodies: unknown[] = [];
    const reviewer = createReviewerAgent({
      client: {
        session: {
          create: async () => ({ data: { id: "review-model-allow" } }),
          prompt: async (input: unknown) => { promptBodies.push(input); return { data: { decision: "allow", reasonCodes: ["safe"] } }; },
          abort: async () => undefined,
          delete: async () => undefined,
        },
      },
    });
    const hooks = createSmartApproveHooks({ reviewer, approve: async (id) => { pending.delete(id); } });
    try {
      await hooks.event({ event: asked("model-allow", "printf safe") });
      await tick();
      expect(promptBodies).toHaveLength(0);
      expect(pending.has("model-allow")).toBe(true);
      expect(hooks.state("model-allow")).toBe("manual");
    } finally {
      await hooks.dispose();
    }
  });

  test("unsafe and disabled-model requests preserve the pending prompt", async () => {
    const pending = new Set(["unsafe", "timeout", "error"]);
    const review = mock(async () => { throw new Error("provider must not be called"); });
    const hooks = createSmartApproveHooks({
      reviewer: { review },
      approve: async (id) => { pending.delete(id); },
    });
    try {
      await hooks.event({ event: asked("unsafe", "rm -rf /tmp/not-safe") });
      await hooks.event({ event: asked("timeout", "printf waits") });
      await hooks.event({ event: asked("error", "printf fails") });
      await tick(40);
      expect(pending.has("unsafe")).toBe(true);
      expect(pending.has("timeout")).toBe(true);
      expect(pending.has("error")).toBe(true);
      expect(hooks.state("unsafe")).toBe("manual");
      expect(hooks.state("timeout")).toBe("manual");
      expect(hooks.state("error")).toBe("manual");
      expect(review).not.toHaveBeenCalled();
    } finally {
      await hooks.dispose();
    }
  });

  test("disabled model does not attempt a user-first reply race", async () => {
    const reply = mock(async () => { throw new Error("permission not found"); });
    const hooks = createSmartApproveHooks({
      reviewer: { review: async () => ({ decision: "allow" as const, requestID: "race", sessionID: "race-review", toolCounters: ZERO_TOOL_COUNTERS }) },
      approve: reply,
    });
    try {
      await hooks.event({ event: asked("race", "printf race") });
      await tick();
      expect(reply).not.toHaveBeenCalled();
      expect(hooks.state("race")).toBe("manual");
    } finally {
      await hooks.dispose();
    }
  });
});
