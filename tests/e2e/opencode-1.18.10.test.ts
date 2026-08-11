import { readFileSync, statSync } from "node:fs";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, mock, spyOn, test } from "bun:test";
import { createSmartApproveHooks } from "../../src/plugin";
import { createReviewerAgent, ZERO_TOOL_COUNTERS } from "../../src/reviewer/agent";
import {
  createDisposableOpenCode,
  REQUIRED_OPENCODE_VERSION,
  requireOpenCodeVersion,
  runOpenCodeVersion,
} from "../../scripts/e2e-opencode";

const fixturePath = new URL("../fixtures/opencode/opencode.jsonc", import.meta.url).pathname;
const asked = (id: string, command: string) => ({
  type: "permission.asked",
  properties: { id, sessionID: "parent", permission: "bash", metadata: { command } },
});
const tick = (ms = 25) => new Promise<void>((resolve) => setTimeout(resolve, ms));

describe("OpenCode 1.18.10 disposable integration", () => {
  test("smoke uses the installed binary and isolated XDG config/data/cache", async () => {
    const sandbox = await createDisposableOpenCode({ fixturePath });
    try {
      const result = runOpenCodeVersion(sandbox);
      expect(result.exitCode).toBe(0);
      expect(result.stdout.trim()).toBe("1.18.10");
      expect(readFileSync(sandbox.configPath, "utf8")).toContain('"plugin"');
      expect(readFileSync(sandbox.configPath, "utf8")).toContain('"bash": "ask"');
      expect(statSync(sandbox.cacheHome).isDirectory()).toBe(true);
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

  test("version seam defaults locally and rejects mismatched, malformed, empty, and failed overrides", async () => {
    const sandbox = await createDisposableOpenCode({ fixturePath });
    const fakeBin = await mkdtemp(join(tmpdir(), "smart-approve-fake-opencode-"));
    try {
      const mismatchedBinary = join(fakeBin, "opencode");
      await writeFile(mismatchedBinary, "#!/bin/sh\nprintf '1.18.15\\n'\n", "utf8");
      await chmod(mismatchedBinary, 0o755);

      const exact = requireOpenCodeVersion(sandbox, { ...process.env, OPENCODE_BIN: undefined, PATH: fakeBin });
      expect(exact.stdout.trim()).toBe(REQUIRED_OPENCODE_VERSION);

      const mismatchedOverride = { ...process.env, OPENCODE_BIN: mismatchedBinary, PATH: fakeBin };
      expect(() => requireOpenCodeVersion(sandbox, mismatchedOverride)).toThrow("OpenCode 1.18.10 is required");

      for (const [name, body] of [
        ["malformed", "printf 'not-a-version\\n'\n"],
        ["empty", "exit 0\n"],
        ["failed", "exit 7\n"],
      ] as const) {
        const binary = join(fakeBin, name);
        await writeFile(binary, `#!/bin/sh\n${body}`, "utf8");
        await chmod(binary, 0o755);
        expect(() => requireOpenCodeVersion(sandbox, { ...process.env, OPENCODE_BIN: binary })).toThrow(
          "OpenCode 1.18.10 is required",
        );
      }
    } finally {
      await rm(fakeBin, { recursive: true, force: true });
      await sandbox.cleanup();
    }
  });

  test("version seam rejects missing and non-executable explicit overrides before spawning", async () => {
    const sandbox = await createDisposableOpenCode({ fixturePath });
    const fakeBin = await mkdtemp(join(tmpdir(), "smart-approve-non-executable-opencode-"));
    const nonExecutableBinary = join(fakeBin, "opencode");
    const spawn = spyOn(Bun, "spawnSync");
    try {
      await writeFile(nonExecutableBinary, "#!/bin/sh\nprintf '1.18.10\\n'\n", "utf8");
      await chmod(nonExecutableBinary, 0o644);

      expect(() => requireOpenCodeVersion(sandbox, { ...process.env, OPENCODE_BIN: join(fakeBin, "missing") })).toThrow(
        "OpenCode 1.18.10 is required",
      );
      expect(() => requireOpenCodeVersion(sandbox, { ...process.env, OPENCODE_BIN: fakeBin })).toThrow(
        "OpenCode 1.18.10 is required",
      );
      expect(() => requireOpenCodeVersion(sandbox, { ...process.env, OPENCODE_BIN: nonExecutableBinary })).toThrow(
        "OpenCode 1.18.10 is required",
      );
      expect(spawn).not.toHaveBeenCalled();
    } finally {
      spawn.mockRestore();
      await rm(fakeBin, { recursive: true, force: true });
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
