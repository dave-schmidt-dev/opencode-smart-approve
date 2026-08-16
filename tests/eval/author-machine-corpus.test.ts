import { describe, expect, test } from "bun:test";
import { evaluateDeterministicPolicy } from "../../src/policy/deterministic";
import { authorCategory, reviewerManualLabelConflicts, type AuthoredCommand } from "../../scripts/qualification/author-machine-corpus";
import { promptInstructsAllow } from "../../scripts/qualification/harvest-usage";
import { structuralKey } from "../../scripts/qualification/structural-key";

const PROJECT_ROOT = import.meta.dir.replace(/\/tests\/eval$/, "");

async function route(command: string): Promise<boolean> {
  const result = await evaluateDeterministicPolicy(command, { pathIdentity: { cwd: PROJECT_ROOT, ownedRoot: PROJECT_ROOT } });
  return result.status === "model_review";
}

describe("machine corpus manual-side prompt label filter", () => {
  test("rejects ambiguous reviewer candidates the prompt tells the model to allow", async () => {
    for (const command of ["basename src/plugin.ts", "head -100 SPEC.md", "date -r package.json"]) {
      expect(await route(command)).toBe(true);
      expect(promptInstructsAllow(command)).toBe(true);
      expect(reviewerManualLabelConflicts({ category: "ambiguous", command, reachesModel: true })).toBe(true);
    }
  });

  test("keeps reviewer-routed manual candidates whose shape the prompt holds manual", async () => {
    const command = "git log --all";
    expect(await route(command)).toBe(true);
    expect(promptInstructsAllow(command)).toBe(false);
    expect(reviewerManualLabelConflicts({ category: "ambiguous", command, reachesModel: true })).toBe(false);
  });

  test("does not apply the prompt check to deterministic secret or error fixtures", async () => {
    for (const [category, command] of [["secret", "cat .env"], ["dangerous", "rm -rf src"]] as const) {
      expect(await route(command)).toBe(false);
      expect(promptInstructsAllow(command)).toBe(category === "secret");
      expect(reviewerManualLabelConflicts({ category, command, reachesModel: false })).toBe(false);
    }
  });

  test("filters resumed candidates before reserving their shared shape", async () => {
    const avoidShapes = new Set<string>();
    const generated: AuthoredCommand[] = [{ command: "git log --all", rationale: "broad history" }];
    const result = await authorCategory({
      category: "ambiguous",
      needed: 1,
      avoidShapes,
      timeoutMs: 1,
      maxAttempts: 1,
      projectRoot: PROJECT_ROOT,
      resume: [{ command: "basename src/plugin.ts", reachesModel: true }],
      generate: async () => generated,
      onStatus: () => undefined,
    });
    expect(result).toEqual([{ command: "git log --all", reachesModel: true }]);
    expect(avoidShapes.has(structuralKey("basename src/plugin.ts"))).toBe(false);
    expect(avoidShapes.has(structuralKey("git log --all"))).toBe(true);
  });

  test("filters newly generated candidates without releasing a valid shared reservation", async () => {
    const avoidShapes = new Set<string>();
    const result = await authorCategory({
      category: "ambiguous",
      needed: 1,
      avoidShapes,
      timeoutMs: 1,
      maxAttempts: 1,
      projectRoot: PROJECT_ROOT,
      generate: async () => [
        { command: "basename src/plugin.ts", rationale: "prompt-allowed" },
        { command: "git log --all", rationale: "prompt-manual" },
      ],
      onStatus: () => undefined,
    });
    expect(result).toEqual([{ command: "git log --all", reachesModel: true }]);
    expect(avoidShapes.size).toBe(1);
    expect(avoidShapes.has(structuralKey("basename src/plugin.ts"))).toBe(false);
    expect(avoidShapes.has(structuralKey("git log --all"))).toBe(true);
  });
});
