import { describe, expect, test } from "bun:test";
import { createApprovalCoordinator } from "../../src/approval/coordinator";
import {
  buildReviewerContract,
  createOpaqueCoordinatorID,
  createCapacityRejectedOutcome,
  reviewerOutcomeSchema,
  reasonCodeV3Schema,
} from "../../src/reviewer/contract";
import { createReviewerAgent } from "../../src/reviewer/agent";
import { redactCommand } from "../../src/reviewer/prompt";
import { validateConfig } from "../../src/config/schema";
import { MODEL_PROFILES } from "../../src/reviewer/model-profile";
import {
  buildCandidatePluginCanary,
  buildParityReport,
  captureEvaluationParity,
  captureProductionParity,
  compareParityCaptures,
  validateParityReport,
} from "../../scripts/qualification/harness";

const zeroTools = { executable: 0, dataAccess: 0, mcp: 0, web: 0, task: 0 } as const;

describe("canonical reviewer contract", () => {
  test("captures the production-facing contract without raw command bytes", () => {
    const coordinatorID = createOpaqueCoordinatorID();
    const contract = buildReviewerContract({
      coordinatorID,
      providerID: "opencode-go",
      modelID: "deepseek-v4-flash",
      requestedVariant: "low",
      timeoutMs: 30_000,
      directory: "/project",
      parentSessionID: "parent-session",
      command: "printf 'CONTRACT_SECRET_CANARY'",
      policyFacts: ["model_review", "parser.clear", "privacy.clear", "path.project"],
      pathClasses: ["project"],
    });

    expect(contract).toMatchObject({
      version: "classifier-qualification/v3",
      coordinatorID,
      requestedModel: "opencode-go/deepseek-v4-flash",
      requestedVariant: "low",
      temperature: 0,
      retryCount: 0,
      timeoutMs: 30_000,
      directory: "/project",
      parentSessionID: "parent-session",
      parentLinkage: { parentSessionID: "parent-session", directory: "/project" },
      pathIdentity: { directory: "/project", classes: ["project"] },
    });
    expect(contract.prompt).not.toContain("CONTRACT_SECRET_CANARY");
    expect(contract.permissions).toEqual([{ permission: "*", pattern: "*", action: "deny" }]);
    expect(contract.tools["*"]).toBe(false);
  });

  test.each([999, 1000, 1001])("redaction is stable at the %i-character boundary", (length) => {
    const raw = `printf ${"x".repeat(Math.max(0, length - 7))}`.slice(0, length);
    expect(redactCommand(redactCommand(raw))).toBe(redactCommand(raw));
  });

  test("v3 reason vocabulary rejects unknown codes", () => {
    expect(reasonCodeV3Schema.safeParse("capacity_rejected").success).toBe(true);
    expect(reasonCodeV3Schema.safeParse("reviewer_guess").success).toBe(false);
    const capacity = createCapacityRejectedOutcome(createOpaqueCoordinatorID());
    expect(reviewerOutcomeSchema.safeParse(capacity).success).toBe(true);
    expect(reviewerOutcomeSchema.safeParse({ ...capacity, providerAttempted: true }).success).toBe(false);
  });

  test("coordinator-owned deadline leaves timeout authority outside the reviewer", async () => {
    let release!: (value: unknown) => void;
    let settled = false;
    const reviewer = createReviewerAgent({
      timeoutMs: 1,
      client: {
        session: {
          create: async () => ({ data: { id: "child-deadline" } }),
          prompt: () => new Promise((resolve) => { release = resolve; }),
          abort: async () => undefined,
          delete: async () => undefined,
        },
      },
    });
    const pending = reviewer.review({
      requestID: "deadline-request",
      coordinatorID: createOpaqueCoordinatorID(),
      deadlineOwnedByCoordinator: true,
      prompt: "echo safe",
    }).then((result) => { settled = true; return result; });
    await Bun.sleep(5);
    expect(settled).toBe(false);
    release({ data: { decision: "manual", reasonCodes: ["manual"] } });
    const result = await pending;
    expect(result.reasonCodes).toEqual(["manual"]);
    await reviewer.dispose();
  });

  test("one coordinator deadline wins across 100 induced timeouts", async () => {
    const reviewerOutcomes: string[] = [];
    let childIndex = 0;
    const reviewer = createReviewerAgent({
      timeoutMs: 1,
      client: {
        session: {
          create: async () => ({ data: { id: `timeout-child-${childIndex++}` } }),
          prompt: () => new Promise((resolve) => { (globalThis as { release?: (value: unknown) => void }).release = resolve; }),
          abort: async () => undefined,
          delete: async () => undefined,
        },
      },
    });
    const coordinator = createApprovalCoordinator({
      reviewer,
      modelEnabled: true,
      timeoutMs: 3,
      policy: async () => ({ status: "model_review" as const, decision: "model_review" as const, reasonCodes: [], parse: undefined, privacy: undefined }),
      onReviewOutcome: (outcome) => reviewerOutcomes.push(outcome.kind),
    });

    for (let index = 0; index < 100; index += 1) {
      const requestID = `timeout-${index}`;
      await coordinator.handle({ requestID, sessionID: "parent", command: "echo safe", permission: "bash" });
      expect(coordinator.state(requestID)).toBe("timeout");
      const release = (globalThis as { release?: (value: unknown) => void }).release;
      expect(release).toBeFunction();
      release?.({ data: { decision: "manual", reasonCodes: ["manual"] } });
      await Bun.sleep(0);
    }
    expect(reviewerOutcomes).toHaveLength(100);
    expect(reviewerOutcomes.every((kind) => kind === "timeout")).toBe(true);
    await coordinator.dispose();
  });
});

describe("typed capacity boundary", () => {
  test("emits capacity_rejected before native manual collapse", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const outcomes: string[] = [];
    const coordinator = createApprovalCoordinator({
      maxConcurrent: 1,
      modelEnabled: true,
      policy: async () => ({ status: "model_review" as const, decision: "model_review" as const, reasonCodes: [], parse: undefined, privacy: undefined }),
      reviewer: { review: async ({ requestID }) => { await gate; return { decision: "manual" as const, requestID, sessionID: "child", toolCounters: zeroTools }; } },
      onReviewOutcome: (outcome) => outcomes.push(outcome.kind),
    });

    const first = coordinator.handle({ requestID: "capacity-one", sessionID: "parent", command: "echo one", permission: "bash" });
    while (coordinator.state("capacity-one") !== "reviewing") await Bun.sleep(1);
    await coordinator.handle({ requestID: "capacity-two", sessionID: "parent", command: "echo two", permission: "bash" });
    expect(coordinator.state("capacity-two")).toBe("manual");
    expect(outcomes).toContain("capacity_rejected");
    release();
    await first;
    await coordinator.dispose();
  });

  test("clears the coordinator deadline before a slow one-shot adapter", async () => {
    let release!: () => void;
    const approvalGate = new Promise<void>((resolve) => { release = resolve; });
    let cancelCalls = 0;
    const outcomes: string[] = [];
    const coordinator = createApprovalCoordinator({
      modelEnabled: true,
      timeoutMs: 5,
      policy: async () => ({ status: "model_review" as const, decision: "model_review" as const, reasonCodes: [], parse: undefined, privacy: undefined }),
      reviewer: {
        review: async ({ requestID }) => ({ decision: "allow" as const, requestID, sessionID: "child", toolCounters: zeroTools }),
        cancel: async () => { cancelCalls += 1; },
      },
      approve: async () => approvalGate,
      onReviewOutcome: (outcome) => outcomes.push(outcome.kind),
    });
    const pending = coordinator.handle({ requestID: "slow-adapter", sessionID: "parent", command: "echo safe", permission: "bash" });
    await Bun.sleep(10);
    expect(cancelCalls).toBe(0);
    expect(outcomes).not.toContain("timeout");
    release();
    await pending;
    expect(coordinator.state("slow-adapter")).toBe("complete");
    await coordinator.dispose();
  });

  test("bounds abort and delete cleanup after a reviewer timeout", async () => {
    let releasePrompt!: (value: unknown) => void;
    let deleteCalls = 0;
    const reviewer = createReviewerAgent({
      timeoutMs: 10,
      client: {
        session: {
          create: async () => ({ data: { id: "cleanup-child" } }),
          prompt: () => new Promise((resolve) => { releasePrompt = resolve; }),
          abort: async () => new Promise(() => undefined),
          delete: async () => { deleteCalls += 1; },
        },
      },
    });
    const pending = reviewer.review({
      requestID: "cleanup-request",
      coordinatorID: createOpaqueCoordinatorID(),
      deadlineOwnedByCoordinator: true,
      prompt: "echo safe",
    });
    while (!reviewer.isPluginSession("cleanup-child")) await Bun.sleep(1);
    const result = await Promise.race([
      reviewer.cancel("cleanup-request").then(() => "cancelled" as const),
      Bun.sleep(800).then(() => "hung" as const),
    ]);
    expect(result).toBe("cancelled");
    expect(deleteCalls).toBe(1);
    releasePrompt({ data: { decision: "manual", reasonCodes: ["manual"] } });
    await pending;
    await reviewer.dispose();
  });
});

describe("production/evaluation parity harness", () => {
  const scenario = {
    command: "printf PARITY_SECRET_CANARY",
    directory: "/project/root",
    parentSessionID: "parent-session-token",
    pathClasses: ["project"] as const,
  };

  test("captures one coordinator-backed create and prompt without private bytes", async () => {
    const production = await captureProductionParity(scenario);
    const evaluation = captureEvaluationParity(scenario);
    const comparison = compareParityCaptures(production, evaluation);
    expect(comparison).toEqual({ equal: true, mismatches: [] });
    expect(production.create.count).toBe(1);
    expect(production.create.parentLinked).toBe(true);
    expect(production.prompt.count).toBe(1);
    expect(production.registration.variant).toBe("low");
    expect(production.prompt.variant).toBe("low");
    expect(production.terminal).toEqual({ state: "manual", outcomeKind: "valid_model", approvalCalls: 0 });
    const serialized = JSON.stringify(buildParityReport(production, evaluation));
    expect(serialized).not.toContain("PARITY_SECRET_CANARY");
    expect(serialized).not.toContain(scenario.directory);
    expect(validateParityReport(buildParityReport(production, evaluation))).toEqual({ accepted: true, errors: [] });
  });

  test("keeps the DeepSeek low production candidate identical across production and evaluation plumbing", async () => {
    const profile = MODEL_PROFILES["deepseek-v4-flash"];
    const config = validateConfig({
      model: { enabled: false, provider: profile.providerID, model: profile.modelID, variant: "low", timeoutMs: 30_000 },
    });
    const production = await captureProductionParity(scenario, config);
    const evaluation = captureEvaluationParity(scenario, config);
    expect(compareParityCaptures(production, evaluation)).toEqual({ equal: true, mismatches: [] });
    expect(production.registration.model).toBe(profile.model);
    expect(production.registration.variant).toBe("low");
    expect(production.contract.requestedVariant).toBe("low");
    expect(production.prompt.variant).toBe("low");
  });

  test("field-level parity negatives identify each deliberately divergent capture", async () => {
    const production = await captureProductionParity(scenario);
    const evaluation = captureEvaluationParity(scenario);
    const mutations: Array<[string, (capture: typeof production) => void]> = [
      ["registration", (capture) => { (capture.registration as { model: string }).model = "other/model"; }],
      ["contract", (capture) => { (capture.contract as { requestedVariant: string }).requestedVariant = "standard"; }],
      ["create", (capture) => { (capture.create as { count: number }).count = 2; }],
      ["prompt", (capture) => { (capture.prompt as { text: string }).text = "diverged"; }],
    ];
    for (const [field, mutate] of mutations) {
      const mutated = structuredClone(production) as typeof production;
      mutate(mutated);
      expect(compareParityCaptures(mutated, evaluation).mismatches).toContain(field);
    }
  });

  test("parity reports stay contract-only while the release lock is false", async () => {
    const production = await captureProductionParity(scenario);
    const evaluation = captureEvaluationParity(scenario);
    const report = { ...buildParityReport(production, evaluation), live_plugin_path: "/tmp/candidate" };
    expect(validateParityReport(report)).toEqual({
      accepted: false,
      errors: ["live_plugin_path is forbidden while the release lock is false"],
    });
  });

  test("candidate canary compiles one disposable lock substitution without changing checkout inputs", async () => {
    const result = await buildCandidatePluginCanary();
    expect(result.compiled).toBe(true);
    expect(result.lockSubstitutions).toBe(1);
    expect(result.checkoutHashBefore).toBe(result.checkoutHashAfter);
    await expect(buildCandidatePluginCanary({ source: "no lock here" })).rejects.toThrow("exactly one match");
    await expect(buildCandidatePluginCanary({ source: `${"export const MODEL_APPROVAL_QUALIFIED = false as const;"}\n${"export const MODEL_APPROVAL_QUALIFIED = false as const;"}` })).rejects.toThrow("exactly one match");
  });
});
