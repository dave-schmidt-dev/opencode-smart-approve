import { describe, expect, mock, test } from "bun:test";
import { createApprovalCoordinator } from "../../src/approval/coordinator";
import { ApprovalStateStore } from "../../src/approval/state";
import type { BashPermissionRequest } from "../../src/opencode/permission-event";
import type { ReviewerResult } from "../../src/reviewer/agent";
import type { DeterministicPolicyResult } from "../../src/policy/deterministic";

const zeroTools = { executable: 0, dataAccess: 0, mcp: 0, web: 0, task: 0 } as const;
const request = (requestID: string, sessionID = "parent"): BashPermissionRequest => ({
  requestID,
  sessionID,
  command: `printf '${requestID} secret-value\\n'`,
  permission: "bash",
});
const modelReview = async (): Promise<DeterministicPolicyResult> => ({
  status: "model_review" as const,
  decision: "model_review" as const,
  reasonCodes: [],
  parse: undefined,
  privacy: undefined,
});
const modelReviewWithFacts = async (): Promise<DeterministicPolicyResult> => ({
  ...(await modelReview()),
  parse: { features: { pipeline: false, redirects: false, substitutions: false, processSubstitutions: false, backticks: false, functions: false, loops: false, heredocs: false, unresolvedExpansions: false, eval: false, exec: false, source: false, environmentAssignments: false, segmentCount: 1, maxDepth: 2, unsupported: [] } } as unknown as NonNullable<DeterministicPolicyResult["parse"]>,
});
const allow = (requestID: string): ReviewerResult => ({ decision: "allow", requestID, sessionID: `child-${requestID}`, toolCounters: zeroTools });

describe("race-safe approval coordinator", () => {
  test("the long-lived request store retains a command hash, never raw command text", () => {
    const store = new ApprovalStateStore();
    const raw = "printf CANARY_RAW_COMMAND";
    const record = store.begin("hashed", raw, "parent");
    expect(record).toBeDefined();
    expect(record).not.toHaveProperty("command");
    expect(JSON.stringify(record)).not.toContain(raw);
    expect(record?.commandHash).toMatch(/^[a-f0-9]{64}$/);
  });

  test("duplicate delivery starts one classification and one exact one-shot reply", async () => {
    const reviewer = { review: mock(async ({ requestID }: { requestID: string }) => allow(requestID)) };
    const approve = mock(async (_requestID: string, _sessionID?: string) => undefined);
    const policy = mock(modelReview);
    const coordinator = createApprovalCoordinator({ reviewer, approve, policy });

    await Promise.all([coordinator.handle(request("same")), coordinator.handle(request("same"))]);

    expect(policy).toHaveBeenCalledTimes(1);
    expect(reviewer.review).toHaveBeenCalledTimes(1);
    expect(approve).toHaveBeenCalledTimes(1);
    expect(approve).toHaveBeenCalledWith("same", "parent");
    expect(coordinator.state("same")).toBe("complete");
  });

  test("passes only redacted command shape and bounded parser/policy/path facts", async () => {
    const seen: unknown[] = [];
    const coordinator = createApprovalCoordinator({
      reviewer: { review: async (input) => { seen.push(input); return { ...allow(input.requestID), decision: "manual" }; } },
      approve: async () => undefined,
      policy: modelReviewWithFacts,
    });
    await coordinator.handle(request("facts"));
    expect(seen).toHaveLength(1);
    expect(JSON.stringify(seen[0])).not.toContain("secret-value");
    expect(seen[0]).toMatchObject({
      requestID: "facts",
      parentSessionID: "parent",
      parserFeatures: { pipeline: false, segmentCount: 1 },
      policyFacts: ["model_review", "parser.clear", "privacy.clear", "path.unknown"],
      pathClasses: ["unknown"],
    });
  });

  test("starts exactly four reviews and sends the fifth directly to manual with no queue", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const reviewed: string[] = [];
    const reviewer = { review: mock(async ({ requestID }: { requestID: string }) => { reviewed.push(requestID); await gate; return { ...allow(requestID), decision: "manual" as const }; }) };
    const approve = mock(async () => undefined);
    const coordinator = createApprovalCoordinator({ reviewer, approve, policy: modelReview, maxConcurrent: 99 });

    const pending = [1, 2, 3, 4, 5].map((id) => coordinator.handle(request(`cap-${id}`)));
    await Bun.sleep(5);
    expect(reviewed).toEqual(["cap-1", "cap-2", "cap-3", "cap-4"]);
    expect(coordinator.state("cap-5")).toBe("manual");
    expect(approve).not.toHaveBeenCalled();
    release();
    await Promise.all(pending);
    expect(reviewer.review).toHaveBeenCalledTimes(4);
  });

  test("user-first and mismatched late results cannot approve this or a different request", async () => {
    let releaseA!: (value: ReviewerResult) => void;
    let releaseB!: (value: ReviewerResult) => void;
    const a = new Promise<ReviewerResult>((resolve) => { releaseA = resolve; });
    const b = new Promise<ReviewerResult>((resolve) => { releaseB = resolve; });
    const reviewer = { review: ({ requestID }: { requestID: string }) => requestID === "A" ? a : b };
    const approve = mock(async () => undefined);
    const coordinator = createApprovalCoordinator({ reviewer, approve, policy: modelReview });
    const pendingA = coordinator.handle(request("A"));
    const pendingB = coordinator.handle(request("B"));
    await Bun.sleep(1);
    await coordinator.event({ type: "permission.replied", properties: { requestID: "unrelated", sessionID: "other", reply: "once" } });
    expect(coordinator.state("A")).toBe("reviewing");
    expect(coordinator.state("B")).toBe("reviewing");
    await coordinator.event({ type: "permission.replied", properties: { requestID: "A", sessionID: "parent", reply: "once" } });
    releaseA(allow("A"));
    releaseB(allow("A"));
    await Promise.all([pendingA, pendingB]);
    expect(coordinator.state("A")).toBe("stale");
    expect(coordinator.state("B")).toBe("manual");
    expect(approve).not.toHaveBeenCalled();
  });

  test("a not-found one-shot attempt becomes stale and is never retried", async () => {
    const approve = mock(async () => { throw Object.assign(new Error("permission not found"), { status: 404 }); });
    const coordinator = createApprovalCoordinator({ reviewer: { review: async ({ requestID }) => allow(requestID) }, approve, policy: modelReview });
    await coordinator.handle(request("missing"));
    expect(approve).toHaveBeenCalledTimes(1);
    expect(coordinator.state("missing")).toBe("stale");
  });

  test("the permission.replied event emitted by our in-flight one-shot does not relabel success stale", async () => {
    let releaseReply!: () => void;
    const replyGate = new Promise<void>((resolve) => { releaseReply = resolve; });
    const approve = mock(async () => replyGate);
    const coordinator = createApprovalCoordinator({ reviewer: { review: async ({ requestID }) => allow(requestID) }, approve, policy: modelReview });
    const pending = coordinator.handle(request("own-reply"));
    while (coordinator.state("own-reply") !== "replying") await Bun.sleep(1);
    await coordinator.event({ type: "permission.replied", properties: { requestID: "own-reply", sessionID: "parent", reply: "once" } });
    expect(coordinator.state("own-reply")).toBe("replying");
    releaseReply();
    await pending;
    expect(coordinator.state("own-reply")).toBe("complete");
    expect(approve).toHaveBeenCalledTimes(1);
  });

  test("a non-404 approval transport failure is terminal and never retried", async () => {
    const approve = mock(async () => { throw new Error("transport unavailable"); });
    const reviewer = { review: mock(async ({ requestID }: { requestID: string }) => allow(requestID)) };
    const coordinator = createApprovalCoordinator({ reviewer, approve, policy: modelReview });
    await coordinator.handle(request("transport-failure"));
    await coordinator.handle(request("transport-failure"));
    expect(approve).toHaveBeenCalledTimes(1);
    expect(reviewer.review).toHaveBeenCalledTimes(1);
    expect(coordinator.state("transport-failure")).toBe("error");
  });

  test("timeout cancels only the exact request and a late allow sends zero replies", async () => {
    let release!: (value: ReviewerResult) => void;
    const pendingReview = new Promise<ReviewerResult>((resolve) => { release = resolve; });
    const cancel = mock(async (_requestID: string) => undefined);
    const approve = mock(async () => undefined);
    const coordinator = createApprovalCoordinator({ reviewer: { review: async () => pendingReview, cancel }, approve, policy: modelReview, timeoutMs: 5 });
    await coordinator.handle(request("timeout-one"));
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(cancel).toHaveBeenCalledWith("timeout-one");
    expect(coordinator.state("timeout-one")).toBe("timeout");
    release(allow("timeout-one"));
    await Bun.sleep(1);
    expect(approve).not.toHaveBeenCalled();
  });
});
