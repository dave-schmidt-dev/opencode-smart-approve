import { describe, expect, mock, test } from "bun:test";
import { createApprovalCoordinator } from "../../src/approval/coordinator";
import type { BashPermissionRequest } from "../../src/opencode/permission-event";

const request = (requestID: string): BashPermissionRequest => ({
  requestID,
  sessionID: "parent",
  command: `printf '${requestID}\\n'`,
  permission: "bash",
});

const modelReview = async () => ({
  status: "model_review" as const,
  decision: "model_review" as const,
  reasonCodes: [],
  parse: undefined,
  privacy: undefined,
});

describe("race-safe approval coordinator", () => {
  test("deduplicates request IDs and replies once to the exact ID", async () => {
    const reviewer = { review: mock(async (input: { requestID: string }) => ({ decision: "allow" as const, sessionID: "child", toolCounters: { executable: 0, dataAccess: 0, mcp: 0, web: 0, task: 0 }, requestID: input.requestID })) };
    const approve = mock(async (_requestID: string) => undefined);
    const coordinator = createApprovalCoordinator({ reviewer, approve, policy: modelReview });

    await Promise.all([coordinator.handle(request("same")), coordinator.handle(request("same"))]);

    expect(reviewer.review).toHaveBeenCalledTimes(1);
    expect(approve).toHaveBeenCalledTimes(1);
    expect(approve).toHaveBeenCalledWith("same");
    expect(coordinator.state("same")).toBe("complete");
  });

  test("limits active reviews to four and leaves the fifth manual", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const reviewer = { review: mock(async () => { await gate; return { decision: "manual" as const, sessionID: "child", toolCounters: { executable: 0, dataAccess: 0, mcp: 0, web: 0, task: 0 } }; }) };
    const coordinator = createApprovalCoordinator({ reviewer, approve: async () => undefined, policy: modelReview, maxConcurrent: 4 });

    const pending = [1, 2, 3, 4, 5].map((id) => coordinator.handle(request(`cap-${id}`)));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(reviewer.review).toHaveBeenCalledTimes(4);
    expect(coordinator.state("cap-5")).toBe("manual");
    release();
    await Promise.all(pending);
  });

  test("does not reply after the user wins the race", async () => {
    type ReviewResult = { decision: "allow"; sessionID: string; toolCounters: { executable: number; dataAccess: number; mcp: number; web: number; task: number } };
    let resolveReview!: (value: ReviewResult) => void;
    const review = new Promise<ReviewResult>((resolve) => { resolveReview = resolve; });
    const reviewer = { review: mock(async () => review) };
    const approve = mock(async (_requestID: string) => undefined);
    const coordinator = createApprovalCoordinator({ reviewer, approve, policy: modelReview });
    const pending = coordinator.handle(request("user-first"));
    await new Promise((resolve) => setTimeout(resolve, 0));
    coordinator.markUserAnswered("user-first");
    resolveReview({ decision: "allow", sessionID: "child", toolCounters: { executable: 0, dataAccess: 0, mcp: 0, web: 0, task: 0 } });
    await pending;
    expect(approve).not.toHaveBeenCalled();
    expect(coordinator.state("user-first")).toBe("stale");
  });

  test("treats a not-found reply as stale without retry", async () => {
    const approve = mock(async (_requestID: string) => { throw new Error("permission not found"); });
    const coordinator = createApprovalCoordinator({
      reviewer: { review: async () => ({ decision: "allow" as const, sessionID: "child", toolCounters: { executable: 0, dataAccess: 0, mcp: 0, web: 0, task: 0 } }) },
      approve,
      policy: modelReview,
    });
    await coordinator.handle(request("missing"));
    expect(approve).toHaveBeenCalledTimes(1);
    expect(coordinator.state("missing")).toBe("stale");
  });
});
