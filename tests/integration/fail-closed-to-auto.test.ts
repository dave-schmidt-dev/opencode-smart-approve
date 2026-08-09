import { describe, expect, mock, test } from "bun:test";
import { createApprovalCoordinator } from "../../src/approval/coordinator";
import type { BashPermissionRequest } from "../../src/opencode/permission-event";

const request: BashPermissionRequest = { requestID: "fail-closed", sessionID: "parent", command: "echo safe", permission: "bash" };
const allowReviewer = { review: mock(async () => ({ decision: "allow" as const, sessionID: "child", toolCounters: { executable: 0, dataAccess: 0, mcp: 0, web: 0, task: 0 } })) };

describe("fail-closed routing", () => {
  test("deterministic manual never invokes reviewer or approval", async () => {
    const approve = mock(async (_id: string) => undefined);
    const coordinator = createApprovalCoordinator({ reviewer: allowReviewer, approve, policy: async () => ({ status: "manual", decision: "manual", reasonCodes: ["privacy"], parse: undefined, privacy: undefined }) });
    await coordinator.handle(request);
    expect(allowReviewer.review).not.toHaveBeenCalled();
    expect(approve).not.toHaveBeenCalled();
    expect(coordinator.state(request.requestID)).toBe("manual");
  });

  test("policy and reviewer exceptions remain manual with no reply", async () => {
    const approve = mock(async (_id: string) => undefined);
    const policyFailure = createApprovalCoordinator({ reviewer: allowReviewer, approve, policy: async () => { throw new Error("provider failure"); } });
    await policyFailure.handle({ ...request, requestID: "policy-failure" });
    expect(approve).not.toHaveBeenCalled();
    expect(policyFailure.state("policy-failure")).toBe("manual");

    const reviewerFailure = createApprovalCoordinator({ reviewer: { review: async () => { throw new Error("unexpected reviewer failure"); } }, approve, policy: async () => ({ status: "model_review", decision: "model_review", reasonCodes: [], parse: undefined, privacy: undefined }) });
    await reviewerFailure.handle({ ...request, requestID: "reviewer-failure" });
    expect(approve).not.toHaveBeenCalled();
    expect(reviewerFailure.state("reviewer-failure")).toBe("manual");
  });
});
