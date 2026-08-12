import { describe, expect, mock, test } from "bun:test";
import { createApprovalCoordinator } from "../../src/approval/coordinator";
import { createSmartApproveHooks } from "../../src/plugin";
import type { BashPermissionRequest } from "../../src/opencode/permission-event";

const request: BashPermissionRequest = { requestID: "fail-closed", sessionID: "parent", command: "echo safe", permission: "bash" };
const zeroTools = { executable: 0, dataAccess: 0, mcp: 0, web: 0, task: 0 } as const;
const modelReview = async () => ({ status: "model_review" as const, decision: "model_review" as const, reasonCodes: [], parse: undefined, privacy: undefined });
const event = (id: string) => ({ type: "permission.asked", properties: { id, sessionID: "parent", permission: "bash", metadata: { command: "echo safe" } } });

describe("fail-closed routing", () => {
  test("hard manual and model kill switch create no reviewer job and no reply", async () => {
    for (const options of [
      { policy: async () => ({ status: "manual" as const, decision: "manual" as const, reasonCodes: ["privacy" as const], parse: undefined, privacy: undefined }) },
      { policy: modelReview, modelEnabled: false },
    ]) {
      const review = mock(async () => ({ decision: "allow" as const, requestID: "fail-closed", sessionID: "child", toolCounters: zeroTools }));
      const approve = mock(async () => undefined);
      const coordinator = createApprovalCoordinator({ reviewer: { review }, approve, ...options });
      await coordinator.handle(request);
      expect(review).not.toHaveBeenCalled();
      expect(approve).not.toHaveBeenCalled();
      expect(coordinator.state(request.requestID)).toBe("manual");
    }
  });

  test("closed replan results remain native manual with no reviewer or reply edge", async () => {
    const review = mock(async () => ({ decision: "allow" as const, requestID: "replan", sessionID: "child", toolCounters: zeroTools }));
    const approve = mock(async () => undefined);
    const coordinator = createApprovalCoordinator({
      reviewer: { review },
      approve,
      modelEnabled: true,
      policy: async () => ({ status: "replan" as unknown as "manual", decision: "replan" as const, reasonCodes: ["replan" as const], parse: undefined, privacy: undefined }),
    });
    await coordinator.handle({ ...request, requestID: "replan-native" });
    expect(review).not.toHaveBeenCalled();
    expect(approve).not.toHaveBeenCalled();
    expect(coordinator.state("replan-native")).toBe("manual");
  });

  test("every pre-reply exception is contained and emits zero permission replies", async () => {
    const cases = [
      { approve: mock(async () => undefined), reviewer: { review: async ({ requestID }: { requestID: string }) => ({ decision: "allow" as const, requestID, sessionID: "child", toolCounters: zeroTools }) }, policy: async () => { throw new Error("policy"); } },
      { approve: mock(async () => undefined), reviewer: { review: async () => { throw new Error("reviewer"); } }, policy: modelReview },
      { approve: mock(async () => undefined), reviewer: { review: async ({ requestID }: { requestID: string }) => ({ decision: "allow" as const, requestID: `${requestID}-wrong`, sessionID: "child", toolCounters: zeroTools }) }, policy: modelReview },
    ];
    for (const [index, entry] of cases.entries()) {
      const coordinator = createApprovalCoordinator(entry);
      await expect(coordinator.handle({ ...request, requestID: `exception-${index}` })).resolves.toBeUndefined();
      expect(entry.approve).not.toHaveBeenCalled();
      expect(coordinator.state(`exception-${index}`)).toBe("manual");
    }
  });

  test("synchronous and asynchronous detached handler failures leave the host callback alive", async () => {
    const approve = mock(async () => undefined);
    let calls = 0;
    const hooks = createSmartApproveHooks({
      reviewer: { review: async ({ requestID }) => {
        calls += 1;
        if (calls === 1) throw new Error("async detached failure");
        return { decision: "manual", requestID, sessionID: "child", toolCounters: zeroTools };
      } },
      approve,
      policy: async () => { if (calls === 0) return modelReview(); throw new Error("later policy failure"); },
      shellCompatible: true,
    });
    await expect(hooks.event({ event: event("detached-1") })).resolves.toBeUndefined();
    await Bun.sleep(2);
    await expect(hooks.event({ event: event("detached-2") })).resolves.toBeUndefined();
    await Bun.sleep(2);
    expect(approve).not.toHaveBeenCalled();
    expect([hooks.state("detached-1"), hooks.state("detached-2")]).toEqual(["manual", "manual"]);
  });

  test("recursive-permission and cleanup failures are contained without approving", async () => {
    const approve = mock(async () => undefined);
    const coordinator = createApprovalCoordinator({
      reviewer: {
        review: async ({ requestID }) => ({ decision: "manual", requestID, sessionID: "child", toolCounters: zeroTools }),
        handlePermission: async () => { throw new Error("recursive reject failed"); },
        dispose: async () => { throw new Error("cleanup failed"); },
      },
      approve,
      policy: modelReview,
    });
    await expect(coordinator.event({ type: "permission.asked", properties: { id: "child-permission", sessionID: "child", permission: "bash", metadata: { command: "echo child" } } })).resolves.toBeUndefined();
    await expect(coordinator.dispose()).resolves.toBeUndefined();
    expect(approve).not.toHaveBeenCalled();
  });
});
