import { describe, expect, mock, test } from "bun:test";
import { createApprovalCoordinator } from "../../src/approval/coordinator";
import { createProgressMetrics, createProgressReporter, createReplanProgressReporter, validateReviewTimeout, type ProgressMetrics } from "../../src/progress/reporter";

const modelReview = async () => ({
  status: "model_review" as const,
  decision: "model_review" as const,
  reasonCodes: [],
  parse: undefined,
  privacy: undefined,
});

describe("persistent review progress", () => {
  test("writes immediate information and success or manual terminal statuses", () => {
    const statuses: Array<{ phase: string; variant: string; message: string }> = [];
    const callbacks: Array<() => void> = [];
    const reporter = createProgressReporter({
      requestID: "request-success",
      timer: {
        setInterval: (callback) => { callbacks.push(callback); return callback; },
        clearInterval: () => undefined,
      },
      onStatus: (status) => statuses.push(status),
    });

    reporter.start();
    expect(statuses).toEqual([{
      phase: "started",
      variant: "info",
      message: "Reviewing command request-success",
    }]);
    reporter.finish("success", "Review passed; permission approved once");
    expect(statuses.at(-1)).toEqual({
      phase: "finished",
      variant: "success",
      message: "Review passed; permission approved once",
    });

    const manual: string[] = [];
    const manualReporter = createProgressReporter({
      requestID: "request-manual",
      timer: {
        setInterval: () => 1,
        clearInterval: () => undefined,
      },
      onStatus: ({ variant }) => manual.push(variant),
    });
    manualReporter.start();
    manualReporter.finish("warning", "Review requires a manual decision");
    expect(manual).toEqual(["info", "warning"]);
  });

  test("sink failures leave the coordinator allow decision unchanged", async () => {
    const sink = { tui: { showToast: mock(() => { throw new Error("sink unavailable"); }) } };
    const approve = mock(async () => undefined);
    const coordinator = createApprovalCoordinator({
      progressSink: sink,
      policy: modelReview,
      reviewer: {
        review: async ({ requestID }) => ({
          requestID,
          sessionID: `child-${requestID}`,
          decision: "allow" as const,
          toolCounters: { executable: 0, dataAccess: 0, mcp: 0, web: 0, task: 0 },
        }),
      },
      approve,
    });

    await coordinator.handle({
      requestID: "sink-failure",
      sessionID: "parent",
      permission: "bash",
      command: "printf safe",
    });

    expect(approve).toHaveBeenCalledTimes(1);
    expect(approve).toHaveBeenCalledWith("sink-failure", "parent");
    expect(coordinator.state("sink-failure")).toBe("complete");
  });

  test("writes one initial, two heartbeats, and one terminal status over simulated 30 seconds", () => {
    const callbacks: Array<() => void> = [];
    const cleared: unknown[] = [];
    const statuses: Array<{ phase: string; variant: string }> = [];
    let now = 0;
    const metrics = createProgressMetrics();
    const reporter = createProgressReporter({
      requestID: "request-30s",
      intervalMs: 10_000,
      now: () => now,
      timer: {
        setInterval: (callback, delay) => {
          expect(delay).toBe(10_000);
          callbacks.push(callback);
          return "heartbeat-handle";
        },
        clearInterval: (handle) => { cleared.push(handle); },
      },
      metrics,
      onStatus: (status) => statuses.push(status),
    });

    reporter.start();
    now = 10_000;
    callbacks[0]?.();
    now = 20_000;
    callbacks[0]?.();
    now = 30_000;
    reporter.finish("warning", "Review timed out; native prompt remains available");

    expect(statuses.map(({ phase, variant }) => ({ phase, variant }))).toEqual([
      { phase: "started", variant: "info" },
      { phase: "updated", variant: "info" },
      { phase: "updated", variant: "info" },
      { phase: "finished", variant: "warning" },
    ]);
    expect(cleared).toEqual(["heartbeat-handle"]);
    expect(metrics.snapshot()).toEqual({
      reviewCount: 1,
      heartbeatCount: 2,
      completedCount: 1,
      timeoutCount: 1,
      manualFallbackCount: 1,
      cumulativeLatencyMs: 30_000,
      replanAttemptCount: 0,
      replanBlockedCount: 0,
      replanDuplicateCount: 0,
      replanExhaustionCount: 0,
      replanFallthroughCount: 0,
      replanInternalFailureCount: 0,
    });
  });

  test("finish-before-start preserves phase order and bounded metrics", () => {
    const phases: string[] = [];
    let now = 45_000;
    const metrics = createProgressMetrics();
    const reporter = createProgressReporter({
      requestID: "defensive-finish",
      now: () => now,
      timer: { setInterval: () => 1, clearInterval: () => undefined },
      metrics,
      onStatus: ({ phase }) => phases.push(phase),
    });
    reporter.finish("warning", "Review unavailable");
    now = 9_999_999;
    reporter.finish("warning", "duplicate terminal");

    expect(phases).toEqual(["started", "finished"]);
    expect(metrics.snapshot()).toMatchObject({
      reviewCount: 1,
      completedCount: 1,
      cumulativeLatencyMs: 0,
    });
  });

  test("session metrics expose aggregate counts without accepting command text", () => {
    const canaryCommand = "printf API_KEY=CANARY_METRICS_SECRET";
    const metrics = createProgressMetrics();
    metrics.begin();
    metrics.heartbeat?.();
    metrics.finish("success", 250);
    const snapshot = metrics.snapshot();

    expect(Object.keys(snapshot).sort()).toEqual([
      "completedCount",
      "cumulativeLatencyMs",
      "heartbeatCount",
      "manualFallbackCount",
      "replanAttemptCount",
      "replanBlockedCount",
      "replanDuplicateCount",
      "replanExhaustionCount",
      "replanFallthroughCount",
      "replanInternalFailureCount",
      "reviewCount",
      "timeoutCount",
    ]);
    expect(JSON.stringify(snapshot)).not.toContain(canaryCommand);
    expect(snapshot.cumulativeLatencyMs).toBe(250);
    expect(snapshot.replanAttemptCount).toBe(0);
  });

  test("accepts only the canary-qualified 10 to 60 second timeout range", () => {
    expect(validateReviewTimeout(10_000)).toBe(10_000);
    expect(validateReviewTimeout(30_000)).toBe(30_000);
    expect(validateReviewTimeout(60_000)).toBe(60_000);
    for (const invalid of [9_999, 60_001, 10_000.5, Number.NaN]) {
      expect(() => validateReviewTimeout(invalid)).toThrow(RangeError);
    }
  });

  test("replan progress has fixed start/terminal statuses and bounded counters", () => {
    const statuses: Array<{ phase: string; status: string; message: string; variant: string }> = [];
    const calls = { attempt: 0, blocked: 0, duplicate: 0, exhaustion: 0, fallthrough: 0, internalFailure: 0 };
    const metrics = {
      replanAttempt: () => { calls.attempt += 1; },
      replanBlocked: () => { calls.blocked += 1; },
      replanDuplicate: () => { calls.duplicate += 1; },
      replanExhaustion: () => { calls.exhaustion += 1; },
      replanFallthrough: () => { calls.fallthrough += 1; },
      replanInternalFailure: () => { calls.internalFailure += 1; },
    } as unknown as ProgressMetrics;
    const reporter = createReplanProgressReporter({
      metrics,
      sink: { tui: { showToast: () => { throw new Error("sink unavailable"); } } },
      onStatus: (status) => statuses.push(status),
    });
    reporter.start();
    reporter.finish("exhausted_fallthrough", "exhausted");
    reporter.finish("blocked");

    expect(statuses).toEqual([
      { phase: "started", status: "started", message: "Smart Approve replan attempt started", variant: "info" },
      { phase: "finished", status: "exhausted_fallthrough", message: "Smart Approve replan exhausted; native permission remains available", variant: "info" },
    ]);
    expect(calls).toEqual({
      attempt: 1,
      blocked: 0,
      duplicate: 0,
      exhaustion: 1,
      fallthrough: 1,
      internalFailure: 0,
    });
  });
});
