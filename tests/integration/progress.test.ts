import { describe, expect, mock, test } from "bun:test";
import { createProgressMetrics, createProgressReporter, validateReviewTimeout } from "../../src/progress/reporter";

describe("persistent review progress", () => {
  test("emits an immediate status, heartbeats, and one terminal status", () => {
    const callbacks: Array<() => void> = [];
    const statuses: Array<{ phase: string; message: string }> = [];
    const metrics = createProgressMetrics();
    const reporter = createProgressReporter({
      requestID: "request-30s",
      intervalMs: 10_000,
      timer: {
        setInterval: (callback) => { callbacks.push(callback); return callbacks.length; },
        clearInterval: () => undefined,
      },
      metrics,
      onStatus: (status) => statuses.push(status),
    });
    reporter.start();
    callbacks[0]?.();
    callbacks[0]?.();
    reporter.finish("success", "Review passed; permission approved once");

    expect(statuses.map((status) => status.phase)).toEqual(["started", "updated", "updated", "finished"]);
    expect(statuses[0]?.message).toContain("Reviewing command");
    expect(metrics.snapshot()).toMatchObject({ reviewCount: 1, heartbeatCount: 2, completedCount: 1 });
  });

  test("sink failures cannot change reporting or decision flow", () => {
    const sink = { tui: { showToast: mock(() => { throw new Error("sink unavailable"); }) } };
    const statuses: string[] = [];
    const reporter = createProgressReporter({ requestID: "sink-failure", sink, onStatus: (status) => statuses.push(status.phase) });
    expect(() => reporter.start()).not.toThrow();
    expect(() => reporter.finish("warning", "Review unavailable; native prompt remains available")).not.toThrow();
    expect(statuses).toEqual(["started", "finished"]);
  });

  test("accepts only the canary-qualified timeout range", () => {
    expect(validateReviewTimeout(10_000)).toBe(10_000);
    expect(validateReviewTimeout(30_000)).toBe(30_000);
    expect(validateReviewTimeout(60_000)).toBe(60_000);
    expect(() => validateReviewTimeout(9_999)).toThrow();
    expect(() => validateReviewTimeout(60_001)).toThrow();
  });
});
