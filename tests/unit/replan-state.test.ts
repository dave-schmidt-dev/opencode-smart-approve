import { describe, expect, test } from "bun:test";
import { ReplanStateStore, type ReplanGeneration } from "../../src/replan/state";

const generation = (store: ReplanStateStore, sessionID: string, messageID: string): ReplanGeneration => {
  const value = store.observeUserMessage(sessionID, messageID);
  if (!value) throw new Error("expected generation");
  return value;
};

describe("replan generation state", () => {
  test("rejects a budget wider than the fixed three-block contract", () => {
    for (const value of [4, 5]) expect(() => new ReplanStateStore(value)).toThrow(/1 through 3/);
  });

  test("deduplicates user-message redelivery without resetting its generation", () => {
    const store = new ReplanStateStore(3);
    const first = generation(store, "session-a", "message-a");
    expect(store.reserve(first, "call-1")).toEqual({ outcome: "blocked", reason: "reserved", duplicate: false });

    const redelivered = generation(store, "session-a", "message-a");
    expect(redelivered).toBe(first);
    expect(store.snapshot("session-a")).toEqual({ blockedCount: 1, retainedCallCount: 1, exhausted: false });
  });

  test("a new user message resets only its own session generation", () => {
    const store = new ReplanStateStore(3);
    const oldA = generation(store, "session-a", "message-a1");
    const generationB = generation(store, "session-b", "message-b1");
    store.reserve(oldA, "call-a");
    store.reserve(generationB, "call-b");

    const newA = generation(store, "session-a", "message-a2");
    expect(newA).not.toBe(oldA);
    expect(store.captureGeneration("session-a")).toBe(newA);
    expect(store.snapshot("session-a")).toEqual({ blockedCount: 0, retainedCallCount: 0, exhausted: false });
    expect(store.snapshot("session-b")).toEqual({ blockedCount: 1, retainedCallCount: 1, exhausted: false });
  });

  test("three unique calls block and the fourth falls through at the configured limit", () => {
    const store = new ReplanStateStore(3);
    const current = generation(store, "session", "message");

    for (const callID of ["call-1", "call-2", "call-3"]) {
      expect(store.reserve(current, callID)).toEqual({ outcome: "blocked", reason: "reserved", duplicate: false });
    }
    expect(store.reserve(current, "call-4")).toEqual({ outcome: "fallthrough", reason: "exhausted", duplicate: false });
    expect(store.snapshot("session")).toEqual({ blockedCount: 3, retainedCallCount: 4, exhausted: true });
  });

  test("duplicate blocked and fallthrough call IDs replay without another debit", () => {
    const store = new ReplanStateStore(1);
    const current = generation(store, "session", "message");
    store.reserve(current, "blocked-call");
    store.reserve(current, "fallthrough-call");

    expect(store.reserve(current, "blocked-call")).toEqual({ outcome: "blocked", reason: "reserved", duplicate: true });
    expect(store.reserve(current, "fallthrough-call")).toEqual({ outcome: "fallthrough", reason: "exhausted", duplicate: true });
    expect(store.snapshot("session")).toEqual({ blockedCount: 1, retainedCallCount: 2, exhausted: true });
  });

  test("a stale captured generation falls through without debiting the replacement", () => {
    const store = new ReplanStateStore(3);
    const stale = generation(store, "session", "message-1");
    generation(store, "session", "message-2");

    expect(store.reserve(stale, "late-call")).toEqual({ outcome: "fallthrough", reason: "stale_generation", duplicate: false });
    expect(store.snapshot("session")).toEqual({ blockedCount: 0, retainedCallCount: 0, exhausted: false });
  });

  test("parallel reservations atomically admit only the configured winners", async () => {
    const store = new ReplanStateStore(3);
    const current = generation(store, "session", "message");
    const results = await Promise.all(
      Array.from({ length: 10 }, (_, index) => Promise.resolve().then(() => store.reserve(current, `parallel-${index}`))),
    );

    expect(results.filter((result) => result.outcome === "blocked")).toHaveLength(3);
    expect(results.filter((result) => result.outcome === "fallthrough")).toHaveLength(7);
    expect(store.snapshot("session")).toEqual({ blockedCount: 3, retainedCallCount: 4, exhausted: true });
  });

  test("retains at most the block limit plus one exhaustion marker", () => {
    const store = new ReplanStateStore(3);
    const current = generation(store, "session", "message");
    for (let index = 0; index < 100; index += 1) store.reserve(current, `bounded-${index}`);

    expect(store.snapshot("session")).toEqual({ blockedCount: 3, retainedCallCount: 4, exhausted: true });
  });

  test("missing identities fall through without creating state", () => {
    const store = new ReplanStateStore(3);
    expect(store.observeUserMessage(undefined, "message")).toBeUndefined();
    expect(store.observeUserMessage("session", "")).toBeUndefined();
    expect(store.reserve(undefined, "call")).toEqual({ outcome: "fallthrough", reason: "missing_identity", duplicate: false });
    expect(store.sessionCount).toBe(0);
  });

  test("session deletion and dispose remove every retained record", () => {
    const store = new ReplanStateStore(3);
    const generationA = generation(store, "session-a", "message-a");
    const generationB = generation(store, "session-b", "message-b");
    store.reserve(generationA, "call-a");
    store.reserve(generationB, "call-b");

    expect(store.deleteSession("session-a")).toBe(true);
    expect(store.snapshot("session-a")).toBeUndefined();
    expect(store.reserve(generationA, "late-call")).toEqual({ outcome: "fallthrough", reason: "stale_generation", duplicate: false });
    expect(store.sessionCount).toBe(1);

    store.dispose();
    expect(store.sessionCount).toBe(0);
    expect(store.snapshot("session-b")).toBeUndefined();
    expect(store.reserve(generationB, "late-call")).toEqual({ outcome: "fallthrough", reason: "stale_generation", duplicate: false });
  });
});
