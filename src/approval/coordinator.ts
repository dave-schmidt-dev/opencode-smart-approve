import { parsePermissionAskedEvent, type BashPermissionRequest } from "../opencode/permission-event";
import { createProgressReporter, type ProgressReporter, type ProgressSink } from "../progress/reporter";
import { evaluateDeterministicPolicy, type DeterministicPolicyResult } from "../policy/deterministic";
import type { SmartApproveConfig } from "../config/schema";
import type { ReviewerAgent, ReviewerResult } from "../reviewer/agent";
import { ApprovalStateStore, transition, type ApprovalRequestRecord, type ApprovalState } from "./state";

export interface ApprovalCoordinatorOptions {
  readonly reviewer?: Pick<ReviewerAgent, "review"> & Partial<Pick<ReviewerAgent, "handlePermission" | "dispose">>;
  readonly approve?: (requestID: string) => void | Promise<void>;
  readonly policy?: (command: string, options?: { readonly config?: SmartApproveConfig }) => DeterministicPolicyResult | Promise<DeterministicPolicyResult>;
  readonly config?: SmartApproveConfig;
  readonly modelEnabled?: boolean;
  readonly maxConcurrent?: number;
  readonly progressSink?: ProgressSink;
  readonly timeoutMs?: number;
  readonly onState?: (requestID: string, state: ApprovalState) => void;
}

export interface ApprovalCoordinator {
  readonly event: (event: unknown) => Promise<void>;
  readonly handle: (request: BashPermissionRequest) => Promise<void>;
  readonly markUserAnswered: (requestID: string) => void;
  readonly state: (requestID: string) => ApprovalState | undefined;
  readonly dispose: () => Promise<void>;
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null;

const isNotFoundRace = (error: unknown): boolean => {
  if (isRecord(error) && (error.status === 404 || error.statusCode === 404)) return true;
  const message = error instanceof Error ? error.message : isRecord(error) && typeof error.message === "string" ? error.message : String(error);
  return /not[ -]?found|no pending|already handled|unknown request/i.test(message);
};

/**
 * Coordinates deterministic routing, isolated model review, and one-shot
 * replies. All callbacks re-check the exact request record before replying.
 */
export function createApprovalCoordinator(options: ApprovalCoordinatorOptions): ApprovalCoordinator {
  const store = new ApprovalStateStore();
  const policy = options.policy ?? evaluateDeterministicPolicy;
  // The coordinator is deliberately bounded even when a caller supplies an
  // overly large value; there is no queue behind the four active reviews.
  const requestedCap = typeof options.maxConcurrent === "number" && Number.isFinite(options.maxConcurrent)
    ? Math.floor(options.maxConcurrent)
    : 4;
  const cap = Math.min(4, Math.max(1, requestedCap));
  const reporters = new Map<string, ProgressReporter>();
  let active = 0;
  let disposed = false;
  const notify = (requestID: string, state: ApprovalState): void => {
    try { options.onState?.(requestID, state); } catch { /* observer failures cannot affect approval */ }
  };

  const emit = (record: ApprovalRequestRecord, next: ApprovalState): void => {
    if (transition(record, next)) notify(record.requestID, next);
  };

  const finish = (record: ApprovalRequestRecord, next: ApprovalState): void => {
    if (record.state !== next && !transition(record, next)) return;
    notify(record.requestID, next);
  };

  const process = async (request: BashPermissionRequest, record: ApprovalRequestRecord): Promise<void> => {
    let decision: DeterministicPolicyResult;
    try {
      decision = await policy(request.command, { config: options.config });
    } catch {
      finish(record, "manual");
      return;
    }
    if (store.get(request.requestID) !== record || record.command !== request.command || record.terminal) return;
    if (disposed || !options.reviewer || options.modelEnabled === false || decision.status !== "model_review") {
      finish(record, "manual");
      return;
    }
    if (active >= cap) {
      finish(record, "manual");
      return;
    }
    active += 1;
    emit(record, "reviewing");
    let reporter: ProgressReporter;
    try {
      reporter = createProgressReporter({ requestID: request.requestID, sink: options.progressSink });
      reporters.set(request.requestID, reporter);
      reporter.start();
    } catch {
      active -= 1;
      finish(record, "manual");
      return;
    }
    let reviewTimer: ReturnType<typeof setTimeout> | undefined;
    try {
      const reviewPromise = options.reviewer.review({
        requestID: request.requestID,
        parentSessionID: request.sessionID,
        prompt: request.command,
      });
      const result: ReviewerResult = options.timeoutMs && options.timeoutMs > 0
        ? await Promise.race([
          reviewPromise,
          new Promise<never>((_, reject) => {
            reviewTimer = setTimeout(() => reject(new Error("reviewer timeout")), options.timeoutMs);
          }),
        ])
        : await reviewPromise;
      if (store.get(request.requestID) !== record || record.command !== request.command || record.terminal) {
        if (record.state === "stale") reporter.finish("warning", "Permission was already answered; native prompt remains authoritative");
        return;
      }
      if (disposed) {
        finish(record, "manual");
        reporter.finish("warning", "Review stopped; native prompt remains available");
        return;
      }
      if (result.decision !== "allow") {
        finish(record, "manual");
        reporter.finish("warning", "Review requires a manual decision");
        return;
      }
      // A reviewer result alone is never an approval.  Integrations that do
      // not provide the narrow adapter retain the native manual prompt.
      if (!options.approve) {
        finish(record, "manual");
        reporter.finish("warning", "Review passed; native approval adapter unavailable");
        return;
      }
      emit(record, "approved");
      if (store.get(request.requestID) !== record || record.state !== "approved" || record.replyAttempted) return;
      record.replyAttempted = true;
      emit(record, "replying");
      try {
        await options.approve(request.requestID);
        // The native prompt can win while the adapter call is in flight.  A
        // successful transport response must not overwrite that stale outcome.
        if ((record as ApprovalRequestRecord).state === "stale") {
          reporter.finish("warning", "Permission was already answered; native prompt remains authoritative");
          return;
        }
        finish(record, "complete");
        reporter.finish("success", "Review passed; permission approved once");
      } catch (error) {
        // OpenCode's not-found response is the normal user-first race. Never retry it.
        if (isNotFoundRace(error)) {
          finish(record, "stale");
          reporter.finish("warning", "Permission was already answered; native prompt remains authoritative");
        } else {
          finish(record, "manual");
          reporter.finish("warning", "Approval reply failed; native prompt remains available");
        }
      }
    } catch (error) {
      if (store.get(request.requestID) === record && !record.terminal) finish(record, /timeout/i.test(String(error)) ? "timeout" : "manual");
      reporter.finish("warning", /timeout/i.test(String(error)) ? "Review timed out" : "Review unavailable");
    } finally {
      if (reviewTimer !== undefined) clearTimeout(reviewTimer);
      active -= 1;
      reporters.delete(request.requestID);
    }
  };

  const handle = async (request: BashPermissionRequest): Promise<void> => {
    if (disposed) return;
    const record = store.begin(request.requestID, request.command, request.sessionID);
    if (!record) return;
    notify(request.requestID, "received");
    await process(request, record);
  };

  const event = async (raw: unknown): Promise<void> => {
    if (disposed) return;
    // Recursive permission events are rejected in the child session and never
    // enter the parent request state machine.
    const root = isRecord(raw) ? raw : undefined;
    const body = root && (isRecord(root.properties) ? root.properties : isRecord(root.data) ? root.data : undefined);
    if (body && typeof body.id === "string" && typeof body.sessionID === "string" && options.reviewer?.handlePermission) {
      try {
        if (await options.reviewer.handlePermission({ requestID: body.id, sessionID: body.sessionID })) return;
      } catch {
        return;
      }
    }
    const request = parsePermissionAskedEvent(raw);
    if (!request) return;
    await handle(request);
  };

  return {
    event,
    handle,
    markUserAnswered: (requestID) => {
      const record = store.get(requestID);
      if (record && transition(record, "stale")) notify(requestID, "stale");
    },
    state: (requestID) => store.get(requestID)?.state,
    dispose: async () => {
      disposed = true;
      for (const reporter of reporters.values()) reporter.dispose();
      reporters.clear();
      await options.reviewer?.dispose?.();
    },
  };
}

export const createApprovalOrchestrator = createApprovalCoordinator;
