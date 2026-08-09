import { parsePermissionAskedEvent, type BashPermissionRequest } from "../opencode/permission-event";
import type { AuditRecord } from "../audit/schema";
import type { AuditWriter } from "../audit/writer";
import { createProgressReporter, type ProgressMetrics, type ProgressReporter, type ProgressSink } from "../progress/reporter";
import { evaluateDeterministicPolicy, type DeterministicPolicyResult } from "../policy/deterministic";
import type { SmartApproveConfig } from "../config/schema";
import type { ReviewerAgent, ReviewerResult } from "../reviewer/agent";
import { redactCommand } from "../reviewer/prompt";
import { ApprovalStateStore, hashCommand, transition, type ApprovalRequestRecord, type ApprovalState } from "./state";

export interface ApprovalCoordinatorOptions {
  readonly reviewer?: Pick<ReviewerAgent, "review"> & Partial<Pick<ReviewerAgent, "handlePermission" | "dispose">> & {
    /** Cancel only the child owned by this permission request. */
    readonly cancel?: (requestID: string) => void | Promise<void>;
  };
  readonly approve?: (requestID: string, sessionID?: string) => void | Promise<void>;
  readonly policy?: (command: string, options?: { readonly config?: SmartApproveConfig }) => DeterministicPolicyResult | Promise<DeterministicPolicyResult>;
  readonly config?: SmartApproveConfig;
  readonly modelEnabled?: boolean;
  readonly maxConcurrent?: number;
  readonly progressSink?: ProgressSink;
  readonly metrics?: ProgressMetrics;
  readonly auditWriter?: AuditWriter;
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

/** Reduce parser output to bounded structural facts; raw command bytes never enter audit state. */
function commandShape(result: DeterministicPolicyResult): string {
  const features = result.parse?.features;
  if (!features) return "unparsed";
  return JSON.stringify({
    pipeline: features.pipeline,
    redirects: features.redirects,
    substitutions: features.substitutions,
    processSubstitutions: features.processSubstitutions,
    backticks: features.backticks,
    functions: features.functions,
    loops: features.loops,
    heredocs: features.heredocs,
    unresolvedExpansions: features.unresolvedExpansions,
    eval: features.eval,
    exec: features.exec,
    source: features.source,
    environmentAssignments: features.environmentAssignments,
    segmentCount: features.segmentCount,
    maxDepth: features.maxDepth,
    unsupportedCount: features.unsupported.length,
  });
}

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
  const audited = new WeakSet<ApprovalRequestRecord>();
  const auditContexts = new WeakMap<ApprovalRequestRecord, {
    readonly startedAt: number;
    commandShape: string;
    reasonCodes: string[];
    promptID: string;
  }>();
  let active = 0;
  let disposed = false;
  const notify = (requestID: string, state: ApprovalState): void => {
    try { options.onState?.(requestID, state); } catch { /* observer failures cannot affect approval */ }
  };

  const emit = (record: ApprovalRequestRecord, next: ApprovalState): void => {
    if (transition(record, next)) notify(record.requestID, next);
  };

  const auditTerminal = (record: ApprovalRequestRecord, next: ApprovalState): void => {
    if (!options.auditWriter || audited.has(record) || !record.terminal) return;
    audited.add(record);
    const context = auditContexts.get(record);
    const decision: AuditRecord["decision"] = next === "complete" ? "allow"
      : next === "timeout" || next === "error" || next === "stale" ? next
        : "manual";
    const reasons = context?.reasonCodes ?? [];
    const raceState: AuditRecord["raceState"] = reasons.includes("reply_not_found") ? "not_found"
      : next === "stale" && !record.replyAttempted ? "user_first"
        : next === "stale" ? "stale"
          : record.replyAttempted ? "replying" : "none";
    try {
      void options.auditWriter.append({
        requestID: record.requestID,
        commandShape: context?.commandShape ?? "unparsed",
        policyID: "deterministic-v1",
        promptID: context?.promptID ?? "none",
        modelID: options.config ? `${options.config.model.provider}/${options.config.model.model}` : "none",
        decision,
        reasonCodes: reasons,
        latencyMs: Math.max(0, Date.now() - (context?.startedAt ?? Date.now())),
        raceState,
      });
    } catch { /* audit diagnostics never affect permission handling */ }
  };

  const finish = (record: ApprovalRequestRecord, next: ApprovalState): void => {
    if (record.state !== next && !transition(record, next)) return;
    notify(record.requestID, next);
    auditTerminal(record, next);
  };

  const process = async (request: BashPermissionRequest, record: ApprovalRequestRecord): Promise<void> => {
    const audit = auditContexts.get(record)!;
    let decision: DeterministicPolicyResult;
    try {
      decision = await policy(request.command, { config: options.config });
    } catch {
      audit.reasonCodes = ["policy_error"];
      finish(record, "manual");
      return;
    }
    audit.commandShape = commandShape(decision);
    audit.reasonCodes = [...decision.reasonCodes];
    if (store.get(request.requestID) !== record || record.commandHash !== hashCommand(request.command) || record.terminal) return;
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
      reporter = createProgressReporter({ requestID: request.requestID, sink: options.progressSink, metrics: options.metrics });
      reporters.set(request.requestID, reporter);
      reporter.start();
    } catch {
      active -= 1;
      finish(record, "manual");
      return;
    }
    let reviewTimer: ReturnType<typeof setTimeout> | undefined;
    try {
      audit.promptID = "reviewer-v1";
      const pathClasses = decision.pathClasses ?? ["unknown"];
      const reviewPromise = options.reviewer.review({
        requestID: request.requestID,
        parentSessionID: request.sessionID,
        prompt: redactCommand(request.command),
        redactedCommand: redactCommand(request.command),
        parserFeatures: decision.parse ? { ...decision.parse.features } : undefined,
        policyFacts: ["model_review", "parser.clear", "privacy.clear", ...pathClasses.map((value) => `path.${value}`)],
        pathClasses,
      });
      // The production reviewer owns its child-session timeout and cleanup.
      // A coordinator-level deadline is used only when an injected reviewer
      // exposes exact-request cancellation, so unrelated children are never
      // aborted by a broad dispose call.
      const result: ReviewerResult = options.timeoutMs && options.timeoutMs > 0
        ? await Promise.race([
          reviewPromise,
          new Promise<never>((_, reject) => {
            reviewTimer = setTimeout(() => {
              try {
                Promise.resolve(options.reviewer?.cancel?.(request.requestID)).catch(() => undefined);
              } catch { /* cancellation failure cannot delay fail-closed timeout */ }
              reject(new Error("reviewer timeout"));
            }, options.timeoutMs);
          }),
        ])
        : await reviewPromise;
      audit.reasonCodes = [...(result.reasonCodes ?? (result.decision === "allow" ? ["safe"] : ["manual_review"]))];
      if (store.get(request.requestID) !== record || record.commandHash !== hashCommand(request.command) || record.terminal) {
        if (record.state === "stale") reporter.finish("warning", "Permission was already answered; native prompt remains authoritative");
        return;
      }
      if (disposed) {
        finish(record, "manual");
        reporter.finish("warning", "Review stopped; native prompt remains available");
        return;
      }
      if (result.requestID !== request.requestID || result.decision !== "allow") {
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
        await options.approve(request.requestID, request.sessionID);
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
          audit.reasonCodes = ["reply_not_found"];
          finish(record, "stale");
          reporter.finish("warning", "Permission was already answered; native prompt remains authoritative");
        } else {
          audit.reasonCodes = ["reply_error"];
          finish(record, "error");
          reporter.finish("warning", "Approval reply failed; native prompt remains available");
        }
      }
    } catch (error) {
      const timedOut = /timeout/i.test(String(error));
      audit.reasonCodes = [timedOut ? "timeout" : "reviewer_error"];
      if (store.get(request.requestID) === record && !record.terminal) finish(record, timedOut ? "timeout" : "manual");
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
    auditContexts.set(record, { startedAt: Date.now(), commandShape: "unparsed", reasonCodes: [], promptID: "none" });
    notify(request.requestID, "received");
    await process(request, record);
  };

  const event = async (raw: unknown): Promise<void> => {
    if (disposed) return;
    // Recursive permission events are rejected in the child session and never
    // enter the parent request state machine.
    const root = isRecord(raw) ? raw : undefined;
    const body = root && (isRecord(root.properties) ? root.properties : isRecord(root.data) ? root.data : undefined);
    if (root?.type === "permission.replied" && body && typeof body.requestID === "string") {
      const record = store.get(body.requestID);
      // Our own one-shot call also emits permission.replied. Once its exact
      // attempt has started, let the transport result distinguish success from
      // the user-first NotFound race instead of mislabelling our reply stale.
      if (record && !record.replyAttempted) finish(record, "stale");
      return;
    }
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
      if (record) finish(record, "stale");
    },
    state: (requestID) => store.get(requestID)?.state,
    dispose: async () => {
      disposed = true;
      for (const reporter of reporters.values()) reporter.dispose();
      reporters.clear();
      try { await options.reviewer?.dispose?.(); } catch { /* cleanup is non-authoritative */ }
    },
  };
}

export const createApprovalOrchestrator = createApprovalCoordinator;
