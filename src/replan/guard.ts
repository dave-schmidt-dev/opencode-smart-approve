import { evaluateDeterministicPolicy, type DeterministicPolicyResult } from "../policy/deterministic";
import { sha256 } from "../audit/schema";
import type { AuditWriter } from "../audit/writer";
import { createReplanProgressReporter, type ProgressMetrics, type ProgressSink, type ReplanProgressReporter, type ReplanProgressStatus } from "../progress/reporter";
import { ReplanBlockedError } from "./error";
import { ReplanStateStore, type ReplanGeneration } from "./state";
import { findReplanExecutableIdentity } from "../policy/executable-identity";

export interface ReplanGuardInput {
  readonly tool?: unknown;
  readonly sessionID?: unknown;
  readonly callID?: unknown;
  readonly generation?: ReplanGeneration;
  readonly output?: unknown;
}

export interface ReplanGuardOptions {
  readonly state: ReplanStateStore;
  readonly policy?: (command: string, options?: unknown) => DeterministicPolicyResult | Promise<DeterministicPolicyResult>;
  readonly config?: unknown;
  readonly progressSink?: ProgressSink;
  readonly metrics?: ProgressMetrics;
  readonly auditWriter?: Pick<AuditWriter, "append">;
  readonly onStatus?: (status: ReplanProgressStatus) => void;
  readonly now?: () => number;
}

export interface ReplanGuard {
  readonly before: (input: ReplanGuardInput, output?: unknown) => Promise<void>;
}

const validID = (value: unknown): value is string => typeof value === "string" && value.length > 0;

function commandFrom(input: ReplanGuardInput, output: unknown): string | undefined {
  const candidate = output ?? input.output;
  if (!candidate || typeof candidate !== "object") return undefined;
  const args = (candidate as { readonly args?: unknown }).args;
  if (!args || typeof args !== "object") return undefined;
  const command = (args as { readonly command?: unknown }).command;
  return typeof command === "string" && command.length > 0 ? command : undefined;
}

/**
 * Capability-free pre-execution gate. Every invalid, stale, duplicate,
 * exhausted, non-replan, and internal-error path falls through to native Bash.
 */
export function createReplanGuard(options: ReplanGuardOptions): ReplanGuard {
  const policy = options.policy ?? ((command, policyOptions) => evaluateDeterministicPolicy(command, policyOptions as never));

  const safeMetric = (callback: (() => void) | undefined): void => {
    try { callback?.(); } catch { /* metrics are non-authoritative */ }
  };

  const appendBlockedAudit = (callID: string, latencyMs: number): void => {
    if (!options.auditWriter) return;
    try {
      void options.auditWriter.append({
        requestHash: sha256(callID),
        commandShape: "replan",
        policyID: "replan-v1",
        promptID: "none",
        modelID: "none",
        decision: "replan_blocked",
        reasonCodes: ["replan"],
        latencyMs: Math.max(0, Math.min(Math.floor(latencyMs), 86_400_000)),
        raceState: "none",
      }).catch(() => undefined);
    } catch { /* audit is diagnostic only */ }
  };

  const before = async (input: ReplanGuardInput, output?: unknown): Promise<void> => {
    let progress: ReplanProgressReporter | undefined;
    try {
      if (input?.tool !== "bash" || !validID(input.sessionID) || !validID(input.callID) || !input.generation) return;
      const command = commandFrom(input, output);
      if (!command) return;
      const startedAt = (options.now ?? Date.now)();
      progress = createReplanProgressReporter({
        sink: options.progressSink,
        metrics: options.metrics,
        onStatus: options.onStatus,
        now: options.now,
      });
      progress.start();
      const result = await policy(command, { config: options.config });
      if ((result as unknown as { readonly status?: unknown }).status !== "replan") {
        progress.finish("exhausted_fallthrough", "fallthrough");
        return;
      }
      const reservation = options.state.reserve(input.generation, input.callID);
      if (reservation.outcome !== "blocked" || reservation.duplicate) {
        if (reservation.duplicate) safeMetric(options.metrics?.replanDuplicate);
        const reason = reservation.reason === "exhausted" ? "exhausted" : reservation.duplicate ? "duplicate" : "fallthrough";
        progress.finish("exhausted_fallthrough", reason);
        return;
      }
      progress.finish("blocked");
      appendBlockedAudit(input.callID, (options.now ?? Date.now)() - startedAt);
      throw new ReplanBlockedError(findReplanExecutableIdentity(command));
    } catch (error) {
      if (error instanceof ReplanBlockedError) throw error;
      try { progress?.finish("internal_failure_fallthrough"); } catch { /* observers are non-authoritative */ }
    }
  };

  return { before };
}

export const replanGuard = createReplanGuard;
