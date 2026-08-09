/** Best-effort, persistent TUI status for a pending reviewer request. */

export type ProgressVariant = "info" | "success" | "warning" | "error";

export interface ProgressSink {
  readonly tui?: {
    readonly showToast: (input: unknown) => unknown | Promise<unknown>;
  };
}

export interface ProgressTimer {
  readonly setInterval: (callback: () => void, delay: number) => unknown;
  readonly clearInterval: (handle: unknown) => void;
}

export interface ProgressMetricsSnapshot {
  readonly reviewCount: number;
  readonly heartbeatCount: number;
  readonly completedCount: number;
  readonly timeoutCount: number;
  readonly manualFallbackCount: number;
  readonly cumulativeLatencyMs: number;
}

export interface ProgressMetrics {
  readonly begin: () => void;
  readonly heartbeat?: () => void;
  readonly timeout?: () => void;
  readonly finish: (variant: Exclude<ProgressVariant, "info">, latencyMs: number) => void;
  readonly snapshot: () => ProgressMetricsSnapshot;
}

/** In-memory session counters. It deliberately never accepts command text. */
export function createProgressMetrics(): ProgressMetrics {
  const values: {
    reviewCount: number;
    heartbeatCount: number;
    completedCount: number;
    timeoutCount: number;
    manualFallbackCount: number;
    cumulativeLatencyMs: number;
  } = {
    reviewCount: 0,
    heartbeatCount: 0,
    completedCount: 0,
    timeoutCount: 0,
    manualFallbackCount: 0,
    cumulativeLatencyMs: 0,
  };
  return {
    begin: () => { values.reviewCount += 1; },
    heartbeat: () => { values.heartbeatCount += 1; },
    timeout: () => { values.timeoutCount += 1; },
    finish: (variant, latencyMs) => {
      values.completedCount += 1;
      values.cumulativeLatencyMs += Number.isFinite(latencyMs) && latencyMs >= 0 ? latencyMs : 0;
      if (variant === "warning" || variant === "error") values.manualFallbackCount += 1;
    },
    snapshot: () => ({ ...values }),
  };
}

export interface ProgressReporter {
  readonly start: () => void;
  readonly update: (message?: string) => void;
  readonly finish: (variant: Exclude<ProgressVariant, "info">, message: string) => void;
  readonly dispose: () => void;
}

export interface ProgressStatus {
  readonly phase: "started" | "updated" | "finished";
  readonly message: string;
  readonly variant: ProgressVariant;
}

export interface ProgressReporterOptions {
  readonly requestID: string;
  readonly sink?: ProgressSink;
  /** Heartbeats may be more frequent, but never less frequent than 10 seconds. */
  readonly intervalMs?: number;
  /** The validated global model timeout, retained as a configuration seam. */
  readonly timeoutMs?: number;
  readonly timer?: ProgressTimer;
  readonly metrics?: ProgressMetrics;
  readonly onStatus?: (status: ProgressStatus) => void;
}

export const MIN_REVIEW_TIMEOUT_MS = 10_000;
export const DEFAULT_REVIEW_TIMEOUT_MS = 30_000;
export const MAX_REVIEW_TIMEOUT_MS = 60_000;

export function validateReviewTimeout(timeoutMs: number): number {
  if (!Number.isInteger(timeoutMs) || timeoutMs < MIN_REVIEW_TIMEOUT_MS || timeoutMs > MAX_REVIEW_TIMEOUT_MS) {
    throw new RangeError("review timeout must be between 10000 and 60000 ms");
  }
  return timeoutMs;
}

const safeMessage = (message: string): string => message.replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, 240);

/**
 * Create a reporter that emits immediately, refreshes while pending, and
 * always emits one terminal status. Sink failures are intentionally swallowed.
 */
export function createProgressReporter(options: ProgressReporterOptions): ProgressReporter {
  const intervalMs = options.intervalMs ?? 10_000;
  if (!Number.isInteger(intervalMs) || intervalMs < 1 || intervalMs > 10_000) {
    throw new RangeError("progress interval must be at most 10000 ms");
  }
  if (options.timeoutMs !== undefined) validateReviewTimeout(options.timeoutMs);
  const timer = options.timer ?? globalThis;
  let handle: unknown;
  let startedAt = 0;
  let finished = false;
  let updates = 0;

  const emit = (message: string, variant: ProgressVariant, duration?: number): void => {
    const bounded = safeMessage(message);
    const phase: ProgressStatus["phase"] = variant === "info"
      ? (updates === 0 ? "started" : "updated")
      : "finished";
    try { options.onStatus?.({ phase, message: bounded, variant }); } catch { /* observers are non-authoritative */ }
    const showToast = options.sink?.tui?.showToast;
    if (!showToast) return;
    try {
      Promise.resolve(showToast({
        body: {
          title: "Smart Approve",
          message: bounded,
          variant,
          ...(duration === undefined ? {} : { duration }),
        },
      })).catch(() => undefined);
    } catch { /* a failing progress sink cannot affect a decision */ }
  };

  const update = (message = `Reviewing command ${options.requestID}`): void => {
    if (finished) return;
    updates += 1;
    options.metrics?.heartbeat?.();
    emit(message, "info");
  };

  return {
    start: () => {
      if (finished || handle !== undefined) return;
      startedAt = Date.now();
      options.metrics?.begin();
      emit(`Reviewing command ${options.requestID}`, "info");
      handle = timer.setInterval(() => update(), intervalMs);
    },
    update,
    finish: (variant, message) => {
      if (finished) return;
      finished = true;
      if (handle !== undefined) timer.clearInterval(handle as never);
      handle = undefined;
      options.metrics?.finish(variant, Math.max(0, Date.now() - startedAt));
      if (/\btime(?:d out|out)\b/i.test(message)) options.metrics?.timeout?.();
      emit(message, variant, 5_000);
    },
    dispose: () => {
      if (handle !== undefined) timer.clearInterval(handle as never);
      handle = undefined;
      finished = true;
    },
  };
}
