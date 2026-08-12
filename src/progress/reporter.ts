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
  readonly replanAttemptCount: number;
  readonly replanBlockedCount: number;
  readonly replanDuplicateCount: number;
  readonly replanExhaustionCount: number;
  readonly replanFallthroughCount: number;
  readonly replanInternalFailureCount: number;
}

export interface ProgressMetrics {
  readonly begin: () => void;
  readonly heartbeat?: () => void;
  readonly timeout?: () => void;
  readonly finish: (variant: Exclude<ProgressVariant, "info">, latencyMs: number) => void;
  readonly replanAttempt?: () => void;
  readonly replanBlocked?: () => void;
  readonly replanDuplicate?: () => void;
  readonly replanExhaustion?: () => void;
  readonly replanFallthrough?: () => void;
  readonly replanInternalFailure?: () => void;
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
    replanAttemptCount: number;
    replanBlockedCount: number;
    replanDuplicateCount: number;
    replanExhaustionCount: number;
    replanFallthroughCount: number;
    replanInternalFailureCount: number;
  } = {
    reviewCount: 0,
    heartbeatCount: 0,
    completedCount: 0,
    timeoutCount: 0,
    manualFallbackCount: 0,
    cumulativeLatencyMs: 0,
    replanAttemptCount: 0,
    replanBlockedCount: 0,
    replanDuplicateCount: 0,
    replanExhaustionCount: 0,
    replanFallthroughCount: 0,
    replanInternalFailureCount: 0,
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
    replanAttempt: () => { values.replanAttemptCount += 1; },
    replanBlocked: () => { values.replanBlockedCount += 1; },
    replanDuplicate: () => { values.replanDuplicateCount += 1; },
    replanExhaustion: () => { values.replanExhaustionCount += 1; },
    replanFallthrough: () => { values.replanFallthroughCount += 1; },
    replanInternalFailure: () => { values.replanInternalFailureCount += 1; },
    snapshot: () => ({ ...values }),
  };
}

export type ReplanTerminalStatus = "blocked" | "exhausted_fallthrough" | "internal_failure_fallthrough";

export interface ReplanProgressStatus {
  readonly phase: "started" | "finished";
  readonly status: "started" | ReplanTerminalStatus;
  readonly message: string;
  readonly variant: ProgressVariant;
}

export interface ReplanProgressReporter {
  readonly start: () => void;
  readonly finish: (status: ReplanTerminalStatus, reason?: "duplicate" | "exhausted" | "fallthrough") => void;
}

export interface ReplanProgressReporterOptions {
  readonly sink?: ProgressSink;
  readonly metrics?: ProgressMetrics;
  readonly onStatus?: (status: ReplanProgressStatus) => void;
  readonly now?: () => number;
}

const REPLAN_MESSAGES: Readonly<Record<ReplanProgressStatus["status"], string>> = {
  started: "Smart Approve replan attempt started",
  blocked: "Smart Approve replan blocked",
  exhausted_fallthrough: "Smart Approve replan exhausted; native permission remains available",
  internal_failure_fallthrough: "Smart Approve replan unavailable; native permission remains available",
};

/** Fixed, command-free progress for the pre-execution replan boundary. */
export function createReplanProgressReporter(options: ReplanProgressReporterOptions = {}): ReplanProgressReporter {
  let started = false;
  let finished = false;
  let startedAt = 0;
  const now = options.now ?? Date.now;
  const emit = (phase: ReplanProgressStatus["phase"], status: ReplanProgressStatus["status"], variant: ProgressVariant): void => {
    const bounded: ReplanProgressStatus = { phase, status, message: REPLAN_MESSAGES[status], variant };
    try { options.onStatus?.(bounded); } catch { /* observers are non-authoritative */ }
    const showToast = options.sink?.tui?.showToast;
    if (!showToast) return;
    try {
      Promise.resolve(showToast({ body: { title: "Smart Approve", message: bounded.message, variant } })).catch(() => undefined);
    } catch { /* a failing progress sink cannot affect routing */ }
  };
  const start = (): void => {
    if (started || finished) return;
    started = true;
    startedAt = now();
    try { options.metrics?.replanAttempt?.(); } catch { /* metrics are non-authoritative */ }
    emit("started", "started", "info");
  };
  return {
    start,
    finish: (status, reason = status === "exhausted_fallthrough" ? "exhausted" : "fallthrough") => {
      if (finished) return;
      if (!started) start();
      finished = true;
      if (status === "blocked") {
        try { options.metrics?.replanBlocked?.(); } catch { /* metrics are non-authoritative */ }
      } else if (status === "exhausted_fallthrough") {
        try {
          if (reason === "exhausted") options.metrics?.replanExhaustion?.();
          options.metrics?.replanFallthrough?.();
        } catch { /* metrics are non-authoritative */ }
      } else {
        try {
          options.metrics?.replanInternalFailure?.();
          options.metrics?.replanFallthrough?.();
        } catch { /* metrics are non-authoritative */ }
      }
      emit("finished", status, status === "internal_failure_fallthrough" ? "error" : status === "blocked" ? "warning" : "info");
    },
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
  /** Injectable monotonic-enough clock for deterministic latency tests. */
  readonly now?: () => number;
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
  const now = options.now ?? Date.now;
  let handle: unknown;
  let startedAt = 0;
  let started = false;
  let finished = false;

  const emit = (
    phase: ProgressStatus["phase"],
    message: string,
    variant: ProgressVariant,
    duration?: number,
  ): void => {
    const bounded = safeMessage(message);
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

  const start = (): void => {
    if (finished || started) return;
    started = true;
    startedAt = now();
    options.metrics?.begin();
    emit("started", `Reviewing command ${options.requestID}`, "info");
    handle = timer.setInterval(() => update(), intervalMs);
  };

  const update = (message = `Reviewing command ${options.requestID}`): void => {
    if (finished) return;
    if (!started) start();
    if (finished) return;
    options.metrics?.heartbeat?.();
    emit("updated", message, "info");
  };

  return {
    start,
    update,
    finish: (variant, message) => {
      if (finished) return;
      // Defensive callers may finish before start. Preserve the public
      // initial/terminal contract and record bounded latency from this call.
      if (!started) start();
      finished = true;
      if (handle !== undefined) timer.clearInterval(handle as never);
      handle = undefined;
      options.metrics?.finish(variant, Math.max(0, now() - startedAt));
      if (/\btime(?:d out|out)\b/i.test(message)) options.metrics?.timeout?.();
      emit("finished", message, variant, 5_000);
    },
    dispose: () => {
      if (handle !== undefined) timer.clearInterval(handle as never);
      handle = undefined;
      finished = true;
    },
  };
}
