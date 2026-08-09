import type { Plugin } from "@opencode-ai/plugin";
import { createApprovalAdapter } from "./opencode/client";
import { createApprovalCoordinator, type ApprovalCoordinator } from "./approval/coordinator";
import type { SmartApproveConfig } from "./config/schema";
import type { DeterministicPolicyResult } from "./policy/deterministic";
import { createReviewerAgent, type ReviewerAgent, type ReviewerSessionClient } from "./reviewer/agent";
import type { ProgressSink } from "./progress/reporter";

export type RequestState = "reviewing" | "approved" | "manual" | "stale" | "timeout";

export interface SmartApprovePluginOptions {
  readonly reviewer?: Pick<ReviewerAgent, "review">;
  readonly reviewerClient?: ReviewerSessionClient;
  readonly approve?: (requestID: string) => void | Promise<void>;
  readonly policy?: (command: string, options?: { readonly config?: SmartApproveConfig }) => DeterministicPolicyResult | Promise<DeterministicPolicyResult>;
  readonly config?: SmartApproveConfig;
  readonly modelEnabled?: boolean;
  readonly maxConcurrent?: number;
  readonly progressSink?: ProgressSink;
  readonly timeoutMs?: number;
  readonly shellCompatible?: boolean;
  readonly directory?: string;
  readonly onState?: (requestID: string, state: RequestState) => void;
}

export interface SmartApproveHooks {
  readonly event: (input: { event: unknown }) => Promise<void>;
  readonly dispose: () => Promise<void>;
  readonly state: (requestID: string) => RequestState | undefined;
}

/** Return whether the configured shell can be interpreted by the Bash parser. */
export function isBashCompatibleInterpreter(interpreter: string | undefined): boolean {
  if (!interpreter) return true;
  const name = interpreter.split("/").at(-1)?.toLowerCase();
  return name === "bash" || name === "sh" || name === "zsh";
}

function makeReviewer(options: SmartApprovePluginOptions): Pick<ReviewerAgent, "review"> | undefined {
  if (options.reviewer) return options.reviewer;
  if (!options.reviewerClient) return undefined;
  return createReviewerAgent({ client: options.reviewerClient, timeoutMs: options.timeoutMs, directory: options.directory });
}

/** Build hooks while keeping review work detached from the OpenCode event bridge. */
export function createSmartApproveHooks(options: SmartApprovePluginOptions = {}): SmartApproveHooks {
  const reviewer = makeReviewer(options);
  const states = new Map<string, RequestState>();
  const visibleState = (state: import("./approval/state").ApprovalState): RequestState | undefined => {
    if (state === "reviewing" || state === "approved" || state === "manual" || state === "stale" || state === "timeout") return state;
    if (state === "error") return "manual";
    return undefined;
  };
  const coordinator: ApprovalCoordinator = createApprovalCoordinator({
    reviewer,
    approve: options.approve,
    policy: options.policy,
    config: options.config,
    modelEnabled: options.shellCompatible === false ? false : options.modelEnabled,
    maxConcurrent: options.maxConcurrent,
    progressSink: options.progressSink,
    timeoutMs: options.timeoutMs,
    onState: (requestID, state) => {
      const next = visibleState(state);
      if (next === undefined) return;
      states.set(requestID, next);
      options.onState?.(requestID, next);
    },
  });
  return {
    event: async (input) => {
      // Keep the OpenCode event bridge non-blocking while retaining a catch at
      // the detached boundary so plugin failures never become approvals.
      void coordinator.event(input.event).catch(() => undefined);
    },
    dispose: async () => {
      await coordinator.dispose();
    },
    state: (requestID) => states.get(requestID),
  };
}

/** OpenCode entry point; it does not mutate global configuration or install a loader. */
export const SmartApprovePlugin: Plugin = async (input, options) => {
  const configured = (options ?? {}) as SmartApprovePluginOptions;
  const hooks = createSmartApproveHooks({
    ...configured,
    reviewerClient: configured.reviewerClient ?? input.client as unknown as ReviewerSessionClient,
    approve: configured.approve ?? createApprovalAdapter(input.client as unknown as Parameters<typeof createApprovalAdapter>[0]).approve,
  });
  return { event: (input) => hooks.event({ event: input.event }), dispose: hooks.dispose };
};

export default SmartApprovePlugin;
