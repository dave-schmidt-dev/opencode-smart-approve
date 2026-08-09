import type { Config as OpenCodeConfig, Plugin } from "@opencode-ai/plugin";
import { join } from "node:path";
import { createApprovalCoordinator, type ApprovalCoordinator, type ApprovalCoordinatorOptions } from "./approval/coordinator";
import { createAuditWriter } from "./audit/writer";
import { loadGlobalConfig } from "./config/load";
import { DEFAULT_CONFIG, type SmartApproveConfig } from "./config/schema";
import type { DeterministicPolicyResult } from "./policy/deterministic";
import { createReviewerAgent, REVIEWER_AGENT, type ReviewerAgent, type ReviewerSessionClient } from "./reviewer/agent";
import { REVIEWER_TOOL_DENY } from "./reviewer/client";
import { createProgressMetrics, type ProgressMetricsSnapshot, type ProgressSink } from "./progress/reporter";

export type RequestState = "reviewing" | "approved" | "manual" | "stale" | "timeout";

/**
 * Immutable release gate for model-backed approval. This remains false until
 * a complete live qualification artifact passes every threshold.
 */
export const MODEL_APPROVAL_QUALIFIED = false as const;

export interface SmartApprovePluginOptions {
  readonly reviewer?: ApprovalCoordinatorOptions["reviewer"];
  readonly reviewerClient?: ReviewerSessionClient;
  readonly approve?: (requestID: string, sessionID?: string) => void | Promise<void>;
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
  readonly config: (input: OpenCodeConfig) => Promise<void>;
  readonly dispose: () => Promise<void>;
  readonly state: (requestID: string) => RequestState | undefined;
  /** Read-only, command-free session counters for diagnostics and tests. */
  readonly metricsSnapshot: () => ProgressMetricsSnapshot;
  /** Wait only for diagnostic writes; permission decisions never await this. */
  readonly flushDiagnostics: () => Promise<void>;
}

/** Return whether the configured shell can be interpreted by the Bash parser. */
export function isBashCompatibleInterpreter(interpreter: string | undefined): boolean {
  if (!interpreter) return true;
  const name = interpreter.split("/").at(-1)?.toLowerCase();
  return name === "bash" || name === "sh" || name === "zsh";
}

/**
 * Resolve the interpreter selected for the host process.  The OpenCode plugin
 * API does not expose a shell selector, so an absent or empty SHELL is treated
 * as unknown and disables model approvals at the production entry point.
 */
export function configuredShellCompatible(env: Pick<NodeJS.ProcessEnv, "SHELL"> = { SHELL: process.env.SHELL }): boolean {
  const shell = env.SHELL;
  return typeof shell === "string" && shell.length > 0 && isBashCompatibleInterpreter(shell);
}

function makeReviewer(options: SmartApprovePluginOptions): ApprovalCoordinatorOptions["reviewer"] {
  if (options.reviewer) return options.reviewer;
  if (!options.reviewerClient) return undefined;
  return createReviewerAgent({
    client: options.reviewerClient,
    timeoutMs: options.timeoutMs ?? options.config?.model.timeoutMs,
    directory: options.directory,
    providerID: options.config?.model.provider,
    modelID: options.config?.model.model,
    variant: options.config?.model.variant,
  });
}

/** Build hooks while keeping review work detached from the OpenCode event bridge. */
export function createSmartApproveHooks(options: SmartApprovePluginOptions = {}): SmartApproveHooks {
  const config = options.config ?? DEFAULT_CONFIG;
  const reviewer = makeReviewer(options);
  const metrics = createProgressMetrics();
  const auditWriter = createAuditWriter({
    enabled: config.audit.enabled,
    directory: config.audit.directory ?? join(options.directory ?? process.cwd(), ".logs"),
    maxBytes: config.audit.maxBytes,
    maxFiles: config.audit.maxFiles,
  });
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
    config,
    modelEnabled: MODEL_APPROVAL_QUALIFIED
      && options.shellCompatible !== false
      && config.model.enabled
      && options.modelEnabled !== false,
    maxConcurrent: options.maxConcurrent,
    progressSink: options.progressSink,
    metrics,
    auditWriter,
    timeoutMs: options.timeoutMs ?? config.model.timeoutMs,
    onState: (requestID, state) => {
      const next = visibleState(state);
      if (next === undefined) return;
      states.set(requestID, next);
      options.onState?.(requestID, next);
    },
  });
  return {
    config: async (input) => {
      input.agent ??= {};
      input.agent[REVIEWER_AGENT] = {
        description: "Tool-free command safety reviewer",
        mode: "subagent",
        model: `${config.model.provider}/${config.model.model}`,
        variant: config.model.variant,
        temperature: 0,
        prompt: "Classify only the supplied bounded data. Never use tools or request permissions. Return strict JSON only.",
        tools: { ...REVIEWER_TOOL_DENY },
        permission: {
          edit: "deny",
          bash: "deny",
          webfetch: "deny",
          doom_loop: "deny",
          external_directory: "deny",
        },
      };
    },
    event: async (input) => {
      // Keep the OpenCode event bridge non-blocking while retaining a catch at
      // the detached boundary so plugin failures never become approvals.
      void coordinator.event(input.event).catch(() => undefined);
    },
    dispose: async () => {
      await coordinator.dispose();
      await auditWriter.flush();
    },
    state: (requestID) => states.get(requestID),
    metricsSnapshot: metrics.snapshot,
    flushDiagnostics: auditWriter.flush,
  };
}

/** OpenCode entry point; it does not mutate global configuration or install a loader. */
export const SmartApprovePlugin: Plugin = async (input, options) => {
  const configured = (options ?? {}) as SmartApprovePluginOptions;
  const config = configured.config ?? await loadGlobalConfig();
  const shellCompatible = configured.shellCompatible ?? configuredShellCompatible();
  const hooks = createSmartApproveHooks({
    ...configured,
    config,
    shellCompatible,
    modelEnabled: MODEL_APPROVAL_QUALIFIED && config.model.enabled && configured.modelEnabled !== false,
    timeoutMs: configured.timeoutMs ?? config.model.timeoutMs,
    directory: configured.directory ?? input.directory,
    reviewerClient: configured.reviewerClient ?? input.client as unknown as ReviewerSessionClient,
    approve: configured.approve ?? (async (requestID, sessionID) => {
      if (!sessionID) throw new Error("permission reply requires the originating session ID");
      await input.client.postSessionIdPermissionsPermissionId({
        path: { id: sessionID, permissionID: requestID },
        body: { response: "once" },
        query: { directory: configured.directory ?? input.directory },
      });
    }),
    progressSink: configured.progressSink ?? {
      tui: {
        showToast: (toast) => {
          const body = typeof toast === "object" && toast !== null && "body" in toast
            ? (toast as { body: { message: string; variant: "info" | "success" | "warning" | "error"; title?: string; duration?: number } }).body
            : { message: "Smart Approve review status", variant: "info" as const };
          return input.client.tui.showToast({ body, query: { directory: configured.directory ?? input.directory } });
        },
      },
    },
  });
  return { config: hooks.config, event: (input) => hooks.event({ event: input.event }), dispose: hooks.dispose };
};

export default SmartApprovePlugin;
