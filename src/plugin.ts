import type { Config as OpenCodeConfig, Plugin } from "@opencode-ai/plugin";
import type { AgentConfig } from "@opencode-ai/sdk";
import { join } from "node:path";
import { createApprovalCoordinator, type ApprovalCoordinator, type ApprovalCoordinatorOptions } from "./approval/coordinator";
import { createAuditWriter, type AuditWriter } from "./audit/writer";
import { loadGlobalConfig } from "./config/load";
import { DEFAULT_CONFIG, type SmartApproveConfig } from "./config/schema";
import type { DeterministicPolicyResult } from "./policy/deterministic";
import { createReviewerAgent, REVIEWER_AGENT, type ReviewerAgent, type ReviewerSessionClient } from "./reviewer/agent";
import { REVIEWER_TOOL_DENY } from "./reviewer/client";
import { createProgressMetrics, type ProgressMetrics, type ProgressMetricsSnapshot, type ProgressSink } from "./progress/reporter";
import { createReplanGuard } from "./replan/guard";
import { ReplanStateStore } from "./replan/state";
import { verifyRuntimeVersion } from "./replan/runtime-version";
import type { RuntimeHealthFetcher } from "./replan/runtime-version";

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
  /** Test seam; production uses the OpenCode server health endpoint. */
  readonly runtimeHealthFetcher?: RuntimeHealthFetcher;
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
  /** Shared diagnostics used by the optional pre-execution replan guard. */
  readonly replanMetrics: ProgressMetrics;
  readonly replanAuditWriter: AuditWriter;
}

export type ReviewerRegistration = AgentConfig & {
  readonly description: string;
  readonly mode: "subagent";
  readonly model: string;
  readonly variant: string;
  readonly temperature: 0;
  readonly prompt: string;
};

/**
 * Build the exact agent registration installed by the production config hook.
 * Qualification code imports this function instead of maintaining a second
 * copy of the registration contract.
 */
export function buildReviewerRegistration(config: SmartApproveConfig): ReviewerRegistration {
  return {
    description: "Tool-free command safety reviewer",
    mode: "subagent",
    model: `${config.model.provider}/${config.model.model}`,
    variant: config.model.variant,
    temperature: 0,
    prompt: "Classify only the supplied bounded data. Never use tools or request permissions. Return strict JSON only.",
    tools: REVIEWER_TOOL_DENY,
    permission: {
      edit: "deny",
      bash: "deny",
      webfetch: "deny",
      doom_loop: "deny",
      external_directory: "deny",
    },
  };
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
    directory: options.directory,
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
      input.agent[REVIEWER_AGENT] = buildReviewerRegistration(config);
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
    replanMetrics: metrics,
    replanAuditWriter: auditWriter,
  };
}

/** OpenCode entry point; it does not mutate global configuration or install a loader. */
export const SmartApprovePlugin: Plugin = async (input, options) => {
  const configured = (options ?? {}) as SmartApprovePluginOptions;
  const config = configured.config ?? await loadGlobalConfig();
  const shellCompatible = configured.shellCompatible ?? configuredShellCompatible();
  const progressSink = configured.progressSink ?? {
    tui: {
      showToast: (toast: unknown) => {
        const body = typeof toast === "object" && toast !== null && "body" in toast
          ? (toast as { body: { message: string; variant: "info" | "success" | "warning" | "error"; title?: string; duration?: number } }).body
          : { message: "Smart Approve review status", variant: "info" as const };
        return input.client.tui.showToast({ body, query: { directory: configured.directory ?? input.directory } });
      },
    },
  };
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
    progressSink,
  });
  if (!config.replan.enabled) {
    return { config: hooks.config, event: (eventInput) => hooks.event({ event: eventInput.event }), dispose: hooks.dispose };
  }
  const showRuntimeStatus = (message: string, variant: "info" | "success" | "warning"): void => {
    const showToast = progressSink.tui?.showToast;
    if (!showToast) return;
    try {
      Promise.resolve(showToast({ body: { title: "Smart Approve", message, variant } })).catch(() => undefined);
    } catch { /* runtime status is non-authoritative */ }
  };
  showRuntimeStatus("Smart Approve checking runtime compatibility", "info");
  const runtimeActive = await verifyRuntimeVersion(input.serverUrl, configured.runtimeHealthFetcher);
  showRuntimeStatus(
    runtimeActive ? "Smart Approve replan boundary active" : "Smart Approve replan boundary inactive; native permission remains available",
    runtimeActive ? "success" : "warning",
  );
  if (!runtimeActive) {
    return { config: hooks.config, event: (eventInput) => hooks.event({ event: eventInput.event }), dispose: hooks.dispose };
  }

  const replanState = new ReplanStateStore(config.replan.maxBlocksPerTurn);
  const replanGuard = createReplanGuard({
    state: replanState,
    policy: configured.policy as never,
    config,
    progressSink,
    metrics: hooks.replanMetrics,
    auditWriter: hooks.replanAuditWriter,
  });
  const replanHooks = {
    "chat.message": async (messageInput: { sessionID: string; messageID?: string }, output: { message?: { id?: string; role?: string } }) => {
      if (output?.message?.role !== "user") return;
      const messageID = typeof messageInput.messageID === "string" && messageInput.messageID.length > 0
        ? messageInput.messageID
        : typeof output.message?.id === "string" && output.message.id.length > 0 ? output.message.id : undefined;
      if (messageID) replanState.observeUserMessage(messageInput.sessionID, messageID);
    },
    "tool.execute.before": async (toolInput: { tool: string; sessionID: string; callID: string }, output: { args: unknown }) => {
      const generation = replanState.captureGeneration(toolInput.sessionID);
      await replanGuard.before({ ...toolInput, generation }, output);
    },
  };
  return {
    config: hooks.config,
    event: async (eventInput: { event: unknown }) => {
      const event = eventInput.event as { type?: unknown; properties?: unknown };
      if (event?.type === "session.deleted") {
        const properties = event.properties as { id?: unknown; info?: { id?: unknown } } | undefined;
        const sessionID = typeof properties?.info?.id === "string" ? properties.info.id : properties?.id;
        if (typeof sessionID === "string") replanState.deleteSession(sessionID);
      }
      await hooks.event({ event: eventInput.event });
    },
    dispose: async () => { replanState.dispose(); await hooks.dispose(); },
    ...replanHooks,
  };
};

export default SmartApprovePlugin;
