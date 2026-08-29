import {
  buildReviewerContract,
  createOpaqueCoordinatorID,
  REVIEWER_OUTPUT_FORMAT as CONTRACT_OUTPUT_FORMAT,
  type ReviewerOutcome,
  type ReviewerPathClass,
} from "./contract";
import {
  manualReviewerResponse,
  parseReviewerResponse,
  ReviewerParseError,
  type ReviewReasonCode,
  type ReviewerResponse,
} from "./schema";
import {
  rejectReviewerPermission,
  type ReviewerSessionClient,
} from "./client";
import { ACTIVE_PRODUCTION_PROFILE, profileForModel } from "./model-profile";

export const REVIEWER_MODEL = ACTIVE_PRODUCTION_PROFILE.model;
export const REVIEWER_VARIANT = ACTIVE_PRODUCTION_PROFILE.requestedVariant;
export const REVIEWER_AGENT = "smart-approve-reviewer" as const;
/** Compatibility export; the canonical payload lives in reviewer/contract.ts. */
export const REVIEWER_OUTPUT_FORMAT = CONTRACT_OUTPUT_FORMAT;

export type ReviewerDecision = "allow" | "manual";
export type { ReviewerResponse };

export interface ToolCounters {
  readonly executable: number;
  readonly dataAccess: number;
  readonly mcp: number;
  readonly web: number;
  readonly task: number;
}

export const ZERO_TOOL_COUNTERS: ToolCounters = Object.freeze({
  executable: 0,
  dataAccess: 0,
  mcp: 0,
  web: 0,
  task: 0,
});

export interface ReviewerRequest {
  readonly requestID: string;
  /** Opaque coordinator identity used in provider-facing contract metadata. */
  readonly coordinatorID?: string;
  /** The coordinator owns the deadline for production requests. */
  readonly deadlineOwnedByCoordinator?: boolean;
  readonly parentSessionID?: string;
  /** Legacy callers may provide the command here; it is redacted before use. */
  readonly prompt: string;
  readonly redactedCommand?: string;
  readonly parserFeatures?: Record<string, boolean | number | string | readonly string[]>;
  readonly policyFacts?: readonly string[];
  readonly pathClasses?: readonly ReviewerPathClass[];
}

export interface ReviewerResult {
  readonly decision: ReviewerDecision;
  /** Production reviewer results always include schema-validated codes. Optional for narrow test doubles. */
  readonly reasonCodes?: readonly ReviewReasonCode[];
  readonly reason?: string;
  /** Bound by the plugin, never accepted from model output. */
  readonly requestID?: string;
  readonly coordinatorID?: string;
  readonly sessionID: string;
  readonly toolCounters: ToolCounters;
  readonly outcome?: ReviewerOutcome;
}

export interface ReviewerAgentOptions {
  readonly client: ReviewerSessionClient;
  readonly timeoutMs?: number;
  readonly directory?: string;
  readonly model?: string;
  readonly providerID?: string;
  readonly modelID?: string;
  readonly variant?: string | null;
}

export interface ReviewerAgent {
  readonly review: (request: ReviewerRequest) => Promise<ReviewerResult>;
  /** Cancel only the reviewer child owned by this exact request. */
  readonly cancel: (requestID: string) => Promise<void>;
  readonly isPluginSession: (sessionID: string) => boolean;
  readonly handlePermission: (input: { requestID: string; sessionID?: string }) => Promise<boolean>;
  readonly dispose: () => Promise<void>;
}

type RecordValue = Record<string, unknown>;
const isRecord = (value: unknown): value is RecordValue => typeof value === "object" && value !== null;
const unwrap = (value: unknown): unknown => (isRecord(value) && "data" in value ? value.data : value);

function sessionIDFrom(value: unknown): string {
  const body = unwrap(value);
  if (isRecord(body) && typeof body.id === "string" && body.id.length > 0) return body.id;
  throw new Error("reviewer session creation returned no session ID");
}

function toolCountersFrom(value: unknown): ToolCounters {
  const body = unwrap(value);
  const counters = isRecord(body) && isRecord(body.toolCounters) ? body.toolCounters : undefined;
  const numberOrZero = (key: string): number =>
    counters && typeof counters[key] === "number" && Number.isFinite(counters[key]) ? counters[key] as number : 0;
  const reported = counters
    ? { executable: numberOrZero("executable"), dataAccess: numberOrZero("dataAccess"), mcp: numberOrZero("mcp"), web: numberOrZero("web"), task: numberOrZero("task") }
    : ZERO_TOOL_COUNTERS;
  if (Object.values(reported).some((count) => count > 0)) return reported;

  const observed = { executable: 0, dataAccess: 0, mcp: 0, web: 0, task: 0 };
  walkRecords(body, (record) => {
    if (!isToolPart(record)) return;
    const name = typeof record.tool === "string"
      ? record.tool.toLowerCase()
      : typeof record.name === "string"
        ? record.name.toLowerCase()
        : "unknown";
    if (/^(?:bash|shell|terminal|exec)$/.test(name)) observed.executable += 1;
    else if (/^(?:read|write|edit|patch|multiedit|glob|grep|list|lsp|external_directory)$/.test(name)) observed.dataAccess += 1;
    else if (name === "mcp" || name.startsWith("mcp_")) observed.mcp += 1;
    else if (/^(?:webfetch|websearch|fetch|http|network)$/.test(name)) observed.web += 1;
    else observed.task += 1;
  });
  return Object.values(observed).some((count) => count > 0) ? observed : ZERO_TOOL_COUNTERS;
}

class ReviewerDeadlineError extends Error {
  constructor() {
    super("reviewer deadline exceeded");
    this.name = "ReviewerDeadlineError";
  }
}

function failureDetailsFor(error: unknown): {
  readonly reasonCode: ReviewReasonCode;
  readonly reason?: "reviewer_deadline" | "upstream_timeout";
} {
  if (error instanceof ReviewerDeadlineError) return { reasonCode: "timeout", reason: "reviewer_deadline" };
  if (error instanceof ReviewerParseError) return { reasonCode: error.reasonCode };
  if (error instanceof Error && /timeout/i.test(error.message)) return { reasonCode: "timeout", reason: "upstream_timeout" };
  return { reasonCode: "provider_error" };
}

function outcomeFor(
  coordinatorID: string,
  sessionID: string,
  parsed: ReviewerResponse | undefined,
  reasonCode: ReviewReasonCode | undefined,
  providerAttempted: boolean,
): ReviewerOutcome {
  if (parsed) {
    return {
      kind: "valid_model",
      coordinatorID,
      sessionID,
      providerAttempted,
      decision: parsed.decision,
      reasonCodes: parsed.reasonCodes,
      schemaValid: true,
      metricEligible: true,
    };
  }
  const reason = reasonCode && reasonCode !== "safe" ? reasonCode : "provider_error";
  const transportKinds = new Set<ReviewReasonCode>([
    "malformed", "empty", "truncated", "timeout", "provider_error", "tool_violation", "permission_violation",
  ]);
  return {
    kind: transportKinds.has(reason)
      ? reason as "malformed" | "empty" | "truncated" | "timeout" | "provider_error" | "tool_violation" | "permission_violation"
      : "manual",
    coordinatorID,
    sessionID,
    providerAttempted,
    decision: "manual",
    reasonCode: reason,
    schemaValid: false,
    metricEligible: false,
  };
}

function walkRecords(value: unknown, visit: (record: RecordValue) => void): void {
  if (Array.isArray(value)) {
    for (const entry of value) walkRecords(entry, visit);
    return;
  }
  if (!isRecord(value)) return;
  visit(value);
  for (const entry of Object.values(value)) walkRecords(entry, visit);
}

function isToolPart(record: RecordValue): boolean {
  return record.type === "tool" || record.type === "tool-call" || record.type === "tool_call" || record.type === "tool-invocation";
}

function parseModel(model: string | undefined): { providerID?: string; modelID?: string } {
  if (model === undefined) return {};
  const separator = model.indexOf("/");
  if (separator <= 0 || separator === model.length - 1) throw new TypeError("reviewer model must be provider/model");
  return { providerID: model.slice(0, separator), modelID: model.slice(separator + 1) };
}

const validRequestID = (value: string): boolean => /^[A-Za-z0-9_.:-]{1,200}$/.test(value);
const REVIEWER_CLEANUP_TIMEOUT_MS = 250;

async function boundedCleanup(operation: () => unknown | Promise<unknown>): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      Promise.resolve().then(operation),
      new Promise<void>((resolve) => { timer = setTimeout(resolve, REVIEWER_CLEANUP_TIMEOUT_MS); }),
    ]);
  } catch { /* cleanup is best effort and must never reopen the permission path */ }
  finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

export function createReviewerAgent(options: ReviewerAgentOptions): ReviewerAgent {
  const timeoutMs = options.timeoutMs ?? 30_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 60_000) {
    throw new RangeError("reviewer timeout must be between 1 and 60000 ms");
  }
  const owned = new Map<string, { readonly requestID: string; permissionViolated: boolean }>();
  let disposed = false;
  const configuredModel = parseModel(options.model);
  const providerID = options.providerID ?? configuredModel.providerID ?? "opencode-go";
  const modelID = options.modelID ?? configuredModel.modelID ?? ACTIVE_PRODUCTION_PROFILE.modelID;
  const selectedProfile = options.model ? profileForModel(options.model) : profileForModel(`${providerID}/${modelID}`);
  const explicitModel = options.model !== undefined || options.providerID !== undefined || options.modelID !== undefined;
  const variant = options.variant !== undefined ? options.variant : selectedProfile?.requestedVariant ?? (explicitModel ? null : REVIEWER_VARIANT);

  const cleanup = async (sessionID: string, requestID: string): Promise<void> => {
    if (owned.get(sessionID)?.requestID !== requestID) return;
    await boundedCleanup(() => options.client.session.abort({ path: { id: sessionID }, query: { directory: options.directory } }));
    await boundedCleanup(() => options.client.session.delete({ path: { id: sessionID }, query: { directory: options.directory } }));
    // Keep ownership registered until both bounded cleanup calls finish. A
    // permission event can arrive during teardown and must still be rejected
    // as a child request rather than falling through to the native path.
    if (owned.get(sessionID)?.requestID === requestID) owned.delete(sessionID);
  };

  const review = async (request: ReviewerRequest): Promise<ReviewerResult> => {
    const coordinatorID = request.coordinatorID ?? createOpaqueCoordinatorID();
    if (!validRequestID(request.requestID)) {
      const outcome = outcomeFor(coordinatorID, "", undefined, "malformed", false);
      return { ...manualReviewerResponse("malformed", "invalid request identifier"), requestID: request.requestID, coordinatorID, sessionID: "", toolCounters: ZERO_TOOL_COUNTERS, outcome };
    }
    if (disposed) {
      const outcome = outcomeFor(coordinatorID, "", undefined, "provider_error", false);
      return { ...manualReviewerResponse("provider_error", "reviewer disposed"), requestID: request.requestID, coordinatorID, sessionID: "", toolCounters: ZERO_TOOL_COUNTERS, outcome };
    }
    let sessionID = "";
    let ownsSession = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let providerAttempted = false;
    try {
      const contract = buildReviewerContract({
        coordinatorID,
        providerID,
        modelID,
        ...(variant === null ? {} : { requestedVariant: variant }),
        timeoutMs,
        directory: options.directory,
        parentSessionID: request.parentSessionID,
        redactedCommand: request.redactedCommand ?? request.prompt,
        parserFeatures: request.parserFeatures,
        policyFacts: request.policyFacts,
        pathClasses: request.pathClasses,
      });
      const created = await options.client.session.create({
        body: {
          ...(request.parentSessionID ? { parentID: request.parentSessionID } : {}),
          // Direct unit callers predate the opaque coordinator contract. The
          // production coordinator always supplies coordinatorID, so provider
          // sessions never receive the raw OpenCode request ID on that path.
          title: `smart-approve:${request.coordinatorID ? coordinatorID : request.requestID}`,
        },
        query: { directory: options.directory },
      });
      sessionID = sessionIDFrom(created);
      if (owned.has(sessionID)) {
        sessionID = "";
        throw new Error("reviewer session identifier collision");
      }
      owned.set(sessionID, { requestID: request.requestID, permissionViolated: false });
      ownsSession = true;
      const prompt = Promise.resolve(options.client.session.prompt({
          path: { id: sessionID },
          query: { directory: options.directory },
          body: {
            agent: REVIEWER_AGENT,
            model: { providerID: contract.providerID, modelID: contract.modelID },
            format: CONTRACT_OUTPUT_FORMAT,
            tools: contract.tools,
            system: contract.system,
            parts: [{ type: "text", text: contract.prompt }],
          },
        }));
      providerAttempted = true;
      const response = request.deadlineOwnedByCoordinator
        ? await prompt
        : await Promise.race([
          prompt,
          new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new ReviewerDeadlineError()), timeoutMs); }),
        ]);
      const parsed = parseReviewerResponse(response);
      const toolCounters = toolCountersFrom(response);
      const usedTool = Object.values(toolCounters).some((count) => count > 0);
      if (usedTool) {
        const outcome = outcomeFor(coordinatorID, sessionID, undefined, "tool_violation", providerAttempted);
        return { ...manualReviewerResponse("tool_violation", "reviewer used a disabled tool"), requestID: request.requestID, coordinatorID, sessionID, toolCounters, outcome };
      }
      if (owned.get(sessionID)?.permissionViolated) {
        const outcome = outcomeFor(coordinatorID, sessionID, undefined, "permission_violation", providerAttempted);
        return { ...manualReviewerResponse("permission_violation", "reviewer requested a forbidden permission"), requestID: request.requestID, coordinatorID, sessionID, toolCounters, outcome };
      }
      const outcome = outcomeFor(coordinatorID, sessionID, parsed, undefined, providerAttempted);
      return { ...parsed, requestID: request.requestID, coordinatorID, sessionID, toolCounters, outcome };
    } catch (error) {
      // Never echo provider/error text: it may contain command or secret bytes.
      const { reasonCode, reason } = failureDetailsFor(error);
      const fallback = manualReviewerResponse(reasonCode, reason);
      const outcome = outcomeFor(coordinatorID, sessionID, undefined, reasonCode, providerAttempted);
      return { ...fallback, requestID: request.requestID, coordinatorID, sessionID, toolCounters: ZERO_TOOL_COUNTERS, outcome };
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      if (ownsSession && sessionID) await cleanup(sessionID, request.requestID).catch(() => undefined);
    }
  };

  return {
    review,
    cancel: async (requestID: string) => {
      for (const [sessionID, context] of [...owned]) {
        if (context.requestID === requestID) await cleanup(sessionID, requestID).catch(() => undefined);
      }
    },
    isPluginSession: (sessionID: string) => owned.has(sessionID),
    handlePermission: async ({ requestID, sessionID }) => {
      if (!sessionID) return false;
      const context = owned.get(sessionID);
      if (!context) return false;
      context.permissionViolated = true;
      return rejectReviewerPermission(options.client, requestID, new Set(owned.keys()), sessionID, options.directory);
    },
    dispose: async () => {
      disposed = true;
      for (const [sessionID, context] of [...owned]) await cleanup(sessionID, context.requestID).catch(() => undefined);
    },
  };
}

export { parseReviewerResponse } from "./schema";
export type { ReviewerSessionClient } from "./client";
