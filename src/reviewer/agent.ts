import { buildReviewerPrompt, type ReviewerPathClass } from "./prompt";
import {
  manualReviewerResponse,
  parseReviewerResponse,
  ReviewerParseError,
  type ReviewReasonCode,
  type ReviewerResponse,
} from "./schema";
import {
  rejectReviewerPermission,
  REVIEWER_TOOL_DENY,
  type ReviewerSessionClient,
} from "./client";

export const REVIEWER_MODEL = "opencode-go/deepseek-v4-flash" as const;
export const REVIEWER_VARIANT = "max" as const;
export const REVIEWER_AGENT = "smart-approve-reviewer" as const;
export const REVIEWER_OUTPUT_FORMAT = Object.freeze({
  type: "json_schema" as const,
  retryCount: 0,
  schema: Object.freeze({
    type: "object",
    additionalProperties: false,
    required: ["decision", "reasonCodes"],
    properties: {
      decision: { enum: ["allow", "manual"] },
      reasonCodes: {
        type: "array",
        minItems: 1,
        maxItems: 4,
        items: { enum: ["safe", "ambiguous", "dangerous", "uncertain", "manual"] },
      },
    },
  }),
});

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
  readonly sessionID: string;
  readonly toolCounters: ToolCounters;
}

export interface ReviewerAgentOptions {
  readonly client: ReviewerSessionClient;
  readonly timeoutMs?: number;
  readonly directory?: string;
  readonly model?: string;
  readonly providerID?: string;
  readonly modelID?: string;
  readonly variant?: string;
}

export interface ReviewerAgent {
  readonly review: (request: ReviewerRequest) => Promise<ReviewerResult>;
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

function reasonFor(error: unknown): ReviewReasonCode {
  if (error instanceof ReviewerParseError) return error.reasonCode;
  if (error instanceof Error && /timeout/i.test(error.message)) return "timeout";
  return "provider_error";
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

export function createReviewerAgent(options: ReviewerAgentOptions): ReviewerAgent {
  const timeoutMs = options.timeoutMs ?? 30_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 60_000) {
    throw new RangeError("reviewer timeout must be between 1 and 60000 ms");
  }
  const owned = new Map<string, { readonly requestID: string; permissionViolated: boolean }>();
  let disposed = false;
  const configuredModel = parseModel(options.model);
  const providerID = options.providerID ?? configuredModel.providerID ?? "opencode-go";
  const modelID = options.modelID ?? configuredModel.modelID ?? "deepseek-v4-flash";
  const variant = options.variant ?? REVIEWER_VARIANT;

  const cleanup = async (sessionID: string, requestID: string): Promise<void> => {
    if (owned.get(sessionID)?.requestID !== requestID) return;
    try {
      await options.client.session.abort({ path: { id: sessionID }, query: { directory: options.directory } });
    } finally {
      try {
        await options.client.session.delete({ path: { id: sessionID }, query: { directory: options.directory } });
      } finally {
        // Keep ownership registered until both cleanup calls finish. A
        // permission event can arrive during teardown and must still be
        // rejected as a child request rather than falling through to the
        // parent/native permission path.
        if (owned.get(sessionID)?.requestID === requestID) owned.delete(sessionID);
      }
    }
  };

  const review = async (request: ReviewerRequest): Promise<ReviewerResult> => {
    if (!validRequestID(request.requestID)) {
      return { ...manualReviewerResponse("malformed", "invalid request identifier"), requestID: request.requestID, sessionID: "", toolCounters: ZERO_TOOL_COUNTERS };
    }
    if (disposed) return { ...manualReviewerResponse("provider_error", "reviewer disposed"), requestID: request.requestID, sessionID: "", toolCounters: ZERO_TOOL_COUNTERS };
    let sessionID = "";
    let ownsSession = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const created = await options.client.session.create({
        body: {
          ...(request.parentSessionID ? { parentID: request.parentSessionID } : {}),
          title: `smart-approve:${request.requestID}`,
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
      const response = await Promise.race([
        Promise.resolve(options.client.session.prompt({
          path: { id: sessionID },
          query: { directory: options.directory },
          body: {
            agent: REVIEWER_AGENT,
            model: { providerID, modelID },
            format: REVIEWER_OUTPUT_FORMAT,
            tools: REVIEWER_TOOL_DENY,
            system: "You are a deny-all, data-only classifier. Return strict JSON and never request permissions.",
            parts: [{ type: "text", text: buildReviewerPrompt({
              redactedCommand: request.redactedCommand ?? request.prompt,
              parserFeatures: request.parserFeatures,
              policyFacts: request.policyFacts,
              pathClasses: request.pathClasses,
            }) }],
          },
        })),
        new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("reviewer timeout")), timeoutMs); }),
      ]);
      const parsed = parseReviewerResponse(response);
      const toolCounters = toolCountersFrom(response);
      const usedTool = Object.values(toolCounters).some((count) => count > 0);
      if (usedTool) {
        return { ...manualReviewerResponse("tool_violation", "reviewer used a disabled tool"), requestID: request.requestID, sessionID, toolCounters };
      }
      if (owned.get(sessionID)?.permissionViolated) {
        return { ...manualReviewerResponse("permission_violation", "reviewer requested a forbidden permission"), requestID: request.requestID, sessionID, toolCounters };
      }
      return { ...parsed, requestID: request.requestID, sessionID, toolCounters };
    } catch (error) {
      // Never echo provider/error text: it may contain command or secret bytes.
      const fallback = manualReviewerResponse(reasonFor(error));
      return { ...fallback, requestID: request.requestID, sessionID, toolCounters: ZERO_TOOL_COUNTERS };
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      if (ownsSession && sessionID) await cleanup(sessionID, request.requestID).catch(() => undefined);
    }
  };

  return {
    review,
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
