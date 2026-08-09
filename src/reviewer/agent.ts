import { buildReviewerPrompt, redactCommand } from "./prompt";
import {
  manualReviewerResponse,
  parseReviewerResponse,
  type ReviewReasonCode,
  type ReviewerResponse,
} from "./schema";
import { rejectReviewerPermission, REVIEWER_TOOL_DENY, type ReviewerSessionClient } from "./client";

export const REVIEWER_MODEL = "opencode-go/deepseek-v4-flash" as const;
export const REVIEWER_VARIANT = "max" as const;
export const REVIEWER_AGENT = "smart-approve-reviewer" as const;

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
  readonly parserFeatures?: Record<string, boolean | number | string>;
  readonly policyFacts?: readonly string[];
  readonly pathClasses?: readonly string[];
}

export interface ReviewerResult extends ReviewerResponse {
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
  return counters
    ? { executable: numberOrZero("executable"), dataAccess: numberOrZero("dataAccess"), mcp: numberOrZero("mcp"), web: numberOrZero("web"), task: numberOrZero("task") }
    : ZERO_TOOL_COUNTERS;
}

function reasonFor(error: unknown): ReviewReasonCode {
  if (error instanceof Error && /timeout/i.test(error.message)) return "timeout";
  if (error instanceof Error && /malformed|uncertain|invalid/i.test(error.message)) return "malformed";
  return "provider_error";
}

export function createReviewerAgent(options: ReviewerAgentOptions): ReviewerAgent {
  const timeoutMs = options.timeoutMs ?? 30_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 60_000) {
    throw new RangeError("reviewer timeout must be between 1 and 60000 ms");
  }
  const owned = new Set<string>();
  let disposed = false;
  const providerID = options.providerID ?? "opencode-go";
  const modelID = options.modelID ?? (options.model?.split("/").slice(1).join("/") || "deepseek-v4-flash");
  const variant = options.variant ?? REVIEWER_VARIANT;

  const cleanup = async (sessionID: string): Promise<void> => {
    if (!owned.delete(sessionID)) return;
    try {
      await options.client.session.abort({ path: { id: sessionID }, query: { directory: options.directory } });
    } finally {
      await options.client.session.delete({ path: { id: sessionID }, query: { directory: options.directory } });
    }
  };

  const review = async (request: ReviewerRequest): Promise<ReviewerResult> => {
    if (disposed) return { ...manualReviewerResponse("provider_error", "reviewer disposed"), sessionID: "", toolCounters: ZERO_TOOL_COUNTERS };
    let sessionID = "";
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const created = await options.client.session.create({
        body: { ...(request.parentSessionID ? { parentID: request.parentSessionID } : {}), title: `smart-approve:${request.requestID}` },
        query: { directory: options.directory },
      });
      sessionID = sessionIDFrom(created);
      owned.add(sessionID);
      const response = await Promise.race([
        Promise.resolve(options.client.session.prompt({
          path: { id: sessionID },
          query: { directory: options.directory },
          body: {
            agent: REVIEWER_AGENT,
            model: { providerID, modelID },
            variant,
            tools: REVIEWER_TOOL_DENY,
            system: "You are a deny-all, data-only classifier. Return strict JSON and never request permissions.",
            parts: [{ type: "text", text: buildReviewerPrompt({
              redactedCommand: redactCommand(request.redactedCommand ?? request.prompt),
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
        return { ...manualReviewerResponse("tool_violation", "reviewer used a disabled tool"), sessionID, toolCounters };
      }
      return { ...parsed, sessionID, toolCounters };
    } catch (error) {
      // Never echo provider/error text: it may contain command or secret bytes.
      const fallback = manualReviewerResponse(reasonFor(error));
      return { ...fallback, sessionID, toolCounters: ZERO_TOOL_COUNTERS };
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      if (sessionID) await cleanup(sessionID).catch(() => undefined);
    }
  };

  return {
    review,
    isPluginSession: (sessionID: string) => owned.has(sessionID),
    handlePermission: async ({ requestID, sessionID }) => rejectReviewerPermission(options.client, requestID, owned, sessionID),
    dispose: async () => {
      disposed = true;
      for (const sessionID of [...owned]) await cleanup(sessionID).catch(() => undefined);
    },
  };
}

export { parseReviewerResponse } from "./schema";
export type { ReviewerSessionClient } from "./client";
