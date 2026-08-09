import { z } from "zod";

/** Stable, bounded explanations emitted by the reviewer. */
export const REVIEW_REASON_CODES = [
  "safe",
  "ambiguous",
  "dangerous",
  "uncertain",
  "inconsistent",
  "malformed",
  "empty",
  "truncated",
  "timeout",
  "provider_error",
  "tool_violation",
  "permission_violation",
  "manual",
] as const;

export type ReviewReasonCode = (typeof REVIEW_REASON_CODES)[number];
export type ReviewerDecision = "allow" | "manual";

export const reviewerResponseSchema = z
  .object({
    decision: z.enum(["allow", "manual"]),
    reasonCodes: z.array(z.enum(REVIEW_REASON_CODES)).min(1).max(4),
    reason: z.string().max(500).optional(),
  })
  .strict();

export type ReviewerResponse = z.infer<typeof reviewerResponseSchema>;

export interface ParsedReviewerResponse extends ReviewerResponse {
  readonly reasonCodes: ReviewReasonCode[];
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

export class ReviewerParseError extends Error {
  constructor(readonly reasonCode: Extract<ReviewReasonCode, "empty" | "malformed" | "truncated" | "uncertain" | "inconsistent">) {
    super(`reviewer returned ${reasonCode} output`);
    this.name = "ReviewerParseError";
  }
}

const unwrap = (value: unknown): unknown => {
  if (!isRecord(value)) return value;
  return "data" in value ? value.data : value;
};

function candidates(value: unknown): unknown[] {
  const root = unwrap(value);
  const result: unknown[] = [root];
  if (isRecord(root)) {
    result.push(root.structured, root.output, root.result, root.response);
    if (Array.isArray(root.parts)) {
      for (const part of root.parts) {
        if (isRecord(part) && part.type === "text" && typeof part.text === "string") {
          result.push(part.text);
        }
      }
    }
    if (isRecord(root.info)) {
      result.push(root.info.structured);
      result.push(root.info);
    }
  }
  return result;
}

function isEmpty(value: unknown): boolean {
  const root = unwrap(value);
  if (root === undefined || root === null || root === "") return true;
  if (!isRecord(root) || !Array.isArray(root.parts) || root.parts.length !== 0) return false;
  if (root.structured !== undefined) return false;
  return !(isRecord(root.info) && root.info.structured !== undefined);
}

function isTruncated(value: unknown): boolean {
  const root = unwrap(value);
  if (isRecord(root)) {
    const errorName = isRecord(root.info) && isRecord(root.info.error) ? root.info.error.name : undefined;
    if (errorName === "MessageOutputLengthError") return true;
    if (root.finishReason === "length" || root.finish_reason === "length" || root.truncated === true) return true;
  }
  return candidates(value).some((candidate) => {
    if (typeof candidate !== "string") return false;
    const text = candidate.trim();
    return (text.startsWith("{") && !text.endsWith("}")) || (text.startsWith("[") && !text.endsWith("]"));
  });
}

/** Parse only strict reviewer JSON. Any ambiguity is a caller-visible manual result. */
export function parseReviewerResponse(value: unknown): ParsedReviewerResponse {
  if (isEmpty(value)) throw new ReviewerParseError("empty");
  if (isTruncated(value)) throw new ReviewerParseError("truncated");
  const matches: ParsedReviewerResponse[] = [];
  let schemaCandidateSeen = false;
  for (const candidate of candidates(value)) {
    let decoded: unknown = candidate;
    if (typeof candidate === "string") {
      try {
        const trimmed = candidate.trim();
        const fenced = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
        decoded = JSON.parse(fenced?.[1] ?? trimmed);
      } catch {
        continue;
      }
    }
    // OpenCode may attach transport metadata (for example toolCounters) next
    // to the model object. Remove only that known envelope field; the model
    // payload itself remains strict and schema-validated.
    if (isRecord(decoded) && "toolCounters" in decoded) {
      const { toolCounters: _ignored, ...modelPayload } = decoded;
      decoded = modelPayload;
    }
    if (isRecord(decoded) && ("decision" in decoded || "reasonCodes" in decoded)) schemaCandidateSeen = true;
    const parsed = reviewerResponseSchema.safeParse(decoded);
    if (!parsed.success) continue;
    const codes = parsed.data.reasonCodes;
    if (parsed.data.decision === "allow" && (codes.length !== 1 || codes[0] !== "safe")) continue;
    if (parsed.data.decision === "manual" && codes.includes("safe")) continue;
    matches.push({
      ...parsed.data,
      reasonCodes: codes,
    });
  }
  if (matches.length === 1) return matches[0]!;
  if (matches.length > 1) {
    const first = JSON.stringify(matches[0]);
    if (matches.every((match) => JSON.stringify(match) === first)) return matches[0]!;
    throw new ReviewerParseError("inconsistent");
  }
  throw new ReviewerParseError(schemaCandidateSeen ? "uncertain" : "malformed");
}

export function manualReviewerResponse(reasonCode: ReviewReasonCode, reason?: string): ParsedReviewerResponse {
  return {
    decision: "manual",
    reasonCodes: [reasonCode],
    ...(reason ? { reason: reason.slice(0, 500) } : {}),
  };
}
