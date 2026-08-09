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
  "manual",
] as const;

export type ReviewReasonCode = (typeof REVIEW_REASON_CODES)[number];
export type ReviewerDecision = "allow" | "manual";

export const reviewerResponseSchema = z
  .object({
    decision: z.enum(["allow", "manual"]),
    reasonCodes: z.array(z.enum(REVIEW_REASON_CODES)).max(4).optional(),
    reason: z.string().max(500).optional(),
  })
  .strict();

export type ReviewerResponse = z.infer<typeof reviewerResponseSchema>;

export interface ParsedReviewerResponse extends ReviewerResponse {
  readonly reasonCodes: ReviewReasonCode[];
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

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
    if (isRecord(root.info) && typeof root.info === "object") result.push(root.info);
  }
  return result;
}

/** Parse only strict reviewer JSON. Any ambiguity is a caller-visible manual result. */
export function parseReviewerResponse(value: unknown): ParsedReviewerResponse {
  const matches: ParsedReviewerResponse[] = [];
  for (const candidate of candidates(value)) {
    let decoded: unknown = candidate;
    if (typeof candidate === "string") {
      try {
        decoded = JSON.parse(candidate);
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
    const parsed = reviewerResponseSchema.safeParse(decoded);
    if (!parsed.success) continue;
    const codes = parsed.data.reasonCodes ?? [];
    if (parsed.data.decision === "allow" && codes.some((code) => code !== "safe")) continue;
    if (parsed.data.decision === "manual" && codes.includes("safe")) continue;
    matches.push({
      ...parsed.data,
      reasonCodes: codes.length ? codes : (parsed.data.decision === "allow" ? ["safe"] : ["manual"]),
    });
  }
  if (matches.length === 1) return matches[0]!;
  if (matches.length > 1) {
    const first = JSON.stringify(matches[0]);
    if (matches.every((match) => JSON.stringify(match) === first)) return matches[0]!;
    throw new Error("reviewer returned inconsistent JSON");
  }
  throw new Error("reviewer returned malformed or uncertain JSON");
}

export function manualReviewerResponse(reasonCode: ReviewReasonCode, reason?: string): ParsedReviewerResponse {
  return {
    decision: "manual",
    reasonCodes: [reasonCode],
    ...(reason ? { reason: reason.slice(0, 500) } : {}),
  };
}
