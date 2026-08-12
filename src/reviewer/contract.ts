import { z } from "zod";
import { randomUUID } from "node:crypto";
import { REVIEWER_PERMISSION_DENY, REVIEWER_TOOL_DENY } from "./client";
import { buildReviewerPrompt, type ReviewerPathClass } from "./prompt";
import { REVIEW_REASON_CODES, type ReviewReasonCode } from "./schema";

export type { ReviewerPathClass } from "./prompt";

/** The versioned contract shared by production reviewer calls and evaluation captures. */
export const REVIEWER_CONTRACT_VERSION = "classifier-qualification/v3" as const;
export const REVIEWER_SYSTEM_PROMPT = "You are a deny-all, data-only classifier. Return strict JSON and never request permissions." as const;

/** The model-facing response schema is intentionally unchanged from the MVP prompt contract. */
export const REVIEWER_OUTPUT_SCHEMA = Object.freeze({
  type: "object" as const,
  additionalProperties: false as const,
  required: ["decision", "reasonCodes"] as const,
  properties: {
    decision: { enum: ["allow", "manual"] as const },
    reasonCodes: {
      type: "array" as const,
      minItems: 1,
      maxItems: 4,
      items: { enum: ["safe", "ambiguous", "dangerous", "uncertain", "manual"] as const },
    },
  },
});

export const REVIEWER_OUTPUT_FORMAT = Object.freeze({
  type: "json_schema" as const,
  retryCount: 0 as const,
  schema: REVIEWER_OUTPUT_SCHEMA,
});

/** All bounded reason codes emitted by policy, reviewer, coordinator, and reply paths. */
export const REASON_CODES_V3 = [
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
  "interpreter",
  "package_script",
  "unknown_binary",
  "dynamic_syntax",
  "environment_assignment",
  "parse_failure",
  "privacy",
  "path_identity",
  "model_disabled",
  "user_rule",
  "invalid_command",
  "replan",
  "manual_executable",
  "policy_error",
  "capacity_rejected",
  "reply_not_found",
  "reply_error",
] as const;

export type ReasonCodeV3 = (typeof REASON_CODES_V3)[number];
export const reasonCodeV3Schema = z.enum(REASON_CODES_V3);

export type ReviewerDecision = "allow" | "manual";

export interface ReviewerOutcomeContext {
  readonly coordinatorID: string;
  readonly sessionID: string;
  readonly providerAttempted: boolean;
}

/**
 * A reviewer result is discriminated before the coordinator turns it into a
 * native permission state.  This keeps transport faults out of classifier
 * accuracy denominators and makes fail-closed handling explicit.
 */
export type ReviewerOutcome =
  | (ReviewerOutcomeContext & {
      readonly kind: "valid_model";
      readonly decision: ReviewerDecision;
      readonly reasonCodes: readonly ReviewReasonCode[];
      readonly schemaValid: true;
      readonly metricEligible: true;
    })
  | (ReviewerOutcomeContext & {
      readonly kind: "manual" | "malformed" | "empty" | "truncated" | "timeout" | "provider_error" | "tool_violation" | "permission_violation";
      readonly decision: "manual";
      readonly reasonCode: Extract<ReviewReasonCode, "manual" | "ambiguous" | "dangerous" | "uncertain" | "inconsistent" | "malformed" | "empty" | "truncated" | "timeout" | "provider_error" | "tool_violation" | "permission_violation">;
      readonly schemaValid: boolean;
      readonly metricEligible: false;
    });

export interface CapacityRejectedOutcome {
  readonly kind: "capacity_rejected";
  readonly coordinatorID: string;
  readonly sessionID: "";
  readonly decision: "manual";
  readonly reasonCode: "capacity_rejected";
  readonly providerAttempted: false;
  readonly schemaValid: false;
  readonly metricEligible: false;
}

export type CoordinatorReviewOutcome = ReviewerOutcome | CapacityRejectedOutcome;

const outcomeContextSchema = z.object({
  coordinatorID: z.string().regex(/^coord_[a-f0-9-]{36}$/),
  sessionID: z.string(),
  providerAttempted: z.boolean(),
}).strict();

const validModelOutcomeSchema = outcomeContextSchema.extend({
  kind: z.literal("valid_model"),
  decision: z.enum(["allow", "manual"]),
  reasonCodes: z.array(z.enum(REVIEW_REASON_CODES)).min(1).max(4),
  schemaValid: z.literal(true),
  metricEligible: z.literal(true),
}).strict();

const manualOutcomeSchema = outcomeContextSchema.extend({
  kind: z.enum(["manual", "malformed", "empty", "truncated", "timeout", "provider_error", "tool_violation", "permission_violation"]),
  decision: z.literal("manual"),
  reasonCode: z.enum(["manual", "ambiguous", "dangerous", "uncertain", "inconsistent", "malformed", "empty", "truncated", "timeout", "provider_error", "tool_violation", "permission_violation"]),
  schemaValid: z.boolean(),
  metricEligible: z.literal(false),
}).strict();

const capacityRejectedOutcomeSchema = z.object({
  kind: z.literal("capacity_rejected"),
  coordinatorID: z.string().regex(/^coord_[a-f0-9-]{36}$/),
  sessionID: z.literal(""),
  decision: z.literal("manual"),
  reasonCode: z.literal("capacity_rejected"),
  providerAttempted: z.literal(false),
  schemaValid: z.literal(false),
  metricEligible: z.literal(false),
}).strict();

export const reviewerOutcomeSchema = z.discriminatedUnion("kind", [
  validModelOutcomeSchema,
  manualOutcomeSchema,
  capacityRejectedOutcomeSchema,
]);
export const coordinatorReviewOutcomeSchema = reviewerOutcomeSchema;

export function createCapacityRejectedOutcome(coordinatorID: string): CapacityRejectedOutcome {
  return {
    kind: "capacity_rejected",
    coordinatorID,
    sessionID: "",
    decision: "manual",
    reasonCode: "capacity_rejected",
    providerAttempted: false,
    schemaValid: false,
    metricEligible: false,
  };
}

/** Coordinator-owned deadline outcome; the reviewer never owns this timer. */
export function createCoordinatorTimeoutOutcome(coordinatorID: string): ReviewerOutcome {
  return {
    kind: "timeout",
    coordinatorID,
    sessionID: "",
    decision: "manual",
    reasonCode: "timeout",
    providerAttempted: true,
    schemaValid: false,
    metricEligible: false,
  };
}

const reviewerContractSchemaShape = {
  version: z.literal(REVIEWER_CONTRACT_VERSION),
  coordinatorID: z.string().regex(/^coord_[a-f0-9-]{36}$/),
  requestedModel: z.string().min(3).max(200),
  providerID: z.string().min(1).max(100),
  modelID: z.string().min(1).max(100),
  requestedVariant: z.string().min(1).max(100),
  temperature: z.literal(0),
  retryCount: z.literal(0),
  schema: z.object({
    type: z.literal("object"),
    additionalProperties: z.literal(false),
    required: z.array(z.enum(["decision", "reasonCodes"])).length(2),
    properties: z.object({
      decision: z.object({ enum: z.array(z.enum(["allow", "manual"])).length(2) }).strict(),
      reasonCodes: z.object({
        type: z.literal("array"),
        minItems: z.literal(1),
        maxItems: z.literal(4),
        items: z.object({ enum: z.array(z.enum(["safe", "ambiguous", "dangerous", "uncertain", "manual"])).length(5) }).strict(),
      }).strict(),
    }).strict(),
  }).strict(),
  system: z.string().min(1).max(1_000),
  prompt: z.string().min(1).max(8_000),
  tools: z.record(z.string(), z.boolean()),
  permissions: z.array(z.object({ permission: z.string(), pattern: z.string(), action: z.literal("deny") }).strict()),
  timeoutMs: z.number().int().positive().max(60_000),
  directory: z.string().min(1).max(4_096).nullable(),
  parentSessionID: z.string().min(1).max(200).nullable(),
  parentLinkage: z.object({
    parentSessionID: z.string().min(1).max(200).nullable(),
    directory: z.string().min(1).max(4_096).nullable(),
  }).strict(),
  pathIdentity: z.object({
    directory: z.string().min(1).max(4_096).nullable(),
    classes: z.array(z.enum(["project", "external", "none", "unknown"])),
  }).strict(),
};

/** Runtime validator for the exact outbound contract. */
export const reviewerContractSchema = z.object(reviewerContractSchemaShape).strict();
export const ReviewerContractSchema = reviewerContractSchema;

export type ReviewerContract = z.infer<typeof reviewerContractSchema>;

export interface ReviewerContractInput {
  readonly coordinatorID: string;
  readonly providerID: string;
  readonly modelID: string;
  readonly requestedVariant: string;
  readonly timeoutMs: number;
  readonly directory?: string;
  readonly parentSessionID?: string;
  readonly command?: string;
  readonly redactedCommand?: string;
  readonly prompt?: string;
  readonly parserFeatures?: Record<string, boolean | number | string | readonly string[]>;
  readonly policyFacts?: readonly string[];
  readonly pathClasses?: readonly ReviewerPathClass[];
}

/**
 * Build the one reviewer payload used by both the production agent and parity
 * evaluation. The input may already be redacted; redactCommand is idempotent.
 */
export function buildReviewerContract(input: ReviewerContractInput): ReviewerContract {
  const directory = input.directory ?? null;
  const parentSessionID = input.parentSessionID ?? null;
  const redactedCommand = input.redactedCommand ?? input.command ?? input.prompt ?? "";
  const prompt = buildReviewerPrompt({
    redactedCommand,
    parserFeatures: input.parserFeatures,
    policyFacts: input.policyFacts,
    pathClasses: input.pathClasses,
  });
  const classes = [...(input.pathClasses ?? [])].slice(0, 16).map((value) =>
    value === "project" || value === "external" || value === "none" || value === "unknown" ? value : "unknown");
  const requestedModel = `${input.providerID}/${input.modelID}`;
  return reviewerContractSchema.parse({
    version: REVIEWER_CONTRACT_VERSION,
    coordinatorID: input.coordinatorID,
    requestedModel,
    providerID: input.providerID,
    modelID: input.modelID,
    requestedVariant: input.requestedVariant,
    temperature: 0,
    retryCount: 0,
    schema: REVIEWER_OUTPUT_SCHEMA,
    system: REVIEWER_SYSTEM_PROMPT,
    prompt,
    tools: REVIEWER_TOOL_DENY,
    permissions: REVIEWER_PERMISSION_DENY,
    timeoutMs: input.timeoutMs,
    directory,
    parentSessionID,
    parentLinkage: { parentSessionID, directory },
    pathIdentity: { directory, classes },
  });
}

/** Stable opaque coordinator identity. Raw OpenCode request IDs never leave the coordinator. */
export function createOpaqueCoordinatorID(): string {
  return `coord_${randomUUID()}`;
}

export const opaqueCoordinatorID = createOpaqueCoordinatorID;
