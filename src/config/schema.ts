import { z } from "zod";
import { MAX_AST_DEPTH, MAX_INPUT_BYTES, MAX_SEGMENTS } from "../parser/limits";

export const DEFAULT_MODEL_PROVIDER = "opencode-go" as const;
export const DEFAULT_MODEL_ID = "deepseek-v4-flash" as const;
export const DEFAULT_MODEL_VARIANT = "max" as const;
export const DEFAULT_TIMEOUT_MS = 30_000 as const;
export const DEFAULT_AUDIT_MAX_BYTES = 1_000_000 as const;
export const DEFAULT_AUDIT_MAX_FILES = 2 as const;
export const DEFAULT_REPLAN_MAX_BLOCKS_PER_TURN = 3 as const;

const UserRuleSchema = z.object({
  pattern: z.string().min(1),
  action: z.enum(["manual", "model_review"]),
}).strict();

const ModelSchema = z.object({
  enabled: z.boolean().default(false),
  provider: z.string().min(1).default(DEFAULT_MODEL_PROVIDER),
  model: z.string().min(1).default(DEFAULT_MODEL_ID),
  variant: z.string().min(1).default(DEFAULT_MODEL_VARIANT),
  timeoutMs: z.number().int().min(10_000).max(60_000).default(DEFAULT_TIMEOUT_MS),
}).strict();

const LimitsSchema = z.object({
  maxInputBytes: z.number().int().positive().max(MAX_INPUT_BYTES).default(MAX_INPUT_BYTES),
  maxAstDepth: z.number().int().positive().max(MAX_AST_DEPTH).default(MAX_AST_DEPTH),
  maxSegments: z.number().int().positive().max(MAX_SEGMENTS).default(MAX_SEGMENTS),
}).strict();

const PolicySchema = z.object({
  rules: z.array(UserRuleSchema).default([]),
  sensitivePathPatterns: z.array(z.string().min(1)).default([]),
  secretPatterns: z.array(z.string().min(1)).default([]),
}).strict();

const AuditConfigSchema = z.object({
  enabled: z.boolean().default(false),
  directory: z.string().min(1).optional(),
  maxBytes: z.number().int().min(1_024).max(100_000_000).default(DEFAULT_AUDIT_MAX_BYTES),
  maxFiles: z.number().int().min(2).max(8).default(DEFAULT_AUDIT_MAX_FILES),
}).strict();

const ReplanSchema = z.object({
  enabled: z.boolean().default(false),
  maxBlocksPerTurn: z.number().int().min(1).max(DEFAULT_REPLAN_MAX_BLOCKS_PER_TURN).default(DEFAULT_REPLAN_MAX_BLOCKS_PER_TURN),
}).strict();

const DEFAULT_MODEL = {
  enabled: false,
  provider: DEFAULT_MODEL_PROVIDER,
  model: DEFAULT_MODEL_ID,
  variant: DEFAULT_MODEL_VARIANT,
  timeoutMs: DEFAULT_TIMEOUT_MS,
};
const DEFAULT_LIMITS = { maxInputBytes: MAX_INPUT_BYTES, maxAstDepth: MAX_AST_DEPTH, maxSegments: MAX_SEGMENTS };
const DEFAULT_POLICY = { rules: [], sensitivePathPatterns: [], secretPatterns: [] };
const DEFAULT_AUDIT = { enabled: false, maxBytes: DEFAULT_AUDIT_MAX_BYTES, maxFiles: DEFAULT_AUDIT_MAX_FILES };
const DEFAULT_REPLAN = { enabled: false, maxBlocksPerTurn: DEFAULT_REPLAN_MAX_BLOCKS_PER_TURN };

export const configSchema = z.object({
  source: z.literal("global").default("global"),
  model: ModelSchema.default(DEFAULT_MODEL),
  limits: LimitsSchema.default(DEFAULT_LIMITS),
  policy: PolicySchema.default(DEFAULT_POLICY),
  audit: AuditConfigSchema.default(DEFAULT_AUDIT),
  replan: ReplanSchema.default(DEFAULT_REPLAN),
}).strict();
export const ConfigSchema = configSchema;

export type UserRule = z.infer<typeof UserRuleSchema>;
export type ModelConfig = z.infer<typeof ModelSchema>;
export type LimitsConfig = z.infer<typeof LimitsSchema>;
export type PolicyConfig = z.infer<typeof PolicySchema>;
export type AuditConfig = z.infer<typeof AuditConfigSchema>;
export type ReplanConfig = z.infer<typeof ReplanSchema>;
export type SmartApproveConfig = z.infer<typeof configSchema>;

export const DEFAULT_CONFIG = Object.freeze({
  source: "global",
  model: Object.freeze(DEFAULT_MODEL),
  limits: Object.freeze(DEFAULT_LIMITS),
  policy: Object.freeze(DEFAULT_POLICY),
  audit: Object.freeze(DEFAULT_AUDIT),
  replan: Object.freeze(DEFAULT_REPLAN),
}) as SmartApproveConfig;

export class ConfigValidationError extends Error {
  readonly issues: readonly z.ZodIssue[];
  constructor(issues: readonly z.ZodIssue[]) {
    super(`Invalid global configuration: ${issues.map((issue) => issue.message).join("; ")}`);
    this.name = "ConfigValidationError";
    this.issues = issues;
  }
}

/** Validate only the global schema; project/source values cannot widen it. */
export function validateConfig(input: unknown = {}): SmartApproveConfig {
  const result = configSchema.safeParse(input);
  if (!result.success) throw new ConfigValidationError(result.error.issues);
  return result.data;
}

export const parseConfig = validateConfig;
export const validateGlobalConfig = validateConfig;
