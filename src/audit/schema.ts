import { createHash } from "node:crypto";
import { z } from "zod";

const identifier = z.string().min(1).max(160);
const reasonCode = z.string().regex(/^[a-z][a-z0-9_.-]{0,63}$/);

/** The only fields permitted in a persisted audit line. */
export const AuditRecordSchema = z.object({
  timestamp: z.string().datetime(),
  requestHash: z.string().regex(/^[a-f0-9]{64}$/),
  commandShapeHash: z.string().regex(/^[a-f0-9]{64}$/),
  policyID: identifier,
  promptID: identifier,
  modelID: identifier,
  decision: z.enum(["allow", "manual", "timeout", "error", "stale", "complete"]),
  reasonCodes: z.array(reasonCode).max(32),
  latencyMs: z.number().int().nonnegative().max(86_400_000),
  raceState: z.enum(["none", "user_first", "not_found", "stale", "replying", "unknown"]),
}).strict();

export type AuditRecord = z.infer<typeof AuditRecordSchema>;

export interface AuditRecordInput {
  readonly timestamp?: string | Date;
  readonly requestID?: string;
  readonly requestHash?: string;
  readonly command?: string;
  readonly commandShape?: string;
  readonly commandShapeHash?: string;
  readonly policyID?: string;
  readonly promptID?: string;
  readonly modelID?: string;
  readonly decision: AuditRecord["decision"] | string;
  readonly reasonCodes?: readonly string[];
  readonly latencyMs?: number;
  readonly raceState?: AuditRecord["raceState"] | string;
  /** Accepted for callers but deliberately ignored by the schema builder. */
  readonly prompt?: unknown;
  readonly output?: unknown;
  readonly environment?: unknown;
}

export function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

const boundedIdentifier = (value: unknown, fallback: string): string => {
  if (typeof value !== "string" || value.length === 0) return fallback;
  return value.slice(0, 160);
};

const boundedReasons = (values: readonly string[] | undefined): string[] => (values ?? [])
  .filter((value): value is string => typeof value === "string")
  .map((value) => value.toLowerCase().replace(/[^a-z0-9_.-]/g, "_").slice(0, 64))
  .filter((value) => /^[a-z][a-z0-9_.-]{0,63}$/.test(value))
  .slice(0, 32);

const decisions = new Set<AuditRecord["decision"]>(["allow", "manual", "timeout", "error", "stale", "complete"]);
const races = new Set<AuditRecord["raceState"]>(["none", "user_first", "not_found", "stale", "replying", "unknown"]);

/** Build a strict, redacted record. Raw command/prompt/output/env values never survive. */
export function createAuditRecord(input: AuditRecordInput): AuditRecord {
  const timestamp = input.timestamp instanceof Date
    ? input.timestamp.toISOString()
    : typeof input.timestamp === "string" ? input.timestamp : new Date().toISOString();
  const requestHash = input.requestHash && /^[a-f0-9]{64}$/.test(input.requestHash)
    ? input.requestHash
    : sha256(input.requestID ?? "unknown-request");
  const commandShapeHash = input.commandShapeHash && /^[a-f0-9]{64}$/.test(input.commandShapeHash)
    ? input.commandShapeHash
    // A raw command is accepted only so callers can hand an untrusted object
    // to this boundary. It is never persisted or used as hash material.
    : sha256(input.commandShape ?? "unknown-command-shape");
  const candidate = {
    timestamp,
    requestHash,
    commandShapeHash,
    policyID: boundedIdentifier(input.policyID, "unknown-policy"),
    promptID: boundedIdentifier(input.promptID, "unknown-prompt"),
    modelID: boundedIdentifier(input.modelID, "unknown-model"),
    decision: decisions.has(input.decision as AuditRecord["decision"]) ? input.decision : "error",
    reasonCodes: boundedReasons(input.reasonCodes),
    latencyMs: Number.isFinite(input.latencyMs) && (input.latencyMs ?? 0) >= 0 ? Math.floor(input.latencyMs ?? 0) : 0,
    raceState: races.has(input.raceState as AuditRecord["raceState"]) ? input.raceState : "unknown",
  };
  return AuditRecordSchema.parse(candidate);
}

export const parseAuditRecord = (value: unknown): AuditRecord => AuditRecordSchema.parse(value);
export const AuditSchema = AuditRecordSchema;
export const validateAuditRecord = parseAuditRecord;
