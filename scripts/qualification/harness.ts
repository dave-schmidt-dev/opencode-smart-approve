import { buildReviewerRegistration, type ReviewerRegistration } from "../../src/plugin";
import { createApprovalCoordinator } from "../../src/approval/coordinator";
import { DEFAULT_CONFIG, type SmartApproveConfig } from "../../src/config/schema";
import {
  buildReviewerContract,
  REVIEWER_CONTRACT_VERSION,
  REVIEWER_OUTPUT_SCHEMA,
  type ReviewerContract,
  type ReviewerPathClass,
} from "../../src/reviewer/contract";
import { createReviewerAgent } from "../../src/reviewer/agent";
import type { ReviewerSessionClient } from "../../src/reviewer/client";
import type { DeterministicPolicyResult } from "../../src/policy/deterministic";

const OPAQUE_COORDINATOR = "<opaque-coordinator>";

export interface ParityScenario {
  readonly command: string;
  readonly directory: string;
  readonly parentSessionID: string;
  readonly pathClasses: readonly ReviewerPathClass[];
}

export interface PublicReviewerContract {
  readonly version: typeof REVIEWER_CONTRACT_VERSION;
  readonly requestedModel: string;
  readonly requestedVariant?: string;
  readonly temperature: 0;
  readonly retryCount: 0;
  readonly schema: typeof REVIEWER_OUTPUT_SCHEMA;
  readonly system: string;
  readonly prompt: string;
  readonly tools: Readonly<Record<string, boolean>>;
  readonly permissions: readonly { readonly permission: string; readonly pattern: string; readonly action: "deny" }[];
  readonly timeoutMs: number;
  readonly directoryClass: "project" | "external" | "none" | "unknown";
  readonly parentSessionPresent: boolean;
  readonly pathClasses: readonly ReviewerPathClass[];
}

export interface ParityCapture {
  readonly registration: ReviewerRegistration;
  readonly contract: PublicReviewerContract;
  readonly create: {
    readonly count: number;
    readonly parentLinked: boolean;
    readonly directoryClass: PublicReviewerContract["directoryClass"];
    readonly title: typeof OPAQUE_COORDINATOR;
  };
  readonly prompt: {
    readonly count: number;
    readonly model: string;
    readonly variant: string | undefined;
    readonly temperature: 0;
  readonly format: unknown;
    readonly system: string;
    readonly text: string;
    readonly tools: Readonly<Record<string, boolean>>;
  };
  readonly terminal: {
    readonly state: "manual";
    readonly outcomeKind: "valid_model" | "manual" | "malformed" | "empty" | "truncated" | "timeout" | "provider_error" | "tool_violation" | "permission_violation" | "capacity_rejected";
    readonly approvalCalls: number;
  };
}

export interface ParityComparison {
  readonly equal: boolean;
  readonly mismatches: readonly string[];
}

export interface ParityReport {
  readonly schemaVersion: "qualification-parity/v1";
  readonly lock: false;
  readonly mode: "contract_only";
  readonly production: ParityCapture;
  readonly evaluation: ParityCapture;
  readonly comparison: ParityComparison;
}

export interface ParityValidation {
  readonly accepted: boolean;
  readonly errors: readonly string[];
}

export { buildCandidatePluginCanary } from "./candidate-plugin-canary";
export type { CandidateCanaryResult } from "./candidate-plugin-canary";

const directoryClassFor = (directory: string): PublicReviewerContract["directoryClass"] =>
  directory.startsWith("/") && !directory.startsWith("/private/") && !directory.startsWith("/tmp/")
    ? "project"
    : directory.length > 0 ? "external" : "none";

const policyForCapture = (pathClasses: readonly ReviewerPathClass[]): DeterministicPolicyResult => ({
  status: "model_review",
  decision: "model_review",
  reasonCodes: [],
  parse: undefined,
  privacy: undefined,
  pathClasses: pathClasses.filter((value): value is "project" | "none" => value === "project" || value === "none"),
});

const publicContract = (contract: ReviewerContract): PublicReviewerContract => ({
  version: contract.version,
  requestedModel: contract.requestedModel,
  ...(contract.requestedVariant === undefined ? {} : { requestedVariant: contract.requestedVariant }),
  temperature: contract.temperature,
  retryCount: contract.retryCount,
    schema: REVIEWER_OUTPUT_SCHEMA,
  system: contract.system,
  prompt: contract.prompt,
  tools: contract.tools,
  permissions: contract.permissions,
  timeoutMs: contract.timeoutMs,
  directoryClass: directoryClassFor(contract.directory ?? ""),
  parentSessionPresent: contract.parentSessionID !== null,
  pathClasses: contract.pathIdentity.classes,
});

function scrubPromptBody(value: unknown): ParityCapture["prompt"] {
  const body = value as {
    model?: { providerID?: unknown; modelID?: unknown };
    variant?: unknown;
    temperature?: unknown;
    format?: unknown;
    system?: unknown;
    tools?: unknown;
    parts?: readonly { type?: unknown; text?: unknown }[];
  };
  const part = body.parts?.find((entry) => entry.type === "text");
  return {
    count: 1,
    model: `${String(body.model?.providerID ?? "")}/${String(body.model?.modelID ?? "")}`,
    variant: typeof body.variant === "string" ? body.variant : undefined,
    temperature: 0,
    format: body.format,
    system: typeof body.system === "string" ? body.system : "",
    text: typeof part?.text === "string" ? part.text : "",
    tools: typeof body.tools === "object" && body.tools !== null ? body.tools as Readonly<Record<string, boolean>> : {},
  };
}

/** Capture one real coordinator path with a disposable one-shot session adapter. */
export async function captureProductionParity(scenario: ParityScenario, config: SmartApproveConfig = DEFAULT_CONFIG): Promise<ParityCapture> {
  const registration = buildReviewerRegistration(config);
  let createCount = 0;
  let promptCapture: ParityCapture["prompt"] | undefined;
  let approvalCalls = 0;
  let outcomeKind: ParityCapture["terminal"]["outcomeKind"] = "manual";
  const client: ReviewerSessionClient = {
    session: {
      create: async (input) => {
        createCount += 1;
        const body = (input as { body?: { parentID?: unknown; title?: unknown } }).body;
        if (body?.parentID !== scenario.parentSessionID) throw new Error("parent linkage was not forwarded");
        if (typeof body?.title !== "string" || !/^smart-approve:coord_[a-f0-9-]{36}$/.test(body.title)) throw new Error("opaque title missing");
        if (body.title.includes("permission-request-token")) throw new Error("raw request ID crossed the provider title boundary");
        return { data: { id: "reviewer-session-token" } };
      },
      prompt: async (input) => {
        const request = input as { body?: unknown };
        promptCapture = scrubPromptBody(request.body);
        return { data: { decision: "manual", reasonCodes: ["manual"] } };
      },
      abort: async () => undefined,
      delete: async () => undefined,
    },
  };
  const reviewer = createReviewerAgent({
    client,
    timeoutMs: config.model.timeoutMs,
    directory: scenario.directory,
    providerID: config.model.provider,
    modelID: config.model.model,
    variant: config.model.variant,
  });
  const coordinator = createApprovalCoordinator({
    reviewer,
    config,
    modelEnabled: true,
    directory: scenario.directory,
    timeoutMs: config.model.timeoutMs,
    policy: async () => policyForCapture(scenario.pathClasses),
    approve: async () => { approvalCalls += 1; },
    onReviewOutcome: (outcome) => { outcomeKind = outcome.kind; },
  });
  try {
    await coordinator.handle({
      requestID: "permission-request-token",
      sessionID: scenario.parentSessionID,
      command: scenario.command,
      permission: "bash",
    });
  } finally {
    await coordinator.dispose();
  }
  if (!promptCapture) throw new Error("production parity capture did not observe a prompt");
  const coordinatorID = "coord_00000000-0000-4000-8000-000000000000";
  const contract = buildReviewerContract({
    coordinatorID,
    providerID: config.model.provider,
    modelID: config.model.model,
    requestedVariant: config.model.variant,
    timeoutMs: config.model.timeoutMs,
    directory: scenario.directory,
    parentSessionID: scenario.parentSessionID,
    redactedCommand: scenario.command,
    policyFacts: ["model_review", "parser.clear", "privacy.clear", ...scenario.pathClasses.map((value) => `path.${value}`)],
    pathClasses: scenario.pathClasses,
  });
  return {
    registration,
    contract: publicContract(contract),
    create: {
      count: createCount,
      parentLinked: true,
      directoryClass: directoryClassFor(scenario.directory),
      title: OPAQUE_COORDINATOR,
    },
    prompt: promptCapture,
    terminal: { state: "manual", outcomeKind, approvalCalls },
  };
}

/** Build the evaluation-side capture from the same canonical contract input. */
export function captureEvaluationParity(scenario: ParityScenario, config: SmartApproveConfig = DEFAULT_CONFIG): ParityCapture {
  const registration = buildReviewerRegistration(config);
  const contract = buildReviewerContract({
    coordinatorID: "coord_00000000-0000-4000-8000-000000000000",
    providerID: config.model.provider,
    modelID: config.model.model,
    requestedVariant: config.model.variant,
    timeoutMs: config.model.timeoutMs,
    directory: scenario.directory,
    parentSessionID: scenario.parentSessionID,
    redactedCommand: scenario.command,
    policyFacts: ["model_review", "parser.clear", "privacy.clear", ...scenario.pathClasses.map((value) => `path.${value}`)],
    pathClasses: scenario.pathClasses,
  });
  return {
    registration,
    contract: publicContract(contract),
    create: { count: 1, parentLinked: true, directoryClass: directoryClassFor(scenario.directory), title: OPAQUE_COORDINATOR },
    prompt: {
      count: 1,
      model: contract.requestedModel,
      variant: contract.requestedVariant,
      temperature: contract.temperature,
      format: { type: "json_schema", retryCount: contract.retryCount, schema: REVIEWER_OUTPUT_SCHEMA },
      system: contract.system,
      text: contract.prompt,
      tools: contract.tools,
    },
    terminal: { state: "manual", outcomeKind: "valid_model", approvalCalls: 0 },
  };
}

const comparable = (capture: ParityCapture): unknown => ({
  registration: capture.registration,
  contract: capture.contract,
  create: capture.create,
  prompt: capture.prompt,
});

export function compareParityCaptures(production: ParityCapture, evaluation: ParityCapture): ParityComparison {
  const mismatches: string[] = [];
  const left = comparable(production) as Record<string, unknown>;
  const right = comparable(evaluation) as Record<string, unknown>;
  for (const key of ["registration", "contract", "create", "prompt"] as const) {
    if (JSON.stringify(left[key]) !== JSON.stringify(right[key])) mismatches.push(key);
  }
  return { equal: mismatches.length === 0, mismatches };
}

export function buildParityReport(production: ParityCapture, evaluation: ParityCapture): ParityReport {
  return {
    schemaVersion: "qualification-parity/v1",
    lock: false,
    mode: "contract_only",
    production,
    evaluation,
    comparison: compareParityCaptures(production, evaluation),
  };
}

export function validateParityReport(value: unknown): ParityValidation {
  const errors: string[] = [];
  if (typeof value !== "object" || value === null) return { accepted: false, errors: ["report is not an object"] };
  const report = value as Record<string, unknown>;
  if (report.schemaVersion !== "qualification-parity/v1") errors.push("schema version is not v1");
  if (report.lock !== false) errors.push("parity reports require the model lock to remain false");
  if (report.mode !== "contract_only") errors.push("only contract_only reports are valid before release enablement");
  if ("live_plugin_path" in report) errors.push("live_plugin_path is forbidden while the release lock is false");
  const comparison = report.comparison as Record<string, unknown> | undefined;
  if (comparison?.equal !== true) errors.push("production and evaluation contracts are not equal");
  return { accepted: errors.length === 0, errors };
}
