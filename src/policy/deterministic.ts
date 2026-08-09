import { parseBash, type BashParseResult } from "../parser/bash-parser";
import { scanForSecrets, type SecretScanOptions, type SecretScanResult } from "../privacy/secret-scan";
import { evaluateBuiltinRules, type BuiltinRuleReason } from "./builtin-rules";
import type { SmartApproveConfig } from "../config/schema";

export type DeterministicDecision = "manual" | "model_review";
export type DeterministicReasonCode = BuiltinRuleReason | "parse_failure" | "privacy" | "model_disabled" | "user_rule" | "invalid_command";

export interface DeterministicPolicyOptions {
  readonly config?: {
    readonly model?: Pick<SmartApproveConfig["model"], "enabled">;
    readonly policy?: {
      readonly rules?: SmartApproveConfig["policy"]["rules"];
      readonly sensitivePathPatterns?: SmartApproveConfig["policy"]["sensitivePathPatterns"];
      readonly secretPatterns?: SmartApproveConfig["policy"]["secretPatterns"];
    };
  };
  readonly privacy?: SecretScanResult;
  readonly secretScan?: SecretScanOptions;
}

export interface DeterministicPolicyResult {
  readonly status: DeterministicDecision;
  readonly decision: DeterministicDecision;
  readonly reasonCodes: readonly DeterministicReasonCode[];
  readonly parse: BashParseResult | undefined;
  readonly privacy: SecretScanResult | undefined;
}

const manual = (
  reasonCodes: readonly DeterministicReasonCode[],
  parse?: BashParseResult,
  privacy?: SecretScanResult,
): DeterministicPolicyResult => ({ status: "manual", decision: "manual", reasonCodes, parse, privacy });

/**
 * Run the parser, privacy boundary, and deterministic rules in precedence order.
 * This function intentionally has no approval adapter and can only return the
 * two routing states consumed by the reviewer coordinator.
 */
export async function evaluateDeterministicPolicy(
  command: string,
  options: DeterministicPolicyOptions = {},
): Promise<DeterministicPolicyResult> {
  if (typeof command !== "string" || command.length === 0) return manual(["invalid_command"]);
  if (options.config?.model?.enabled === false) return manual(["model_disabled"]);

  const parse = await parseBash(command);
  if (!parse.ok) return manual(["parse_failure"], parse);

  const configuredPolicy = options.config?.policy;
  const privacy = options.privacy ?? scanForSecrets(command, {
    ...options.secretScan,
    ...((options.secretScan?.additionalPatterns?.length || configuredPolicy?.sensitivePathPatterns?.length)
      ? { additionalPatterns: [...(options.secretScan?.additionalPatterns ?? []), ...(configuredPolicy?.sensitivePathPatterns ?? [])] }
      : {}),
    ...((options.secretScan?.additionalSecretPatterns?.length || configuredPolicy?.secretPatterns?.length)
      ? { additionalSecretPatterns: [...(options.secretScan?.additionalSecretPatterns ?? []), ...(configuredPolicy?.secretPatterns ?? [])] }
      : {}),
  });
  if (privacy.status === "manual" || privacy.suspected || containsSensitivePathToken(command)) return manual(["privacy"], parse, privacy);

  const reasons = [...evaluateBuiltinRules({ command, features: parse.features })];
  if (reasons.length) return manual(reasons, parse, privacy);

  const userRules = options.config?.policy?.rules ?? [];
  for (const rule of userRules) {
    if (rule.pattern && command.includes(rule.pattern) && rule.action === "manual") {
      return manual(["user_rule"], parse, privacy);
    }
  }
  return { status: "model_review", decision: "model_review", reasonCodes: [], parse, privacy };
}

export const evaluatePolicy = evaluateDeterministicPolicy;
export const deterministicPolicy = evaluateDeterministicPolicy;

// The privacy scanner deliberately treats paths as tokens. Keep a small
// basename check here as well so root-relative names such as `.env` (which do
// not contain a slash) remain hard blocked.
function containsSensitivePathToken(command: string): boolean {
  return /(?:^|[/\\\s"'=])(?:\.env(?:\.[^\s/;&|]*)?|\.npmrc|\.pypirc|\.netrc|credentials?(?:\.[^\s/;&|]*)?|secrets?(?:\.[^\s/;&|]*)?|.*(?:keychain|private.key|id_(?:rsa|dsa|ecdsa|ed25519))(?:\.[^\s/;&|]*)?)(?=$|[\s"';&|])/i.test(command);
}
