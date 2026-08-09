import {
  createSensitivePathMatcher,
  type SensitivePathMatch,
  type SensitivePathMatcherOptions,
  type SensitivePathPattern,
} from "./sensitive-paths";

export type SecretReasonCode =
  | "credential_name"
  | "token_format"
  | "secret_flag"
  | "sensitive_path"
  | "configured_secret_pattern"
  | "configured_sensitive_path"
  | "prompt_injection"
  | "detector_error";

export interface SecretMatch {
  readonly reason: SecretReasonCode;
  /** Byte offsets are internal redaction data and are not returned by scans. */
  readonly start: number;
  readonly end: number;
}

export type SecretDetector = (
  command: string,
) => readonly SecretMatch[] | SecretMatch[] | boolean;

export interface SecretScanOptions extends SensitivePathMatcherOptions {
  /** Additional literal or regular-expression command patterns. */
  readonly additionalSecretPatterns?: readonly SensitivePathPattern[];
  /** Alias accepted for configuration loaders that call these secret patterns. */
  readonly secretPatterns?: readonly SensitivePathPattern[];
  /** Optional test/integration detectors. A thrown detector fails closed. */
  readonly detectors?: readonly SecretDetector[];
  readonly customDetectors?: readonly SecretDetector[];
  readonly detector?: SecretDetector;
}

export interface SecretScanResult {
  readonly status: "manual" | "model_review";
  readonly decision: "manual" | "model_review";
  readonly suspected: boolean;
  readonly reasonCodes: readonly SecretReasonCode[];
  /** Safe data-only representation suitable for a future provider prompt. */
  readonly redactedCommand: string;
  readonly commandShape: string;
}

const NAME_PATTERN = /(?:^|[\s;'"({])((?:export\s+)?(?:[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|PWD|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIALS?|AUTH(?:ORIZATION)?)[A-Z0-9_-]*|(?:SECRET|TOKEN|PASSWORD|PASSWD|PWD|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIALS?|AUTH(?:ORIZATION)?)[A-Z0-9_-]*)\s*=\s*[^\s;&|)]+)/gi;
const FLAG_PATTERN = /(?:^|[\s])((?:--?(?:api[-_]?key|access[-_]?key|secret|token|password|passwd|pwd|credential|auth(?:orization)?)(?:[=\s]+)(?:"[^"]*"|'[^']*'|[^\s;&|]+)))/gi;
const BEARER_PATTERN = /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi;
const PROMPT_INJECTION_PATTERN = /(?:\b(?:ignore|disregard|override)\b[^\n;|]{0,80}\b(?:instructions?|policy|prompt|rules?)\b|\b(?:system|developer)\s+(?:message|prompt)\b|\byou\s+are\s+now\b|\bjailbreak\b|<\/?system>|\[\s*system\s*\])/gi;
const TOKEN_PATTERNS: readonly RegExp[] = [
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{12,}\b/g,
  /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{12,}\b/g,
  /\bwhsec_[A-Za-z0-9]{12,}\b/g,
  /\bAIza[0-9A-Za-z_-]{20,}\b/g,
  /\bsk-[A-Za-z0-9_-]{20,}\b/g,
  /-----BEGIN\s+(?:[A-Z0-9 ]+)?PRIVATE KEY-----[\s\S]+?-----END\s+(?:[A-Z0-9 ]+)?PRIVATE KEY-----/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  BEARER_PATTERN,
];
const PATH_TOKEN_PATTERN = /(?:^|[\s=:(,'"])((?:~|\$HOME|\$USER|\.|\/)[^\s;|&()<>"']+|(?:[A-Za-z0-9_.-]+\/)+[A-Za-z0-9_.-]+|[A-Za-z0-9_.-]+)/g;

/**
 * Scan command text before any provider/reviewer construction.
 *
 * The return value never contains matched bytes. Any malformed configuration,
 * non-string input, or custom detector exception returns `manual`.
 */
export function scanForSecrets(
  command: string,
  options: SecretScanOptions = {},
): SecretScanResult {
  const safeFallback = (reasonCodes: readonly SecretReasonCode[]): SecretScanResult => ({
    status: "manual",
    decision: "manual",
    suspected: true,
    reasonCodes,
    redactedCommand: "[redacted]",
    commandShape: "secret-boundary-error",
  });
  if (typeof command !== "string") return safeFallback(["detector_error"]);

  try {
    const pathMatcher = createSensitivePathMatcher(options);
    const configuredPatterns = [
      ...(options.additionalSecretPatterns ?? []),
      ...(options.secretPatterns ?? []),
    ].map(compileCommandPattern);
    const matches: SecretMatch[] = [];
    collectRegexMatches(NAME_PATTERN, command, "credential_name", matches, 1);
    collectRegexMatches(FLAG_PATTERN, command, "secret_flag", matches, 1);
    collectRegexMatches(PROMPT_INJECTION_PATTERN, command, "prompt_injection", matches);
    for (const pattern of TOKEN_PATTERNS) collectRegexMatches(pattern, command, "token_format", matches);
    for (const pattern of configuredPatterns) collectRegexMatches(pattern, command, "configured_secret_pattern", matches);

    PATH_TOKEN_PATTERN.lastIndex = 0;
    let pathMatch: RegExpExecArray | null;
    while ((pathMatch = PATH_TOKEN_PATTERN.exec(command)) !== null) {
      const path = pathMatch[1] ?? "";
      const result: SensitivePathMatch = pathMatcher(path);
      if (result.matched) {
        const start = pathMatch.index + pathMatch[0].lastIndexOf(path);
        matches.push({
          reason: result.configured ? "configured_sensitive_path" : "sensitive_path",
          start,
          end: start + path.length,
        });
      }
    }

    const detectors = [
      ...(options.detectors ?? []),
      ...(options.customDetectors ?? []),
      ...(options.detector ? [options.detector] : []),
    ];
    for (const detector of detectors) {
      if (typeof detector !== "function") throw new TypeError("secret detector must be callable");
      const result = detector(command);
      if (result === true) matches.push({ reason: "configured_secret_pattern", start: 0, end: command.length });
      else if (Array.isArray(result)) {
        for (const match of result) {
          if (!isValidMatch(match, command.length)) throw new TypeError("secret detector returned an invalid match");
          matches.push(match);
        }
      }
    }

    const reasons = uniqueReasons(matches);
    return {
      status: reasons.length ? "manual" : "model_review",
      decision: reasons.length ? "manual" : "model_review",
      suspected: reasons.length > 0,
      reasonCodes: reasons,
      redactedCommand: redact(command, matches),
      commandShape: commandShape(command, matches),
    };
  } catch {
    return safeFallback(["detector_error"]);
  }
}

/** Alias emphasizing that this scan is the pre-provider authorization gate. */
export const scanSecretBoundary = scanForSecrets;
export const classifySecretBoundary = scanForSecrets;

function compileCommandPattern(pattern: SensitivePathPattern): RegExp {
  if (pattern instanceof RegExp) {
    // `exec` iteration requires a global expression. Clone caller-owned
    // expressions so we never mutate their lastIndex or hang on a non-global
    // configured detector.
    return new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`);
  }
  if (typeof pattern !== "string" || pattern.length === 0) throw new TypeError("secret patterns must be non-empty");
  return new RegExp(escapeRegExp(pattern), "g");
}

function collectRegexMatches(
  pattern: RegExp,
  command: string,
  reason: SecretReasonCode,
  matches: SecretMatch[],
  captureGroup?: number,
): void {
  pattern.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(command)) !== null) {
    const value = captureGroup === undefined ? match[0] : match[captureGroup];
    if (value === undefined) throw new TypeError("secret pattern capture is missing");
    const start = match.index + match[0].lastIndexOf(value);
    matches.push({ reason, start, end: start + value.length });
    if (match[0].length === 0) pattern.lastIndex += 1;
  }
}

function isValidMatch(match: SecretMatch, length: number): boolean {
  return Boolean(
    match && typeof match === "object" && typeof match.reason === "string" &&
      Number.isInteger(match.start) && Number.isInteger(match.end) &&
      match.start >= 0 && match.end >= match.start && match.end <= length,
  );
}

function uniqueReasons(matches: readonly SecretMatch[]): SecretReasonCode[] {
  return [...new Set(matches.map((match) => match.reason))];
}

function redact(command: string, matches: readonly SecretMatch[]): string {
  if (!matches.length) return command;
  const ranges = matches
    .filter((match) => match.end > match.start)
    .sort((left, right) => left.start - right.start || right.end - left.end);
  let result = "";
  let cursor = 0;
  for (const match of ranges) {
    if (match.start < cursor) continue;
    result += command.slice(cursor, match.start) + "[redacted]";
    cursor = match.end;
  }
  return result + command.slice(cursor);
}

function commandShape(command: string, matches: readonly SecretMatch[]): string {
  if (matches.length) return "secret-bearing-command";
  return command
    .replace(/[A-Za-z0-9_./:@+-]+/g, "word")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 256);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
