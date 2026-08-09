/**
 * Sensitive-path matching is deliberately metadata-free: it only inspects a
 * path token already present in the command. It never stats or opens a path.
 */

export const DEFAULT_SENSITIVE_PATH_PATTERNS = [
  // Environment and package-manager credentials.
  "**/.env",
  "**/.env.*",
  "**/.npmrc",
  "**/.pypirc",
  "**/.netrc",
  "**/.docker/config.json",
  "**/.config/gcloud/application_default_credentials.json",
  "**/.aws/credentials",
  "**/.aws/config",
  "**/.kube/config",
  // SSH, GPG, and key material.
  "**/.ssh/**",
  "**/.gnupg/**",
  "**/id_rsa",
  "**/id_dsa",
  "**/id_ecdsa",
  "**/id_ed25519",
  "**/*.pem",
  "**/*.key",
  "**/*.p12",
  "**/*.pfx",
  "**/*private*key*",
  // Generic credential stores and macOS keychain exports.
  "**/*credentials*",
  "**/*secrets*",
  "**/*keychain*",
  "**/*auth*.json",
] as const;

export type SensitivePathPattern = string | RegExp;

export interface SensitivePathMatcherOptions {
  readonly additionalPatterns?: readonly SensitivePathPattern[];
}

export interface SensitivePathMatch {
  readonly matched: boolean;
  readonly configured: boolean;
}

/** Compile a glob-like path pattern without importing a filesystem matcher. */
export function compileSensitivePathPattern(pattern: SensitivePathPattern): RegExp {
  if (pattern instanceof RegExp) return pattern;
  if (typeof pattern !== "string" || pattern.length === 0) {
    throw new TypeError("sensitive path patterns must be non-empty strings or regular expressions");
  }
  // Match path separators consistently and permit a leading home-variable or
  // absolute prefix. `**` crosses separators; `*` does not.
  let source = "";
  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index];
    if (char === "*" && pattern[index + 1] === "*") {
      source += ".*";
      index += 1;
    } else if (char === "*") {
      source += "[^/]*";
    } else if (char === "?") {
      source += "[^/]";
    } else if (char === "/") {
      source += "[/\\\\]";
    } else {
      source += escapeRegExp(char);
    }
  }
  return new RegExp(`(?:^|[/\\\\])${source}$`, "i");
}

/** Create a matcher and validate configured additions up front. */
export function createSensitivePathMatcher(
  options: SensitivePathMatcherOptions = {},
): (path: string) => SensitivePathMatch {
  const configured = [...(options.additionalPatterns ?? [])].map(compileSensitivePathPattern);
  const defaults = DEFAULT_SENSITIVE_PATH_PATTERNS.map(compileSensitivePathPattern);
  return (path: string): SensitivePathMatch => {
    if (typeof path !== "string") throw new TypeError("path must be a string");
    const normalized = normalizePathToken(path);
    const configuredMatch = configured.some((pattern) => testRegex(pattern, normalized));
    const defaultMatch = defaults.some((pattern) => testRegex(pattern, normalized));
    return { matched: configuredMatch || defaultMatch, configured: configuredMatch };
  };
}

/** Return whether a command path token identifies a commonly sensitive file. */
export function isSensitivePath(
  path: string,
  options: SensitivePathMatcherOptions = {},
): boolean {
  return createSensitivePathMatcher(options)(path).matched;
}

/** Strip shell quoting and a leading `./` while retaining path identity. */
export function normalizePathToken(path: string): string {
  return path
    .trim()
    .replace(/^['"]|['"]$/g, "")
    .replace(/^\.\//, "")
    .replace(/\\/g, "/");
}

function testRegex(pattern: RegExp, value: string): boolean {
  pattern.lastIndex = 0;
  return pattern.test(value);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
