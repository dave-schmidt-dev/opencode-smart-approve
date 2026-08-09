import { homedir } from "node:os";
import { readFile } from "node:fs/promises";
import { validateConfig, DEFAULT_CONFIG, type SmartApproveConfig } from "./schema";

export interface LoadConfigOptions {
  /** Explicit global file path, primarily useful for isolated tests. */
  readonly globalPath?: string;
  /** Presence is rejected to ensure project configuration is never loaded. */
  readonly projectPath?: string;
  readonly readFile?: (path: string, encoding: "utf8") => Promise<string>;
}

export const DEFAULT_GLOBAL_CONFIG_PATH = `${homedir()}/.config/opencode-smart-approve/config.json`;

/** Parse an already-read global document. JSON is deliberately the only format. */
export function parseGlobalConfig(document: string | unknown): SmartApproveConfig {
  if (typeof document === "string") {
    let value: unknown;
    try {
      value = JSON.parse(document);
    } catch (error) {
      throw new Error(`Invalid global configuration JSON: ${error instanceof Error ? error.message : String(error)}`);
    }
    return validateConfig(value);
  }
  return validateConfig(document);
}

/**
 * Load global configuration only. A missing global file means defaults; any
 * present but malformed file is a startup error. No project path is inspected.
 */
export async function loadGlobalConfig(options: LoadConfigOptions = {}): Promise<SmartApproveConfig> {
  if (options.projectPath !== undefined) {
    throw new Error("Project configuration is not supported; only global configuration may be loaded");
  }
  const path = options.globalPath ?? DEFAULT_GLOBAL_CONFIG_PATH;
  const reader: (path: string, encoding: "utf8") => Promise<string> = options.readFile ?? ((filePath, encoding) => readFile(filePath, encoding));
  try {
    const content = await reader(path, "utf8");
    return parseGlobalConfig(content);
  } catch (error) {
    if (isMissingFile(error)) return DEFAULT_CONFIG;
    throw error;
  }
}

export const loadConfig = loadGlobalConfig;
export const loadGlobalConfiguration = loadGlobalConfig;

function isMissingFile(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && error.code === "ENOENT");
}
