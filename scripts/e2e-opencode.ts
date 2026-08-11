import { accessSync, constants, statSync } from "node:fs";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";

/** Filesystem sandbox used by the attended OpenCode checks. */
export interface DisposableOpenCode {
  readonly root: string;
  readonly configHome: string;
  readonly dataHome: string;
  readonly stateHome: string;
  readonly cacheHome: string;
  readonly configPath: string;
  readonly removeLoader: () => Promise<void>;
  readonly cleanup: () => Promise<void>;
}

export interface OpenCodeProcessResult {
  readonly exitCode: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

export const REQUIRED_OPENCODE_VERSION = "1.18.10" as const;
export const DEFAULT_OPENCODE_BINARY = join(process.cwd(), "node_modules", ".bin", "opencode");

const decoder = new TextDecoder();
const opencodeBinary = (environment: NodeJS.ProcessEnv): string | undefined => {
  const configured = environment.OPENCODE_BIN ?? DEFAULT_OPENCODE_BINARY;
  const candidates = /[\\/]/.test(configured)
    ? [configured]
    : (environment.PATH ?? "").split(delimiter).filter(Boolean).map((entry) => join(entry, configured));
  return candidates.find((candidate) => {
    try {
      accessSync(candidate, constants.X_OK);
      return statSync(candidate).isFile();
    } catch {
      return false;
    }
  });
};

/**
 * Create a disposable XDG layout. Nothing is written below the real user
 * configuration, data, or cache directories. The returned loader entry is a
 * symlink-like config reference that can be removed without touching session
 * data.
 */
export async function createDisposableOpenCode(options: {
  readonly fixturePath: string;
  readonly loaderPath?: string;
}): Promise<DisposableOpenCode> {
  const root = await mkdtemp(join(tmpdir(), "smart-approve-opencode-"));
  const configHome = join(root, "config");
  const dataHome = join(root, "data");
  const stateHome = join(root, "state");
  const cacheHome = join(root, "cache");
  const configDir = join(configHome, "opencode");
  await Promise.all([
    mkdir(configDir, { recursive: true }),
    mkdir(dataHome, { recursive: true }),
    mkdir(stateHome, { recursive: true }),
    mkdir(cacheHome, { recursive: true }),
  ]);
  const configPath = join(configDir, "opencode.jsonc");
  const fixture = await readFile(options.fixturePath, "utf8");
  const loaderPath = options.loaderPath ?? join(root, "loader.mjs");
  await writeFile(loaderPath, "throw new Error('disposable loader failure');\n", "utf8");
  // Keep the fixture's native ask posture and add only the disposable loader.
  const config = `${fixture.replace(/\s*}\s*$/, "")}\n,\n  \"plugin\": [${JSON.stringify(loaderPath)}]\n}\n`;
  await writeFile(configPath, config, "utf8");
  return {
    root,
    configHome,
    dataHome,
    stateHome,
    cacheHome,
    configPath,
    removeLoader: async () => {
      const stock = fixture.replace(/\s*}\s*$/, "}\n");
      await writeFile(configPath, stock, "utf8");
    },
    cleanup: async () => { await rm(root, { recursive: true, force: true }); },
  };
}

/** Run only the selected OpenCode binary's version probe. */
export function runOpenCodeVersion(
  options: { readonly configHome: string; readonly dataHome: string; readonly stateHome: string; readonly cacheHome: string },
  environment: NodeJS.ProcessEnv = process.env,
): OpenCodeProcessResult {
  const binary = opencodeBinary(environment);
  if (!binary) return { exitCode: -1, stdout: "", stderr: "selected OpenCode binary is not executable" };
  const result = Bun.spawnSync([binary, "--version"], {
    env: {
      ...environment,
      XDG_CONFIG_HOME: options.configHome,
      XDG_DATA_HOME: options.dataHome,
      XDG_STATE_HOME: options.stateHome,
      XDG_CACHE_HOME: options.cacheHome,
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  return { exitCode: result.exitCode, stdout: decoder.decode(result.stdout), stderr: decoder.decode(result.stderr) };
}

/** Fail closed unless the selected binary reports the exact tested version. */
export function requireOpenCodeVersion(
  options: { readonly configHome: string; readonly dataHome: string; readonly stateHome: string; readonly cacheHome: string },
  environment: NodeJS.ProcessEnv = process.env,
): OpenCodeProcessResult {
  const result = runOpenCodeVersion(options, environment);
  if (result.exitCode !== 0 || result.stdout.trim() !== REQUIRED_OPENCODE_VERSION) {
    throw new Error(`OpenCode ${REQUIRED_OPENCODE_VERSION} is required (exit ${result.exitCode})`);
  }
  return result;
}

/** The explicit attended gate; never called by `bun run check`. */
if (import.meta.main) {
  const fixturePath = process.argv[2] ?? join(process.cwd(), "tests/fixtures/opencode/opencode.jsonc");
  const sandbox = await createDisposableOpenCode({ fixturePath });
  try {
    requireOpenCodeVersion(sandbox);
    console.log(`OpenCode ${REQUIRED_OPENCODE_VERSION} disposable E2E sandbox ready`);
  } finally {
    await sandbox.cleanup();
  }
}
