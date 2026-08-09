import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Filesystem sandbox used by the attended OpenCode checks. */
export interface DisposableOpenCode {
  readonly root: string;
  readonly configHome: string;
  readonly dataHome: string;
  readonly stateHome: string;
  readonly configPath: string;
  readonly removeLoader: () => Promise<void>;
  readonly cleanup: () => Promise<void>;
}

export interface OpenCodeProcessResult {
  readonly exitCode: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

const decoder = new TextDecoder();
const opencodeBinary = (): string => process.env.OPENCODE_BIN ?? "opencode";

/**
 * Create a disposable XDG layout. Nothing is written below the real user
 * configuration or data directories. The returned loader entry is a symlink-
 * like config reference that can be removed without touching session data.
 */
export async function createDisposableOpenCode(options: {
  readonly fixturePath: string;
  readonly loaderPath?: string;
}): Promise<DisposableOpenCode> {
  const root = await mkdtemp(join(tmpdir(), "smart-approve-opencode-"));
  const configHome = join(root, "config");
  const dataHome = join(root, "data");
  const stateHome = join(root, "state");
  const configDir = join(configHome, "opencode");
  await Promise.all([mkdir(configDir, { recursive: true }), mkdir(dataHome, { recursive: true }), mkdir(stateHome, { recursive: true })]);
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
    configPath,
    removeLoader: async () => {
      const stock = fixture.replace(/\s*}\s*$/, "}\n");
      await writeFile(configPath, stock, "utf8");
    },
    cleanup: async () => { await rm(root, { recursive: true, force: true }); },
  };
}

/** Run only the local installed OpenCode binary's version probe. */
export function runOpenCodeVersion(options: { readonly configHome: string; readonly dataHome: string; readonly stateHome: string }): OpenCodeProcessResult {
  const result = Bun.spawnSync([opencodeBinary(), "--version"], {
    env: {
      ...process.env,
      XDG_CONFIG_HOME: options.configHome,
      XDG_DATA_HOME: options.dataHome,
      XDG_STATE_HOME: options.stateHome,
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  return { exitCode: result.exitCode, stdout: decoder.decode(result.stdout), stderr: decoder.decode(result.stderr) };
}

/** The explicit attended gate; never called by `bun run check`. */
if (import.meta.main) {
  const fixturePath = process.argv[2] ?? join(process.cwd(), "tests/fixtures/opencode/opencode.jsonc");
  const sandbox = await createDisposableOpenCode({ fixturePath });
  try {
    const result = runOpenCodeVersion(sandbox);
    if (result.exitCode !== 0 || !/^1\.18\.10\b/m.test(result.stdout)) {
      throw new Error(`OpenCode 1.18.10 is required (exit ${result.exitCode})`);
    }
    console.log("OpenCode 1.18.10 disposable E2E sandbox ready");
  } finally {
    await sandbox.cleanup();
  }
}
