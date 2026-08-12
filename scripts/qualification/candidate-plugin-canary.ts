import { createHash } from "node:crypto";
import { cp, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const MODEL_LOCK = "export const MODEL_APPROVAL_QUALIFIED = false as const;";

export interface CandidateCanaryResult {
  readonly compiled: true;
  readonly lockSubstitutions: 1;
  readonly candidateHash: string;
  readonly checkoutHashBefore: string;
  readonly checkoutHashAfter: string;
}
function hashFiles(root: string, paths: readonly string[]): string {
  const hash = createHash("sha256");
  for (const path of paths) {
    const absolute = join(root, path);
    if (statSync(absolute).isDirectory()) {
      const entries = readdirSync(absolute, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
      hash.update(`${path}\0`);
      for (const entry of entries) {
        if (entry.name === "node_modules" || entry.name === ".git") continue;
        const nested = relative(root, join(absolute, entry.name));
        hash.update(hashFiles(root, [nested]));
      }
    } else {
      hash.update(`${path}\0${readFileSync(absolute)}`);
    }
  }
  return hash.digest("hex");
}

/** Compile a one-lock-substitution candidate entirely in a disposable temp tree. */
export async function buildCandidatePluginCanary(options: { readonly projectRoot?: string; readonly source?: string } = {}): Promise<CandidateCanaryResult> {
  const projectRoot = resolve(options.projectRoot ?? join(dirname(fileURLToPath(import.meta.url)), "../.."));
  const pluginPath = join(projectRoot, "src/plugin.ts");
  const source = options.source ?? readFileSync(pluginPath, "utf8");
  const matches = source.match(new RegExp(MODEL_LOCK.replace(/[.*+?^${}()|[\\]\\]/g, "\\$&"), "g")) ?? [];
  if (matches.length !== 1) throw new Error(`candidate lock substitution requires exactly one match; found ${matches.length}`);
  const before = hashFiles(projectRoot, ["src", "package.json", "bun.lock"]);
  const candidateSource = source.replace(MODEL_LOCK, "export const MODEL_APPROVAL_QUALIFIED = true as const;");
  const temporaryRoot = await mkdtemp(join(tmpdir(), "smart-approve-candidate-"));
  try {
    await cp(join(projectRoot, "src"), join(temporaryRoot, "src"), { recursive: true });
    await writeFile(join(temporaryRoot, "src/plugin.ts"), candidateSource, "utf8");
    const modules = join(projectRoot, "node_modules");
    if (existsSync(modules)) await symlink(modules, join(temporaryRoot, "node_modules"), "junction");
    const result = await Bun.build({ entrypoints: [join(temporaryRoot, "src/plugin.ts")], outdir: join(temporaryRoot, "dist"), target: "bun", sourcemap: "none" });
    if (!result.success) throw new Error("candidate plugin compilation failed");
    const after = hashFiles(projectRoot, ["src", "package.json", "bun.lock"]);
    if (before !== after) throw new Error("candidate build changed checkout inputs");
    return {
      compiled: true,
      lockSubstitutions: 1,
      candidateHash: createHash("sha256").update(candidateSource).digest("hex"),
      checkoutHashBefore: before,
      checkoutHashAfter: after,
    };
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
}
