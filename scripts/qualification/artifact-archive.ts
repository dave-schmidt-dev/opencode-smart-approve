import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, extname, join, resolve } from "node:path";

/**
 * Preserve a qualification artifact before its path is reused.
 *
 * Qualification receipts and frozen candidate manifests were written to single
 * fixed paths, so each draw destroyed its predecessor's evidence. The
 * 2026-08-16 MiMo comparison overwrote the DeepSeek development receipt that
 * README and SPEC were citing, and the re-freeze that followed overwrote the
 * manifest that receipt named. `eval-results/` is gitignored, so there was no
 * second copy and no git recovery, which is why both are now prose claims with
 * no artifact behind them (TASK-027).
 *
 * The canonical path is deliberately left where it is. Every reader —
 * `assertDevelopmentGate`, `verify-terminal.ts`, the `qualify:*` scripts —
 * resolves the fixed name, and moving that would be a far larger change than
 * the defect warrants. Instead the predecessor is copied aside first, under a
 * name carrying its own identity, and only then is the canonical path
 * overwritten.
 *
 * Copy rather than move, and archive before the caller writes: if the new
 * write fails, the canonical path still holds the old receipt and the archive
 * holds a second copy. A move would leave a window with neither.
 */

/** Identity used to name an archived artifact. */
export interface ArtifactIdentity {
  /** The artifact's own `generatedAt`, compacted for use in a filename. */
  readonly stamp: string;
  /** Candidate manifest hash prefix, which is what ties a receipt to a freeze. */
  readonly hash: string;
}

const HASH_PREFIX_LENGTH = 12;
const CONTENT_PREFIX_LENGTH = 16;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Compact an ISO timestamp into a filename-safe stamp, e.g.
 * `2026-08-26T14:40:00.000Z` becomes `20260826T144000Z`. Anything unparseable
 * yields `undated` rather than throwing; losing the artifact is worse than
 * archiving it under a vague name.
 */
function compactStamp(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "undated";
  return parsed.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

/**
 * Read identity out of a parsed artifact. Both artifacts this covers carry
 * `generatedAt`; the report names its candidate as `candidateManifestHash` and
 * the manifest names itself as `manifestHash`, so one extractor serves both and
 * degrades to `undefined` for anything else.
 */
export function identifyArtifact(parsed: unknown): ArtifactIdentity | undefined {
  if (!isRecord(parsed)) return undefined;
  const generatedAt = parsed.generatedAt;
  const hash = parsed.candidateManifestHash ?? parsed.manifestHash;
  if (typeof generatedAt !== "string" || typeof hash !== "string") return undefined;
  if (!/^[0-9a-f]{64}$/.test(hash)) return undefined;
  return { stamp: compactStamp(generatedAt), hash: hash.slice(0, HASH_PREFIX_LENGTH) };
}

/** Directory holding preserved predecessors, alongside the artifacts themselves. */
export function archiveDirectoryFor(path: string): string {
  return join(dirname(resolve(path)), "archive");
}

/**
 * Copy whatever currently occupies `path` into the archive directory, and
 * return the archive path. Returns `undefined` when nothing was there.
 *
 * An artifact that does not parse, or that carries no recognizable identity, is
 * archived under a hash of its own bytes. That case matters more than the happy
 * one: a truncated or hand-edited receipt is exactly the artifact whose loss
 * would be hardest to explain later.
 */
export function archiveExistingArtifact(path: string): string | undefined {
  const absolute = resolve(path);
  if (!existsSync(absolute)) return undefined;

  const bytes = readFileSync(absolute);
  const extension = extname(absolute);
  const stem = basename(absolute, extension);
  const contentHash = createHash("sha256").update(bytes).digest("hex");

  let identity: ArtifactIdentity | undefined;
  try {
    identity = identifyArtifact(JSON.parse(bytes.toString("utf8")) as unknown);
  } catch {
    identity = undefined;
  }

  const directory = archiveDirectoryFor(absolute);
  mkdirSync(directory, { recursive: true });

  const base = identity
    ? `${stem}-${identity.stamp}-${identity.hash}`
    : `${stem}-unidentified-${contentHash.slice(0, CONTENT_PREFIX_LENGTH)}`;

  // Two draws can share a timestamp and candidate: `generatedAt` has
  // second-level granularity here and the manifest hash is stable across
  // re-runs of the same freeze. Distinguish them by content rather than
  // silently dropping the second, which would reintroduce the defect inside
  // the archive.
  let target = join(directory, `${base}${extension}`);
  if (existsSync(target) && !readFileSync(target).equals(bytes)) {
    target = join(directory, `${base}-${contentHash.slice(0, CONTENT_PREFIX_LENGTH)}${extension}`);
  }

  writeFileSync(target, bytes, { mode: 0o600 });
  return target;
}
