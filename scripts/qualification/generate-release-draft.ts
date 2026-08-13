import { createHash } from "node:crypto";
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, writeSync } from "node:fs";
import { dirname, resolve } from "node:path";
import {
  AUTOMATED_DRAFT_AUTHORITY,
  AUTOMATED_DRAFT_SCHEMA,
  parseReleaseCorpus,
  type AutomatedDraftCorpus,
  type PrivateReleaseFixture,
} from "./release-corpus";
import { CATEGORIES, MINIMUMS, REPEAT_COUNT, REVIEW_TIMEOUT_MS, TEMPERATURE, canonical } from "./core";

export const DEFAULT_DRAFT_PATH = resolve(process.cwd(), "eval-results/release-corpus-draft.json");
export const DEFAULT_DRAFT_TIMESTAMP = "1970-01-01T00:00:00.000Z";
export const AUTOMATED_DRAFT_VERSION = "2026-08-13-automated-draft-v1";

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function assertDigest(value: string): void {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new Error("candidate manifest hash must be a SHA-256 hex digest");
}

function canary(kind: string, candidateManifestHash: string, id: string, label: string): string {
  return `${kind}_${sha256(canonical({ candidateManifestHash, id, label }))}`;
}

function fixture(candidateManifestHash: string, category: (typeof CATEGORIES)[number], index: number, stratum: PrivateReleaseFixture["stratum"]): PrivateReleaseFixture {
  const id = `synthetic-release-${stratum}-${category}-${String(index).padStart(2, "0")}`;
  const errorPath = category === "dangerous" && index === 1;
  const deterministic = category === "secret" || errorPath;
  const expectedDecision = category === "benign" ? "allow" as const : "manual" as const;
  return {
    id,
    category,
    command: `synthetic://classifier/${stratum}/${category}/${String(index).padStart(2, "0")}`,
    expectedDecision,
    stratum,
    structuralKey: `synthetic-shape-${stratum}-${category}-${String(index).padStart(2, "0")}`,
    route: deterministic ? "deterministic" : "reviewer",
    providerAttempted: !deterministic,
    ...(errorPath ? { errorPath: true } : {}),
    canaries: {
      structural: canary("structural", candidateManifestHash, id, category),
      label: canary("label", candidateManifestHash, id, expectedDecision),
      ...(category === "secret" ? { secret: canary("secret", candidateManifestHash, id, "opaque") } : {}),
    },
  };
}

/** Create a deterministic, synthetic, non-eligible draft. It is not qualification evidence. */
export function generateAutomatedDraft(candidateManifestHash: string, generatedAt = DEFAULT_DRAFT_TIMESTAMP): AutomatedDraftCorpus {
  assertDigest(candidateManifestHash);
  const release = CATEGORIES.flatMap((category) => Array.from({ length: MINIMUMS[category] }, (_, index) => fixture(candidateManifestHash, category, index + 1, "qualification")));
  const generalization = CATEGORIES.map((category) => fixture(candidateManifestHash, category, 1, "generalization"));
  const draft: AutomatedDraftCorpus = {
    schemaVersion: AUTOMATED_DRAFT_SCHEMA,
    authority: AUTOMATED_DRAFT_AUTHORITY,
    releaseEligible: false,
    bindings: { candidateManifestHash, rubric: "fixtures/eval/authoring-rubric.md" },
    corpusVersion: AUTOMATED_DRAFT_VERSION,
    minimums: MINIMUMS,
    repeats: REPEAT_COUNT,
    temperature: TEMPERATURE,
    timeoutMs: REVIEW_TIMEOUT_MS,
    generatedAt,
    release,
    generalization,
  };
  return parseReleaseCorpus(draft) as AutomatedDraftCorpus;
}

/** Write one private draft without overwriting an existing path. */
export function writeAutomatedDraft(path: string, draft: AutomatedDraftCorpus): AutomatedDraftCorpus {
  const validated = parseReleaseCorpus(draft);
  if (validated.schemaVersion !== AUTOMATED_DRAFT_SCHEMA || validated.releaseEligible !== false) throw new Error("only an automated non-eligible draft may be written");
  const absolute = resolve(path);
  mkdirSync(dirname(absolute), { recursive: true, mode: 0o700 });
  if (existsSync(absolute)) throw new Error("release draft already exists");
  const bytes = Buffer.from(`${JSON.stringify(validated, null, 2)}\n`, "utf8");
  let fd: number | undefined;
  try {
    fd = openSync(absolute, "wx", 0o600);
    writeSync(fd, bytes, 0, bytes.length);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    const parent = openSync(dirname(absolute), "r");
    try { fsyncSync(parent); } finally { closeSync(parent); }
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    throw error;
  }
  return validated;
}

export * from "./release-corpus";

export function main(argv = process.argv.slice(2)): number {
  const candidateManifestHash = argv[0];
  if (!candidateManifestHash || argv.length > 3) {
    console.error("usage: generate-release-draft <candidate-manifest-hash> [generated-at] [output-path]");
    return 1;
  }
  const draft = generateAutomatedDraft(candidateManifestHash, argv[1] ?? DEFAULT_DRAFT_TIMESTAMP);
  writeAutomatedDraft(argv[2] ?? DEFAULT_DRAFT_PATH, draft);
  return 0;
}

if (import.meta.main) process.exit(main());
