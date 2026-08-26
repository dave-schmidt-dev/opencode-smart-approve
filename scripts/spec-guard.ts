import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

export interface TraceabilityReport {
  requirements: string[];
  tasks: string[];
  invariants: string[];
  errors: string[];
}

const read = (root: string, file: string): string => {
  const path = resolve(root, file);
  if (!existsSync(path)) {
    throw new Error(`missing required file: ${file}`);
  }
  return readFileSync(path, "utf8");
};

const unique = (values: string[]): string[] => Array.from(new Set(values)).sort();

interface Mapping {
  task: string;
  requirements: string[];
  testSelector: string;
}

const isTableHeader = (line: string): boolean =>
  /^\s*\|\s*task\s*\|\s*requirements?\s*\|\s*(?:concrete\s+)?tests?(?:\s+selectors?)?\s*\|\s*$/i.test(
    line,
  );

const isTableDivider = (line: string): boolean =>
  /^\s*\|(?:\s*:?-+:?\s*\|){3}\s*$/.test(line);

/** Parse the public traceability table without turning TASKS into history. */
const parseTraceabilityTable = (root: string, traceabilityFile: string): { found: boolean; mappings: Mapping[]; errors: string[] } => {
  const lines = traceabilityFile.split(/\r?\n/);
  const headerIndex = lines.findIndex(isTableHeader);
  if (headerIndex < 0) return { found: false, mappings: [], errors: [] };

  const errors: string[] = [];
  const mappings: Mapping[] = [];
  let sawRow = false;
  for (const line of lines.slice(headerIndex + 1)) {
    if (!line.trim()) {
      if (sawRow) break;
      continue;
    }
    if (isTableDivider(line)) continue;
    if (!/^\s*\|/.test(line)) break;
    sawRow = true;
    const cells = line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((cell) => cell.trim());
    if (cells.length !== 3) {
      errors.push(`traceability table row must have Task, Requirements, and Tests columns: ${line.trim()}`);
      continue;
    }
    const task = cells[0].match(/^TASK-\d{3}$/)?.[0] ?? "";
    const requirements = unique(cells[1].match(/\bREQ-\d{3}\b/g) ?? []);
    if (!task) errors.push(`traceability table has invalid task ID: ${cells[0]}`);
    if (requirements.length === 0) errors.push(`${cells[0] || "traceability table row"} has no requirement mapping`);
    if (!cells[2]) errors.push(`${task || cells[0] || "traceability table row"} has no concrete test selector`);
    else if (!/\btests?\//i.test(cells[2])) {
      errors.push(`${task || cells[0] || "traceability table row"} has no concrete test selector`);
    } else {
      const testPaths = Array.from(cells[2].matchAll(/\btests?\/[A-Za-z0-9._/-]+/g), (match) => match[0]);
      for (const testPath of testPaths) {
        if (!existsSync(resolve(root, testPath))) errors.push(`test selector file is missing: ${testPath}`);
      }
    }
    mappings.push({ task, requirements, testSelector: cells[2] });
  }
  if (!sawRow) errors.push("traceability table has no data rows");
  return { found: true, mappings, errors };
};

/**
 * Documents that are committed, and therefore the ones a reader outside this
 * machine can see. `eval-results/` is gitignored, so a claim made here about an
 * artifact is a claim nothing can check on a fresh clone -- which is exactly how
 * three documents came to name three different "current" freezes, none of which
 * matched the manifest on disk (TASK-026).
 */
const EVIDENCE_DOCS = ["README.md", "SPEC.md", "TRACEABILITY.md", "INVARIANTS.md"] as const;

/**
 * Words that mark a quoted hash as historical. A hash carrying one of these is
 * identifying which artifact a past measurement was taken against, which is a
 * legitimate and permanent use; a hash without one asserts currency, and
 * currency is checkable.
 *
 * The marker must sit within `MARKER_WINDOW` characters of the hash, not merely
 * somewhere in the same paragraph. A paragraph-wide test was tried first and is
 * useless: these paragraphs are long enough that one almost always contains
 * some hedging word about a different sentence's subject, so a hash asserted as
 * current passed on the strength of an unrelated clause.
 */
const SUPERSEDED_MARKERS = ["superseded", "stale", "retired", "no longer"];
const MARKER_WINDOW = 100;

/**
 * Currency claims are checked by literal phrase rather than by parsing English.
 * The phrase list covers what these documents actually say; a new way of saying
 * it is not caught until it is added here, and that limit is deliberate --
 * approximate claim detection either misses the real case or fails on prose it
 * misreads, and a gate that cries wolf gets deleted.
 */
const CURRENCY_CLAIMS: readonly { readonly phrase: string; readonly assertsCurrent: boolean }[] = [
  { phrase: "validates as source-current", assertsCurrent: true },
  { phrase: "is the source-current candidate", assertsCurrent: true },
  { phrase: "the current valid freeze", assertsCurrent: true },
  { phrase: "the freeze is stale", assertsCurrent: false },
  { phrase: "reports the candidate stale", assertsCurrent: false },
];

/**
 * Text deleted by a decision, which nothing stops from surviving in a document
 * that was not edited at the time. Unlike a currency claim this is exact: the
 * string already existed, so there is no future rephrasing to miss.
 */
const RETIRED_TEXT: readonly { readonly text: string; readonly reason: string }[] = [
  { text: "pending fresh private corpus authorship, independent adjudication, and human custody", reason: "the 2026-08-14 owner decision (INV-9) removed the human-authorship precondition" },
];

const HEX64 = /\b[0-9a-f]{64}\b/g;

/** Every candidate manifest on disk, including archived predecessors. */
const manifestFiles = (root: string): string[] => {
  const base = resolve(root, "eval-results");
  if (!existsSync(base)) return [];
  const collect = (directory: string): string[] => {
    if (!existsSync(directory)) return [];
    return readdirSync(directory, { withFileTypes: true })
      .filter((entry) => entry.isFile() && /^frozen-candidate-manifest.*\.json$/.test(entry.name))
      .map((entry) => join(directory, entry.name));
  };
  return [...collect(base), ...collect(join(base, "archive"))];
};

/**
 * Whether the canonical frozen candidate still validates against source.
 *
 * `undefined` means the question could not be asked -- no manifest on disk, or
 * no runtime binary to hash -- and every check that depends on it is skipped
 * rather than failed. A fresh clone has no `eval-results/` at all, and a gate
 * that fails there would be reporting on the checkout, not on the documents.
 */
export function canonicalCandidateIsCurrent(root: string, validate: (value: unknown) => unknown): boolean | undefined {
  const path = resolve(root, "eval-results/frozen-candidate-manifest.json");
  if (!existsSync(path)) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return undefined;
  }
  try {
    validate(parsed);
    return true;
  } catch (error) {
    // Only a hash mismatch means stale. A missing runtime binary or an
    // unreadable source file is this machine's problem, not the document's.
    return error instanceof Error && /hashes are stale/.test(error.message) ? false : undefined;
  }
}

/**
 * Check the claims committed documents make about qualification artifacts.
 *
 * Two kinds, both of which have been asserted falsely in this repository and
 * both times were caught by a human reading the file rather than by a gate: a
 * quoted candidate hash that no longer validates, and a sentence asserting the
 * current freeze is source-current when `--validate-candidate` disagrees.
 */
export function validateQuotedEvidence(root: string, validate: (value: unknown) => unknown): string[] {
  const errors: string[] = [];
  const manifests = manifestFiles(root);
  const knownCurrentHashes = new Set<string>();
  for (const file of manifests) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(file, "utf8"));
    } catch {
      continue;
    }
    try {
      validate(parsed);
    } catch {
      continue;
    }
    const hash = (parsed as { manifestHash?: unknown }).manifestHash;
    if (typeof hash === "string") knownCurrentHashes.add(hash);
  }

  const current = canonicalCandidateIsCurrent(root, validate);

  for (const doc of EVIDENCE_DOCS) {
    const path = resolve(root, doc);
    if (!existsSync(path)) continue;
    const text = readFileSync(path, "utf8");
    // Claims are matched against whitespace-collapsed text: these documents are
    // hard-wrapped, and SPEC's own currency claim straddles a line break, so a
    // raw includes() would have missed the one instance that was false.
    const flowed = text.replace(/\s+/g, " ");

    for (const retired of RETIRED_TEXT) {
      if (flowed.includes(retired.text.replace(/\s+/g, " "))) errors.push(`${doc} still contains retired text "${retired.text}": ${retired.reason}`);
    }

    if (current !== undefined) {
      for (const claim of CURRENCY_CLAIMS) {
        if (!flowed.includes(claim.phrase)) continue;
        if (claim.assertsCurrent !== current) {
          errors.push(`${doc} says "${claim.phrase}" but eval-results/frozen-candidate-manifest.json is ${current ? "source-current" : "stale"}`);
        }
      }
    }

    // Skip the hash check when no manifest is on disk: every quoted hash would
    // report unverifiable, which is noise rather than a finding.
    if (manifests.length === 0) continue;
    HEX64.lastIndex = 0;
    for (const match of flowed.matchAll(HEX64)) {
      const hash = match[0];
      if (knownCurrentHashes.has(hash)) continue;
      const vicinity = flowed.slice(match.index, match.index + hash.length + MARKER_WINDOW).toLowerCase();
      if (SUPERSEDED_MARKERS.some((marker) => vicinity.includes(marker))) continue;
      errors.push(`${doc} quotes ${hash.slice(0, 12)}... as current, but no manifest under eval-results/ with that hash validates against source; mark it superseded or remove it`);
    }
  }
  return errors;
}

/** Validate the requirement/task/test/invariant links before a release. */
/**
 * Injected so the document gate can be tested without the qualification module,
 * and so a checkout without a runtime binary degrades to a skip.
 */
export type CandidateValidator = (value: unknown) => unknown;

function defaultCandidateValidator(value: unknown): unknown {
  // Imported lazily: spec-guard is a document gate and must stay runnable in a
  // checkout where the qualification module's dependencies are not loadable.
  const { validateFrozenCandidateManifest } = require("./classifier-gate") as { validateFrozenCandidateManifest: CandidateValidator };
  return validateFrozenCandidateManifest(value);
}

export function validateTraceability(root = process.cwd(), evidenceValidator: CandidateValidator = defaultCandidateValidator): TraceabilityReport {
  const errors: string[] = [];
  let spec = "";
  let traceabilityFile = "";
  let invariantsFile = "";
  try {
    spec = read(root, "SPEC.md");
    traceabilityFile = existsSync(resolve(root, "TRACEABILITY.md"))
      ? read(root, "TRACEABILITY.md")
      : read(root, "TASKS.md");
    invariantsFile = read(root, "INVARIANTS.md");
  } catch (error) {
    errors.push(error instanceof Error ? error.message : String(error));
  }

  const requirements = unique(spec.match(/\bREQ-\d{3}\b/g) ?? []);
  const taskIds = unique(traceabilityFile.match(/\bTASK-\d{3}\b/g) ?? []);
  const invariantIds = unique(invariantsFile.match(/\bINV-\d+\b/g) ?? []);
  const mappedRequirements = new Set<string>();

  const addMapping = (mapping: Mapping, validateSelector: boolean): void => {
    const { task, requirements: specs, testSelector } = mapping;
    if (!task) return;
    if (specs.length === 0) errors.push(`${task} has no requirement mapping`);
    if (!testSelector) errors.push(`${task} has no concrete test selector`);
    else if (validateSelector && !/\btests?\//i.test(testSelector)) {
      errors.push(`${task} has no concrete test selector`);
    }
    for (const requirement of specs) {
      mappedRequirements.add(requirement);
      if (!testSelector) errors.push(`${requirement} has no concrete test selector via ${task}`);
      if (!requirements.includes(requirement)) {
        errors.push(`${requirement} mapped by ${task} is not declared in SPEC.md`);
      }
    }
  };

  const taskSections = traceabilityFile.split(/(?=^[ \t]*-[ \t]*\[[^\]]+\][ \t]+TASK-\d{3}\b)/m);
  let hasCheckboxMapping = false;
  for (const section of taskSections) {
    const task = section.match(/^[ \t]*-[ \t]*\[[^\]]+\][ \t]+(TASK-\d{3})\b/m)?.[1];
    if (!task) continue;
    hasCheckboxMapping = true;
    const specs = unique(section.match(/\bREQ-\d{3}\b/g) ?? []);
    const testLine = section.match(/^\s*-\s*test:\s*(.+)$/m)?.[1]?.trim() ?? "";
    addMapping({ task, requirements: specs, testSelector: testLine }, false);
  }

  const table = parseTraceabilityTable(root, traceabilityFile);
  errors.push(...table.errors);
  for (const mapping of table.mappings) addMapping(mapping, true);
  if (!table.found && !hasCheckboxMapping && requirements.length > 0) {
    errors.push("traceability source has no checkbox task fixtures or mapping table");
  }

  for (const requirement of requirements) {
    if (!mappedRequirements.has(requirement)) {
      errors.push(`${requirement} is not mapped to a TASK-###`);
    }
  }

  errors.push(...validateQuotedEvidence(root, evidenceValidator));

  const gateTests = Array.from(
    invariantsFile.matchAll(/^\s*gate_test:\s*(\S+)/gm),
    (match) => match[1],
  );
  for (const gateTest of gateTests) {
    if (!existsSync(resolve(root, gateTest))) {
      errors.push(`invariant gate test is missing: ${gateTest}`);
    }
  }

  return { requirements, tasks: taskIds, invariants: invariantIds, errors };
}

export function main(root = process.cwd()): number {
  const report = validateTraceability(root);
  if (report.errors.length > 0) {
    for (const error of report.errors) console.error(`spec-guard: ${error}`);
    return 1;
  }
  console.log(
    `spec-guard: ${report.requirements.length} requirements, ${report.tasks.length} tasks, ${report.invariants.length} invariants`,
  );
  return 0;
}

if (process.argv[1]?.endsWith("/scripts/spec-guard.ts")) process.exit(main());
