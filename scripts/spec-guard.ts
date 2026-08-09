import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

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

/** Validate the requirement/task/test/invariant links before a release. */
export function validateTraceability(root = process.cwd()): TraceabilityReport {
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
