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

/** Validate the requirement/task/test/invariant links before a release. */
export function validateTraceability(root = process.cwd()): TraceabilityReport {
  const errors: string[] = [];
  let spec = "";
  let tasksFile = "";
  let invariantsFile = "";
  try {
    spec = read(root, "SPEC.md");
    tasksFile = read(root, "TASKS.md");
    invariantsFile = read(root, "INVARIANTS.md");
  } catch (error) {
    errors.push(error instanceof Error ? error.message : String(error));
  }

  const requirements = unique(spec.match(/\bREQ-\d{3}\b/g) ?? []);
  const taskIds = unique(tasksFile.match(/\bTASK-\d{3}\b/g) ?? []);
  const invariantIds = unique(invariantsFile.match(/\bINV-\d+\b/g) ?? []);
  const mappedRequirements = new Set<string>();

  const taskSections = tasksFile.split(/(?=^\s*- \[[^\]]+\] TASK-\d{3}\b)/m);
  for (const section of taskSections) {
    const task = section.match(/\bTASK-\d{3}\b/)?.[0];
    if (!task) continue;
    const specs = unique(section.match(/\bREQ-\d{3}\b/g) ?? []);
    const testLine = section.match(/^\s*-\s*test:\s*(.+)$/m)?.[1]?.trim() ?? "";
    if (specs.length === 0) errors.push(`${task} has no requirement mapping`);
    if (!testLine) errors.push(`${task} has no concrete test selector`);
    for (const requirement of specs) {
      mappedRequirements.add(requirement);
      if (!testLine) errors.push(`${requirement} has no concrete test selector via ${task}`);
    }
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
