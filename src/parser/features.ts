import type { Node } from "web-tree-sitter";

export interface BashFeatures {
  pipeline: boolean;
  redirects: boolean;
  substitutions: boolean;
  processSubstitutions: boolean;
  backticks: boolean;
  functions: boolean;
  loops: boolean;
  heredocs: boolean;
  unresolvedExpansions: boolean;
  eval: boolean;
  exec: boolean;
  source: boolean;
  environmentAssignments: boolean;
  segmentCount: number;
  maxDepth: number;
  unsupported: string[];
}

export function emptyFeatures(): BashFeatures {
  return {
    pipeline: false,
    redirects: false,
    substitutions: false,
    processSubstitutions: false,
    backticks: false,
    functions: false,
    loops: false,
    heredocs: false,
    unresolvedExpansions: false,
    eval: false,
    exec: false,
    source: false,
    environmentAssignments: false,
    segmentCount: 0,
    maxDepth: 0,
    unsupported: [],
  };
}

const loopNodes = new Set(["for_statement", "while_statement", "until_statement", "do_group"]);
const unsupportedNodes = new Set([
  "case_statement",
  "c_style_for_statement",
  "arithmetic_command",
  "coprocess",
  "subshell",
]);

/** Extracts facts only; it never produces an approval decision. */
export function extractFeatures(root: Node, source: string): BashFeatures {
  const features = emptyFeatures();
  let commandCount = 0;
  const walk = (node: Node, depth: number): void => {
    features.maxDepth = Math.max(features.maxDepth, depth);
    const type = node.type;
    if (type === "command") commandCount += 1;
    if (type === "pipeline") features.pipeline = true;
    if (["file_redirect", "heredoc_redirect", "herestring_redirect", "redirect"].includes(type)) features.redirects = true;
    if (type === "command_substitution") features.substitutions = true;
    if (type === "process_substitution") features.processSubstitutions = true;
    if (type === "heredoc_redirect" || type === "heredoc_start" || type === "heredoc_body" || type === "heredoc_end") features.heredocs = true;
    if (type === "function_definition") features.functions = true;
    if (loopNodes.has(type)) features.loops = true;
    if (["expansion", "simple_expansion", "arithmetic_expansion"].includes(type)) features.unresolvedExpansions = true;
    if (type === "variable_assignment") features.environmentAssignments = true;
    if (unsupportedNodes.has(type) && !features.unsupported.includes(type)) features.unsupported.push(type);
    if (node.namedChildren) for (const child of node.namedChildren) walk(child, depth + 1);
  };
  walk(root, 0);
  features.segmentCount = commandCount || root.namedChildCount;
  features.backticks = /`(?:\\.|[^`])*`/s.test(source);

  for (const command of findNodes(root, "command")) {
    const name = command.childForFieldName("name");
    const commandName = name?.text.trim().replace(/^['"]|['"]$/g, "");
    if (commandName === "eval") features.eval = true;
    if (commandName === "exec") features.exec = true;
    if (commandName === "source" || commandName === ".") features.source = true;
  }
  return features;
}

function findNodes(root: Node, type: string): Node[] {
  const result: Node[] = [];
  const walk = (node: Node): void => {
    if (node.type === type) result.push(node);
    for (const child of node.namedChildren) walk(child);
  };
  walk(root);
  return result;
}
