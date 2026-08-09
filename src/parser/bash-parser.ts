import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { Language, Parser, type Node, type Tree } from "web-tree-sitter";
import { extractFeatures, type BashFeatures } from "./features";
import { MAX_AST_DEPTH, MAX_INPUT_BYTES, MAX_SEGMENTS, type LimitViolation } from "./limits";

const grammarPath = fileURLToPath(new URL("../assets/tree-sitter-bash.wasm", import.meta.url));
const checksumPath = fileURLToPath(new URL("../assets/tree-sitter-bash.sha256", import.meta.url));
const parserWasmPath = fileURLToPath(new URL("../../node_modules/web-tree-sitter/web-tree-sitter.wasm", import.meta.url));

export type ParseFailureReason = "input_too_large" | "control_byte" | "grammar_checksum" | "parse_error" | "missing_node" | "limit_exceeded" | "unsupported_construct" | "initialization_error";
export interface BashParseSuccess { ok: true; status: "model_review"; tree: Tree; rootNode: Node; features: BashFeatures; }
export interface BashParseFailure { ok: false; status: "manual"; reason: ParseFailureReason; message: string; features: BashFeatures; limits?: LimitViolation[]; }
export type BashParseResult = BashParseSuccess | BashParseFailure;

let parserPromise: Promise<Parser> | undefined;
let checksumPromise: Promise<void> | undefined;

export async function validateGrammarChecksum(): Promise<void> {
  checksumPromise ??= (async () => {
    const [wasm, expectedText] = await Promise.all([readFile(grammarPath), readFile(checksumPath, "utf8")]);
    const expected = expectedText.trim().split(/\s+/)[0]?.toLowerCase();
    const actual = createHash("sha256").update(wasm).digest("hex");
    if (!expected || expected !== actual) throw new Error(`Bash grammar checksum mismatch: expected ${expected ?? "missing"}, got ${actual}`);
  })();
  return checksumPromise;
}

async function getParser(): Promise<Parser> {
  if (!parserPromise) {
    parserPromise = (async () => {
      await validateGrammarChecksum();
      await Parser.init({ locateFile: () => parserWasmPath });
      const parser = new Parser();
      parser.setLanguage(await Language.load(grammarPath));
      return parser;
    })();
  }
  return parserPromise;
}

export async function parseBash(source: string): Promise<BashParseResult> {
  const bytes = Buffer.byteLength(source, "utf8");
  const blank = extractEmptyFeatures(source);
  if (bytes > MAX_INPUT_BYTES) return failure("input_too_large", `Input is ${bytes} bytes; limit is ${MAX_INPUT_BYTES}.`, blank, [{ limit: "input_bytes", actual: bytes, maximum: MAX_INPUT_BYTES }]);
  if (hasControlByte(source)) return failure("control_byte", "Control bytes are not valid shell input.", blank);
  let tree: Tree;
  try {
    const parsed = (await getParser()).parse(source);
    if (!parsed) return failure("parse_error", "Bash parser returned no syntax tree.", blank);
    tree = parsed;
  }
  catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return failure(message.includes("checksum mismatch") ? "grammar_checksum" : "initialization_error", message, blank);
  }
  const root = tree.rootNode;
  const features = extractFeatures(root, source);
  const limits: LimitViolation[] = [];
  if (features.maxDepth > MAX_AST_DEPTH) limits.push({ limit: "ast_depth", actual: features.maxDepth, maximum: MAX_AST_DEPTH });
  if (features.segmentCount > MAX_SEGMENTS) limits.push({ limit: "segments", actual: features.segmentCount, maximum: MAX_SEGMENTS });
  if (hasMissingNode(root)) return failure("missing_node", "Bash grammar inserted a missing node.", features);
  if (root.hasError) return failure("parse_error", "Bash grammar reported a parse error.", features);
  if (limits.length) return failure("limit_exceeded", "Parser limits exceeded.", features, limits);
  if (features.unsupported.length) return failure("unsupported_construct", `Unsupported Bash construct: ${features.unsupported.join(", ")}.`, features);
  return { ok: true, status: "model_review", tree, rootNode: root, features };
}

export const parseShellCommand = parseBash;
export const parseCommand = parseBash;

function failure(reason: ParseFailureReason, message: string, features: BashFeatures, limits?: LimitViolation[]): BashParseFailure { return { ok: false, status: "manual", reason, message, features, ...(limits ? { limits } : {}) }; }
function extractEmptyFeatures(_source: string): BashFeatures { return { pipeline: false, redirects: false, substitutions: false, processSubstitutions: false, backticks: false, functions: false, loops: false, heredocs: false, unresolvedExpansions: false, eval: false, exec: false, source: false, environmentAssignments: false, segmentCount: 0, maxDepth: 0, unsupported: [] }; }
function hasControlByte(source: string): boolean { for (const char of source) { const code = char.codePointAt(0) ?? 0; if ((code < 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) || code === 0x7f) return true; } return false; }
function hasMissingNode(root: Node): boolean { let missing = false; const walk = (node: Node): void => { if (node.isMissing) missing = true; for (const child of node.children) walk(child); }; walk(root); return missing; }
