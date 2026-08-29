/**
 * Tests for the aggregate-only parser-history analyzer.
 */
import { afterAll, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  analyzeParserHistory,
  checkBashSyntaxWithBashN,
  parseArgs,
  type AnalyzeParserHistoryOptions,
} from "../../scripts/qualification/analyze-parser-history";
import type { BashParseResult } from "../../src/parser/bash-parser";
import type { LocalExecution } from "../../scripts/qualification/harvest-usage";

const scratch: string[] = [];
afterAll(() => { for (const path of scratch) rmSync(path, { recursive: true, force: true }); });

function tempHome(): string {
  const path = mkdtempSync(join(tmpdir(), "parser-history-test-"));
  scratch.push(path);
  return path;
}

describe("analyzeParserHistory cutoff and stable aggregation", () => {
  test("produces stable aggregate counts over a synthetic mixed Claude/Codex home with explicit cutoff", async () => {
    const home = tempHome();

    // 1. Synthetic Claude session
    const claudeDir = join(home, ".claude/projects/test-proj");
    mkdirSync(claudeDir, { recursive: true });
    const claudeLines = [
      JSON.stringify({
        timestamp: "2026-08-20T10:00:00.000Z",
        cwd: "/tmp/proj",
        message: { content: [{ type: "tool_use", name: "Bash", input: { command: "git status --short" } }] },
      }),
      JSON.stringify({
        timestamp: "2026-08-20T12:00:00.000Z",
        cwd: "/tmp/proj",
        message: { content: [{ type: "tool_use", name: "Bash", input: { command: "pwd && ls" } }] },
      }),
      // After cutoff
      JSON.stringify({
        timestamp: "2026-08-22T10:00:00.000Z",
        cwd: "/tmp/proj",
        message: { content: [{ type: "tool_use", name: "Bash", input: { command: "git diff" } }] },
      }),
      // Invalid timestamp
      JSON.stringify({
        timestamp: "not-a-valid-date",
        cwd: "/tmp/proj",
        message: { content: [{ type: "tool_use", name: "Bash", input: { command: "cat README.md" } }] },
      }),
      // Missing timestamp
      JSON.stringify({
        cwd: "/tmp/proj",
        message: { content: [{ type: "tool_use", name: "Bash", input: { command: "ls -la" } }] },
      }),
    ];
    writeFileSync(join(claudeDir, "session.jsonl"), `${claudeLines.join("\n")}\n`);

    // 2. Synthetic Codex sqlite
    const codexDir = join(home, ".codex");
    mkdirSync(codexDir, { recursive: true });
    const db = new Database(join(codexDir, "thread_history_1.sqlite"));
    db.run(`CREATE TABLE thread_items (
      thread_id TEXT, turn_id TEXT, item_id TEXT, rollout_ordinal INTEGER,
      created_at_ms INTEGER, item_json TEXT, item_type TEXT
    )`);
    const t1 = new Date("2026-08-20T11:00:00.000Z").getTime();
    const t2 = new Date("2026-08-20T13:00:00.000Z").getTime();
    const tAfter = new Date("2026-08-23T10:00:00.000Z").getTime();
    db.run(
      `INSERT INTO thread_items (thread_id, turn_id, item_id, rollout_ordinal, created_at_ms, item_json, item_type) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ["th1", "tu1", "it1", 1, t1, JSON.stringify({ command: `/bin/zsh -lc 'git status --short'`, cwd: "/tmp/proj" }), "commandExecution"],
    );
    db.run(
      `INSERT INTO thread_items (thread_id, turn_id, item_id, rollout_ordinal, created_at_ms, item_json, item_type) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ["th1", "tu1", "it2", 2, t2, JSON.stringify({ command: `/bin/zsh -lc "echo \\"hello\\""`, cwd: "/tmp/proj" }), "commandExecution"],
    );
    db.run(
      `INSERT INTO thread_items (thread_id, turn_id, item_id, rollout_ordinal, created_at_ms, item_json, item_type) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ["th1", "tu1", "it3", 3, tAfter, JSON.stringify({ command: `/bin/zsh -lc 'git log'`, cwd: "/tmp/proj" }), "commandExecution"],
    );
    db.close();

    const cutoff = "2026-08-21T00:00:00.000Z";
    const report1 = await analyzeParserHistory({ home, cutoff });
    const report2 = await analyzeParserHistory({ home, cutoff });

    expect(report1).toEqual(report2);
    expect(report1.cutoff).toBe(cutoff);
    expect(report1.totalExecutions).toBe(4); // 2 from Claude + 2 from Codex
    expect(report1.distinctCommands).toBe(3); // 'git status --short', 'pwd && ls', 'echo "hello"'
    expect(report1.parsedCleanly).toBe(3);
    expect(report1.targetFailures).toBe(0);
    expect(report1.parseFailures).toBe(0);
  });
});

describe("privacy and output redaction", () => {
  test("analyzer output contains none of the synthetic commands, operands, cwd paths, or hashes and progress is observable", async () => {
    let progressCalls = 0;
    const executions: LocalExecution[] = [
      { command: "cat /private/secret/path/credentials.json", cwd: "/sensitive/cwd/path", recordedAt: "2026-08-20T10:00:00.000Z" },
      { command: "export API_KEY_SECRET_12345678901234567890=val", cwd: "/sensitive/cwd/path", recordedAt: "2026-08-20T10:01:00.000Z" },
    ];

    const result = await analyzeParserHistory({
      cutoff: "2026-08-21T00:00:00.000Z",
      executions,
      onProgress: (_p, _t) => { progressCalls++; },
    });

    expect(progressCalls).toBe(2);

    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("credentials");
    expect(serialized).not.toContain("API_KEY");
    expect(serialized).not.toContain("sensitive");
    expect(serialized).not.toContain("/private/secret");
    expect(serialized).not.toContain("credentials.json");
  });
});

describe("classification by failure reason and retry evidence fixtures", () => {
  test("classifies syntax errors, limit violations, unsupported constructs, and divergence", async () => {
    // 1. echo ( -> parse_error, bash-invalid
    // 2. echo | -> missing_node, bash-invalid
    // 3. four-level nested substitution -> limit_exceeded, ast_depth, alreadyManualUnderBuiltinRules
    // 4. 129 true commands -> limit_exceeded, segments, notManualUnderBuiltinRules
    // 5. unsupported constructs -> unsupported_construct

    let fourLevelNested = "echo leaf";
    for (let index = 0; index < 4; index += 1) {
      fourLevelNested = `echo $(${fourLevelNested})`;
    }

    const maxSegmentsCommand = Array.from({ length: 129 }, () => "true").join(";");

    const executions: LocalExecution[] = [
      { command: "echo (", recordedAt: "2026-08-20T00:00:00.000Z" },
      { command: "echo |", recordedAt: "2026-08-20T00:00:00.000Z" },
      { command: fourLevelNested, recordedAt: "2026-08-20T00:00:00.000Z" },
      { command: maxSegmentsCommand, recordedAt: "2026-08-20T00:00:00.000Z" },
      { command: "case x in y) echo y;; esac", recordedAt: "2026-08-20T00:00:00.000Z" },
      { command: "[[ -f file ]]", recordedAt: "2026-08-20T00:00:00.000Z" },
    ];

    const result = await analyzeParserHistory({
      cutoff: "2026-08-21T00:00:00.000Z",
      executions,
    });

    expect(result.distinctCommands).toBe(6);
    expect(result.parsedCleanly).toBe(0);
    expect(result.targetFailures).toBe(4);
    expect(result.parseFailures).toBe(6);

    // Failures by reason
    expect(result.failuresByReason["parse_error"]).toBe(1);
    expect(result.failuresByReason["missing_node"]).toBe(1);
    expect(result.failuresByReason["limit_exceeded"]).toBe(2);
    expect(result.failuresByReason["unsupported_construct"]).toBe(2);

    // Syntax validation
    expect(result.bashInvalidSyntax).toBe(2); // echo ( and echo |
    expect(result.divergence).toBe(0);

    // Limit violations
    expect(result.limitViolations.astDepth).toBe(1);
    expect(result.limitViolations.segments).toBe(1);
    expect(result.limitViolations.alreadyManualUnderBuiltinRules).toBe(1); // fourLevelNested has substitutions
    expect(result.limitViolations.notManualUnderBuiltinRules).toBe(1); // 129 true has no builtin manual rule

    // Unsupported constructs
    expect(result.unsupportedConstructs.total).toBe(2);
    expect(result.unsupportedConstructs.byConstruct["case_statement"]).toBe(1);
    expect(result.unsupportedConstructs.byConstruct["test_command"]).toBe(1);
  });

  test("injected parser result aggregates divergence when tree-sitter fails on bash-valid syntax", async () => {
    const injectedParseBash = async (command: string): Promise<BashParseResult> => {
      if (command === "echo valid_syntax") {
        return {
          ok: false,
          status: "manual",
          reason: "parse_error",
          message: "synthetic parser failure",
          features: {
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
            segmentCount: 1,
            maxDepth: 1,
            unsupported: [],
          },
        };
      }
      return {
        ok: true,
        status: "model_review",
        tree: {} as any,
        rootNode: {} as any,
        features: {
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
          segmentCount: 1,
          maxDepth: 1,
          unsupported: [],
        },
      };
    };

    const executions: LocalExecution[] = [
      { command: "echo valid_syntax", recordedAt: "2026-08-20T00:00:00.000Z" },
    ];

    const result = await analyzeParserHistory({
      cutoff: "2026-08-21T00:00:00.000Z",
      executions,
      parseBash: injectedParseBash,
    });

    expect(result.parseFailures).toBe(1);
    expect(result.failuresByReason["parse_error"]).toBe(1);
    expect(result.divergence).toBe(1);
    expect(result.bashInvalidSyntax).toBe(0);
  });

  test("counts reproducible Bash-valid tree-sitter grammar gaps as divergence", async () => {
    const executions: LocalExecution[] = [
      { command: "cat 2<<<x", recordedAt: "2026-08-20T00:00:00.000Z" },
      { command: 'echo "${(x)x:-}"', recordedAt: "2026-08-20T00:00:00.000Z" },
      { command: 'x=("${(x)"$(echo x)"}")', recordedAt: "2026-08-20T00:00:00.000Z" },
    ];

    for (const { command } of executions) {
      expect(checkBashSyntaxWithBashN(command)).toBe(true);
    }

    const result = await analyzeParserHistory({
      cutoff: "2026-08-21T00:00:00.000Z",
      executions,
    });

    expect(result.failuresByReason["parse_error"]).toBe(2);
    expect(result.failuresByReason["missing_node"]).toBe(1);
    expect(result.targetFailures).toBe(3);
    expect(result.bashInvalidSyntax).toBe(0);
    expect(result.divergence).toBe(3);
  });
});

describe("CLI argument and cutoff validation", () => {
  test("parseArgs extracts cutoff and home", () => {
    expect(parseArgs(["--cutoff", "2026-08-20T00:00:00.000Z"])).toEqual({
      cutoff: "2026-08-20T00:00:00.000Z",
      home: undefined,
    });
    expect(parseArgs(["--cutoff=2026-08-20T00:00:00.000Z", "--home=/tmp/home"])).toEqual({
      cutoff: "2026-08-20T00:00:00.000Z",
      home: "/tmp/home",
    });
  });

  test("throws error when cutoff is missing or invalid", async () => {
    await expect(analyzeParserHistory({ cutoff: "" })).rejects.toThrow("Mandatory CLI ISO cutoff is required");
    await expect(analyzeParserHistory({ cutoff: "invalid-iso-string" })).rejects.toThrow("Invalid cutoff ISO timestamp");
  });

  test("checkBashSyntaxWithBashN correctly validates syntax", () => {
    expect(checkBashSyntaxWithBashN("echo hello")).toBe(true);
    expect(checkBashSyntaxWithBashN("git status --short && git diff")).toBe(true);
    expect(checkBashSyntaxWithBashN("echo (")).toBe(false);
    expect(checkBashSyntaxWithBashN("echo |")).toBe(false);
  });
});
