import { describe, expect, test } from "bun:test";
import { parseBash } from "../../src/parser/bash-parser";
import { MAX_AST_DEPTH, MAX_INPUT_BYTES, MAX_SEGMENTS } from "../../src/parser/limits";
import { evaluateDeterministicPolicy } from "../../src/policy/deterministic";

describe("bounded Bash parser", () => {
  test("parses ordinary commands and extracts explicit features", async () => {
    const result = await parseBash("FOO=bar printf '%s' \"${USER}\" | tee out");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.status).toBe("model_review");
      expect(result.features.pipeline).toBe(true);
      expect(result.features.redirects).toBe(false);
      expect(result.features.environmentAssignments).toBe(true);
      expect(result.features.unresolvedExpansions).toBe(true);
    }
  });

  test("detects substitutions, backticks, functions, loops, heredocs, and execution escapes", async () => {
    const result = await parseBash("f(){ for x in a; do eval echo `date` $(date); done; }; cat <<EOF\nhi\nEOF");
    expect(result.features).toMatchObject({ substitutions: true, backticks: true, functions: true, loops: true, heredocs: true, eval: true });
  });

  test("fails closed for control bytes, syntax errors, unsupported constructs, and bounds", async () => {
    expect((await parseBash("echo\u0000x")).status).toBe("manual");
    expect((await parseBash("echo (")).status).toBe("manual");
    expect((await parseBash("case x in y) echo y;; esac")).status).toBe("manual");
    expect((await parseBash("x".repeat(MAX_INPUT_BYTES + 1))).status).toBe("manual");
    expect((await parseBash(Array.from({ length: MAX_SEGMENTS + 1 }, () => "true").join(";"))).status).toBe("manual");
    expect(MAX_AST_DEPTH).toBe(8);
  });
});

describe("deterministic policy", () => {
  test("routes ordinary commands to model review without an approval edge", async () => {
    const result = await evaluateDeterministicPolicy("echo hello");
    expect(["manual", "model_review"]).toContain(result.status);
    expect(result.status).toBe("model_review");
    expect(result.decision).toBe("model_review");
    expect("approve" in result).toBe(false);
  });

  test("hard blocks parser, privacy, interpreter, package, unknown, and dynamic cases", async () => {
    for (const command of [
      "echo (",
      "cat .env",
      "python -c pass",
      "npm run build",
      "unknown-smart-approve-command",
      "echo $(date)",
    ]) {
      expect((await evaluateDeterministicPolicy(command)).status).toBe("manual");
    }
  });

  test("disabled model leaves every request manual", async () => {
    const result = await evaluateDeterministicPolicy("echo hello", {
      config: { model: { enabled: false }, policy: { rules: [] } },
    });
    expect(result.status).toBe("manual");
    expect(result.reasonCodes).toContain("model_disabled");
  });
});
