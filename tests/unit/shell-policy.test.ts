import { describe, expect, test } from "bun:test";
import { parseBash, validateGrammarChecksum } from "../../src/parser/bash-parser";
import { MAX_AST_DEPTH, MAX_INPUT_BYTES, MAX_SEGMENTS } from "../../src/parser/limits";
import { evaluateBuiltinRules } from "../../src/policy/builtin-rules";
import { evaluateDeterministicPolicy } from "../../src/policy/deterministic";

describe("bounded Bash parser", () => {
  test("verifies the bundled grammar checksum before parser use", async () => {
    await expect(validateGrammarChecksum()).resolves.toBeUndefined();
  });

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
    const result = await parseBash("f(){ for x in a; do eval date; exec date; source file; done; }; cat <(date) `date` $(date) <<EOF >out\nhi\nEOF");
    expect(result.features).toMatchObject({
      substitutions: true,
      processSubstitutions: true,
      backticks: true,
      functions: true,
      loops: true,
      heredocs: true,
      redirects: true,
      eval: true,
      exec: true,
      source: true,
    });
  });

  test("returns typed manual failures for parser safety gates", async () => {
    expect(await parseBash("echo\u0000x")).toMatchObject({ ok: false, status: "manual", reason: "control_byte" });
    expect(await parseBash("echo (")).toMatchObject({ ok: false, status: "manual", reason: "parse_error" });
    expect(await parseBash("echo |")).toMatchObject({ ok: false, status: "manual", reason: "missing_node" });
    expect(await parseBash("case x in y) echo y;; esac")).toMatchObject({ ok: false, status: "manual", reason: "unsupported_construct" });
    expect(await parseBash("x".repeat(MAX_INPUT_BYTES + 1))).toMatchObject({ ok: false, status: "manual", reason: "input_too_large" });
  });

  test("enforces the AST depth limit with a genuinely nested command", async () => {
    let source = "echo leaf";
    for (let index = 0; index < 4; index += 1) source = `echo $(${source})`;
    const result = await parseBash(source);
    expect(result).toMatchObject({ ok: false, status: "manual", reason: "limit_exceeded" });
    if (!result.ok) {
      expect(result.limits).toEqual([{ limit: "ast_depth", actual: expect.any(Number), maximum: MAX_AST_DEPTH }]);
      expect(result.features.maxDepth).toBeGreaterThan(MAX_AST_DEPTH);
    }
  });

  test("enforces the segment limit with more than 128 commands", async () => {
    const result = await parseBash(Array.from({ length: MAX_SEGMENTS + 1 }, () => "true").join(";"));
    expect(result).toMatchObject({ ok: false, status: "manual", reason: "limit_exceeded" });
    if (!result.ok) {
      expect(result.limits).toEqual([{ limit: "segments", actual: MAX_SEGMENTS + 1, maximum: MAX_SEGMENTS }]);
      expect(result.features.segmentCount).toBe(MAX_SEGMENTS + 1);
    }
  });

  test("marks grammar constructs without a complete risk summary unsupported", async () => {
    for (const source of ["[[ -f file ]]", "! echo hi", "if true; then echo hi; fi", "((x++))", "coproc worker", "select x in a; do echo $x; done"]) {
      const result = await parseBash(source);
      expect(result).toMatchObject({ ok: false, status: "manual", reason: "unsupported_construct" });
    }
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

  test("does not confuse ordinary flags or printf escapes with execution or paths", async () => {
    for (const command of ["wc -c LICENSE", "printf '%s\\n' hello", "realpath README.md"]) {
      expect((await evaluateDeterministicPolicy(command)).status).toBe("model_review");
    }
  });

  test("retains only bounded path classes after metadata validation", async () => {
    expect((await evaluateDeterministicPolicy("pwd")).pathClasses).toEqual(["none"]);
    expect((await evaluateDeterministicPolicy("cat README.md")).pathClasses).toEqual(["project"]);
  });

  test("hard blocks parser, privacy, interpreter, package, unknown, and dynamic cases", async () => {
    for (const command of [
      "echo (",
      "cat .env",
      "python -c pass",
      "npm run build",
      "unknown-smart-approve-command",
      "echo $(date)",
      "echo ok | unknown-smart-approve-command",
      "npm install",
    ]) {
      expect((await evaluateDeterministicPolicy(command)).status).toBe("manual");
    }
  });

  test("hard blocks commands whose visible effect is mutating", async () => {
    for (const command of ["rm -f README.md", "git reset --hard", "git push --force", "printf x > README.md", "tee README.md", "find src -delete"]) {
      const result = await evaluateDeterministicPolicy(command);
      expect(result.status).toBe("manual");
      expect(result.reasonCodes).toContain("dangerous_command");
    }
  });

  test("keeps less on the deterministic manual path because it permits execution escapes", async () => {
    for (const command of ["less README.md", "cat README.md | less", "command less README.md", "env less README.md"]) {
      const result = await evaluateDeterministicPolicy(command);
      expect(result.status).toBe("manual");
      if (command.startsWith("less") || command.includes("| less")) expect(result.reasonCodes).toContain("dangerous_command");
    }
  });

  test("user model-review rules cannot widen parser or privacy hard blocks", async () => {
    expect((await evaluateDeterministicPolicy("echo (", {
      config: { policy: { rules: [{ pattern: "echo", action: "model_review" }] } },
    })).status).toBe("manual");
    expect((await evaluateDeterministicPolicy("cat .env", {
      config: { policy: { rules: [{ pattern: ".env", action: "model_review" }] } },
    })).status).toBe("manual");
  });

  test("path identity uses metadata only and fails closed", async () => {
    const uid = typeof process.getuid === "function" ? process.getuid() : -1;
    const metadata = {
      lstat: async (path: string) => ({ uid, isSymbolicLink: () => path.endsWith("link") }),
      realpath: async (path: string) => path,
    };
    expect((await evaluateDeterministicPolicy("cat owned.txt", {
      pathIdentity: { cwd: "/owned", ownedRoot: "/owned", ...metadata },
    })).status).toBe("model_review");
    expect((await evaluateDeterministicPolicy("cat link", {
      pathIdentity: { cwd: "/owned", ownedRoot: "/owned", ...metadata },
    })).status).toBe("manual");
    expect((await evaluateDeterministicPolicy("cat ../outside", {
      pathIdentity: { cwd: "/owned", ownedRoot: "/owned", ...metadata },
    })).status).toBe("manual");
    expect((await evaluateDeterministicPolicy("echo /", {
      pathIdentity: { cwd: "/owned", ownedRoot: "/owned", ...metadata },
    })).status).toBe("manual");
  });

  // A file-oriented executable used to force every non-flag operand through the
  // path check, so `sed -n '1,5p' notes.txt` failed on its range expression and
  // never reached the reviewer. On real usage that pattern alone accounted for
  // the largest single block of manual verdicts.
  const identityFixture = () => {
    const uid = typeof process.getuid === "function" ? process.getuid() : -1;
    // Only these exist. Every other token throws, which is how the real lstat
    // answers for a sed range, a grep pattern, or a find name filter.
    const present = new Set(["/owned", "/owned/notes.txt", "/owned/src"]);
    const metadata = {
      lstat: async (path: string) => {
        if (!present.has(path)) throw new Error("ENOENT");
        return { uid, isSymbolicLink: () => false };
      },
      realpath: async (path: string) => {
        if (!present.has(path)) throw new Error("ENOENT");
        return path;
      },
    };
    return async (command: string) => (await evaluateDeterministicPolicy(command, {
      pathIdentity: { cwd: "/owned", ownedRoot: "/owned", ...metadata },
    })).status;
  };

  test("a script, pattern, or flag value is not checked as a path operand", async () => {
    const route = identityFixture();
    expect(await route("sed -n '1,5p' notes.txt")).toBe("model_review");
    expect(await route("grep -n export notes.txt")).toBe("model_review");
    expect(await route("tail -n 50 notes.txt")).toBe("model_review");
    expect(await route("head -n 20 notes.txt")).toBe("model_review");
    expect(await route("sort -k 2 notes.txt")).toBe("model_review");
    expect(await route("cut -d , -f 1 notes.txt")).toBe("model_review");
    expect(await route("uniq -f 2 notes.txt")).toBe("model_review");
  });

  test("a name filter no longer decides find, which its own gate still holds", async () => {
    const uid = typeof process.getuid === "function" ? process.getuid() : -1;
    const metadata = {
      lstat: async (path: string) => {
        if (path !== "/owned" && path !== "/owned/src") throw new Error("ENOENT");
        return { uid, isSymbolicLink: () => false };
      },
      realpath: async (path: string) => path,
    };
    // find stays manual because it can execute, but the reason must now be that
    // gate rather than a name filter mistaken for an unresolvable path.
    const result = await evaluateDeterministicPolicy("find src -name '*.ts' -print", {
      pathIdentity: { cwd: "/owned", ownedRoot: "/owned", ...metadata },
    });
    expect(result.status).toBe("manual");
    expect(result.reasonCodes).toEqual(["manual_executable"]);
  });

  // `executables` is built by splitting the command, while the segment counter
  // advances on separator tokens from a different regex. If the two ever
  // disagree, a later segment is judged with an earlier utility's flag tables.
  test("each pipeline segment is judged with its own utility", async () => {
    const route = identityFixture();
    for (const separator of ["|", "&&", ";", "||"]) {
      expect(await route(`cat notes.txt ${separator} sed -n '1,5p' notes.txt`)).toBe("model_review");
      expect(await route(`cat notes.txt ${separator} sed -n '1,5p' missing.txt`)).toBe("manual");
    }
    expect(await route("sed -n '1,5p' notes.txt | cat")).toBe("model_review");
    expect(await route("cat notes.txt | grep -n export")).toBe("model_review");
  });

  test("a script supplied by a flag leaves the first operand a path again", async () => {
    const route = identityFixture();
    expect(await route("sed -e '1,5p' notes.txt")).toBe("model_review");
    expect(await route("sed -e '1,5p' missing.txt")).toBe("manual");
  });

  test("path-shaped tokens keep their identity check in every operand role", async () => {
    const route = identityFixture();
    // A sed script may itself name a file to write, and a flag whose value is a
    // file is deliberately absent from the value table for exactly this reason.
    expect(await route("sed -n 'w /tmp/out' notes.txt")).toBe("manual");
    expect(await route("sed -f ../outside.sed notes.txt")).toBe("manual");
    expect(await route("grep -f ../patterns.txt notes.txt")).toBe("manual");
    expect(await route("sort -o /tmp/out notes.txt")).toBe("manual");
    // An unverifiable write target stays manual whether or not it is new.
    expect(await route("tee fresh.txt")).toBe("manual");
    expect(await route("sed -n '1,5p' missing.txt")).toBe("manual");
  });

  test("disabled model leaves every request manual", async () => {
    const result = await evaluateDeterministicPolicy("echo hello", {
      config: { model: { enabled: false }, policy: { rules: [] } },
    });
    expect(result.status).toBe("manual");
    expect(result.reasonCodes).toContain("model_disabled");
  });

  test("routes exactly six executable identities to closed replan when enabled", async () => {
    for (const command of ["awk", "xargs", "find", "env", "command", "cmp", "/usr/bin/awk", "'awk'", "echo ok | awk"]) {
      const result = await evaluateDeterministicPolicy(command, { config: { replan: { enabled: true }, model: { enabled: true } } });
      expect(result.status as string, command).toBe("replan");
      expect(result.decision, command).toBe("replan");
      expect(result.reasonCodes).toEqual(["replan"]);
    }
  });

  test("routes exactly six prompt-manual identities away from model review by default", async () => {
    for (const command of ["awk", "xargs", "find", "env", "command", "cmp", "/usr/bin/awk", "'cmp'"]) {
      const result = await evaluateDeterministicPolicy(command, { config: { model: { enabled: true } } });
      expect(result.status, command).toBe("manual");
      expect(result.reasonCodes, command).toEqual(["manual_executable"]);
    }
    for (const command of ["awk '{print $1}'", "xargs rm", "find . -type f", "env FOO=bar echo ok", "command printf ok", "cmp file-a file-b"]) {
      const result = await evaluateDeterministicPolicy(command, { config: { model: { enabled: true } } });
      expect(result.status, command).toBe("manual");
    }
    for (const command of ["echo awk", "awkish", "printf cmp", "findings", "envoy"]) {
      const result = await evaluateDeterministicPolicy(command, { config: { model: { enabled: true } } });
      expect(result.reasonCodes, command).not.toContain("manual_executable");
    }
  });

  test("normalizes wrappers without searching arguments and preserves disabled/manual dominance", async () => {
    for (const command of ["awkish", "echo awk", "echo cmp", "echo 'awk; cmp'"]) {
      const enabled = await evaluateDeterministicPolicy(command, { config: { replan: { enabled: true }, model: { enabled: true } } });
      expect(enabled.status, command).not.toBe("replan");
    }
    for (const command of ["env -i", "env -S awk", "command -p ls", "command env"]) {
      const enabled = await evaluateDeterministicPolicy(command, { config: { replan: { enabled: true }, model: { enabled: true } } });
      expect(enabled.status as string, command).toBe("replan");
    }
    expect((await evaluateDeterministicPolicy("awk", { config: { replan: { enabled: false }, model: { enabled: true } } })).status).not.toBe("replan");
    expect((await evaluateDeterministicPolicy("find -delete", { config: { replan: { enabled: true }, model: { enabled: true } } })).status).toBe("manual");
    expect((await evaluateDeterministicPolicy("awk", { config: { replan: { enabled: true }, model: { enabled: false } } })).status as string).toBe("replan");
  });

  test("applies safety rules to the command behind env and command wrappers", async () => {
    for (const command of ["env -i rm", "command env rm", "env python", "command unknown-smart-approve-command"]) {
      const result = await evaluateDeterministicPolicy(command, { config: { replan: { enabled: true }, model: { enabled: true } } });
      expect(result.status, command).toBe("manual");
      expect(result.reasonCodes.length, command).toBeGreaterThan(0);
    }
    for (const command of ["env -i rm", "command env rm"]) {
      const parsed = await parseBash(command);
      expect(parsed.ok, command).toBe(true);
      if (parsed.ok) expect(evaluateBuiltinRules({ command, features: parsed.features }), command).toContain("dangerous_command");
    }
  });

  test("retains path classes on a deterministic user-rule manual result", async () => {
    const result = await evaluateDeterministicPolicy("cat README.md", {
      config: { policy: { rules: [{ pattern: "README.md", action: "manual" }] } },
    });
    expect(result.status).toBe("manual");
    expect(result.reasonCodes).toEqual(["user_rule"]);
    expect(result.pathClasses).toEqual(["project"]);
  });

  test("keeps every broad manual reason dominant over a replan identity", async () => {
    const cases = [
      "awk .env",
      "awk > output.txt",
      "python -c awk",
      "npm exec awk",
      "echo $(awk)",
      "awk | unknown-smart-approve-command",
    ];
    for (const command of cases) {
      const result = await evaluateDeterministicPolicy(command, { config: { replan: { enabled: true }, model: { enabled: true } } });
      expect(result.status as string, command).toBe("manual");
    }
    expect((await evaluateDeterministicPolicy("awk", {
      config: { replan: { enabled: true }, model: { enabled: true }, policy: { rules: [{ pattern: "awk", action: "manual" }] } },
    })).status as string).toBe("manual");
  });
});
