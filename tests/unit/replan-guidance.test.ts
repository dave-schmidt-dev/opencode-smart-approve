import { describe, expect, test } from "bun:test";
import { REPLAN_EXECUTABLES, findReplanExecutableIdentity } from "../../src/policy/executable-identity";
import { REPLAN_DECOMPOSITION_GUIDANCE, REPLAN_GUIDANCE_CATALOG, REPLAN_GUIDANCE_PREAMBLE } from "../../src/replan/guidance";

describe("static replan guidance", () => {
  test("contains exactly the six policy-owned executable identities", () => {
    expect(Object.keys(REPLAN_GUIDANCE_CATALOG)).toEqual([...REPLAN_EXECUTABLES]);
    expect(Object.keys(REPLAN_GUIDANCE_CATALOG)).toHaveLength(6);
  });

  test("each identity has complete static safety guidance", () => {
    for (const identity of REPLAN_EXECUTABLES) {
      const entry = REPLAN_GUIDANCE_CATALOG[identity];
      expect(entry.unsafeProperty.length, identity).toBeGreaterThan(0);
      expect(entry.nativeAlternative.length, identity).toBeGreaterThan(0);
      expect(entry.shellFallbackProhibition.length, identity).toBeGreaterThan(0);
      expect(entry.nativePromptStopInstruction.length, identity).toBeGreaterThan(0);
      expect(entry.feedback, identity).toContain("Your next action MUST be a native tool call, not prose");
      expect(entry.feedback, identity).toContain("Bash");
      expect(entry.feedback, identity).toContain(entry.unsafeProperty);
      expect(entry.feedback, identity).toContain(entry.nativeAlternative);
      expect(entry.feedback, identity).toContain(entry.shellFallbackProhibition);
      expect(entry.feedback, identity).toContain(entry.nativePromptStopInstruction);
      expect(entry.feedback, identity).toContain("native Bash permission prompt");
      expect(entry.feedback, identity).toContain("waits for a human decision");
      expect(entry.feedback, identity).toContain("stop and explain");
      expect(entry.feedback, identity).toContain(identity);
    }
  });

  test("each identity names a bounded native starting sequence", () => {
    const starts = {
      awk: "glob for known project paths, then read or grep",
      xargs: "glob for a bounded project list, then call read or grep",
      find: "glob scoped to the project, then inspect returned paths with read or grep",
      env: "read on a specifically named project configuration file",
      command: "specific native tool needed, such as read, glob, or grep",
      cmp: "read on the two specifically known project files, then compare",
    } as const;
    for (const identity of REPLAN_EXECUTABLES) expect(REPLAN_GUIDANCE_CATALOG[identity].feedback).toContain(starts[identity]);
  });

  test("includes harness-neutral sequential decomposition guidance", () => {
    expect(REPLAN_DECOMPOSITION_GUIDANCE).toContain("read-only work");
    expect(REPLAN_DECOMPOSITION_GUIDANCE).toContain("sequential native tool calls");
    expect(REPLAN_DECOMPOSITION_GUIDANCE).toContain("bounded text returned by each call into the next");
    expect(REPLAN_DECOMPOSITION_GUIDANCE).toContain("separate Bash commands, wrappers, substitutions, or loops");
    expect(REPLAN_DECOMPOSITION_GUIDANCE).toContain("native tool cannot cover a step");
    expect(REPLAN_DECOMPOSITION_GUIDANCE).toContain("native permission prompt");
    expect(REPLAN_DECOMPOSITION_GUIDANCE).not.toContain("OpenCode");
    expect(REPLAN_GUIDANCE_PREAMBLE).toContain(REPLAN_DECOMPOSITION_GUIDANCE);
    expect(REPLAN_GUIDANCE_PREAMBLE).not.toContain("OpenCode");
    for (const entry of Object.values(REPLAN_GUIDANCE_CATALOG)) expect(entry.feedback).not.toContain("OpenCode");
  });

  test("identity lookup is typed, finite, and does not search arguments", () => {
    expect(findReplanExecutableIdentity("/usr/bin/awk")).toBe("awk");
    expect(findReplanExecutableIdentity("echo awk")).toBeUndefined();
    expect(findReplanExecutableIdentity("echo ok | cmp")).toBe("cmp");
    expect(findReplanExecutableIdentity("unknown-smart-approve-command")).toBeUndefined();
  });

  test("catalog feedback has no dynamic command or context placeholders", () => {
    const feedback = Object.values(REPLAN_GUIDANCE_CATALOG).map((entry) => entry.feedback).join("\n");
    expect(feedback).not.toContain("${");
    expect(feedback).not.toContain("CANARY_SECRET");
    expect(feedback).not.toContain("/tmp/");
  });
});
