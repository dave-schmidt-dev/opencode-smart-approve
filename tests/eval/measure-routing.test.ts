/**
 * Tests for the routing measurement.
 *
 * These exist because the first version of this measurement was wrong in a way
 * that produced a plausible number. It evaluated every command from every local
 * project against *this* project's root, so a command that routes perfectly
 * well where it ran was counted as blocked. The rate built on that denominator
 * went into a findings document before anyone noticed. The first test below is
 * the lock on that specific mistake; the rest hold the properties the numbers
 * are quoted with.
 */
import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { summarizeRouting } from "../../scripts/qualification/measure-routing";
import type { LocalExecution } from "../../scripts/qualification/harvest-usage";

const PROJECT_ROOT = realpathSync(resolve(import.meta.dir, "../.."));
const FOREIGN = realpathSync(mkdtempSync(join(realpathSync(tmpdir()), "measure-routing-")));
afterAll(() => rmSync(FOREIGN, { recursive: true, force: true }));

describe("each execution is evaluated against the cwd it actually ran in", () => {
  test("the same command routes in its own root and is held in a foreign one", async () => {
    // Path identity is what separates these two, and it is the exact rule the
    // broken measurement was accidentally applying to every project at once.
    const command = `cat ${join(PROJECT_ROOT, "README.md")}`;
    const own = await summarizeRouting([{ command, cwd: PROJECT_ROOT }]);
    const foreign = await summarizeRouting([{ command, cwd: FOREIGN }]);

    expect(own.evaluated).toBe(1);
    expect(own.routed).toBe(1);
    expect(own.routedPromptAllows).toBe(1);

    expect(foreign.evaluated).toBe(1);
    expect(foreign.routed).toBe(0);
  });

  test("a mixed population is not collapsed onto one root", async () => {
    const command = `cat ${join(PROJECT_ROOT, "README.md")}`;
    const summary = await summarizeRouting([
      { command, cwd: PROJECT_ROOT },
      { command, cwd: FOREIGN },
    ]);
    expect(summary.evaluated).toBe(2);
    expect(summary.routed).toBe(1);
  });
});

describe("executions without a usable cwd are excluded, never defaulted", () => {
  test("an execution the source recorded no cwd for is dropped", async () => {
    const summary = await summarizeRouting([{ command: "git status --short" }]);
    expect(summary.withoutCwd).toBe(1);
    expect(summary.evaluated).toBe(0);
    expect(summary.routed).toBe(0);
  });

  test("a cwd that no longer exists is dropped", async () => {
    const summary = await summarizeRouting(
      [{ command: "git status --short", cwd: "/vanished/project" }],
      { cwdExists: () => false },
    );
    expect(summary.withoutCwd).toBe(1);
    expect(summary.evaluated).toBe(0);
  });
});

describe("the secret screen runs before the policy, and is reported as its own line", () => {
  test("a screened execution is counted, never evaluated, and never routed", async () => {
    const summary = await summarizeRouting([
      { command: "GIT_PAGER=cat git status --short", cwd: PROJECT_ROOT },
      { command: "git status --short", cwd: PROJECT_ROOT },
    ]);
    expect(summary.screened).toBe(1);
    expect(summary.screenedCarryingAssignment).toBe(1);
    expect(summary.screenedCarryingTokenOnly).toBe(0);
    // The screened one is excluded from the denominator the rates use, because
    // the policy never saw it.
    expect(summary.evaluated).toBe(1);
    expect(summary.routed).toBe(1);
  });
});

describe("the subset relation is counted over distinct pairs, not executions", () => {
  test("repeating one command does not multiply the evidence for the relation", async () => {
    const command = `cat ${join(PROJECT_ROOT, "README.md")}`;
    const executions: LocalExecution[] = Array.from({ length: 5 }, () => ({ command, cwd: PROJECT_ROOT }));
    const summary = await summarizeRouting(executions);

    expect(summary.routed).toBe(5);
    // One command in one directory is one observation of the relation, however
    // many times it ran.
    expect(summary.promptAllowedPairs).toBe(1);
    expect(summary.promptAllowedPairsHeldByPolicy).toBe(0);
    expect(summary.distinctCommands).toBe(1);
    expect(summary.distinctRunOnce).toBe(0);
  });

  test("a prompt-allowed command the policy holds is counted against the relation", async () => {
    const command = `cat ${join(PROJECT_ROOT, "README.md")}`;
    const summary = await summarizeRouting([{ command, cwd: FOREIGN }]);
    expect(summary.promptAllowedPairs).toBe(1);
    expect(summary.promptAllowedPairsHeldByPolicy).toBe(1);
  });
});

describe("no command text escapes into the breakdowns", () => {
  test("every reported head is an executable, not an operand", async () => {
    const summary = await summarizeRouting([
      { command: `sed -n '1,2p' ${join(PROJECT_ROOT, "README.md")}`, cwd: PROJECT_ROOT },
    ]);
    expect(summary.routedPromptManualHeads.map((entry) => entry.head)).toEqual(["sed"]);
    const rendered = JSON.stringify(summary);
    expect(rendered).not.toContain("README");
    expect(rendered).not.toContain("1,2p");
  });
});
