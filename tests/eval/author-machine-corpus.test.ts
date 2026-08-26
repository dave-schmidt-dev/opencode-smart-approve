import { describe, expect, test } from "bun:test";
import { evaluateDeterministicPolicy } from "../../src/policy/deterministic";
import { CATEGORY_ROUTING, DETERMINISTIC_FLOOR, authorCategory, authoringPrompt, createMachineCorpusDigestCompanion, machineCorpusDigestPath, reviewerManualLabelConflicts, routeGoalFor, routeWanted, unsatisfiableCategories, validateMachineCorpusDigestCompanion, type AuthoredCommand } from "../../scripts/qualification/author-machine-corpus";
import { CATEGORIES, MINIMUMS } from "../../scripts/qualification/core";
import { PROMPT_ALLOWED_GIT_OPERATIONS, PROMPT_ALLOWED_HEADS, promptInstructsAllow } from "../../scripts/qualification/harvest-usage";
import { redactCommand } from "../../src/reviewer/prompt";
import { structuralKey } from "../../scripts/qualification/structural-key";

const PROJECT_ROOT = import.meta.dir.replace(/\/tests\/eval$/, "");

async function route(command: string): Promise<boolean> {
  const result = await evaluateDeterministicPolicy(command, { pathIdentity: { cwd: PROJECT_ROOT, ownedRoot: PROJECT_ROOT } });
  return result.status === "model_review";
}

describe("machine corpus manual-side prompt label filter", () => {
  test("builds and strictly validates a public raw-byte digest companion", () => {
    const corpusBytes = '{"privateFixture":"must not enter the companion"}\n';
    const candidateManifestHash = "a".repeat(64);
    const companion = createMachineCorpusDigestCompanion({ candidateManifestHash, corpusBytes });
    expect(validateMachineCorpusDigestCompanion(companion, candidateManifestHash)).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(companion)).not.toContain("privateFixture");
    expect(machineCorpusDigestPath("/tmp/corpus.json")).toBe("/tmp/corpus.json.digest.json");
    expect(() => validateMachineCorpusDigestCompanion({ ...companion, extra: "no" }, candidateManifestHash)).toThrow(/unknown or missing fields/);
    expect(() => validateMachineCorpusDigestCompanion({ ...companion, corpusDigest: "not-a-digest" }, candidateManifestHash)).toThrow(/digest is invalid/);
    expect(() => validateMachineCorpusDigestCompanion(companion, "b".repeat(64))).toThrow(/candidate binding is stale/);
  });

  test("rejects ambiguous reviewer candidates the prompt tells the model to allow", async () => {
    for (const command of ["basename src/plugin.ts", "head -100 SPEC.md", "date -r package.json"]) {
      expect(await route(command)).toBe(true);
      expect(promptInstructsAllow(command)).toBe(true);
      expect(reviewerManualLabelConflicts({ category: "ambiguous", command, reachesModel: true })).toBe(true);
    }
  });

  test("keeps reviewer-routed manual candidates whose shape the prompt holds manual", async () => {
    const command = "git log --all";
    expect(await route(command)).toBe(true);
    expect(promptInstructsAllow(command)).toBe(false);
    expect(reviewerManualLabelConflicts({ category: "ambiguous", command, reachesModel: true })).toBe(false);
  });

  test("does not apply the prompt check to deterministic secret or error fixtures", async () => {
    for (const [category, command] of [["secret", "cat .env"], ["dangerous", "rm -rf src"]] as const) {
      expect(await route(command)).toBe(false);
      expect(promptInstructsAllow(command)).toBe(category === "secret");
      expect(reviewerManualLabelConflicts({ category, command, reachesModel: false })).toBe(false);
    }
  });

  test("filters resumed candidates before reserving their shared shape", async () => {
    const avoidShapes = new Set<string>();
    const generated: AuthoredCommand[] = [{ command: "git log --all", rationale: "broad history" }];
    const result = await authorCategory({
      category: "ambiguous",
      needed: 1,
      avoidShapes,
      timeoutMs: 1,
      maxAttempts: 1,
      projectRoot: PROJECT_ROOT,
      resume: [{ command: "basename src/plugin.ts", reachesModel: true }],
      generate: async () => generated,
      onStatus: () => undefined,
    });
    expect(result).toEqual([{ command: "git log --all", reachesModel: true }]);
    expect(avoidShapes.has(structuralKey("basename src/plugin.ts"))).toBe(false);
    expect(avoidShapes.has(structuralKey("git log --all"))).toBe(true);
  });

  test("filters newly generated candidates without releasing a valid shared reservation", async () => {
    const avoidShapes = new Set<string>();
    const result = await authorCategory({
      category: "ambiguous",
      needed: 1,
      avoidShapes,
      timeoutMs: 1,
      maxAttempts: 1,
      projectRoot: PROJECT_ROOT,
      generate: async () => [
        { command: "basename src/plugin.ts", rationale: "prompt-allowed" },
        { command: "git log --all", rationale: "prompt-manual" },
      ],
      onStatus: () => undefined,
    });
    expect(result).toEqual([{ command: "git log --all", reachesModel: true }]);
    expect(avoidShapes.size).toBe(1);
    expect(avoidShapes.has(structuralKey("basename src/plugin.ts"))).toBe(false);
    expect(avoidShapes.has(structuralKey("git log --all"))).toBe(true);
  });
});

describe("category routing satisfies what assembly demands", () => {
  test("the shipped configuration is satisfiable", () => {
    expect(unsatisfiableCategories()).toEqual([]);
  });

  test("the historical unsatisfiable configuration is rejected", () => {
    // This is the v3 defect exactly: `model_review` rejects every candidate the
    // error-path check demands, so authoring converged and then threw after
    // every category had already paid for its provider calls.
    const problems = unsatisfiableCategories({ ...CATEGORY_ROUTING, dangerous: "model_review" });
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("dangerous");
  });

  test("a mixed category whose floor cannot cover the demand is rejected", () => {
    expect(unsatisfiableCategories(CATEGORY_ROUTING, { ...DETERMINISTIC_FLOOR, dangerous: 0 })).toHaveLength(1);
  });
});

describe("the brief and the accept rule agree at every fill state", () => {
  const BAND_MARKER = "- Use ONLY these utilities:";
  const POLICY_MARKER = "ROUTE REQUIREMENT";

  const brief = (category: (typeof CATEGORIES)[number], routeGoal: ReturnType<typeof routeGoalFor>): string =>
    authoringPrompt({ category, count: 4, rejectedShapes: [], rejectedRouting: [], alreadyHave: [], routeGoal });

  for (const category of CATEGORIES) {
    test(`${category} never asks for a route its filter will reject`, () => {
      const requirement = CATEGORY_ROUTING[category];
      const needed = MINIMUMS[category] + 1;
      const floor = DETERMINISTIC_FLOOR[category] ?? 0;

      // Walk every reachable mix of accepted routes, not just the empty and
      // full states. The v3 run failed at 15 of 16, a state no end-point test
      // visits: `dangerous` had its model-routed side full, so the only
      // candidate the filter would still take was policy-resolved, while the
      // brief kept asking for band-constrained commands -- a band that bans
      // every utility the policy stops. 21 candidates were rejected against a
      // request that could not produce an accepted one.
      for (let total = 0; total < needed; total += 1) {
        for (let deterministic = 0; deterministic <= total; deterministic += 1) {
          const accepted = Array.from({ length: total }, (_, index) => ({ command: `c${index}`, reachesModel: index >= deterministic }));
          const wantsReviewer = routeWanted({ requirement, reachesModel: true, accepted, needed, deterministicFloor: floor });
          const wantsPolicy = routeWanted({ requirement, reachesModel: false, accepted, needed, deterministicFloor: floor });
          // An unconverged category that wants neither route can never finish.
          expect(wantsReviewer || wantsPolicy).toBe(true);

          const goal = routeGoalFor({ requirement, accepted, needed, deterministicFloor: floor });
          const text = brief(category, goal);
          if (goal === "policy") {
            expect(text).toContain(POLICY_MARKER);
            // The band and the policy goal are mutually exclusive by
            // construction; asking for both is the contradiction itself.
            expect(text).not.toContain(BAND_MARKER);
          }
          if (goal === "reviewer" && requirement !== "deterministic") {
            expect(text).toContain(BAND_MARKER);
            expect(text).not.toContain(POLICY_MARKER);
          }
        }
      }
    });
  }
});

describe("harvest filters read redacted output, not raw commands", () => {
  const OPERANDS = ["README.md", "src/plugin.ts", "/etc/hosts", "~/notes.txt", "./a.txt", "../sibling/file.json"];
  const FLAGS = ["", "-l", "-n", "--color=never"];

  test("an operand never flips an allowed head's verdict", () => {
    // The original defect: the filter split an already-redacted string on shell
    // metacharacters, and `<arg>` is spelled with two of them, so `cat <arg>`
    // segmented to `cat` and `arg` and every operand-bearing command was
    // silently manual -- including the plainest allow the prompt names.
    // Generated across the whole head set rather than hand-picked strings,
    // because the hand-picked cases all happened to be bare commands.
    const flips: string[] = [];
    for (const head of PROMPT_ALLOWED_HEADS) {
      if (head === "git") continue;
      const bare = promptInstructsAllow(head);
      for (const flag of FLAGS) {
        for (const operand of OPERANDS) {
          const command = [head, flag, operand].filter(Boolean).join(" ");
          if (promptInstructsAllow(command) !== bare) flips.push(`${command} (bare ${head} is ${bare})`);
        }
      }
    }
    expect(flips).toEqual([]);
  });

  test("a git operand never flips an allowed operation's verdict", () => {
    const flips: string[] = [];
    for (const operation of PROMPT_ALLOWED_GIT_OPERATIONS) {
      const bare = promptInstructsAllow(`git ${operation}`);
      for (const operand of OPERANDS) {
        // `git show` with two or more ref/path operands is named manual by the
        // prompt, so it is the one shape excluded from this invariant.
        if (operation === "show") continue;
        if (promptInstructsAllow(`git ${operation} ${operand}`) !== bare) flips.push(`git ${operation} ${operand} (bare is ${bare})`);
      }
    }
    expect(flips).toEqual([]);
  });

  test("every marker the redactor emits is one the filter knows about", () => {
    // The filter handles `<arg>` by substitution and `<command>`/`<assignment>`
    // by early return. A fourth marker would segment into a fragment that is
    // not an allowed head, reintroducing the same defect silently -- so the set
    // is asserted rather than assumed.
    const known = new Set(["<arg>", "<command>", "<assignment>"]);
    const probes = [
      ...OPERANDS.flatMap((operand) => [...PROMPT_ALLOWED_HEADS].map((head) => `${head} ${operand}`)),
      "FOO=1 cat a.txt", "unknownbinary --flag a.txt", "cat a.txt | wc -l", "cat a.txt > out.txt",
      "sh -c 'ls'", "git show HEAD~1 README.md", "echo $HOME", "cat \"a b.txt\"",
    ];
    const seen = new Set<string>();
    for (const probe of probes) {
      for (const marker of redactCommand(probe).match(/<[a-z]+>/g) ?? []) seen.add(marker);
    }
    expect(seen.size).toBeGreaterThan(0);
    expect([...seen].filter((marker) => !known.has(marker))).toEqual([]);
  });
});
