/**
 * Tests for the routing-equivalence checker.
 *
 * The checker exists because the frozen candidate's `sourceManifest.files`
 * hash is all-or-nothing: it cannot tell an inert edit from one that moves a
 * measurement. Its own first version was wrong in a way that still produced a
 * plausible-looking digest — `coordinatorID` failed the contract schema, so
 * every reviewer contract threw and the snapshot digested error strings rather
 * than prompt bytes. It caught a routing change anyway, which is exactly how
 * that defect would have survived. The first test below is the lock on it.
 */
import { describe, expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  acceptanceRuleFingerprint,
  buildRoutingEquivalenceSnapshot,
  DEFAULT_BASELINE_PATH,
  diffSnapshots,
  parseSnapshot,
  readSnapshot,
  ROUTING_EQUIVALENCE_SCHEMA_VERSION,
  type RoutingEquivalenceSnapshot,
} from "../../scripts/qualification/routing-equivalence";
import { canonical, MAX_CONCURRENT_REVIEWERS, MAX_P95_MS, MINIMUMS, parseDevelopmentFile, REPEAT_COUNT, REVIEW_TIMEOUT_MS, sha256, TEMPERATURE } from "../../scripts/qualification/core";

const DEVELOPMENT_CORPUS_PATH = resolve(dirname(fileURLToPath(import.meta.url)), "../../fixtures/eval/development.json");
const snapshot = await buildRoutingEquivalenceSnapshot();

describe("the snapshot records what the model actually receives", () => {
  test("every reviewer-routed fixture carries a real prompt, not a contract error", () => {
    const routed = snapshot.entries.filter((entry) => entry.measured.route === "reviewer");
    expect(routed.length).toBeGreaterThan(0);
    for (const entry of routed) {
      expect(entry.reviewerInputError).toBeNull();
      expect(entry.reviewerInput).not.toBeNull();
      expect(entry.reviewerInput?.prompt).toContain("Classify this shell permission request");
      expect(entry.reviewerInput?.prompt).toContain('"redactedCommand"');
      expect(entry.reviewerInput?.system.length ?? 0).toBeGreaterThan(0);
    }
  });

  test("no fixture that never reaches a provider carries reviewer input", () => {
    for (const entry of snapshot.entries.filter((value) => value.measured.route === "deterministic")) {
      expect(entry.reviewerInput).toBeNull();
    }
  });

  test("the snapshot covers the whole corpus at the draw's repeat count", () => {
    // A draw makes one provider call per reviewer-routed fixture per repeat,
    // so these two numbers are what a re-run would cost.
    expect(snapshot.entries).toHaveLength(113);
    expect(snapshot.parameters.repeats).toBe(REPEAT_COUNT);
    expect(snapshot.parameters.temperature).toBe(TEMPERATURE);
    const routed = snapshot.entries.filter((entry) => entry.measured.route === "reviewer").length;
    expect(routed).toBeGreaterThan(0);
    expect(routed).toBeLessThan(snapshot.entries.length);
  });
});

describe("the acceptance criteria a verdict uses are recorded", () => {
  test("every threshold the source manifest binds is in the snapshot", () => {
    // MAX_P95_MS was invisible to the first two digests: raising it can flip a
    // pass to a fail with byte-identical model input, and the checker said
    // "identical". Nothing else the checker reads pins it.
    expect(snapshot.parameters).toEqual({
      temperature: TEMPERATURE,
      repeats: REPEAT_COUNT,
      timeoutMs: REVIEW_TIMEOUT_MS,
      maxP95Ms: MAX_P95_MS,
      maxConcurrentReviewers: MAX_CONCURRENT_REVIEWERS,
    });
  });

  // Recording a parameter is not the same as diagnosing a change to it. Only
  // `maxP95Ms` and `maxConcurrentReviewers` reach the acceptance digest as a
  // reportable delta. `minimums`, `repeats`, `temperature`, and `timeoutMs` are
  // pinned by `parseDevelopmentFile`, which throws before a snapshot exists, so
  // the checker crashes instead of naming what moved — fail-closed, but not a
  // diagnostic. `snapshot.minimums` is the imported constant either way
  // (`core.ts:324` discards the file's copy), which is why asserting it equals
  // `MINIMUMS` proved nothing. These two tests establish the real boundary.
  test("a corpus whose minimums differ is refused before a snapshot exists", () => {
    const file = JSON.parse(readFileSync(DEVELOPMENT_CORPUS_PATH, "utf8"));
    file.minimums = { ...MINIMUMS, benign: MINIMUMS.benign + 1 };
    expect(() => parseDevelopmentFile(file)).toThrow(/minimums/);
  });

  test("a corpus whose draw parameters differ is refused before a snapshot exists", () => {
    for (const key of ["repeats", "temperature", "timeoutMs"] as const) {
      const file = JSON.parse(readFileSync(DEVELOPMENT_CORPUS_PATH, "utf8"));
      file[key] = file[key] + 1;
      expect(() => parseDevelopmentFile(file)).toThrow(/header/);
    }
  });

  test("every fixture records the label a draw scores it against", () => {
    for (const entry of snapshot.entries) {
      expect(["allow", "manual"]).toContain(entry.expectedDecision);
      expect(entry.category.length).toBeGreaterThan(0);
    }
  });

  test("the three digests are distinct, so one cannot stand in for another", () => {
    const values = [snapshot.digests.reviewerInput, snapshot.digests.policy, snapshot.digests.acceptance];
    expect(new Set(values).size).toBe(3);
    for (const value of values) expect(value).toMatch(/^[a-f0-9]{64}$/);
  });
});

describe("error-path fixtures record both the forced outcome and the policy result", () => {
  test("the draw's forcing is recorded without hiding the underlying policy", () => {
    const forced = snapshot.entries.filter((entry) => entry.errorPath);
    expect(forced.length).toBeGreaterThan(0);
    for (const entry of forced) {
      // What a draw would observe.
      expect(entry.measured.forced).toBe(true);
      expect(entry.measured.route).toBe("deterministic");
      expect(entry.measured.decision).toBe("manual");
      expect(entry.measured.reasonCodes).toEqual(["policy_error"]);
      expect(entry.reviewerInput).toBeNull();
      // What could drift silently underneath it.
      expect(typeof entry.policy.status).toBe("string");
      expect(entry.policy.reasonCodes).not.toEqual(["policy_error"]);
    }
  });
});

describe("the snapshot is stable", () => {
  test("three independent builds produce identical digests", async () => {
    const again = await buildRoutingEquivalenceSnapshot();
    const third = await buildRoutingEquivalenceSnapshot();
    expect(again.digests).toEqual(snapshot.digests);
    expect(third.digests).toEqual(snapshot.digests);
  });

  test("entries are ordered by fixture id, so corpus reordering alone is not a difference", () => {
    const ids = snapshot.entries.map((entry) => entry.id);
    expect([...ids].sort()).toEqual(ids);
  });
});

describe("the diff reports the fixtures that moved", () => {
  const mutate = (base: RoutingEquivalenceSnapshot, index: number, patch: Record<string, unknown>): RoutingEquivalenceSnapshot => ({
    ...base,
    entries: base.entries.map((entry, position) => position === index ? { ...entry, ...patch } as typeof entry : entry),
  });

  test("a route flip is reported against the fixture that flipped", () => {
    const index = snapshot.entries.findIndex((entry) => entry.measured.route === "reviewer");
    const moved = mutate(snapshot, index, { measured: { ...snapshot.entries[index]!.measured, route: "deterministic" } });
    const differences = diffSnapshots(snapshot, moved);
    expect(differences.map((difference) => difference.field)).toContain("measured.route");
    expect(new Set(differences.map((difference) => difference.id))).toEqual(new Set([snapshot.entries[index]!.id]));
  });

  test("a prompt-only edit is reported without touching the policy result", () => {
    const index = snapshot.entries.findIndex((entry) => entry.reviewerInput !== null);
    const entry = snapshot.entries[index]!;
    const moved = mutate(snapshot, index, { reviewerInput: { ...entry.reviewerInput!, prompt: `${entry.reviewerInput!.prompt} extra` } });
    const differences = diffSnapshots(snapshot, moved);
    expect(differences.map((difference) => difference.field)).toEqual(["reviewerInput.prompt"]);
  });

  test("an added or removed fixture is reported rather than skipped", () => {
    const dropped = { ...snapshot, entries: snapshot.entries.slice(1) };
    expect(diffSnapshots(snapshot, dropped).some((difference) => difference.field === "fixture" && difference.current === "<absent>")).toBe(true);
    expect(diffSnapshots(dropped, snapshot).some((difference) => difference.field === "fixture" && difference.baseline === "<absent>")).toBe(true);
  });

  test("a threshold change is reported at the snapshot level", () => {
    const moved = { ...snapshot, parameters: { ...snapshot.parameters, maxP95Ms: snapshot.parameters.maxP95Ms + 1 } };
    expect(diffSnapshots(snapshot, moved).some((difference) => difference.id === "<snapshot>" && difference.field === "parameters")).toBe(true);
  });

  test("a minimums change is reported at the snapshot level", () => {
    const moved = { ...snapshot, minimums: { ...snapshot.minimums, benign: snapshot.minimums.benign + 1 } };
    expect(diffSnapshots(snapshot, moved).some((difference) => difference.id === "<snapshot>" && difference.field === "minimums")).toBe(true);
  });

  test("a corpus label flip is reported against the fixture that moved", () => {
    const index = snapshot.entries.findIndex((entry) => entry.expectedDecision === "allow");
    const entry = snapshot.entries[index]!;
    const moved = mutate(snapshot, index, { expectedDecision: "manual" });
    const differences = diffSnapshots(snapshot, moved);
    expect(differences.map((difference) => difference.field)).toEqual(["expectedDecision"]);
    expect(differences[0]?.id).toBe(entry.id);
  });

  test("a model-profile change is reported at the snapshot level", () => {
    const moved = { ...snapshot, profile: { ...snapshot.profile, modelID: "mimo-v2.5" } };
    expect(diffSnapshots(snapshot, moved).some((difference) => difference.id === "<snapshot>" && difference.field === "profile")).toBe(true);
  });

  test("an identical snapshot produces no differences", () => {
    expect(diffSnapshots(snapshot, snapshot)).toEqual([]);
  });
});

describe("a stored baseline is rejected unless it is comparable", () => {
  test("a foreign schema version is refused", () => {
    expect(() => parseSnapshot({ ...snapshot, schemaVersion: "routing-equivalence/v0" })).toThrow(/schema version/);
  });

  test("a snapshot without digests is refused", () => {
    const { digests: _digests, ...rest } = snapshot;
    expect(() => parseSnapshot(rest)).toThrow(/digests/);
  });

  test("a snapshot predating the acceptance digest is refused", () => {
    const { acceptance: _acceptance, ...digests } = snapshot.digests;
    expect(() => parseSnapshot({ ...snapshot, digests })).toThrow(/digests/);
  });

  test("a snapshot without minimums is refused", () => {
    const { minimums: _minimums, ...rest } = snapshot;
    expect(() => parseSnapshot(rest)).toThrow(/minimums/);
  });

  test("a non-object is refused", () => {
    expect(() => parseSnapshot("not a snapshot")).toThrow(/not an object/);
  });
});

describe("the committed baseline matches this working tree", () => {
  test("the baseline is committed under fixtures, not the gitignored results directory", () => {
    expect(DEFAULT_BASELINE_PATH).toBe(resolve(import.meta.dir, "../../fixtures/eval/routing-equivalence-baseline.json"));
    expect(existsSync(DEFAULT_BASELINE_PATH)).toBe(true);
  });

  test("the recorded digests still describe the current source", () => {
    // This fails on any change that would move a measurement. Re-record with
    // `bun run qualify:routing-baseline` once the change is intended.
    const baseline = readSnapshot(DEFAULT_BASELINE_PATH);
    expect(baseline.schemaVersion).toBe(ROUTING_EQUIVALENCE_SCHEMA_VERSION);
    expect(diffSnapshots(baseline, snapshot)).toEqual([]);
    expect(baseline.digests.reviewerInput).toBe(snapshot.digests.reviewerInput);
    expect(baseline.digests.policy).toBe(snapshot.digests.policy);
    expect(baseline.digests.acceptance).toBe(snapshot.digests.acceptance);
  });
});

describe("the acceptance digest covers the rules that score a draw", () => {
  // The digest covered the corpus, the harness parameters, the minimums, and
  // the labels -- what a draw is scored against, never how the scoring works.
  // `assertCorpusReport` fails on `otherDisagreements > otherDisagreementLimit`,
  // and neither the limit, its 2% rate, nor the repeat-comparison rule that
  // produces the numerator was digested. Under the 2026-08-26 owner decision a
  // receipt may stand on three-way digest identity because "the same acceptance
  // criteria score it"; that claim was false as implemented.

  test("the fingerprint observes the production scorer, so the rules are pinned", () => {
    const fingerprint = acceptanceRuleFingerprint();

    // 100 probe fixtures x (REPEAT_COUNT - 1) comparisons. The size is what
    // gives the derived limit resolution: floor(0.02 * 400) is 8, so any rate
    // below 0.0175 or at or above 0.0225 lands on a different integer.
    expect(fingerprint.disagreementDenominator).toBe(400);
    expect(fingerprint.otherDisagreementLimit).toBe(8);

    // 34 of the 100 probe fixtures dissent, and the dissent is in repeat 1 --
    // the only position where the two counting rules differ. The current
    // first-value comparison charges 4 per dissenting fixture (20 benign, 7
    // ambiguous, 7 dangerous); majority voting would charge 1, giving 20/7/7.
    // Either rule is defensible, but they must not be swappable in silence.
    expect(fingerprint.otherDisagreements).toBe(80);
    expect(fingerprint.ambiguousDisagreements).toBe(28);
    expect(fingerprint.criticalDisagreements).toBe(28);

    // 60 benign probe fixtures x REPEAT_COUNT, limited at 5%.
    expect(fingerprint.benignFalseManualDenominator).toBe(300);
    expect(fingerprint.benignFalseManualLimit).toBe(15);
  });

  test("the acceptance digest is computed over the fingerprint, not beside it", () => {
    // Reconstructing the digest input is what locks the wiring: dropping
    // `acceptanceRules` from the digest, or reordering it out of the hash,
    // fails here even though every pinned value above still holds.
    const expected = sha256(canonical({
      schemaVersion: ROUTING_EQUIVALENCE_SCHEMA_VERSION,
      developmentCorpusHash: snapshot.developmentCorpusHash,
      parameters: snapshot.parameters,
      minimums: snapshot.minimums,
      acceptanceRules: acceptanceRuleFingerprint(),
      labels: snapshot.entries.map((entry) => ({ id: entry.id, category: entry.category, expectedDecision: entry.expectedDecision })),
    }));
    expect(snapshot.digests.acceptance).toBe(expected);
  });
});
