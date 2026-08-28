/**
 * End-to-end rehearsal of the machine release path with the provider stubbed.
 *
 * Every failure that cost a v4 custody consumption was a harness failure, and
 * each one was found by spending a one-use corpus. These tests drive the real
 * `runMachineRelease` -- real preflight, real custody, real corpus validation,
 * real reviewer agent, real scoring, real artifact write -- against a scripted
 * transport, so the next such defect is found here instead.
 *
 * The one thing a rehearsal cannot tell you is whether the classifier is any
 * good. Every decision in these aggregates was chosen by the script.
 */
import { afterAll, describe, expect, test } from "bun:test";
import { appendFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MAX_CONCURRENT_REVIEWERS, REPEAT_COUNT } from "../../scripts/qualification/core";
import {
  createDevelopmentCandidateReport,
  createFrozenCandidateManifest,
  evaluateCorpus,
  evaluateFaults,
  hashQualificationRecord,
  loadDevelopmentCorpus,
  type QualificationRecord,
} from "../../scripts/classifier-gate";
import {
  CONSECUTIVE_TRANSPORT_FAILURE_LIMIT,
  MACHINE_AGGREGATE_SCHEMA,
  MACHINE_REHEARSAL_SCHEMA,
  MACHINE_THRESHOLDS,
  MachineDrawAbortedError,
  assertAggregateDestination,
  machineAbortRecordPath,
  normalizeMachineTerminalKind,
  runBlindedDraw,
  runMachineRelease,
  runMachineReleasePreflight,
  writeMachineReleaseAggregate,
  type MachineAggregate,
} from "../../scripts/qualification/machine-release";
import {
  agreeableScript,
  buildRehearsalCorpus,
  createScriptedTransport,
  parseRehearsalTitle,
  writeRehearsalArtifacts,
  type RehearsalCall,
  type RehearsalReply,
  type RehearsalScript,
} from "../../scripts/qualification/rehearsal";
import { createReviewerAgent } from "../../src/reviewer/agent";
import { initializeCustodyLedger, readCustodyLedger } from "../../scripts/qualification/custody";
import type { MachineReleaseCorpus } from "../../scripts/qualification/machine-authority";
import type { PrivateReleaseFixture } from "../../scripts/qualification/release-corpus";

const AUTHORED_AT = "2026-08-28T12:00:00.000Z";

/**
 * The gate artifacts a draw reads, built from this checkout so they are
 * source-current by construction rather than by luck. Shared across the suite:
 * they are expensive to build and identical for every scenario.
 */
const gate = (() => {
  const candidate = createFrozenCandidateManifest(AUTHORED_AT);
  const { corpus } = loadDevelopmentCorpus();
  const records = corpus.fixtures.flatMap((entry) => Array.from({ length: REPEAT_COUNT }, (_, index) => {
    const deterministic = entry.errorPath === true || entry.category === "secret" || entry.category === "dangerous" || entry.category === "obfuscated";
    const decision = entry.category === "benign" ? "allow" : "manual";
    const base = {
      observationID: `rehearsal-development-${entry.id}-${index + 1}`,
      fixtureID: entry.id,
      category: entry.category,
      repeat: index + 1,
      expectedDecision: entry.expectedDecision,
      decision,
      route: deterministic ? "deterministic" : "reviewer",
      providerAttempted: !deterministic,
      reasonCodes: [deterministic ? "manual" : decision === "allow" ? "safe" : "ambiguous"],
      schemaValid: true,
      metricEligible: true,
      outcome: "classifier",
      terminalKind: deterministic ? "manual" : "valid_model",
      latencyMs: 100 + index,
    } as Omit<QualificationRecord, "responseHash">;
    return { ...base, responseHash: hashQualificationRecord(base) };
  }));
  return {
    candidate,
    report: createDevelopmentCandidateReport({
      candidate,
      corpusReport: evaluateCorpus("development", corpus, records),
      faults: evaluateFaults([]),
      terminal: "development-pass",
      generatedAt: AUTHORED_AT,
    }),
  };
})();

/** Built once: observing 95 fixtures' routes is the slowest part of the suite. */
const corpusPromise = buildRehearsalCorpus({
  candidateManifestHash: gate.candidate.manifestHash,
  classifierModel: gate.candidate.candidate.modelProfile.model,
  authoredAt: AUTHORED_AT,
});

const roots: string[] = [];
function scratchRoot(label: string): string {
  const root = mkdtempSync(join(tmpdir(), `machine-release-rehearsal-${label}-`));
  roots.push(root);
  return root;
}
afterAll(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }); });

interface RehearsalOutcome {
  readonly aggregate?: MachineAggregate;
  readonly error?: unknown;
  readonly artifacts: ReturnType<typeof writeRehearsalArtifacts>;
  readonly calls: readonly RehearsalCall[];
  readonly status: readonly string[];
}

/**
 * Run the operator's entry point against a scripted transport.
 *
 * `probeProvider` is stubbed alongside the transport because the real probe
 * boots a server and spends a provider call; the ordering it guards is asserted
 * separately, in the test that makes the probe fail.
 */
async function rehearse(input: {
  readonly label: string;
  readonly corpus: MachineReleaseCorpus;
  readonly script: RehearsalScript;
  readonly exitAfterCalls?: number;
  readonly probeProvider?: () => Promise<void>;
  readonly aggregateName?: string;
}): Promise<RehearsalOutcome> {
  const root = scratchRoot(input.label);
  const artifacts = writeRehearsalArtifacts({
    root,
    corpus: input.corpus,
    candidate: gate.candidate,
    developmentReport: gate.report,
    candidateManifestHash: gate.candidate.manifestHash,
  });
  const aggregatePath = input.aggregateName ? join(root, input.aggregateName) : artifacts.aggregatePath;
  const transport = createScriptedTransport({
    script: input.script,
    logPath: join(root, "rehearsal-transport.log"),
    ...(input.exitAfterCalls === undefined ? {} : { exitAfterCalls: input.exitAfterCalls }),
  });
  const status: string[] = [];
  const previousAuth = process.env.OPENCODE_AUTH_PATH;
  process.env.OPENCODE_AUTH_PATH = artifacts.authPath;
  try {
    const aggregate = await runMachineRelease({
      corpusPath: artifacts.corpusPath,
      ledgerPath: artifacts.ledgerPath,
      aggregatePath,
      candidatePath: artifacts.candidatePath,
      developmentReportPath: artifacts.developmentReportPath,
      generatedAt: AUTHORED_AT,
      probeProvider: input.probeProvider ?? (async () => undefined),
      openTransport: async () => transport,
      onStatus: (message) => { status.push(message); },
    });
    return { aggregate, artifacts: { ...artifacts, aggregatePath }, calls: transport.calls, status };
  } catch (error) {
    return { error, artifacts: { ...artifacts, aggregatePath }, calls: transport.calls, status };
  } finally {
    if (previousAuth === undefined) delete process.env.OPENCODE_AUTH_PATH;
    else process.env.OPENCODE_AUTH_PATH = previousAuth;
  }
}

function reviewerRouted(corpus: MachineReleaseCorpus): readonly PrivateReleaseFixture[] {
  return corpus.release.filter((fixture) => fixture.route === "reviewer");
}

describe("rehearsal corpus", () => {
  test("is release-shaped and its routes are observed, not declared", async () => {
    // `buildRehearsalCorpus` runs `validateMachineReleaseCorpus` and
    // `assertObservedRoutes` itself and throws on either. Asserting it resolves
    // is asserting both, and the counts below pin what the scenarios rely on.
    const corpus = await corpusPromise;
    expect(corpus.release.length).toBe(95);
    expect(reviewerRouted(corpus).length).toBeGreaterThanOrEqual(MACHINE_THRESHOLDS.minReviewerRoutedFixtures);
    expect(corpus.release.some((fixture) => fixture.category === "dangerous" && fixture.route === "reviewer")).toBe(true);
    expect(corpus.release.some((fixture) => fixture.category === "benign" && fixture.route === "reviewer")).toBe(true);
    expect(corpus.release.every((fixture) => fixture.category !== "secret" || fixture.route === "deterministic")).toBe(true);
    expect(corpus.release.filter((fixture) => fixture.errorPath === true).length).toBeGreaterThan(0);
    expect(corpus.release.every((fixture) => fixture.errorPath !== true || fixture.route === "deterministic")).toBe(true);
  });

  test("a declared route the policy does not agree with is rejected", async () => {
    // Kills the mutant that drops `assertObservedRoutes` from the builder: with
    // correct routes its removal is invisible, so the check needs a corpus that
    // lies about one.
    await expect(buildRehearsalCorpus({
      candidateManifestHash: gate.candidate.manifestHash,
      classifierModel: gate.candidate.candidate.modelProfile.model,
      authoredAt: AUTHORED_AT,
      mutate: (subject) => ({
        ...subject,
        release: subject.release.map((fixture, index) => (index === 0 ? { ...fixture, route: "deterministic" as const, providerAttempted: false } : fixture)),
      }),
    })).rejects.toThrow(/routes are declared, not observed/);
  }, 60_000);

  test("session titles carry the fixture identity the script needs", () => {
    expect(parseRehearsalTitle("smart-approve:machine:rehearsal-qualification-benign-001:3", 7))
      .toEqual({ fixtureID: "rehearsal-qualification-benign-001", repeat: 3, callIndex: 7 });
    // The pre-spend probe opens a session too, and must not be scripted as a draw.
    expect(parseRehearsalTitle("smart-approve:probe", 0)).toBeUndefined();
    expect(parseRehearsalTitle(undefined, 0)).toBeUndefined();
  });
});

/**
 * `--preflight` moves the corpus checks to the `available` side of the ledger.
 *
 * They cannot move there in a draw: the commands are private, so the corpus is
 * only readable once custody is spent, and a rejection there consumes a
 * consumption and writes no abort record. The preflight runs the same function
 * over the same bytes and spends nothing, so the only thing a cleared draw can
 * still lose to is the transport.
 */
describe("preflight clears a draw without spending it", () => {
  function preflightArtifacts(label: string, corpus: MachineReleaseCorpus) {
    return writeRehearsalArtifacts({
      root: scratchRoot(label),
      corpus,
      candidate: gate.candidate,
      developmentReport: gate.report,
      candidateManifestHash: gate.candidate.manifestHash,
    });
  }

  async function preflight(artifacts: ReturnType<typeof writeRehearsalArtifacts>) {
    const previousAuth = process.env.OPENCODE_AUTH_PATH;
    process.env.OPENCODE_AUTH_PATH = artifacts.authPath;
    try {
      return await runMachineReleasePreflight({
        corpusPath: artifacts.corpusPath,
        ledgerPath: artifacts.ledgerPath,
        aggregatePath: artifacts.aggregatePath,
        candidatePath: artifacts.candidatePath,
        developmentReportPath: artifacts.developmentReportPath,
        // Names the run a rehearsal so the destination check agrees with the
        // artifact name, and proves the preflight never opens it: a preflight
        // that reached the transport would be a draw's first step renamed.
        openTransport: async () => { throw new Error("preflight must not open a transport"); },
      });
    } finally {
      if (previousAuth === undefined) delete process.env.OPENCODE_AUTH_PATH;
      else process.env.OPENCODE_AUTH_PATH = previousAuth;
    }
  }

  test("a sound corpus clears, and the ledger is still untouched", async () => {
    const corpus = await corpusPromise;
    const artifacts = preflightArtifacts("preflight-ok", corpus);
    const report = await preflight(artifacts);
    expect(report.preflight).toBe("ok");
    expect(report.executionMode).toBe("rehearsal");
    expect(report.candidateManifestHash).toBe(gate.candidate.manifestHash);
    expect(report.fixtures).toBe(corpus.release.length);
    expect(report.reviewerRoutedFixtures).toBe(reviewerRouted(corpus).length);
    // The whole point. A preflight that spent would be the thing it prevents.
    expect(report.ledgerExists).toBe(false);
    expect(report.ledgerState).toBe("absent");
    expect(existsSync(artifacts.ledgerPath)).toBe(false);
    expect(existsSync(artifacts.aggregatePath)).toBe(false);
  }, 120_000);

  test("a spent ledger is named, not hidden behind an ok", async () => {
    // `ledgerExists` alone cleared this case, which made the preflight's own
    // claim -- that only the transport can still lose the draw -- untrue for a
    // reused ledger path.
    const corpus = await corpusPromise;
    const artifacts = preflightArtifacts("preflight-spent", corpus);
    initializeCustodyLedger(artifacts.ledgerPath, undefined, 0);
    const report = await preflight(artifacts);
    expect(report.ledgerState).toBe("available");
    writeFileSync(artifacts.ledgerPath, "{ not json", { mode: 0o600 });
    expect((await preflight(artifacts)).ledgerState).toBe("unreadable");
  }, 120_000);

  test("a corpus that fails its own digest is caught with custody intact", async () => {
    const corpus = await corpusPromise;
    const artifacts = preflightArtifacts("preflight-bad", corpus);
    // Any rejection inside `openReleaseCorpus` is one that would otherwise land
    // after the spend and write no abort record; the digest is the cheapest of
    // them to provoke.
    appendFileSync(artifacts.corpusPath, " ");
    await expect(preflight(artifacts)).rejects.toThrow(/digest does not match/);
    expect(existsSync(artifacts.ledgerPath)).toBe(false);
  }, 120_000);

  test("the draw and the preflight validate the corpus through the same function", () => {
    // Two copies of these checks would drift, and a preflight that passed while
    // the draw rejected would be worse than no preflight at all.
    const source = readFileSync(new URL("../../scripts/qualification/machine-release.ts", import.meta.url), "utf8");
    expect(source.match(/await openReleaseCorpus\(/g)?.length).toBe(2);
    expect(source.match(/assertObservedRoutes\(corpus\.release\)/g)?.length).toBe(1);
    // The pre-spend half is shared too, and the preflight must stop before the
    // spend rather than reimplement what precedes it.
    expect(source.match(/validateMachineReleaseInputs\(options\)/g)?.length).toBe(2);
    const body = source.slice(source.indexOf("export async function runMachineReleasePreflight"), source.indexOf("export async function runMachineRelease("));
    expect(body).not.toContain("spendBeforePrivateInput");
    expect(body).not.toContain("probeProvider");
    expect(body).not.toContain("runBlindedDraw");
  });
});

describe("a clean rehearsal scores as a pass", () => {
  test("writes a rehearsal artifact, spends custody once, and reaches every fixture", async () => {
    const corpus = await corpusPromise;
    const outcome = await rehearse({ label: "pass", corpus, script: agreeableScript(corpus) });
    expect(outcome.error).toBeUndefined();
    const aggregate = outcome.aggregate!;

    expect(aggregate.terminal).toBe("machine-release-pass");
    expect(aggregate.failures).toEqual([]);
    expect(aggregate.invalidRuns).toBe(0);
    expect(aggregate.observations).toBe(corpus.release.length * REPEAT_COUNT);
    expect(aggregate.providerCalls).toBe(reviewerRouted(corpus).length * REPEAT_COUNT);
    expect(aggregate.untestedCriticalCategories).toEqual([]);
    expect(aggregate.criticalDenominator).toBeGreaterThan(0);
    expect(aggregate.benignDenominator).toBeGreaterThan(0);
    expect(aggregate.errorPathDenominator).toBeGreaterThan(0);
    expect(aggregate.errorPathManual).toBe(aggregate.errorPathDenominator);

    // The rehearsal is marked three independent ways.
    expect(aggregate.executionMode).toBe("rehearsal");
    expect(aggregate.schemaVersion).toBe(MACHINE_REHEARSAL_SCHEMA);
    expect(aggregate.schemaVersion).not.toBe(MACHINE_AGGREGATE_SCHEMA);
    const written = JSON.parse(readFileSync(outcome.artifacts.aggregatePath, "utf8")) as MachineAggregate;
    expect(written.executionMode).toBe("rehearsal");
    expect(written.terminal).toBe("machine-release-pass");

    const ledger = readCustodyLedger(outcome.artifacts.ledgerPath);
    expect(ledger.state).toBe("spent");
    expect(ledger.consumptionNumber).toBe(1);
    expect(outcome.calls.length).toBe(reviewerRouted(corpus).length * REPEAT_COUNT);
    expect(existsSync(machineAbortRecordPath(outcome.artifacts.aggregatePath))).toBe(false);
  }, 120_000);
});

describe("a rehearsal that answers badly scores as a fail", () => {
  test("one critical false approval fails the run and is counted", async () => {
    const corpus = await corpusPromise;
    const target = corpus.release.find((fixture) => fixture.category === "dangerous" && fixture.route === "reviewer")!;
    const agreeable = agreeableScript(corpus);
    const outcome = await rehearse({
      label: "critical",
      corpus,
      script: (call) => (call.fixtureID === target.id ? { kind: "answer", decision: "allow", reasonCodes: ["safe"] } : agreeable(call)),
    });
    const aggregate = outcome.aggregate!;
    expect(aggregate.terminal).toBe("machine-release-fail");
    expect(aggregate.criticalFalseApprovals).toBe(REPEAT_COUNT);
    expect(aggregate.failures.some((failure) => failure.startsWith("critical false approvals:"))).toBe(true);
    // Still a rehearsal, and still not a claim about the classifier.
    expect(aggregate.executionMode).toBe("rehearsal");
    expect(aggregate.invalidRuns).toBe(0);
  }, 120_000);

  test("unparseable answers are invalid runs, not decisions", async () => {
    const corpus = await corpusPromise;
    const routed = reviewerRouted(corpus);
    const malformedFixture = routed[0]!;
    const toolFixture = routed[1]!;
    const agreeable = agreeableScript(corpus);
    const outcome = await rehearse({
      label: "invalid",
      corpus,
      script: (call) => {
        if (call.fixtureID === malformedFixture.id) return { kind: "malformed" };
        if (call.fixtureID === toolFixture.id) return { kind: "toolViolation" };
        return agreeable(call);
      },
    });
    const aggregate = outcome.aggregate!;
    expect(aggregate.terminal).toBe("machine-release-fail");
    expect(aggregate.invalidRuns).toBe(REPEAT_COUNT * 2);
    expect(aggregate.failures).toContain(`invalid runs: ${REPEAT_COUNT * 2}`);
    expect(aggregate.terminalKindCounts.malformed).toBe(REPEAT_COUNT);
    expect(aggregate.terminalKindCounts.tool_violation).toBe(REPEAT_COUNT);
  }, 120_000);
});

describe("a draw that degrades without dying records why", () => {
  test("scattered transport failures complete the draw and land on the aggregate", async () => {
    const corpus = await corpusPromise;
    const agreeable = agreeableScript(corpus);
    // One in four fails, so the streak never approaches the abort limit and the
    // draw runs to completion. This is the case the raised limit exists for:
    // aborting here would throw away a whole draw over a burst, while
    // completing still fails the gate on invalid runs and now says why.
    const outcome = await rehearse({
      label: "degraded",
      corpus,
      script: (call) => (call.callIndex % 4 === 3
        ? { kind: "promptRejects", error: () => Object.assign(new Error("rehearsal rate limit"), { name: "RateLimitError", status: 429 }) }
        : agreeable(call)),
    });
    expect(outcome.error).toBeUndefined();
    const aggregate = outcome.aggregate!;
    expect(aggregate.terminal).toBe("machine-release-fail");
    expect(aggregate.invalidRuns).toBeGreaterThan(0);
    expect(aggregate.failures).toContain(`invalid runs: ${aggregate.invalidRuns}`);
    // Without this a reader sees only a count of bad runs and cannot tell a bad
    // classifier from a bad transport -- which is how the v4 draw was misread.
    expect(aggregate.transportFaults.length).toBeGreaterThan(0);
    expect(aggregate.transportFaults[0]).toMatchObject({ phase: "session.prompt", name: "RateLimitError", status: 429 });
    const written = JSON.parse(readFileSync(outcome.artifacts.aggregatePath, "utf8")) as MachineAggregate;
    expect(written.transportFaults).toEqual(aggregate.transportFaults);
  }, 120_000);

  test("a clean draw records no faults at all", async () => {
    const corpus = await corpusPromise;
    const outcome = await rehearse({ label: "nofaults", corpus, script: agreeableScript(corpus) });
    expect(outcome.aggregate!.transportFaults).toEqual([]);
  }, 120_000);
});

describe("a rehearsal that loses its transport aborts instead of scoring", () => {
  test("consecutive session-creation failures abort and name the cause", async () => {
    const corpus = await corpusPromise;
    const agreeable = agreeableScript(corpus);
    const outcome = await rehearse({
      label: "cascade",
      corpus,
      // Enough to outlast the concurrency window and the abort limit together,
      // so the streak is reached regardless of which worker claims which job.
      script: (call) => (call.callIndex < CONSECUTIVE_TRANSPORT_FAILURE_LIMIT + MAX_CONCURRENT_REVIEWERS * 2 ? { kind: "createFails", error: () => Object.assign(new Error("rehearsal outage"), { name: "TransportError", status: 503 }) } : agreeable(call)),
    });
    expect(outcome.error).toBeInstanceOf(MachineDrawAbortedError);
    expect((outcome.error as Error).message).toMatch(/consecutive reviewer invocations failed at the transport/);

    // No aggregate: an outage is not a classifier result.
    expect(existsSync(outcome.artifacts.aggregatePath)).toBe(false);
    const record = JSON.parse(readFileSync(machineAbortRecordPath(outcome.artifacts.aggregatePath), "utf8")) as {
      terminal: string;
      executionMode: string;
      custodyNumber: number;
      transportFaults: readonly { phase: string; name: string; status: number | null; count: number }[];
    };
    expect(record.terminal).toBe("machine-release-aborted");
    expect(record.executionMode).toBe("rehearsal");
    expect(record.custodyNumber).toBe(1);
    // The diagnostic the fourth draw exists to produce: which phase failed.
    expect(record.transportFaults[0]).toMatchObject({ phase: "session.create", name: "TransportError", status: 503 });
    expect(readCustodyLedger(outcome.artifacts.ledgerPath).state).toBe("spent");
  }, 120_000);

  test("a transport that goes away mid-draw aborts rather than filling the rest with invalid runs", async () => {
    const corpus = await corpusPromise;
    const outcome = await rehearse({ label: "death", corpus, script: agreeableScript(corpus), exitAfterCalls: 20 });
    expect(outcome.error).toBeInstanceOf(MachineDrawAbortedError);
    expect((outcome.error as Error).message).toMatch(/exited mid-draw/);
    expect(existsSync(outcome.artifacts.aggregatePath)).toBe(false);
    expect(existsSync(machineAbortRecordPath(outcome.artifacts.aggregatePath))).toBe(true);
    // The whole point of aborting: the draw stops claiming jobs instead of
    // converting every remaining fixture into an invalid run.
    expect(outcome.calls.length).toBeLessThan(reviewerRouted(corpus).length * REPEAT_COUNT);
  }, 120_000);
});

describe("the pre-spend probe protects custody", () => {
  test("a probe failure leaves the ledger available and writes nothing", async () => {
    const corpus = await corpusPromise;
    const outcome = await rehearse({
      label: "probe",
      corpus,
      script: agreeableScript(corpus),
      probeProvider: async () => { throw new Error("rehearsal: provider probe failed"); },
    });
    expect((outcome.error as Error).message).toMatch(/provider probe failed/);
    // Never opened: the corpus is still unspent and still one-use.
    expect(readCustodyLedger(outcome.artifacts.ledgerPath).state).toBe("available");
    expect(readCustodyLedger(outcome.artifacts.ledgerPath).consumptionNumber).toBe(0);
    expect(outcome.calls.length).toBe(0);
    expect(existsSync(outcome.artifacts.aggregatePath)).toBe(false);
    expect(existsSync(machineAbortRecordPath(outcome.artifacts.aggregatePath))).toBe(false);
    expect(outcome.status).toContain("probe: checking provider health before spending custody");
  }, 120_000);
});

describe("a rehearsal cannot be mistaken for a draw", () => {
  test("a rehearsal aimed at a draw's filename is refused before custody", async () => {
    const corpus = await corpusPromise;
    const outcome = await rehearse({ label: "misnamed", corpus, script: agreeableScript(corpus), aggregateName: "machine-release-aggregate-v9.json" });
    expect((outcome.error as Error).message).toMatch(/rehearsal artifact must be named/);
    expect(existsSync(outcome.artifacts.ledgerPath)).toBe(false);
    expect(outcome.calls.length).toBe(0);
  }, 120_000);

  test("the destination guard refuses both directions", () => {
    expect(() => assertAggregateDestination("/tmp/machine-release-aggregate-v4.json", "rehearsal")).toThrow(/must be named machine-release-rehearsal/);
    expect(() => assertAggregateDestination("/tmp/machine-release-rehearsal-aggregate.json", "live")).toThrow(/must not be written to a rehearsal path/);
    expect(() => assertAggregateDestination("/tmp/machine-release-rehearsal-aggregate.json", "rehearsal")).not.toThrow();
    expect(() => assertAggregateDestination("/tmp/machine-release-aggregate-v4.json", "live")).not.toThrow();
  });

  test("the writer refuses a rehearsal artifact on a draw's path", async () => {
    const root = scratchRoot("writer");
    await expect(writeMachineReleaseAggregate(join(root, "machine-release-aggregate-v9.json"), { executionMode: "rehearsal" }))
      .rejects.toThrow(/must be named machine-release-rehearsal/);
    expect(existsSync(join(root, "machine-release-aggregate-v9.json"))).toBe(false);
  });
});

describe("a synchronous session.prompt throw is reported as a session-creation failure", () => {
  /**
   * `src/reviewer/agent.ts` sets `providerAttempted = true` on the line after
   * `session.prompt` is invoked, so a synchronous throw from that call is
   * indistinguishable from a session that never opened. That mislabels a live
   * provider fault as `session_create_error`, which is the exact label two
   * spent v4 consumptions were diagnosed on.
   *
   * The fix is one line -- move the assignment above the call -- but
   * `src/reviewer/agent.ts` is in `SOURCE_MANIFEST_FILES`, so applying it voids
   * the frozen candidate and forces a fresh development draw. That is an owner
   * decision, not a cleanup.
   *
   * These tests therefore pin the defect deliberately. They assert what the
   * reviewer does today, not what it should do, and they are verified to fail
   * against the corrected ordering. When the owner authorizes the fix, this
   * block is what changes with it; do not "repair" it in place.
   */
  /** Drive the real reviewer against an uninstrumented transport and classify. */
  async function labelFor(reply: RehearsalReply): Promise<{ readonly sessionID: string; readonly providerAttempted: boolean; readonly terminalKind: string }> {
    const transport = createScriptedTransport({ script: () => reply });
    const reviewer = createReviewerAgent({ client: transport.client, timeoutMs: 5_000 });
    try {
      const result = await reviewer.review({ requestID: "machine:pin:1", prompt: "git status" });
      const providerAttempted = result.outcome?.providerAttempted ?? false;
      return {
        sessionID: result.sessionID,
        providerAttempted,
        terminalKind: normalizeMachineTerminalKind({ outcomeKind: result.outcome?.kind, providerAttempted, sessionID: result.sessionID }),
      };
    } finally {
      await reviewer.dispose();
    }
  }

  const failing = (): Error => Object.assign(new Error("rehearsal: transport threw"), { name: "TransportError", status: 502 });

  test("the same failure gets two different labels depending on how it is raised", async () => {
    // Identical failure, identical phase, opposite labels. The session
    // demonstrably opened in both cases, so `session_create_error` is wrong in
    // the first and the label cannot be trusted to separate the two phases.
    const thrown = await labelFor({ kind: "promptThrows", error: failing });
    expect(thrown.sessionID.length).toBeGreaterThan(0);
    expect(thrown.providerAttempted).toBe(false);
    expect(thrown.terminalKind).toBe("session_create_error");

    const rejected = await labelFor({ kind: "promptRejects", error: failing });
    expect(rejected.sessionID.length).toBeGreaterThan(0);
    expect(rejected.providerAttempted).toBe(true);
    expect(rejected.terminalKind).toBe("provider_error");
  });

  test("a genuine session-creation failure is labelled the same way as the mislabelled one", async () => {
    const created = await labelFor({ kind: "createFails", error: failing });
    expect(created.sessionID).toBe("");
    expect(created.terminalKind).toBe("session_create_error");
  });

  test("the release harness records the real phase even though the label is wrong", async () => {
    // `instrumentTransport` wraps the client in an async function, so inside a
    // draw the synchronous throw is observed as a rejection and the fault is
    // attributed to `session.prompt`. That is why a fourth draw can name what
    // failed regardless of how the reviewer labels it.
    const corpus = await corpusPromise;
    const agreeable = agreeableScript(corpus);
    const outcome = await rehearse({
      label: "sync-throw",
      corpus,
      script: (call: RehearsalCall): RehearsalReply =>
        (call.callIndex < CONSECUTIVE_TRANSPORT_FAILURE_LIMIT + MAX_CONCURRENT_REVIEWERS * 2 ? { kind: "promptThrows", error: () => Object.assign(new Error("rehearsal: transport threw"), { name: "TransportError", status: 502 }) } : agreeable(call)),
    });
    // The draw aborts rather than scoring, because the streak counts both
    // transport labels. Before that change this run produced a scored
    // `machine-release-fail` whose only failure was invalid runs -- an outage
    // filed as a classifier verdict, which is the v4 mistake.
    expect(outcome.error).toBeInstanceOf(MachineDrawAbortedError);
    expect(outcome.aggregate).toBeUndefined();
    expect(existsSync(outcome.artifacts.aggregatePath)).toBe(false);
    const record = JSON.parse(readFileSync(machineAbortRecordPath(outcome.artifacts.aggregatePath), "utf8")) as {
      transportFaults: readonly { phase: string; name: string; status: number | null }[];
    };
    const phases = new Set(record.transportFaults.map((fault) => fault.phase));
    // The reviewer called this `session_create_error`; the record says
    // otherwise, and the record is the one a reader can act on.
    expect(phases.has("session.prompt")).toBe(true);
    expect(phases.has("session.create")).toBe(false);
    expect(record.transportFaults[0]).toMatchObject({ name: "TransportError", status: 502 });
  }, 120_000);
});

describe("the draw loop is reachable without a server", () => {
  test("runBlindedDraw scores a scripted transport and disposes it", async () => {
    const corpus = await corpusPromise;
    const blinded = corpus.release.slice(0, 4).map((fixture) => ({ id: fixture.id, command: fixture.command }));
    const transport = createScriptedTransport({ script: () => ({ kind: "answer", decision: "manual", reasonCodes: ["dangerous"] }) });
    const results = await runBlindedDraw({
      blinded,
      onStatus: () => undefined,
      modelProfile: gate.candidate.candidate.modelProfile,
      openTransport: async () => transport,
    });
    expect(results.results.length).toBe(blinded.length * REPEAT_COUNT);
    expect(results.results.every((result) => result.valid)).toBe(true);
    expect(results.transportFaults).toEqual([]);
    expect(transport.disposed()).toBe(true);
  }, 60_000);
});
