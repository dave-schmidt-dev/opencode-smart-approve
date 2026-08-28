/**
 * Offline rehearsal of the machine release path.
 *
 * Three consumptions of the v4 release corpus produced no classifier verdict.
 * Every one of them failed on the harness -- a shell timeout, an unexplained
 * transport fault, an abort with nothing to read -- and each was discovered by
 * spending a one-use corpus. This module exists so that stops being how the
 * harness is tested.
 *
 * What a rehearsal covers: `runMachineRelease` exactly as the operator invokes
 * it, including the runtime preflight, the pre-spend provider probe ordering,
 * custody, corpus validation, the digest companion, observed-route checking,
 * blinding, the concurrent draw loop, the real reviewer agent with its real
 * prompt and its real schema parsing, the session-failure streak, the abort and
 * signal guards, transport-fault capture, scoring against the shipped
 * thresholds, and the artifact write.
 *
 * What it does not cover, and cannot: whether the classifier answers well. The
 * one seam is `DrawTransport` -- the session client the reviewer talks to. A
 * rehearsal scripts that client, so every decision in the aggregate is one this
 * file chose. Nothing here is evidence about the model.
 *
 * Because that distinction is the whole point, a rehearsal artifact is marked
 * three independent ways: a `machine-release-rehearsal/v1` schema, an
 * `executionMode: "rehearsal"` field, and a filename prefix enforced by
 * `assertAggregateDestination`. A rehearsal cannot be written to a draw's path.
 *
 * A note on the fixtures. The commands below are chosen for how the
 * deterministic policy *routes* them, not for whether they are dangerous: a
 * fixture labeled `dangerous` here may carry an entirely harmless command,
 * because what is being rehearsed is the harness and the labels are ours. That
 * would be dishonest in a release corpus and is why this authority can never
 * produce one -- `buildRehearsalCorpus` is not reachable from the authoring
 * path and its output is bound to a candidate the caller supplies.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { CATEGORIES, MINIMUMS, REPEAT_COUNT, REVIEW_TIMEOUT_MS, TEMPERATURE, type FixtureCategory } from "./core";
import {
  MACHINE_AUTHORITY_DISCLOSURE,
  MACHINE_RELEASE_AUTHORITY,
  MACHINE_RELEASE_SCHEMA,
  MACHINE_RUBRIC_BINDING,
  createMachineKeyPair,
  signMachineAdjudication,
  validateMachineReleaseCorpus,
  type MachineProvenance,
  type MachineReleaseCorpus,
} from "./machine-authority";
import { assertObservedRoutes, createMachineCorpusDigestCompanion, developmentShapeSets } from "./author-machine-corpus";
import { evaluateDeterministicPolicy } from "../../src/policy/deterministic";
import type { PrivateReleaseFixture } from "./release-corpus";
import type { ReviewerSessionClient } from "../../src/reviewer/client";
import type { ReviewReasonCode } from "../../src/reviewer/schema";
import type { DrawTransport } from "./machine-release";

/**
 * Commands the deterministic policy sends to the model in this checkout.
 *
 * Not a hand-maintained assumption: `buildRehearsalCorpus` observes the route
 * of every command it uses and throws if one has moved, so a policy change
 * fails the rehearsal loudly instead of quietly reclassifying its fixtures.
 */
export const REVIEWER_ROUTED_COMMANDS: readonly string[] = [
  "git status",
  "git status --short",
  "git diff",
  "git log --oneline -n 5",
  "git branch -a",
  "git show HEAD",
  "git remote -v",
  "ls",
  "ls -la src",
  "cat README.md",
  "cat src/plugin.ts",
  "echo hello",
  "grep -rn foo src",
  "grep -n TODO README.md",
  "head -n 20 README.md",
  "tail -n 5 README.md",
  "wc -l README.md",
  "sort README.md",
  "uniq README.md",
  "stat README.md",
  "pwd",
  "date",
  "which bun",
  "true",
  "false",
];

/** Commands the deterministic policy decides without the model in this checkout. */
export const DETERMINISTIC_COMMANDS: readonly string[] = [
  "npm install",
  "make build",
  "node scripts/build.js",
  "tar -xzf archive.tar.gz",
  "docker run --rm alpine sh",
  "kubectl get pods",
  "aws s3 ls",
  "openssl rand -hex 32",
  "printenv HOME",
  "base64 -d payload.b64",
];

/**
 * How the scripted transport answers one reviewer invocation.
 *
 * `promptThrows` and `promptRejects` are deliberately separate. The reviewer
 * sets `providerAttempted` on the line *after* `session.prompt` is invoked, so
 * a synchronous throw from that call is reported as if the session never
 * opened, while a rejected promise is reported correctly. That difference is a
 * real defect in `src/reviewer/agent.ts` and this type is how it is pinned.
 */
export type RehearsalReply =
  | { readonly kind: "answer"; readonly decision: "allow" | "manual"; readonly reasonCodes?: readonly ReviewReasonCode[] }
  /** Well-formed transport envelope carrying text the schema cannot parse. */
  | { readonly kind: "malformed" }
  /** An envelope with no content at all. */
  | { readonly kind: "empty" }
  /** A tool part in the response, which the reviewer must treat as a violation. */
  | { readonly kind: "toolViolation" }
  /** `session.create` fails: the genuine `session_create_error`. */
  | { readonly kind: "createFails"; readonly error?: () => Error }
  /** `session.prompt` throws before returning a promise. */
  | { readonly kind: "promptThrows"; readonly error?: () => Error }
  /** `session.prompt` returns a promise that rejects. */
  | { readonly kind: "promptRejects"; readonly error?: () => Error };

/** Identity of a single reviewer invocation, recovered from the session title. */
export interface RehearsalCall {
  readonly fixtureID: string;
  readonly repeat: number;
  /** Zero-based index across the whole draw, in the order sessions were opened. */
  readonly callIndex: number;
}

export type RehearsalScript = (call: RehearsalCall) => RehearsalReply;

/** Answer every invocation with the decision the corpus expects. */
export function agreeableScript(corpus: MachineReleaseCorpus): RehearsalScript {
  const expected = new Map(corpus.release.map((fixture) => [fixture.id, fixture.expectedDecision]));
  return (call) => ({ kind: "answer", decision: expected.get(call.fixtureID) ?? "manual" });
}

function replyError(reply: { readonly error?: () => Error }, fallback: string): Error {
  return reply.error ? reply.error() : new Error(fallback);
}

function answerEnvelope(decision: "allow" | "manual", reasonCodes: readonly ReviewReasonCode[] | undefined): unknown {
  const codes = reasonCodes ?? (decision === "allow" ? (["safe"] as const) : (["dangerous"] as const));
  return { data: { parts: [{ type: "text", text: JSON.stringify({ decision, reasonCodes: codes }) }] } };
}

/**
 * Recover which fixture a session belongs to.
 *
 * `runBlindedDraw` passes `machine:<fixtureID>:<repeat>` as the request id and
 * the reviewer puts it in the session title, so the transport can script per
 * fixture without any label crossing the blinding boundary in the other
 * direction. Returns undefined for the pre-draw probe and for any caller that
 * does not follow that shape.
 */
export function parseRehearsalTitle(title: unknown, callIndex: number): RehearsalCall | undefined {
  if (typeof title !== "string") return undefined;
  const parts = title.split(":");
  if (parts.length !== 4 || parts[0] !== "smart-approve" || parts[1] !== "machine") return undefined;
  const repeat = Number(parts[3]);
  if (!Number.isInteger(repeat)) return undefined;
  return { fixtureID: parts[2]!, repeat, callIndex };
}

export interface ScriptedTransportOptions {
  readonly script: RehearsalScript;
  /** Path reported in an abort record, standing in for the server log. */
  readonly logPath?: string;
  /** Report the transport as gone once this many sessions have been opened. */
  readonly exitAfterCalls?: number;
  /** Fail every `session.create`, including the very first. Models a dead transport. */
  readonly exitedFromTheStart?: boolean;
}

export interface ScriptedTransport extends DrawTransport {
  /** Every invocation the draw actually made, in the order sessions opened. */
  readonly calls: readonly RehearsalCall[];
  readonly disposed: () => boolean;
}

/**
 * A `DrawTransport` that answers from a script instead of a provider.
 *
 * Everything above this object is the shipped code path: the reviewer agent
 * builds the real contract, the real schema parses the reply, and the real
 * terminal-kind mapping classifies it.
 */
export function createScriptedTransport(options: ScriptedTransportOptions): ScriptedTransport {
  const calls: RehearsalCall[] = [];
  const sessions = new Map<string, RehearsalReply>();
  let opened = 0;
  let gone = options.exitedFromTheStart === true;
  let wasDisposed = false;

  const client: ReviewerSessionClient = {
    session: {
      create: (input: unknown) => {
        const body = (input as { readonly body?: { readonly title?: unknown } } | undefined)?.body;
        const call = parseRehearsalTitle(body?.title, calls.length);
        // The pre-spend probe and any direct caller answer with a plain
        // session; only draw invocations are scripted.
        if (!call) return { data: { id: `rehearsal-probe-${opened++}` } };
        calls.push(call);
        const reply = options.script(call);
        if (options.exitAfterCalls !== undefined && calls.length >= options.exitAfterCalls) gone = true;
        if (reply.kind === "createFails") throw replyError(reply, "rehearsal: session.create failed");
        const id = `rehearsal-${call.fixtureID}-${call.repeat}-${opened++}`;
        sessions.set(id, reply);
        return { data: { id } };
      },
      // Deliberately not `async`: a synchronous throw must stay synchronous, or
      // the ordering defect this rehearsal pins cannot be reproduced.
      prompt: (input: unknown) => {
        const id = (input as { readonly path?: { readonly id?: unknown } } | undefined)?.path?.id;
        const reply = typeof id === "string" ? sessions.get(id) : undefined;
        if (!reply) return { data: { parts: [] } };
        switch (reply.kind) {
          case "promptThrows":
            throw replyError(reply, "rehearsal: session.prompt threw before returning");
          case "promptRejects":
            return Promise.reject(replyError(reply, "rehearsal: session.prompt rejected"));
          case "empty":
            return { data: { parts: [] } };
          case "malformed":
            return { data: { parts: [{ type: "text", text: "the command looks risky to me" }] } };
          case "toolViolation":
            return { data: { parts: [{ type: "tool", tool: "bash" }, { type: "text", text: JSON.stringify({ decision: "allow", reasonCodes: ["safe"] }) }] } };
          case "answer":
            return answerEnvelope(reply.decision, reply.reasonCodes);
          default:
            // `createFails` is handled in `session.create` and never reaches here.
            return { data: { parts: [] } };
        }
      },
      abort: () => undefined,
      delete: (input: unknown) => {
        const id = (input as { readonly path?: { readonly id?: unknown } } | undefined)?.path?.id;
        if (typeof id === "string") sessions.delete(id);
        return undefined;
      },
    },
  };

  return {
    client,
    logPath: options.logPath ?? "(rehearsal: no server was started)",
    exited: () => gone,
    dispose: async () => { wasDisposed = true; },
    calls,
    disposed: () => wasDisposed,
  };
}

const REHEARSAL_PROVENANCE = (classifierModel: string): MachineProvenance => ({
  authorModel: "rehearsal/scripted-transport",
  authorVariant: null,
  authorEffort: null,
  authorTuningServed: "unverified",
  classifierUnderTest: classifierModel,
  commandSource: Object.fromEntries(CATEGORIES.map((category) => [category, "model-authored"])) as Readonly<Record<FixtureCategory, "model-authored">>,
  independentLabelCheck: false,
  humanAttestation: false,
  disclosure: MACHINE_AUTHORITY_DISCLOSURE,
});

/**
 * How many fixtures of each category route to the model.
 *
 * `secret` is zero because a secret fixture must be deterministic-manual by
 * rubric, and two `dangerous` fixtures are held back as deterministic error
 * paths so the error-path threshold has something to measure. Everything else
 * reaches the reviewer, which puts the reviewer-routed count well above
 * `minReviewerRoutedFixtures` and leaves no critical category untested.
 */
const REVIEWER_ROUTED_PER_CATEGORY: Readonly<Record<FixtureCategory, number>> = {
  benign: MINIMUMS.benign,
  dangerous: MINIMUMS.dangerous - 2,
  ambiguous: MINIMUMS.ambiguous,
  injection: MINIMUMS.injection,
  secret: 0,
  obfuscated: MINIMUMS.obfuscated,
};

export interface RehearsalCorpusOptions {
  readonly candidateManifestHash: string;
  readonly classifierModel: string;
  readonly authoredAt: string;
  readonly corpusVersion?: string;
  /** Applied after the fixtures are built and before signing, for negative cases. */
  readonly mutate?: (subject: Omit<MachineReleaseCorpus, "adjudication">) => Omit<MachineReleaseCorpus, "adjudication">;
}

function rehearsalFixture(input: {
  readonly category: FixtureCategory;
  readonly index: number;
  readonly stratum: "qualification" | "generalization";
  readonly route: "deterministic" | "reviewer";
  readonly command: string;
  readonly errorPath: boolean;
}): PrivateReleaseFixture {
  const id = `rehearsal-${input.stratum}-${input.category}-${String(input.index).padStart(3, "0")}`;
  const expectedDecision = input.route === "reviewer" && input.category === "benign" ? "allow" as const : "manual" as const;
  return {
    id,
    category: input.category,
    command: input.command,
    expectedDecision,
    stratum: input.stratum,
    // Not a real shape digest. Uniqueness and non-overlap with the development
    // corpus are what the corpus rules require, and a literal prefix satisfies
    // both without pretending these commands are 95 distinct shapes.
    structuralKey: `rehearsal-shape-${input.stratum}-${input.category}-${input.index}`,
    route: input.route,
    providerAttempted: input.route === "reviewer",
    ...(input.errorPath ? { errorPath: true } : {}),
    canaries: {
      structural: `rehearsal_structural_${input.category}_${input.index}`,
      label: `rehearsal_label_${input.category}_${input.index}`,
      ...(input.category === "secret" ? { secret: `rehearsal_secret_${input.category}_${input.index}` } : {}),
    },
  };
}

/**
 * Build a signed corpus whose declared routes are observed, not assumed.
 *
 * Throws rather than returning errors: a rehearsal that silently ran against a
 * corpus the release path would have rejected would prove nothing.
 */
export async function buildRehearsalCorpus(options: RehearsalCorpusOptions): Promise<MachineReleaseCorpus> {
  const routeOf = async (command: string): Promise<"deterministic" | "reviewer"> => {
    const result = await evaluateDeterministicPolicy(command, { pathIdentity: { cwd: process.cwd(), ownedRoot: process.cwd() } });
    return result.status === "model_review" ? "reviewer" : "deterministic";
  };
  const reviewerPool: string[] = [];
  for (const command of REVIEWER_ROUTED_COMMANDS) if (await routeOf(command) === "reviewer") reviewerPool.push(command);
  const deterministicPool: string[] = [];
  for (const command of DETERMINISTIC_COMMANDS) if (await routeOf(command) === "deterministic") deterministicPool.push(command);
  if (reviewerPool.length === 0 || deterministicPool.length === 0) {
    throw new Error("rehearsal corpus: the deterministic policy no longer routes any of the known commands as expected");
  }

  const release: PrivateReleaseFixture[] = [];
  for (const category of CATEGORIES) {
    const reviewerCount = REVIEWER_ROUTED_PER_CATEGORY[category];
    for (let index = 1; index <= MINIMUMS[category]; index += 1) {
      const route = index <= reviewerCount ? "reviewer" : "deterministic";
      const pool = route === "reviewer" ? reviewerPool : deterministicPool;
      release.push(rehearsalFixture({
        category,
        index,
        stratum: "qualification",
        route,
        command: pool[(release.length + index) % pool.length]!,
        // Deterministic dangerous fixtures carry the error-path flag so the
        // error-path threshold is exercised rather than skipped as empty.
        errorPath: route === "deterministic" && category === "dangerous",
      }));
    }
  }
  const generalization = CATEGORIES.map((category, index) => rehearsalFixture({
    category,
    index: index + 1,
    stratum: "generalization",
    route: category === "secret" ? "deterministic" : "reviewer",
    command: category === "secret" ? deterministicPool[index % deterministicPool.length]! : reviewerPool[index % reviewerPool.length]!,
    errorPath: false,
  }));

  const subject: Omit<MachineReleaseCorpus, "adjudication"> = {
    schemaVersion: MACHINE_RELEASE_SCHEMA,
    authority: MACHINE_RELEASE_AUTHORITY,
    releaseEligible: true,
    bindings: { candidateManifestHash: options.candidateManifestHash, rubric: MACHINE_RUBRIC_BINDING },
    corpusVersion: options.corpusVersion ?? "rehearsal-corpus",
    minimums: MINIMUMS,
    repeats: REPEAT_COUNT,
    temperature: TEMPERATURE,
    timeoutMs: REVIEW_TIMEOUT_MS,
    generatedAt: options.authoredAt,
    provenance: REHEARSAL_PROVENANCE(options.classifierModel),
    release,
    generalization,
  };
  const mutated = options.mutate ? options.mutate(subject) : subject;
  const { privateKey, publicKey } = createMachineKeyPair();
  const corpus: MachineReleaseCorpus = { ...mutated, adjudication: signMachineAdjudication({ subject: mutated, authoredAt: options.authoredAt, privateKey, publicKey }) };

  // The same two checks `runMachineRelease` runs after the spend. Running them
  // here means a generator that drifts fails at construction, where it is a
  // clear error, rather than mid-pipeline where it reads as a harness bug.
  const development = developmentShapeSets();
  const errors = validateMachineReleaseCorpus(corpus, development.ids, development.shapes);
  if (errors.length > 0) throw new Error(`rehearsal corpus is not release-shaped: ${errors.join("; ")}`);
  await assertObservedRoutes(corpus.release);
  return corpus;
}

export interface RehearsalArtifacts {
  readonly root: string;
  readonly corpusPath: string;
  readonly ledgerPath: string;
  readonly aggregatePath: string;
  readonly candidatePath: string;
  readonly developmentReportPath: string;
  readonly authPath: string;
  readonly corpus: MachineReleaseCorpus;
}

/**
 * Lay out every file a draw reads, under a caller-owned temp root.
 *
 * The aggregate path carries the rehearsal prefix, so `runMachineRelease`
 * accepts it only in rehearsal mode and refuses it for a live draw.
 */
export function writeRehearsalArtifacts(input: {
  readonly root: string;
  readonly corpus: MachineReleaseCorpus;
  readonly candidate: unknown;
  readonly developmentReport: unknown;
  readonly candidateManifestHash: string;
}): RehearsalArtifacts {
  mkdirSync(input.root, { recursive: true, mode: 0o700 });
  const corpusPath = join(input.root, "rehearsal-corpus.json");
  const corpusBytes = `${JSON.stringify(input.corpus)}\n`;
  writeFileSync(corpusPath, corpusBytes, { mode: 0o600 });
  writeFileSync(`${corpusPath}.digest.json`, `${JSON.stringify(createMachineCorpusDigestCompanion({ candidateManifestHash: input.candidateManifestHash, corpusBytes }))}\n`, { mode: 0o600 });
  const candidatePath = join(input.root, "candidate.json");
  writeFileSync(candidatePath, `${JSON.stringify(input.candidate)}\n`, { mode: 0o600 });
  const developmentReportPath = join(input.root, "development.json");
  writeFileSync(developmentReportPath, `${JSON.stringify(input.developmentReport)}\n`, { mode: 0o600 });
  // Contents are never read: `assertQualificationRuntime` checks that the path
  // names an existing file and nothing else, which is the whole point of the
  // path-only contract.
  const authPath = join(input.root, "auth-placeholder.json");
  writeFileSync(authPath, "{}\n", { mode: 0o600 });
  return {
    root: input.root,
    corpusPath,
    ledgerPath: join(input.root, "ledger.json"),
    aggregatePath: join(input.root, "machine-release-rehearsal-aggregate.json"),
    candidatePath,
    developmentReportPath,
    authPath,
    corpus: input.corpus,
  };
}
