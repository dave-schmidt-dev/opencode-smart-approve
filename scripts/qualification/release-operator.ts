/**
 * Attended file-backed release wrapper.
 *
 * The wrapper spends custody before opening the private corpus, validates the
 * stream digest and human-adjudication envelope in memory, and writes only a
 * sanitized aggregate. Development qualification must not import this file's
 * private-input path.
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import {
  validateDevelopmentCandidateReport,
  validateFrozenCandidateManifest,
  type DevelopmentCandidateReport,
  type FrozenCandidateManifest,
} from "../classifier-gate";
import {
  digestPrivateBytes,
  lintReleaseManifest,
  readCustodyLedger,
  runAttendedRelease,
  sanitizePublicAggregate,
  verifySignedConsumptionCommitment,
  writePublicAggregate,
  type AttendedReleaseResult,
  type OpaqueTokenSet,
  type PublicAggregateArtifact,
  type SignedConsumptionCommitment,
} from "./custody";
import {
  parseReleaseCorpus,
  releaseCorpusIdentifiers,
  toPrivateAuthoringManifest,
  type AuthorizedAdjudicator,
  type PrivateReleaseCorpus,
} from "./release-corpus";
import { REPEAT_COUNT } from "./core";

export interface AttendedFileReleaseOptions<TResult extends PublicAggregateArtifact> {
  readonly corpusPath: string;
  readonly candidate: FrozenCandidateManifest;
  readonly developmentReport: DevelopmentCandidateReport;
  /** Private authoring metadata held by the custodian; never written by this wrapper. */
  readonly developmentManifest: unknown;
  /** Custodian-supplied trust binding; the private corpus cannot authorize itself. */
  readonly authorizedAdjudicator: AuthorizedAdjudicator;
  readonly ledgerPath: string;
  readonly publicArtifactPath: string;
  readonly commitment: SignedConsumptionCommitment;
  readonly onStatus?: (status: "spending" | "spent" | "opening_private_input" | "qualifying" | "writing_public_result") => void;
  readonly qualify: (input: PrivateReleaseCorpus, tokens: OpaqueTokenSet, context: AttendedQualificationContext) => Promise<TResult>;
}

export interface AttendedQualificationContext {
  readonly candidateManifestHash: string;
  readonly corpusDigest: string;
  readonly custodyNumber: number;
}

export interface AttendedFileReleaseResult<TResult extends PublicAggregateArtifact> extends AttendedReleaseResult<TResult> {
  readonly corpusDigest: string;
  readonly fixtureCount: number;
  readonly observationCount: number;
}

function readPrivateCorpusAfterSpend(path: string): string {
  const absolute = resolve(path);
  if (!existsSync(absolute) || !statSync(absolute).isFile()) throw new Error("private release corpus is missing or not a regular file");
  return readFileSync(absolute, "utf8");
}

/** Run one attended release from a private file without persisting its records. */
export async function runAttendedFileRelease<TResult extends PublicAggregateArtifact>(options: AttendedFileReleaseOptions<TResult>): Promise<AttendedFileReleaseResult<TResult>> {
  if (!options.authorizedAdjudicator) throw new Error("attended release requires an authorized adjudicator binding");
  const candidate = validateFrozenCandidateManifest(options.candidate);
  const developmentReport = validateDevelopmentCandidateReport(options.developmentReport, candidate);
  if (developmentReport.terminal !== "development-pass") throw new Error("attended release requires a development-pass report");
  if (existsSync(resolve(options.publicArtifactPath))) throw new Error("public release artifact already exists");
  let parsed: PrivateReleaseCorpus | undefined;
  let corpusDigest = "";
  let fixtureCount = 0;
  const result = await runAttendedRelease<string, TResult>({
    ledgerPath: options.ledgerPath,
    commitment: options.commitment,
    onStatus: options.onStatus,
    readPrivateInput: async () => readPrivateCorpusAfterSpend(options.corpusPath),
    qualify: async (bytes, tokens) => {
      corpusDigest = digestPrivateBytes(bytes);
      if (!/^[0-9a-f]{64}$/.test(corpusDigest) || corpusDigest !== options.commitment.corpusDigest || !verifySignedConsumptionCommitment(options.commitment)) throw new Error("private release digest does not match the signed custody commitment");
      parsed = parseReleaseCorpus(JSON.parse(bytes), { authorizedAdjudicator: options.authorizedAdjudicator });
      if (parsed.bindings.candidateManifestHash !== candidate.manifestHash) throw new Error("private release corpus is bound to a different candidate manifest");
      if (!parsed.releaseEligible) throw new Error("automated draft corpus is not eligible for release");
      const manifest = toPrivateAuthoringManifest(parsed, options.developmentManifest, { authorizedAdjudicator: options.authorizedAdjudicator });
      const lint = lintReleaseManifest(manifest);
      if (!lint.accepted) throw new Error(`private release corpus failed authoring lint: ${lint.errors.join("; ")}`);
      fixtureCount = parsed.release.length;
      const spentLedger = readCustodyLedger(options.ledgerPath);
      const aggregate = await options.qualify(parsed, tokens, {
        candidateManifestHash: candidate.manifestHash,
        corpusDigest,
        custodyNumber: spentLedger.consumptionNumber,
      });
      const sanitized = sanitizePublicAggregate(aggregate, releaseCorpusIdentifiers(parsed, { authorizedAdjudicator: options.authorizedAdjudicator }));
      if (sanitized.corpusDigest !== corpusDigest || sanitized.custodyNumber !== spentLedger.consumptionNumber) throw new Error("public aggregate is not bound to the signed corpus digest and custody number");
      return sanitized as TResult;
    },
  });
  if (!parsed) throw new Error("private release corpus was not opened");
  writePublicAggregate(options.publicArtifactPath, result.publicArtifact, releaseCorpusIdentifiers(parsed, { authorizedAdjudicator: options.authorizedAdjudicator }));
  return { ...result, corpusDigest, fixtureCount, observationCount: fixtureCount * REPEAT_COUNT };
}

/** The CLI deliberately has no unattended key or provider callback path. */
export async function main(argv = process.argv.slice(2)): Promise<number> {
  if (!argv.includes("--attended")) {
    console.error("release operator requires explicit attended mode");
    return 1;
  }
  console.error("release operator requires an in-process qualification callback and custodian-supplied commitment");
  return 1;
}

if (import.meta.main) process.exit(await main());
