import { describe, expect, jest, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { generateKeyPairSync } from "node:crypto";
import { join } from "node:path";
import {
  CUSTODY_LEDGER_SCHEMA_VERSION,
  PUBLIC_FAILURE_SCHEMA_VERSION,
  PUBLIC_PASS_SCHEMA_VERSION,
  PUBLIC_VERIFICATION_STATUS,
  RELEASE_MANIFEST_SCHEMA_VERSION,
  appendReleaseDecisionCommitment,
  canonical,
  createOpaqueTokenSet,
  createPrivateRecomputationReceipt,
  createPublicAttestation,
  createSignedConsumptionCommitment,
  digestPrivateBytes,
  digestOrderedObservations,
  initializeCustodyLedger,
  lintReleaseManifest,
  main,
  publicVerificationStatus,
  readCustodyLedger,
  recoverCustodyBeforeInput,
  runAttendedRelease,
  sanitizePublicAggregate,
  sha256,
  spendBeforePrivateInput,
  validatePrivateRecomputationReceipt,
  validatePublicAttestation,
  verifySignedConsumptionCommitment,
  writePublicAggregate,
  type AuthoringFixture,
  type PublicAggregateArtifact,
} from "../../scripts/qualification/custody";

function root(): string {
  return mkdtempSync(join(process.env.TMPDIR ?? "/tmp", "smart-approve-custody-"));
}

function commitment(corpus = digestPrivateBytes("synthetic-corpus"), consumptionNumber = 1) {
  const pair = generateKeyPairSync("ed25519");
  return createSignedConsumptionCommitment({ corpusDigest: corpus, consumptionNumber, privateKey: pair.privateKey, publicKey: pair.publicKey });
}

function publicAggregate(outcome: "pass" | "failure" = "pass"): PublicAggregateArtifact {
  const base = {
    verification: PUBLIC_VERIFICATION_STATUS,
    custodyNumber: 1,
    corpusDigest: "a".repeat(64),
    aggregateDigest: "b".repeat(64),
    faultGate: outcome === "pass" ? "pass" as const : "fail" as const,
    classifierDenominator: outcome === "pass" ? 1 : 0,
    invalidRunCount: outcome === "pass" ? 0 : 1,
    canaryLeakCount: 0 as const,
    publicToken: "public_synthetic-token",
  };
  return outcome === "pass"
    ? { schemaVersion: PUBLIC_PASS_SCHEMA_VERSION, outcome, ...base }
    : { schemaVersion: PUBLIC_FAILURE_SCHEMA_VERSION, outcome, failureCode: "fault_gate", ...base };
}

function authoringFixtures(prefix: string, stratum: AuthoringFixture["stratum"], category: AuthoringFixture["category"], count: number): AuthoringFixture[] {
  return Array.from({ length: count }, (_, index) => {
    const safety = category === "secret";
    return {
      id: `${prefix}-${category}-${index}`,
      category,
      expectedDecision: category === "benign" ? "allow" : "manual",
      stratum,
      structuralKey: `${prefix}-shape-${category}-${index}`,
      route: safety ? "deterministic" : "reviewer",
      providerAttempted: !safety,
    };
  });
}

function manifest() {
  const categories: Array<[AuthoringFixture["category"], number]> = [["benign", 40], ["dangerous", 15], ["ambiguous", 10], ["injection", 10], ["secret", 10], ["obfuscated", 10]];
  const development = categories.flatMap(([category, count]) => authoringFixtures("dev", "qualification", category, count));
  const release = categories.flatMap(([category, count]) => authoringFixtures("release", "qualification", category, count));
  const generalization = authoringFixtures("generalization", "generalization", "benign", 1);
  return {
    schemaVersion: RELEASE_MANIFEST_SCHEMA_VERSION,
    development,
    release,
    generalization,
    developmentDigest: "1".repeat(64),
    releaseDigest: "2".repeat(64),
  };
}

describe("one-use qualification custody", () => {
  test("signed commitments verify and monotonic public decisions reject reuse", () => {
    const base = commitment();
    expect(verifySignedConsumptionCommitment(base)).toBe(true);
    const path = join(root(), "decisions.json");
    try {
      expect(appendReleaseDecisionCommitment(path, base).entries).toHaveLength(1);
      expect(() => appendReleaseDecisionCommitment(path, base)).toThrow(/already consumed/);
      const next = commitment(digestPrivateBytes("synthetic-corpus-two"), 2);
      expect(appendReleaseDecisionCommitment(path, next).entries).toHaveLength(2);
      const nonIncreasing = commitment(digestPrivateBytes("synthetic-corpus-three"), 2);
      expect(() => appendReleaseDecisionCommitment(path, nonIncreasing)).toThrow(/not increasing/);
    } finally {
      rmSync(path, { force: true });
      rmSync(dirnameOf(path), { recursive: true, force: true });
    }
  });

  test("ledger has one exclusive writer, durable fsync order, and spends before private input", async () => {
    const directory = root();
    const ledgerPath = join(directory, "ledger.json");
    const events: string[] = [];
    initializeCustodyLedger(ledgerPath);
    const signed = commitment();
    const statuses: string[] = [];
    const result = await runAttendedRelease({
      ledgerPath,
      commitment: signed,
      durability: { onEvent: (event) => events.push(event.name) },
      onStatus: (status) => statuses.push(status),
      readPrivateInput: async () => "synthetic-private-stream",
      qualify: async (_input, tokens) => {
        expect(tokens.coordinatorToken).toMatch(/^coord_[a-f0-9-]{36}$/);
        return publicAggregate();
      },
    });
    expect(result.ledger.state).toBe("spent");
    expect(statuses.indexOf("spent")).toBeLessThan(statuses.indexOf("opening_private_input"));
    expect(events.indexOf("spent")).toBeLessThan(events.indexOf("private_input_open"));
    expect(events).toContain("file_fsync");
    expect(events).toContain("parent_fsync");
    expect(() => spendBeforePrivateInput(ledgerPath, signed)).toThrow(/spent/);
    expect(() => {
      const lock = join(directory, "ledger.json.lock");
      writeFileSync(lock, "held", { flag: "wx" });
      try { spendBeforePrivateInput(ledgerPath, signed); } finally { rmSync(lock, { force: true }); }
    }).toThrow(/spent|exclusively held/);
    rmSync(directory, { recursive: true, force: true });
  });

  test("recovery marks a reserved transaction spent before the next input open", () => {
    const directory = root();
    const ledgerPath = join(directory, "ledger.json");
    const signed = commitment();
    initializeCustodyLedger(ledgerPath);
    writeFileSync(ledgerPath, JSON.stringify({
      schemaVersion: CUSTODY_LEDGER_SCHEMA_VERSION,
      state: "reserved",
      consumptionNumber: 1,
      corpusDigest: signed.corpusDigest,
      commitmentHash: sha256(canonical(signed)),
      updatedAt: new Date().toISOString(),
    }));
    const events: string[] = [];
    const recovered = recoverCustodyBeforeInput(ledgerPath, { onEvent: (event) => events.push(event.name) });
    expect(recovered.state).toBe("spent");
    expect(events.indexOf("spent")).toBeGreaterThanOrEqual(0);
    expect(readCustodyLedger(ledgerPath).state).toBe("spent");
    rmSync(directory, { recursive: true, force: true });
  });

  test("failures after spending leave the ledger spent and never reopen input", async () => {
    const directory = root();
    const ledgerPath = join(directory, "ledger.json");
    const signed = commitment();
    initializeCustodyLedger(ledgerPath);
    await expect(runAttendedRelease({
      ledgerPath,
      commitment: signed,
      readPrivateInput: async () => { throw new Error("synthetic read failure"); },
      qualify: async () => publicAggregate(),
    })).rejects.toThrow(/synthetic read failure/);
    expect(readCustodyLedger(ledgerPath).state).toBe("spent");
    rmSync(directory, { recursive: true, force: true });
  });

  test("qualifying callbacks emit bounded heartbeats until they finish", async () => {
    const directory = root();
    jest.useFakeTimers();
    try {
      const ledgerPath = join(directory, "ledger.json");
      const signed = commitment();
      initializeCustodyLedger(ledgerPath);
      const statuses: string[] = [];
      let finish: (() => void) | undefined;
      const pending = new Promise<PublicAggregateArtifact>((resolve) => { finish = () => resolve(publicAggregate()); });
      const operation = runAttendedRelease({
        ledgerPath,
        commitment: signed,
        qualificationHeartbeatMs: 5,
        onStatus: (status) => statuses.push(status),
        readPrivateInput: async () => "synthetic-private-stream",
        qualify: async () => pending,
      });
      await Promise.resolve();
      jest.advanceTimersByTime(15);
      expect(statuses.filter((status) => status === "qualifying").length).toBe(4);
      finish?.();
      await operation;
      expect(statuses.at(-1)).toBe("writing_public_result");
    } finally {
      jest.useRealTimers();
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("opening private input emits bounded heartbeats until it finishes", async () => {
    const directory = root();
    jest.useFakeTimers();
    try {
      const ledgerPath = join(directory, "ledger.json");
      const signed = commitment();
      initializeCustodyLedger(ledgerPath);
      const statuses: string[] = [];
      let finishInput: ((input: string) => void) | undefined;
      const pendingInput = new Promise<string>((resolve) => { finishInput = resolve; });
      const operation = runAttendedRelease({
        ledgerPath,
        commitment: signed,
        qualificationHeartbeatMs: 5,
        onStatus: (status) => statuses.push(status),
        readPrivateInput: async () => pendingInput,
        qualify: async () => publicAggregate(),
      });
      await Promise.resolve();
      jest.advanceTimersByTime(15);
      expect(statuses.filter((status) => status === "opening_private_input").length).toBe(4);
      finishInput?.("synthetic-private-stream");
      await operation;
      expect(statuses.at(-1)).toBe("writing_public_result");
    } finally {
      jest.useRealTimers();
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("status observer failures cannot abort a spent release", async () => {
    const directory = root();
    try {
      const ledgerPath = join(directory, "ledger.json");
      initializeCustodyLedger(ledgerPath);
      const result = await runAttendedRelease({
        ledgerPath,
        commitment: commitment(),
        onStatus: () => { throw new Error("synthetic status sink failure"); },
        readPrivateInput: async () => "synthetic-private-stream",
        qualify: async () => publicAggregate(),
      });
      expect(result.ledger.state).toBe("spent");
      expect(readCustodyLedger(ledgerPath).state).toBe("spent");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("async status observer failures cannot escape a spent release", async () => {
    const directory = root();
    const unhandled: unknown[] = [];
    const onUnhandledRejection = (reason: unknown) => unhandled.push(reason);
    process.on("unhandledRejection", onUnhandledRejection);
    try {
      const ledgerPath = join(directory, "ledger.json");
      initializeCustodyLedger(ledgerPath);
      const result = await runAttendedRelease({
        ledgerPath,
        commitment: commitment(),
        onStatus: async () => { throw new Error("synthetic async status sink failure"); },
        readPrivateInput: async () => "synthetic-private-stream",
        qualify: async () => publicAggregate(),
      });
      await new Promise((resolve) => setTimeout(resolve, 0));
      expect(result.ledger.state).toBe("spent");
      expect(unhandled).toEqual([]);
    } finally {
      process.off("unhandledRejection", onUnhandledRejection);
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("qualifying heartbeat is cleared when qualification rejects", async () => {
    const directory = root();
    jest.useFakeTimers();
    try {
      const ledgerPath = join(directory, "ledger.json");
      const signed = commitment();
      initializeCustodyLedger(ledgerPath);
      const statuses: string[] = [];
      let fail: ((error: Error) => void) | undefined;
      const pending = new Promise<PublicAggregateArtifact>((_, reject) => { fail = reject; });
      const operation = runAttendedRelease({
        ledgerPath,
        commitment: signed,
        qualificationHeartbeatMs: 5,
        onStatus: (status) => statuses.push(status),
        readPrivateInput: async () => "synthetic-private-stream",
        qualify: async () => pending,
      });
      await Promise.resolve();
      jest.advanceTimersByTime(10);
      const heartbeatCount = statuses.filter((status) => status === "qualifying").length;
      expect(heartbeatCount).toBe(3);
      fail?.(new Error("synthetic qualification failure"));
      await expect(operation).rejects.toThrow(/synthetic qualification failure/);
      jest.advanceTimersByTime(100);
      expect(statuses.filter((status) => status === "qualifying").length).toBe(heartbeatCount);
      expect(readCustodyLedger(ledgerPath).state).toBe("spent");
    } finally {
      jest.useRealTimers();
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("public pass/failure writers reject private fields and retain only aggregates", () => {
    const directory = root();
    try {
      const passPath = join(directory, "pass.json");
      const failurePath = join(directory, "failure.json");
      expect(writePublicAggregate(passPath, publicAggregate(), ["SYNTHETIC_CANARY"])).toEqual(publicAggregate());
      expect(writePublicAggregate(failurePath, publicAggregate("failure"))).toMatchObject({ schemaVersion: PUBLIC_FAILURE_SCHEMA_VERSION, outcome: "failure" });
      expect(readFileSync(passPath, "utf8")).not.toContain("SYNTHETIC_CANARY");
      expect(() => sanitizePublicAggregate({ ...publicAggregate(), faultGate: "SYNTHETIC_CANARY" } as never, ["SYNTHETIC_CANARY"])).toThrow(/forbidden private identifier/);
      expect(() => sanitizePublicAggregate({ ...publicAggregate(), records: [] } as never)).toThrow(/forbidden|per-invocation/);
      expect(() => writePublicAggregate(join(directory, "bad.json"), { ...publicAggregate(), command: "secret" } as never)).toThrow(/forbidden/);
      expect(() => writePublicAggregate(join(directory, "unknown.json"), { ...publicAggregate(), providerOutput: "secret" } as never)).toThrow(/unknown or missing/);
      expect(() => writePublicAggregate(passPath, publicAggregate())).toThrow(/EEXIST/);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("private receipt and countersigned attestation require the human custodian gate", () => {
    const receipt = createPrivateRecomputationReceipt({
      custodyNumber: 1,
      corpusDigest: "a".repeat(64),
      orderedObservationDigest: digestOrderedObservations(["obs_1", "obs_2"]),
      recomputedAggregateDigest: "b".repeat(64),
      publicAttestationHash: "c".repeat(64),
      commitmentHash: "d".repeat(64),
    });
    expect(validatePrivateRecomputationReceipt(receipt)).toBe(true);
    const attestation = createPublicAttestation({
      decision: "reject",
      custodianID: "custodian-synthetic",
      custodyNumber: 1,
      privateReceiptHash: receipt.receiptHash,
      countersignature: "human-countersignature-synthetic",
      signedCommitmentHash: "d".repeat(64),
    });
    expect(validatePublicAttestation(attestation, receipt, "custodian-synthetic")).toBe(true);
    expect(publicVerificationStatus()).toBe("not_independently_recomputable");
    expect(() => createPublicAttestation({ ...attestation, countersignature: "" })).toThrow(/countersignature/);
  });

  test("authoring lint enforces category minimums, disjointness, safety routing, and generalization", () => {
    const valid = manifest();
    const result = lintReleaseManifest(valid);
    expect(result).toMatchObject({ accepted: true, errors: [] });
    const duplicate = structuredClone(valid) as any;
    duplicate.release[0].id = duplicate.development[0].id;
    expect(lintReleaseManifest(duplicate).accepted).toBe(false);
    const unsafe = structuredClone(valid) as any;
    unsafe.development.find((fixture: AuthoringFixture) => fixture.category === "secret").route = "reviewer";
    expect(lintReleaseManifest(unsafe).errors.join(";")).toContain("secret/error");
    const noGeneralization = structuredClone(valid) as any;
    noGeneralization.generalization = [];
    expect(lintReleaseManifest(noGeneralization).errors.join(";")).toContain("generalization");
  });

  test("CLI release mode refuses unattended key or private-input handling", async () => {
    expect(await main(["--release-stdin"])).toBe(1);
    expect(createOpaqueTokenSet().auditToken).toMatch(/^audit_[a-f0-9-]{36}$/);
  });
});

function dirnameOf(path: string): string {
  return path.slice(0, path.lastIndexOf("/"));
}
