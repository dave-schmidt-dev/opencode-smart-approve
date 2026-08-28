/**
 * Subject for the signal-guard test: arms the guard exactly as a spent draw
 * does, then waits to be killed. Run as a child process, because the failure
 * being reproduced is process death, which cannot be simulated in-process.
 */
import { armCustodySignalGuard } from "../../scripts/qualification/machine-release";

const [aggregatePath, factsMode] = process.argv.slice(2);
armCustodySignalGuard({
  aggregatePath: aggregatePath!,
  candidateManifestHash: "a".repeat(64),
  corpusDigest: "b".repeat(64),
  custodyNumber: 2,
  generatedAt: "2026-08-28T14:30:00.000Z",
  corpusFacts: () => (factsMode === "parsed" ? { corpusVersion: "2026-08-27-release-v4", reviewerRoutedFixtures: 64 } : undefined),
  onStatus: (message) => console.error(message),
});
console.log("armed");
setInterval(() => undefined, 1_000);
