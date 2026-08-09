import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { scanForSecrets, type SecretReasonCode } from "../../src/privacy/secret-scan";

interface SecretCase {
  readonly name: string;
  readonly command: string;
  readonly reason: SecretReasonCode;
}

const cases = JSON.parse(
  readFileSync(join(process.cwd(), "tests/fixtures/security/secret-cases.json"), "utf8"),
) as SecretCase[];

describe("pre-provider secret boundary", () => {
  test("every secret-bearing fixture is manual before reviewer construction", () => {
    for (const fixture of cases) {
      const result = scanForSecrets(fixture.command, {
        additionalSecretPatterns: fixture.name === "configured token marker" ? ["CANARY_SECRET_ECHO"] : [],
        additionalPatterns: fixture.name === "configured path" ? ["**/tenant-secret.json"] : [],
      });
      expect(result.status, fixture.name).toBe("manual");
      expect(result.decision, fixture.name).toBe("manual");
      expect(result.reasonCodes, fixture.name).toContain(fixture.reason);
      expect(result.redactedCommand, fixture.name).not.toContain("CANARY_SECRET");
      expect(result.commandShape, fixture.name).not.toContain("CANARY_SECRET");
    }
  });

  test("ordinary commands remain eligible for the reviewer", () => {
    const result = scanForSecrets("printf '%s\\n' hello");
    expect(result.status).toBe("model_review");
    expect(result.reasonCodes).toEqual([]);
  });

  test("configured additions are enforced without reading files or environment", () => {
    const result = scanForSecrets("echo tenant-value", {
      additionalSecretPatterns: ["tenant-value"],
      additionalPatterns: ["**/tenant-secret.json"],
    });
    expect(result.status).toBe("manual");
    expect(result.reasonCodes).toContain("configured_secret_pattern");
  });

  test("canary bytes never cross request, status, error, or audit representations", () => {
    const command = "API_KEY=CANARY_SECRET_REQUEST echo ok";
    const result = scanForSecrets(command);
    let providerCalls = 0;
    const captures = [
      { request: result.redactedCommand, shape: result.commandShape },
      { status: `manual:${result.reasonCodes.join(",")}` },
      { error: new Error(`manual:${result.reasonCodes.join(",")}`).message },
      { audit: JSON.stringify({ decision: result.decision, reasons: result.reasonCodes }) },
    ];
    if (result.status === "model_review") providerCalls += 1;
    const serialized = JSON.stringify(captures);
    expect(providerCalls).toBe(0);
    expect(serialized).not.toContain("CANARY_SECRET_REQUEST");
    expect(serialized).not.toContain("API_KEY");
  });

  test("detector errors fail closed and do not construct a provider", () => {
    let providerCalls = 0;
    const result = scanForSecrets("echo harmless", {
      detector: () => {
        throw new Error("detector failed");
      },
    });
    if (result.status === "model_review") providerCalls += 1;
    expect(result.status).toBe("manual");
    expect(result.reasonCodes).toEqual(["detector_error"]);
    expect(providerCalls).toBe(0);
    expect(JSON.stringify(result)).not.toContain("detector failed");
  });

  test("invalid configured patterns fail closed without echoing the command", () => {
    const result = scanForSecrets("echo CANARY_SECRET_INVALID", {
      additionalSecretPatterns: [""],
    });
    expect(result.status).toBe("manual");
    expect(result.reasonCodes).toEqual(["detector_error"]);
    expect(JSON.stringify(result)).not.toContain("CANARY_SECRET_INVALID");
  });
});
