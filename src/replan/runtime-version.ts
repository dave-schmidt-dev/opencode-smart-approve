export const REQUIRED_RUNTIME_VERSION = "1.18.10" as const;

export interface RuntimeHealthResponse {
  readonly ok: boolean;
  readonly json: () => Promise<unknown>;
}

export type RuntimeHealthFetcher = (input: URL) => Promise<RuntimeHealthResponse>;

/** Verify the production runtime signal required before registering replan hooks. */
export async function verifyRuntimeVersion(
  serverURL: URL | string,
  fetcher: RuntimeHealthFetcher = (input) => fetch(input, { signal: AbortSignal.timeout(5_000) }),
): Promise<boolean> {
  try {
    const base = new URL(serverURL.toString());
    const healthURL = new URL("/global/health", base);
    const response = await fetcher(healthURL);
    if (!response.ok) return false;
    const body = await response.json();
    return typeof body === "object" && body !== null && "version" in body && (body as { version?: unknown }).version === REQUIRED_RUNTIME_VERSION;
  } catch {
    return false;
  }
}
