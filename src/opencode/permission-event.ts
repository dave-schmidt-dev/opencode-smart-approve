/**
 * The plugin runtime currently bridges this event as an untyped value.  Keep
 * the boundary deliberately small: everything after this module receives a
 * validated request and never has to trust the bridge payload.
 */
export interface BashPermissionRequest {
  readonly requestID: string;
  readonly sessionID?: string;
  readonly command: string;
  readonly permission: "bash";
}

export type PermissionAskedEvent = {
  readonly type: "permission.asked";
  readonly properties?: unknown;
  readonly data?: unknown;
};

export type ClassifierDecision =
  | boolean
  | "allow"
  | "manual"
  | { readonly decision: "allow" | "manual" };

export type CommandClassifier = (command: string) =>
  | ClassifierDecision
  | Promise<ClassifierDecision>;

export type Approval = (requestID: string) => void | Promise<void>;

type RecordValue = Record<string, unknown>;

const isRecord = (value: unknown): value is RecordValue =>
  typeof value === "object" && value !== null;

/**
 * Validate and extract the one permission shape handled by the MVP.
 *
 * OpenCode 1.18.10 exposes the request under `properties`; the generated SDK
 * exposes the same shape under `data`. Supporting both keeps this runtime
 * bridge tolerant without weakening validation.
 */
export function parsePermissionAskedEvent(
  event: unknown,
): BashPermissionRequest | undefined {
  if (!isRecord(event) || event.type !== "permission.asked") return undefined;

  const body = isRecord(event.properties)
    ? event.properties
    : isRecord(event.data)
      ? event.data
      : undefined;
  if (!body || body.permission !== "bash") return undefined;

  const requestID = body.id;
  if (typeof requestID !== "string" || requestID.length === 0) return undefined;

  const metadata = body.metadata;
  if (!isRecord(metadata) || typeof metadata.command !== "string") {
    return undefined;
  }
  // An empty command cannot be an executable shell request. Do not trim or
  // otherwise rewrite non-empty commands: the exact metadata value is passed
  // to classification.
  if (metadata.command.length === 0) return undefined;

  const sessionID = body.sessionID;
  return {
    requestID,
    ...(typeof sessionID === "string" && sessionID.length > 0
      ? { sessionID }
      : {}),
    command: metadata.command,
    permission: "bash",
  };
}

/** Alias retained for callers that prefer an `extract*` name. */
export const extractBashPermissionRequest = parsePermissionAskedEvent;

function allows(decision: ClassifierDecision): boolean {
  if (decision === true || decision === "allow") return true;
  return typeof decision === "object" && decision.decision === "allow";
}

export interface PermissionEventHandlerOptions {
  readonly classify: CommandClassifier;
  readonly approve: Approval;
}

/**
 * Build the event callback used by the plugin runtime.
 *
 * Invalid events are complete no-ops. A valid event invokes the classifier
 * with the exact command string from `metadata.command`; only an explicit
 * allow decision can invoke the request-scoped approval adapter.
 */
export function createPermissionEventHandler({
  classify,
  approve,
}: PermissionEventHandlerOptions): (event: unknown) => Promise<void> {
  return async (event: unknown): Promise<void> => {
    const request = parsePermissionAskedEvent(event);
    if (!request) return;

    const decision = await classify(request.command);
    if (allows(decision)) await approve(request.requestID);
  };
}

/** A descriptive alias for integrations that register handlers directly. */
export const handlePermissionEvent = createPermissionEventHandler;
