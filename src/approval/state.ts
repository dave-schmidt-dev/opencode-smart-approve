/** Request-scoped state used by the approval coordinator. */
export type ApprovalState =
  | "received"
  | "reviewing"
  | "approved"
  | "replying"
  | "manual"
  | "timeout"
  | "error"
  | "stale"
  | "complete";

export interface ApprovalRequestRecord {
  readonly requestID: string;
  /** Raw command text is never retained in the long-lived request store. */
  readonly commandHash: string;
  readonly sessionID?: string;
  state: ApprovalState;
  replyAttempted: boolean;
  terminal: boolean;
}

const terminalStates = new Set<ApprovalState>(["manual", "timeout", "error", "stale", "complete"]);

const transitions: Readonly<Record<ApprovalState, readonly ApprovalState[]>> = {
  received: ["reviewing", "manual", "stale"],
  reviewing: ["approved", "manual", "timeout", "error", "stale"],
  approved: ["replying", "stale", "error"],
  replying: ["complete", "stale", "error"],
  manual: ["complete"],
  timeout: ["complete"],
  error: ["complete"],
  stale: ["complete"],
  complete: [],
};

export function canTransition(from: ApprovalState, to: ApprovalState): boolean {
  return transitions[from].includes(to);
}

/** Apply a transition without allowing a late callback to reopen a request. */
export function transition(record: ApprovalRequestRecord, next: ApprovalState): boolean {
  // Terminal outcomes cannot be reopened.  They may still be finalized as
  // `complete`, which keeps late callbacks from changing the outcome while
  // allowing callers to observe the full lifecycle.
  if (record.terminal) {
    if (next !== "complete" || record.state === "complete") return false;
    record.state = next;
    record.terminal = true;
    return true;
  }
  if (!canTransition(record.state, next)) return false;
  record.state = next;
  record.terminal = terminalStates.has(next);
  return true;
}

export class ApprovalStateStore {
  private readonly records = new Map<string, ApprovalRequestRecord>();

  get(requestID: string): ApprovalRequestRecord | undefined {
    return this.records.get(requestID);
  }

  begin(requestID: string, command: string, sessionID?: string): ApprovalRequestRecord | undefined {
    if (!requestID || this.records.has(requestID)) return undefined;
    const record: ApprovalRequestRecord = {
      requestID,
      commandHash: hashCommand(command),
      ...(sessionID ? { sessionID } : {}),
      state: "received",
      replyAttempted: false,
      terminal: false,
    };
    this.records.set(requestID, record);
    return record;
  }

  markUserAnswered(requestID: string): boolean {
    const record = this.records.get(requestID);
    if (!record || record.terminal) return false;
    return transition(record, "stale");
  }

  values(): readonly ApprovalRequestRecord[] {
    return [...this.records.values()];
  }
}

/** Compare request identity without retaining command bytes after processing. */
export function hashCommand(command: string): string {
  return createHash("sha256").update(command, "utf8").digest("hex");
}
import { createHash } from "node:crypto";
