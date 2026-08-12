import { DEFAULT_REPLAN_MAX_BLOCKS_PER_TURN } from "../config/schema";

declare const replanGenerationBrand: unique symbol;

/** Opaque token captured before classification and checked again at reservation. */
export interface ReplanGeneration {
  readonly [replanGenerationBrand]: true;
}

export type ReplanCallOutcome = "blocked" | "fallthrough";
export type ReplanReservationReason = "reserved" | "exhausted" | "stale_generation" | "missing_identity";

export interface ReplanReservation {
  readonly outcome: ReplanCallOutcome;
  readonly reason: ReplanReservationReason;
  readonly duplicate: boolean;
}

export interface ReplanSessionSnapshot {
  readonly blockedCount: number;
  readonly retainedCallCount: number;
  readonly exhausted: boolean;
}

interface SessionState {
  readonly messageID: string;
  readonly generation: ReplanGeneration;
  readonly outcomes: Map<string, ReplanReservation>;
  blockedCount: number;
  exhausted: boolean;
}

const MISSING_IDENTITY = Object.freeze({
  outcome: "fallthrough",
  reason: "missing_identity",
  duplicate: false,
}) satisfies ReplanReservation;

const STALE_GENERATION = Object.freeze({
  outcome: "fallthrough",
  reason: "stale_generation",
  duplicate: false,
}) satisfies ReplanReservation;

const BLOCKED = Object.freeze({
  outcome: "blocked",
  reason: "reserved",
  duplicate: false,
}) satisfies ReplanReservation;

const EXHAUSTED = Object.freeze({
  outcome: "fallthrough",
  reason: "exhausted",
  duplicate: false,
}) satisfies ReplanReservation;

const validID = (value: string | undefined): value is string => typeof value === "string" && value.length > 0;

const duplicateOf = (stored: ReplanReservation): ReplanReservation => Object.freeze({
  outcome: stored.outcome,
  reason: stored.reason,
  duplicate: true,
});

/**
 * Keep one bounded, synchronous replan budget per session user-message generation.
 * Generation tokens make an async classify-then-reserve sequence fail closed when
 * a newer user message replaces the generation before reservation.
 */
export class ReplanStateStore {
  private readonly sessions = new Map<string, SessionState>();
  private readonly generationSessions = new WeakMap<ReplanGeneration, string>();

  constructor(readonly maxBlocksPerTurn: number) {
    if (!Number.isInteger(maxBlocksPerTurn) || maxBlocksPerTurn < 1 || maxBlocksPerTurn > DEFAULT_REPLAN_MAX_BLOCKS_PER_TURN) {
      throw new RangeError(`replan max blocks per turn must be an integer from 1 through ${DEFAULT_REPLAN_MAX_BLOCKS_PER_TURN}`);
    }
  }

  /** Establish a generation, or replay the current token for message redelivery. */
  observeUserMessage(sessionID: string | undefined, messageID: string | undefined): ReplanGeneration | undefined {
    if (!validID(sessionID) || !validID(messageID)) return undefined;
    const current = this.sessions.get(sessionID);
    if (current?.messageID === messageID) return current.generation;

    const generation = Object.freeze({}) as ReplanGeneration;
    this.generationSessions.set(generation, sessionID);
    this.sessions.set(sessionID, {
      messageID,
      generation,
      outcomes: new Map(),
      blockedCount: 0,
      exhausted: false,
    });
    return generation;
  }

  /** Capture the token that a later synchronous reservation must still match. */
  captureGeneration(sessionID: string | undefined): ReplanGeneration | undefined {
    if (!validID(sessionID)) return undefined;
    return this.sessions.get(sessionID)?.generation;
  }

  /**
   * Atomically reserve one unique blocked call, replay a stored duplicate, or
   * fall through. Only the first exhausted call is retained as the single
   * exhaustion marker; later exhausted IDs never grow the per-session map.
   */
  reserve(generation: ReplanGeneration | undefined, callID: string | undefined): ReplanReservation {
    if (!generation || !validID(callID)) return MISSING_IDENTITY;
    const sessionID = this.generationSessions.get(generation);
    if (!sessionID) return MISSING_IDENTITY;
    const session = this.sessions.get(sessionID);
    if (!session || session.generation !== generation) return STALE_GENERATION;

    const stored = session.outcomes.get(callID);
    if (stored) return duplicateOf(stored);

    if (session.blockedCount < this.maxBlocksPerTurn) {
      session.outcomes.set(callID, BLOCKED);
      session.blockedCount += 1;
      return BLOCKED;
    }

    if (!session.exhausted) {
      session.outcomes.set(callID, EXHAUSTED);
      session.exhausted = true;
    }
    return EXHAUSTED;
  }

  /** Return bounded counters without exposing retained identifiers. */
  snapshot(sessionID: string): ReplanSessionSnapshot | undefined {
    const session = this.sessions.get(sessionID);
    if (!session) return undefined;
    return Object.freeze({
      blockedCount: session.blockedCount,
      retainedCallCount: session.outcomes.size,
      exhausted: session.exhausted,
    });
  }

  get sessionCount(): number {
    return this.sessions.size;
  }

  deleteSession(sessionID: string | undefined): boolean {
    return validID(sessionID) && this.sessions.delete(sessionID);
  }

  dispose(): void {
    this.sessions.clear();
  }
}
