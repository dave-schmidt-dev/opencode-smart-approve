import { REPLAN_GENERIC_FEEDBACK, replanGuidanceFor } from "./guidance";
import type { ReplanExecutableIdentity } from "../policy/executable-identity";

/** Generic fixed feedback retained for callers that have no identity. */
export const REPLAN_BLOCKED_FEEDBACK = REPLAN_GENERIC_FEEDBACK;

/** The only error the pre-execution guard may raise. */
export class ReplanBlockedError extends Error {
  constructor(identity?: ReplanExecutableIdentity) {
    super(identity === undefined ? REPLAN_BLOCKED_FEEDBACK : replanGuidanceFor(identity).feedback);
    this.name = "ReplanBlockedError";
  }
}
