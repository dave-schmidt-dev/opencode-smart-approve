/** Hard parser bounds. These are intentionally conservative and are not configurable. */
export const MAX_INPUT_BYTES = 128 * 1024;
export const MAX_AST_DEPTH = 8;
export const MAX_SEGMENTS = 128;

export type LimitName = "input_bytes" | "ast_depth" | "segments";

export interface LimitViolation {
  readonly limit: LimitName;
  readonly actual: number;
  readonly maximum: number;
}
