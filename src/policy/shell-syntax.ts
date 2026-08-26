/**
 * Shell-syntax fragments shared by the deterministic gate.
 *
 * `&` separates commands, except inside a file-descriptor duplication such as
 * `2>&1`, `>&2`, or `2>&-`. Splitting on it there scores the `1` of `2>&1` as a
 * command name and reports `unknown_binary` for an ordinary stderr merge. The
 * gate still holds such commands manual, because `dangerous_command` covers
 * every redirect; what the split corrupts is the reason code, the operand
 * classification, and the facts handed to the reviewer.
 *
 * Narrowing this does not relax the gate. `2>&1` duplicates a descriptor and
 * writes no file, but `features.redirects` does not distinguish a duplication
 * from `> out`, so redirects remain uniformly dangerous. Making that
 * distinction is a separate decision, recorded in TASK-018.
 */

/** A file-descriptor duplication or close: `2>&1`, `>&2`, `2>&-`, `<&0`. */
export const FD_DUPLICATION = /^\d*[<>]&[\d-]+$/;

/** Command-list separators, excluding the `&` of a descriptor duplication. */
export const SEGMENT_SEPARATOR = /(?:\|\||&&|[|;]|(?<![<>])&)/;

const SHELL_TOKEN_SOURCE = "\\d*[<>]&[\\d-]+|[^\\s\"';&|]+|\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'|\\|\\||&&|[;&|]";

/**
 * Split a command into shell-ish tokens, keeping a descriptor duplication whole
 * so it is never mistaken for a separator followed by a bare number. A fresh
 * regex per call keeps the global flag's `lastIndex` from leaking across calls.
 */
export function shellTokens(command: string): string[] {
  return command.match(new RegExp(`(?:${SHELL_TOKEN_SOURCE})`, "g")) ?? [];
}
