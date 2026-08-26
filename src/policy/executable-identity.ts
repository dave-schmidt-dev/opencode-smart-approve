/** Executable identities eligible for the closed pre-execution replan route. */
export const REPLAN_EXECUTABLES = ["awk", "xargs", "find", "env", "command", "cmp"] as const;

export type ReplanExecutableIdentity = (typeof REPLAN_EXECUTABLES)[number];

/** Return whether a normalized executable name belongs to the replan catalog. */
export function isReplanExecutableIdentity(value: string): value is ReplanExecutableIdentity {
  return (REPLAN_EXECUTABLES as readonly string[]).includes(value);
}

/**
 * Extract only the first executable identity from each shell list segment.
 * Wrappers are identities themselves: `command env` yields `command` and
 * `env -i awk` yields `env`; arguments are never searched for identities.
 */
export function extractExecutableIdentities(command: string): readonly string[] {
  const identities: string[] = [];
  for (const tokens of shellSegments(command)) {
    const token = tokens.find((value) => !/^(?:[A-Za-z_][A-Za-z0-9_]*=|export$|builtin$|exec$)/.test(value));
    if (!token) continue;
    const executable = token.split("/").at(-1)?.toLowerCase();
    if (executable) identities.push(executable);
  }
  return identities;
}

/** Return whether any shell-list segment begins with a replan-catalog identity. */
export function hasReplanExecutable(command: string): boolean {
  return findReplanExecutableIdentity(command) !== undefined;
}

/** Return the first eligible identity without retaining or exposing command text. */
export function findReplanExecutableIdentity(command: string): ReplanExecutableIdentity | undefined {
  return extractExecutableIdentities(command).find(isReplanExecutableIdentity);
}

/** Tokenize only enough to find the first command in each unquoted list segment. */
function shellSegments(command: string): string[][] {
  const segments: string[][] = [[]];
  let token = "";
  let quote: "'" | '"' | undefined;
  let escaped = false;
  const flush = (): void => {
    if (token.length > 0) segments.at(-1)?.push(token);
    token = "";
  };
  const nextSegment = (): void => {
    flush();
    segments.push([]);
  };
  for (let index = 0; index < command.length; index += 1) {
    const character = command[index];
    if (escaped) {
      token += character;
      escaped = false;
      continue;
    }
    if (quote !== undefined) {
      if (character === quote) quote = undefined;
      else if (character === "\\" && quote === '"') escaped = true;
      else token += character;
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
      continue;
    }
    if (character === "\\") {
      escaped = true;
      continue;
    }
    if (/\s/.test(character)) {
      flush();
      continue;
    }
    if (character === ";" || character === "|" || character === "&") {
      // The `&` of a descriptor duplication (`2>&1`) belongs to the redirect,
      // not to the command list; splitting there invents a segment whose
      // command name is the target descriptor.
      if (character === "&" && /[<>]$/.test(token)) {
        token += character;
        continue;
      }
      nextSegment();
      if ((character === "|" || character === "&") && command[index + 1] === character) index += 1;
      continue;
    }
    token += character;
  }
  flush();
  return segments;
}
