/**
 * Structural key derivation shared by the development and machine-release
 * strata.
 *
 * The release lint rejects a release corpus whose fixture *shapes* overlap the
 * development corpus. That check only means something if both sides derive the
 * key the same way, so the derivation lives here and is used for both. The key
 * abstracts away concrete operands (paths, hosts, numbers, quoted strings) and
 * keeps the command skeleton: the utilities invoked, the option names, and the
 * shell operators joining them. Two commands that differ only in which file
 * they touch collapse to the same key, which is the intent — reusing a
 * development shape with a new path is not a fresh test.
 */

const OPERATORS = /(\|\||&&|[|;&><]|\$\(|`)/g;

function classifyOperand(token: string): string {
  if (/^-{1,2}[A-Za-z0-9][-A-Za-z0-9]*/.test(token)) return token.split("=")[0]!;
  if (/^[~/.]|\//.test(token)) return "<path>";
  if (/^\d+$/.test(token)) return "<num>";
  if (/^["']/.test(token)) return "<str>";
  if (/^\$/.test(token)) return "<var>";
  return "<arg>";
}

/**
 * Reduce a command to a stable skeleton.
 *
 * Not a shell parser: this is a shape fingerprint for corpus hygiene, not a
 * security boundary. The plugin's real parsing lives in `src/parser/`.
 */
export function structuralKey(command: string): string {
  const spaced = command.replace(OPERATORS, " $1 ");
  const tokens = spaced.split(/\s+/).filter((token) => token.length > 0);
  const shape: string[] = [];
  let expectUtility = true;
  for (const token of tokens) {
    if (/^(\|\||&&|[|;&><]|\$\(|`)$/.test(token)) {
      shape.push(token);
      expectUtility = true;
      continue;
    }
    if (expectUtility) {
      shape.push(token.toLowerCase());
      expectUtility = false;
      continue;
    }
    shape.push(classifyOperand(token));
  }
  return shape.join(" ");
}
