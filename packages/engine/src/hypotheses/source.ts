/**
 * Reading code by its text, for brace languages (C, C++, Java, JavaScript, C# and the like).
 *
 * The code graph gives each function's start and end line, but its end line can stop early in
 * code full of macros, so a body is read from the start line to the brace that closes it. Calls
 * are found by name (`name(`), not resolved: two functions with one name count as one, which
 * over-approximates, and every template prints what it found so a helper can check it.
 */

/** A function as the code graph gives it. */
export interface SourceFunction {
  /** Qualified name, unique in the graph. */
  qn: string;
  name: string;
  path: string;
  start: number;
  end: number;
}

/** A body longer than this is cut: no reset or teardown function is, and a runaway match stops. */
const MAX_BODY_LINES = 2000;
const CALL = /\b([A-Za-z_]\w*)\s*\(/g;
const COMMENT = /\/\*[\s\S]*?\*\/|\/\/[^\n]*/g;
/** Words followed by `(` that are not calls. */
const NOT_CALLS = new Set(
  'if for while switch return sizeof defined do else case void typeof alignof _Alignof __typeof__ __attribute__ __declspec'.split(
    ' '
  )
);

/** Every file's lines, by path. */
export function linesByPath(files: { path: string; text: string }[]): Map<string, string[]> {
  return new Map(files.map(f => [f.path, f.text.split('\n')]));
}

/**
 * A function's text from its start line to the brace that closes its body; none without one.
 *
 * Braces inside comments and string or character literals are text, not blocks, both when finding
 * the body's opening brace and its closing one: php-src marks folds with `/* {{{ *\/` after a
 * signature and `/* }}} *\/` after a body, and `log("}")` closes nothing.
 */
export function functionBody(
  f: SourceFunction,
  lines: Map<string, string[]>
): { start: number; text: string } | undefined {
  const fileLines = lines.get(f.path);
  if (!fileLines || f.start < 1) return undefined;
  const from = fileLines.slice(f.start - 1, f.start - 1 + MAX_BODY_LINES).join('\n');
  const open = openingBrace(from);
  if (open < 0) return undefined;
  return { start: f.start, text: from.slice(0, matchingBrace(from, open + 1) + 1) };
}

/**
 * A function's body from its opening brace to the one that closes it, without its signature: a
 * name the signature mentions (its own, a signature macro's arguments) is not a call.
 */
export function bodyAfterSignature(
  f: SourceFunction,
  lines: Map<string, string[]>
): string | undefined {
  const body = functionBody(f, lines);
  return body?.text.slice(openingBrace(body.text));
}

/** The index of the first `{` of code in `s`, comments and literals skipped; -1 without one. */
export function openingBrace(s: string): number {
  for (let i = 0; i < s.length; i++) {
    const text = textEnd(s, i);
    if (text >= 0) i = text;
    else if (s[i] === '{') return i;
  }
  return -1;
}

/** The index of the brace that closes the block opened just before `from`, text skipped. */
export function matchingBrace(s: string, from: number): number {
  let depth = 1;
  for (let i = from; i < s.length; i++) {
    const text = textEnd(s, i);
    if (text >= 0) i = text;
    else if (s[i] === '{') depth++;
    else if (s[i] === '}' && --depth === 0) return i;
  }
  return s.length;
}

/**
 * Where a comment or a string or character literal that starts at `i` ends (its last character),
 * escapes skipped; -1 when none starts there. An unclosed one ends with `s`, or for a literal with
 * its line, as a C compiler reads it.
 */
function textEnd(s: string, i: number): number {
  const c = s[i];
  if (c === '/' && s[i + 1] === '*') {
    const at = s.indexOf('*/', i + 2);
    return at < 0 ? s.length : at + 1;
  }
  if (c === '/' && s[i + 1] === '/') {
    const at = s.indexOf('\n', i + 2);
    return at < 0 ? s.length : at - 1;
  }
  if (c !== '"' && c !== "'") return -1;
  for (let j = i + 1; j < s.length; j++) {
    if (s[j] === '\\') j++;
    else if (s[j] === c || s[j] === '\n') return j;
  }
  return s.length;
}

/** The names `s` calls, comments left out, in order of first call, without `self`. */
export function callNames(s: string, self = ''): string[] {
  const out = new Set<string>();
  for (const m of withoutComments(s).matchAll(CALL)) {
    const name = m[1] as string;
    if (name !== self && !NOT_CALLS.has(name)) out.add(name);
  }
  return [...out];
}

export function withoutComments(s: string): string {
  return s.replace(COMMENT, ' ');
}

/** The 0-based line of `index` in `s`. */
export function lineOf(s: string, index: number): number {
  return s.slice(0, index).split('\n').length - 1;
}

export function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
