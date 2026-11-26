/**
 * What only C-family code needs: macros, `longjmp`, and global state reached through macros.
 *
 * C hides control flow and state where no function shows them. A jump out of a function is a
 * `longjmp` behind a macro (`LONGJMP(a, b)`, an engine's `bailout()`, an allocator that fails
 * over its limit); a global is written through an accessor macro (`G(x).field = 1`) or a
 * file-scope static; and a function whose name a signature macro generates
 * (`PHP_FUNCTION(assert)` defines `zif_assert`) looks, by its text, like the C library function
 * it shadows. The templates read all of these by text, from this file only, so a template stays
 * the same when another language's adapter is added beside it.
 */
import { callNames, functionBody, withoutComments, type SourceFunction } from '../source';

export const C_FAMILY = /\.(c|h|cc|cpp|cxx|hh|hpp|hxx|m|mm|inc)$/i;
/** Sources a definition can be in, including the generated lexers' and parsers' own sources. */
const C_SOURCES = /\.(c|cc|cpp|re|y|l)$/;
const JUMP = /\b(?:sig|_)?longjmp\s*\(/;
const DEFINE = /^\s*#\s*define\s+([A-Za-z_]\w*)(?!\w)(\([^)]*\))?(.*)$/;
/** A global reached through an accessor macro: `X(name)`, `X(name).field` or `X(name)->field`. */
const ACCESSOR = String.raw`[A-Z][A-Z0-9_]*\(\w+\)(?:(?:\.|->)\w+)*`;
/** An accessor written: `=` (not `==`), `++`, `--`, or `memset(&X(name)...`. */
const ACCESSOR_WRITE = new RegExp(
  String.raw`\b(${ACCESSOR})\s*(?:=(?!=)|\+\+|--)|(?:\+\+|--)\s*(${ACCESSOR})|memset\s*\(\s*&\s*(${ACCESSOR})`,
  'g'
);
export function isC(path: string): boolean {
  return C_FAMILY.test(path);
}

/** Whether code calls `longjmp`, `siglongjmp` or `_longjmp` itself, comments left out. */
export function jumps(code: string): boolean {
  return JUMP.test(withoutComments(code));
}

/** A C/C++ macro: where it is defined, whether it takes arguments, and its body. */
export interface Macro {
  name: string;
  /** `path:line` */
  at: string;
  functionLike: boolean;
  body: string;
}

/** Every macro of the C-family files, object-like and function-like, continuation lines joined. */
export function macros(files: { path: string; text: string }[]): Macro[] {
  const out: Macro[] = [];
  for (const file of files) {
    if (!isC(file.path)) continue;
    const lines = file.text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const m = DEFINE.exec(lines[i] as string);
      if (!m) continue;
      const start = i;
      let body = m[3] ?? '';
      while (body.trimEnd().endsWith('\\') && i + 1 < lines.length)
        body = `${body.trimEnd().slice(0, -1)} ${lines[++i]}`;
      out.push({
        name: m[1] as string,
        at: `${file.path}:${start + 1}`,
        functionLike: Boolean(m[2]),
        body,
      });
    }
  }
  return out;
}

/**
 * Whether the line that defines `name` is a signature macro (`PHP_FUNCTION(name)`,
 * `ZEND_METHOD(Class, name)`): the macro makes a symbol of another name, so the function must not
 * capture the calls to `name`.
 */
export function definedBySignatureMacro(line: string, name: string): boolean {
  return new RegExp(`^\\s*[A-Z][A-Z0-9_]*\\s*\\([^)]*\\b${name}\\b[^)]*\\)`).test(line);
}

/**
 * Where `name` is defined outside `exclude`, from the text alone: a line that starts a definition
 * (the name and a parameter list, no semicolon) in a C source, including the lexer and parser
 * sources the code graph does not parse (re2c's `.re`, bison's `.y`, flex's `.l`).
 */
export function definitionByText(
  name: string,
  exclude: string,
  lines: Map<string, string[]>
): { path: string; line: number; body: string } | undefined {
  const definition = new RegExp(String.raw`^[A-Za-z_][\w\s*]*\b${name}\s*\([^;]*$`);
  for (const [path, fileLines] of lines) {
    if (path === exclude || !C_SOURCES.test(path)) continue;
    const at = fileLines.findIndex(l => definition.test(l));
    if (at < 0) continue;
    const fn: SourceFunction = { qn: name, name, path, start: at + 1, end: at + 1 };
    const body = functionBody(fn, lines);
    if (body) return { path, line: at + 1, body: body.text };
  }
  return undefined;
}

/**
 * The global state a C body writes: accessor macros used as lvalues (`G(x).level = 1`,
 * `memset(&G(x), ...)`) and the file-scope statics of its file (`fileText`) that it assigns.
 */
export function globalWrites(body: string, fileText: string): string[] {
  const code = withoutComments(body);
  const out = new Set<string>();
  for (const m of code.matchAll(ACCESSOR_WRITE)) out.add((m[1] ?? m[2] ?? m[3]) as string);
  for (const name of fileStatics(fileText)) {
    if (new RegExp(String.raw`\b${name}\s*(?:=(?!=)|\+\+|--)|(?:\+\+|--)\s*${name}\b`).test(code))
      out.add(name);
  }
  return [...out];
}

/**
 * The file-scope statics a C file declares, by name: `static int depth;`,
 * `static char buf[64] = {0};`, `static const char *name = "x";`, but not a prototype
 * (`static int f(void);`) or a `static inline` function.
 *
 * A declaration is a line that starts with `static`; its name is the first identifier before any
 * `;`, parenthesis or brace that is followed, past spaces and an array size, by `=` or `;`. This is
 * read with a scan, not one regex: a regex reads the spaces after each candidate name two ways (before
 * or after the optional array size), so a prototype with a long run of spaces before its `(` took
 * quadratic time (half a second at 32,000 spaces on Node), once for every function body read.
 */
function fileStatics(fileText: string): string[] {
  const names: string[] = [];
  const next = nextIndexOf(fileText);
  for (const start of staticDeclarationStarts(fileText)) {
    const name = declaredName(fileText, start, next);
    if (name) names.push(name);
  }
  return names;
}

/** Where each `static` declaration's text starts: past `static` and its spaces, not `inline`. */
function* staticDeclarationStarts(text: string): Generator<number> {
  for (const m of text.matchAll(/^static\s+/gm)) {
    const start = m.index + m[0].length;
    if (!/^inline\b/.test(text.slice(start, start + 7))) yield start;
  }
}

/**
 * The name a declaration starting at `start` declares: the first identifier, before any `;`,
 * parenthesis or brace, that is followed (past spaces and an optional `[size]`) by `=` and a later
 * `;`, or by `;`. Each identifier skips only the spaces after it, so the scan is linear.
 */
function declaredName(
  text: string,
  start: number,
  next: (char: string, from: number) => number
): string | undefined {
  for (let i = start; i < text.length && !';(){}'.includes(text[i] as string); i++) {
    if (!isIdentifierStart(text, i)) continue;
    let end = i + 1;
    while (end < text.length && /\w/.test(text[end] as string)) end++;
    let after = skipSpaces(text, end);
    // An array size: `[` up to the next `]`. With no `]`, this name declares nothing.
    if (text[after] === '[') {
      const close = next(']', after);
      after = close < 0 ? -1 : skipSpaces(text, close + 1);
    }
    if (text[after] === ';' || (text[after] === '=' && next(';', after) >= 0))
      return text.slice(i, end);
    i = end - 1;
  }
  return undefined;
}

/** An identifier starts at `i`: a letter or `_` with no word character before it. */
function isIdentifierStart(text: string, i: number): boolean {
  return /[A-Za-z_]/.test(text[i] as string) && (i === 0 || !/\w/.test(text[i - 1] as string));
}

function skipSpaces(text: string, from: number): number {
  let i = from;
  while (i < text.length && /\s/.test(text[i] as string)) i++;
  return i;
}

/**
 * `text.indexOf(char, from)`, remembering the last answer for each character: a later question
 * from no earlier position has the same answer while it lies ahead, so a file with many `[` and no
 * `]` is searched once, not once per `[`.
 */
function nextIndexOf(text: string): (char: string, from: number) => number {
  const last = new Map<string, { from: number; found: number }>();
  return (char, from) => {
    const known = last.get(char);
    if (known && from >= known.from && (known.found < 0 || known.found >= from)) return known.found;
    const found = text.indexOf(char, from);
    last.set(char, { from, found });
    return found;
  };
}

/** For each function-like macro, the names its body calls: a call through it reaches those too. */
export function macroCalls(all: Macro[]): Map<string, string[]> {
  return new Map(all.filter(m => m.functionLike).map(m => [m.name, callNames(m.body, m.name)]));
}
