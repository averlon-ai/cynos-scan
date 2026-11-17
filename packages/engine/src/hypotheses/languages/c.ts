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
const DEFINE = /^\s*#\s*define\s+([A-Za-z_]\w*)(\([^)]*\))?(.*)$/;
/** A global reached through an accessor macro: `X(name)`, `X(name).field` or `X(name)->field`. */
const ACCESSOR = String.raw`[A-Z][A-Z0-9_]*\(\w+\)(?:(?:\.|->)\w+)*`;
/** An accessor written: `=` (not `==`), `++`, `--`, or `memset(&X(name)...`. */
const ACCESSOR_WRITE = new RegExp(
  String.raw`\b(${ACCESSOR})\s*(?:=(?!=)|\+\+|--)|(?:\+\+|--)\s*(${ACCESSOR})|memset\s*\(\s*&\s*(${ACCESSOR})`,
  'g'
);
const FILE_STATIC =
  /^static\s+(?!inline\b)[^;(){}]*?\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*(?:=[^;]*)?;/gm;

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
  for (const m of fileText.matchAll(FILE_STATIC)) {
    const name = m[1] as string;
    if (new RegExp(String.raw`\b${name}\s*(?:=(?!=)|\+\+|--)|(?:\+\+|--)\s*${name}\b`).test(code))
      out.add(name);
  }
  return [...out];
}

/** For each function-like macro, the names its body calls: a call through it reaches those too. */
export function macroCalls(all: Macro[]): Map<string, string[]> {
  return new Map(all.filter(m => m.functionLike).map(m => [m.name, callNames(m.body, m.name)]));
}
