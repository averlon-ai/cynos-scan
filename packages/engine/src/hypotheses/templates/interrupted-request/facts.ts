/**
 * The facts behind the interrupted-request hypotheses, computed once per input.
 *
 * A server that serves many requests from one process keeps state between them, and resets it in
 * each request's start and teardown. Interrupt a request part-way (an error, a limit, a non-local
 * exit while its input is parsed) and the teardown can skip steps or free what is half-built, and
 * the next request on the same worker meets what was left. No file shows this: the jump is behind
 * an ordinary-looking call, the guard is in the teardown, the flag is set in the start, and the
 * state belongs to components the input code called into. So, from the code and the answers:
 *
 *   1  exits       the calls that can leave their caller without returning: in C, every
 *                  function and macro that reaches `longjmp`; elsewhere, the functions the
 *                  decision model says end the operation (`non_local_exit`), and their callers
 *   2  guards      teardown steps (`request_end`) that run only `if (FLAG)`, where FLAG is set in
 *                  the request's start (`request_init`): a request that fails before that line
 *                  skips them
 *   3  components  files whose state-touching functions (`persistent_state`) include input code
 *                  beside their own initialisation and teardown; a reader's or a parser's state
 *                  alone has no reset to miss. Those another file's parser runs come first
 *   4  parsers     the files that run a component's code: the direct callers of its input code,
 *                  and the code that calls a hook the component installs one of its functions in
 *                  (`hook = fn;` then `hook(...)`), which the code graph does not see
 *
 * Without exits there is no interruption to follow, and without phases no lifecycle to break:
 * then every list is empty and the templates compute no hypothesis.
 */
import { calleesOf, callersOf, pathToRoot, propagateToCallers, reachable } from '../../graph';
import { chosen, yes } from '../../labels';
import {
  bodyAfterSignature,
  callNames,
  escapeRegExp,
  functionBody,
  lineOf,
  linesByPath,
  matchingBrace,
  withoutComments,
  type SourceFunction,
} from '../../source';
import {
  definedBySignatureMacro,
  definitionByText,
  globalWrites,
  isC,
  jumps,
  macroCalls,
  macros,
} from '../../languages/c';
import type { HypothesisInput } from '../../types';

/** A yes at this probability counts: recall first, since every fact is printed for checking. */
export const LABEL_P = 0.3;
/** The exits a brief lists, the most widely called first. */
export const MAX_NON_LOCAL_EXITS = 25;
const MAX_PATH_STEPS = 8;
/** More guards than this means the repository is not using one lifecycle flag. */
const MAX_GUARDED_TEARDOWNS = 6;
/** The guard's setter is named with this many of the calls it makes first. */
const MAX_CALLS_BEFORE = 10;
/** Components that get hypotheses: each adds two, and each hypothesis a share of a packet. */
export const MAX_COMPONENTS = 2;
const MAX_PARSERS = 4;
/** A brief's core is filled in seed order within a token budget. */
const MAX_SEEDS = 10;
const MAX_REACHED_STATE = 4;
const MAX_WRITES = 4;
const MAX_BUILDERS = 3;
/** How deep a parser's calls are followed to the functions that build its structures. */
const BUILDER_DEPTH = 3;
/** A builder makes at least this many calls that can jump: one is the allocation it starts with. */
const MIN_JUMPING_CALLS = 2;

/** A call that can unwind, with how many functions call it and its path to the exit. */
export interface NonLocalExit {
  name: string;
  callers: number;
  /** From `name` to the definition that exits itself, e.g. emalloc -> _emalloc -> bailout. */
  path: string[];
  /** Where that definition is: `path:line`. */
  root: string;
}

/** A teardown step that runs only when `flag` is set, and where the request's start sets it. */
export interface GuardedTeardown {
  teardown: SourceFunction;
  /** The line of the `if`. */
  line: number;
  flag: string;
  /** Known functions the guarded block calls. */
  calls: string[];
  setter: SourceFunction;
  setAt: number;
  /** Known functions the setter calls before that line, in order. */
  before: string[];
}

/** State of another component that a component's code reaches: the callee and what it writes. */
export interface ReachedState {
  name: string;
  /** `path:line` of the callee's definition. */
  at: string;
  writes: string[];
}

/** A component with input code, initialisation and teardown of its own. */
export interface Component {
  path: string;
  /** Its functions that run while the request's input is parsed, in line order. */
  inputs: SourceFunction[];
  parsers: string[];
}

export interface Facts {
  exits: NonLocalExit[];
  /** Every name that can unwind, not only the listed exits. */
  unwinding: Set<string>;
  guarded: GuardedTeardown[];
  components: Component[];
}

const computed = new WeakMap<HypothesisInput, Facts>();

/** Steps 1-4, computed once per input: both templates and every brief read them. */
export function facts(input: HypothesisInput): Facts {
  let out = computed.get(input);
  if (!out) {
    const { exits, unwinding } = nonLocalExits(input);
    const guarded = exits.length ? guardedTeardowns(input) : [];
    out = { exits, unwinding, guarded, components: exits.length ? components(input) : [] };
    computed.set(input, out);
  }
  return out;
}

/** The phase a function runs in, when it touches state that outlives a request; else none. */
export function phaseOf(input: HypothesisInput, f: SourceFunction): string | undefined {
  const labels = input.labels.get(f.qn);
  return yes(labels, 'persistent_state') >= LABEL_P ? chosen(labels, 'phase') : undefined;
}

// --------------------------------------------------------------------------- //
// 1. Non-local exits
// --------------------------------------------------------------------------- //

/** One function or macro: its name, where it is, whether it exits itself, what it calls. */
interface Definition {
  name: string;
  at: string;
  exits: boolean;
  calls: string[];
}

/**
 * The calls that can unwind, most widely called first.
 *
 * Names are matched, not resolved, so macros take part: in C the jump and the common entry points
 * are often macros. The roots are where control leaves: `longjmp` in C code; with none, the
 * functions the decision model says exit. A caller of a name that can unwind can unwind too, to a
 * fixed point (graph.ts propagateToCallers).
 */
function nonLocalExits(input: HypothesisInput): { exits: NonLocalExit[]; unwinding: Set<string> } {
  const functions = functionDefinitions(input);
  const definitions = [...functions, ...macroDefinitions(input)];
  let roots = definitions.filter(d => d.exits);
  if (!roots.length) roots = labelledExits(input, functions);
  if (!roots.length) return { exits: [], unwinding: new Set() };
  const calls = definitions.flatMap(d => d.calls.map(c => [d.name, c] as [string, string]));
  const via = propagateToCallers(
    roots.map(r => r.name),
    callersOf(calls)
  );
  return { exits: rankByCallers(via, roots, functions), unwinding: new Set(via.keys()) };
}

/**
 * Every function of the code graph with the names it calls: in C, read from its body (after the
 * opening brace: a signature macro's arguments are not calls); elsewhere, the graph's calls.
 */
function functionDefinitions(input: HypothesisInput): Definition[] {
  const lines = linesByPath(input.files.filter(f => isC(f.path)));
  const nameOf = new Map(input.functions.map(f => [f.qn, f.name]));
  const graphCalls = calleesOf(input.calls);
  const out: Definition[] = [];
  for (const f of input.functions) {
    const fileLines = lines.get(f.path);
    if (!fileLines) {
      const calls = (graphCalls.get(f.qn) ?? []).map(qn => nameOf.get(qn) ?? qn);
      out.push({ name: f.name, at: `${f.path}:${f.start}`, exits: false, calls });
      continue;
    }
    if (f.start < 1 || definedBySignatureMacro(fileLines[f.start - 1] ?? '', f.name)) continue;
    // To its closing brace, not the graph's end line, which can stop early in macro-heavy code.
    const body = bodyAfterSignature(f, lines);
    if (body === undefined) continue;
    out.push({
      name: f.name,
      at: `${f.path}:${f.start}`,
      exits: jumps(body),
      calls: callNames(body, f.name),
    });
  }
  return out;
}

function macroDefinitions(input: HypothesisInput): Definition[] {
  return macros(input.files).map(m => ({
    name: m.name,
    at: m.at,
    exits: jumps(m.body),
    calls: callNames(m.body, m.name),
  }));
}

/** Roots where no code calls longjmp: the functions the decision model says exit. */
function labelledExits(input: HypothesisInput, functions: Definition[]): Definition[] {
  const exiting = new Set(
    input.functions
      .filter(f => yes(input.labels.get(f.qn), 'non_local_exit') >= LABEL_P)
      .map(f => `${f.path}:${f.start}`)
  );
  return functions.filter(d => exiting.has(d.at)).map(d => ({ ...d, exits: true }));
}

/** The names that can unwind by how many functions call them: what a reviewer meets in code. */
function rankByCallers(
  via: Map<string, string>,
  roots: Definition[],
  functions: Definition[]
): NonLocalExit[] {
  const callers = new Map<string, number>();
  for (const f of functions)
    for (const callee of new Set(f.calls))
      if (via.has(callee)) callers.set(callee, (callers.get(callee) ?? 0) + 1);
  const rootAt = new Map(roots.map(r => [r.name, r.at]));
  return [...callers]
    .sort((x, y) => y[1] - x[1] || (x[0] < y[0] ? -1 : 1))
    .slice(0, MAX_NON_LOCAL_EXITS)
    .map(([name, count]) => {
      const path = pathToRoot(name, via, MAX_PATH_STEPS);
      const last = path[path.length - 1] as string;
      return {
        name,
        callers: count,
        path,
        root: via.get(last) === last ? (rootAt.get(last) ?? '') : '',
      };
    });
}

// --------------------------------------------------------------------------- //
// 2. Guarded teardowns
// --------------------------------------------------------------------------- //

/** `name`, `name.field`, `name->field`, or an accessor macro `G(name).field`; not a comparison. */
const FLAG = String.raw`[A-Za-z_]\w*(?:\([A-Za-z_]\w*\))?(?:(?:\.|->)\w+)*`;
const GUARD = new RegExp(String.raw`\bif\s*\(\s*(${FLAG})\s*\)\s*\{`, 'g');

/**
 * The teardown steps a flag guards, the ones with the most guarded calls first: in every
 * `request_end` function, each `if (FLAG) { ... }` block whose body calls a known function, with
 * the first `request_init` function that sets FLAG to 1 or true. A guard with no such setter is a
 * null check or a mode switch, not a lifecycle flag. Brace languages only.
 */
function guardedTeardowns(input: HypothesisInput): GuardedTeardown[] {
  const lines = linesByPath(input.files);
  const known = new Set(input.functions.map(f => f.name));
  const inPhase = (phase: string) => input.functions.filter(f => phaseOf(input, f) === phase);
  const starts = inPhase('request_init');
  const found: GuardedTeardown[] = [];
  for (const teardown of inPhase('request_end'))
    for (const guard of guards(teardown, lines, known)) {
      const set = setter(guard.flag, starts, lines);
      if (set)
        found.push({
          teardown,
          ...guard,
          ...set,
          before: callsBefore(set.setter, set.setAt, lines, known),
        });
    }
  return mergedByFlag(found)
    .sort((a, b) => b.calls.length - a.calls.length || (a.teardown.qn < b.teardown.qn ? -1 : 1))
    .slice(0, MAX_GUARDED_TEARDOWNS);
}

/** Each `if (FLAG) { ... }` block in a teardown whose body calls a known function. */
function guards(
  f: SourceFunction,
  lines: Map<string, string[]>,
  known: Set<string>
): { line: number; flag: string; calls: string[] }[] {
  const body = functionBody(f, lines);
  if (!body) return [];
  const out: { line: number; flag: string; calls: string[] }[] = [];
  for (const m of body.text.matchAll(GUARD)) {
    const open = (m.index ?? 0) + m[0].length;
    const block = body.text.slice(open, matchingBrace(body.text, open));
    const calls = callNames(block).filter(n => known.has(n));
    if (calls.length)
      out.push({ line: body.start + lineOf(body.text, m.index ?? 0), flag: m[1] as string, calls });
  }
  return out;
}

/** The first request-start function that sets `flag` to 1 or true, and the line. */
function setter(
  flag: string,
  starts: SourceFunction[],
  lines: Map<string, string[]>
): { setter: SourceFunction; setAt: number } | undefined {
  const sets = new RegExp(String.raw`(?:^|[^\w.>])${escapeRegExp(flag)}\s*=\s*(?:1|true|TRUE)\s*;`);
  for (const f of starts) {
    const body = functionBody(f, lines);
    const at = body?.text.split('\n').findIndex(line => sets.test(line)) ?? -1;
    if (body && at >= 0) return { setter: f, setAt: body.start + at };
  }
  return undefined;
}

/** The last known calls the setter makes before the line that sets the flag. */
function callsBefore(
  f: SourceFunction,
  line: number,
  lines: Map<string, string[]>,
  known: Set<string>
): string[] {
  const text = (lines.get(f.path) ?? []).slice(f.start - 1, line - 1).join('\n');
  return callNames(text, f.name)
    .filter(n => known.has(n))
    .slice(-MAX_CALLS_BEFORE);
}

/** One entry per teardown and flag: a teardown often checks one flag before several steps. */
function mergedByFlag(found: GuardedTeardown[]): GuardedTeardown[] {
  const byKey = new Map<string, GuardedTeardown>();
  for (const g of found) {
    const key = `${g.teardown.qn}\u0000${g.flag}`;
    const seen = byKey.get(key);
    if (seen) seen.calls = [...new Set([...seen.calls, ...g.calls])];
    else byKey.set(key, { ...g, calls: [...g.calls] });
  }
  return [...byKey.values()];
}

// --------------------------------------------------------------------------- //
// 3-4. Components and their parsers
// --------------------------------------------------------------------------- //

/**
 * The components with input code, initialisation and teardown of their own, the ones another
 * file's input parser runs first.
 *
 * The bug needs input code that a parser in another file runs, possibly before the component's
 * own initialisation: a session module's upload callback, installed in a hook the multipart parser
 * calls. Counting input-labelled functions alone ranks a large table of constructors first (a CSS
 * library's, each labelled input and called directly by its own library). So a component a parsing
 * file runs through a hook it installs comes first: that call is in no file and no graph, so no
 * helper follows it. Then one a parsing file calls directly, then the one with the most input code.
 */
function components(input: HypothesisInput): Component[] {
  const byFile = new Map<string, Map<string, SourceFunction[]>>();
  for (const f of input.functions) {
    const phase = phaseOf(input, f);
    if (phase === undefined) continue;
    const phases = byFile.get(f.path) ?? new Map<string, SourceFunction[]>();
    phases.set(phase, [...(phases.get(phase) ?? []), f]);
    byFile.set(f.path, phases);
  }
  const count = (path: string, phase: string) => byFile.get(path)?.get(phase)?.length ?? 0;
  const parsing = new Set([...byFile].filter(([, phases]) => phases.has('input')).map(([p]) => p));
  const parsingCount = (files: string[]) => files.filter(p => parsing.has(p)).length;
  return [...byFile.keys()]
    .filter(p => count(p, 'input') && count(p, 'request_init') && count(p, 'request_end'))
    .map(path => {
      const inputs = [...(byFile.get(path)?.get('input') ?? [])].sort((a, b) => a.start - b.start);
      const run = runners(path, inputs, input);
      const parsers = [...new Set([...run.viaHook, ...run.direct])].sort(
        (a, b) => Number(parsing.has(b)) - Number(parsing.has(a))
      );
      return { path, inputs, parsers: parsers.slice(0, MAX_PARSERS), run };
    })
    .sort(
      (a, b) =>
        parsingCount(b.run.viaHook) - parsingCount(a.run.viaHook) ||
        parsingCount(b.run.direct) - parsingCount(a.run.direct) ||
        count(b.path, 'input') - count(a.path, 'input') ||
        count(b.path, 'request_init') - count(a.path, 'request_init') ||
        (a.path < b.path ? -1 : 1)
    )
    .slice(0, MAX_COMPONENTS)
    .map(({ path, inputs, parsers }) => ({ path, inputs, parsers }));
}

/** `hook = fn;` or `s.hook = &fn;`: a name a function is installed in (not a call, not `==`). */
const INSTALL = /([A-Za-z_][\w.>-]*)\s*=\s*&?([A-Za-z_]\w*)\s*;/g;

/**
 * The files that run a component's code: the direct callers of its input code, and the files that
 * call a hook the component installs one of its own functions in, which the code graph does not
 * see (`php_rfc1867_callback = php_session_rfc1867_callback;` in the component, then
 * `php_rfc1867_callback(...)` in the parser). Any of its functions counts for a hook: the callback
 * a parser runs is often a dispatcher whose own label missed the input phase.
 */
function runners(
  component: string,
  inputs: SourceFunction[],
  input: HypothesisInput
): { viaHook: string[]; direct: string[] } {
  const pathOf = new Map(input.functions.map(f => [f.qn, f.path]));
  const qns = new Set(inputs.map(f => f.qn));
  const direct = input.calls.filter(([, b]) => qns.has(b)).map(([a]) => pathOf.get(a) ?? '');
  const own = new Set(input.functions.filter(f => f.path === component).map(f => f.name));
  const text = input.files.find(f => f.path === component)?.text ?? '';
  const hooks = new Set(
    [...text.matchAll(INSTALL)].filter(m => own.has(m[2] as string)).map(m => m[1] as string)
  );
  const viaHook = [...hooks].flatMap(h => {
    const call = new RegExp(String.raw`(?:^|[^\w.>])${escapeRegExp(h)}\s*\(`);
    return input.files.filter(f => call.test(f.text)).map(f => f.path);
  });
  const others = (files: string[]) => [...new Set(files)].filter(p => p && p !== component);
  return { viaHook: others(viaHook), direct: others(direct) };
}

/**
 * A component's brief seeds: the component and its parsers first, then the request start and
 * teardown, which are long files whose guard the brief already quotes.
 */
export function seedsOf(component: Component, guarded: GuardedTeardown[]): string[] {
  const lifecycle = guarded.flatMap(g => [g.setter.path, g.teardown.path]);
  return [...new Set([component.path, ...component.parsers, ...lifecycle])].slice(0, MAX_SEEDS);
}

// --------------------------------------------------------------------------- //
// What the hypotheses add: state a component reaches, and the structures a parser builds
// --------------------------------------------------------------------------- //

/**
 * The per-request state of other components that a component's code calls into, the most writes
 * first.
 *
 * A component that runs while input is parsed can fail part-way and leave the state of every
 * component it called into (a serializer's nesting data, a parser's buffers, a cache's entries),
 * each reset only by its own component's initialisation. The call is often a macro, and the
 * definition can be in a file the code graph does not parse (an re2c `.re` source). So, in C:
 * every name the component calls (macros expanded one level), each one's definition in another
 * file (the graph's, else by text), and the global state it writes. Callees that write nothing
 * global are left out; other languages get none.
 */
export function reachedState(component: string, input: HypothesisInput): ReachedState[] {
  if (!isC(component)) return [];
  const lines = linesByPath(input.files);
  const own = input.functions.filter(f => f.path === component);
  const expand = macroCalls(macros(input.files));
  const called = new Set<string>();
  for (const f of own) {
    const body = functionBody(f, lines);
    for (const name of body ? callNames(body.text) : []) {
      called.add(name);
      for (const inner of expand.get(name) ?? []) called.add(inner);
    }
  }
  const out: ReachedState[] = [];
  for (const name of called) {
    const def = definition(name, component, input, lines);
    if (!def) continue;
    const writes = globalWrites(def.body, (lines.get(def.path) ?? []).join('\n'));
    if (writes.length)
      out.push({ name, at: `${def.path}:${def.line}`, writes: writes.slice(0, MAX_WRITES) });
  }
  return out
    .sort((a, b) => b.writes.length - a.writes.length || (a.name < b.name ? -1 : 1))
    .slice(0, MAX_REACHED_STATE);
}

/** A called name's definition outside the component: the code graph's, else by its text. */
function definition(
  name: string,
  component: string,
  input: HypothesisInput,
  lines: Map<string, string[]>
): { path: string; line: number; body: string } | undefined {
  const node = input.functions.find(f => f.name === name && f.path !== component);
  if (!node) return definitionByText(name, component, lines);
  const body = functionBody(node, lines);
  return body ? { path: node.path, line: node.start, body: body.text } : undefined;
}

/**
 * The functions a parser reaches (up to BUILDER_DEPTH calls deep, in other files) that write raw
 * memory (`memory`) with several calls that can jump, the most such calls first: where a jump
 * leaves a structure half-built. What other exits unwind through (`_emalloc`, `bailout`) is the
 * jump's machinery, not a builder; a builder is often a listed exit itself, since it can unwind.
 */
export function stateBuilders(
  parser: string,
  input: HypothesisInput,
  exits: NonLocalExit[]
): SourceFunction[] {
  const jumping = new Set(exits.map(e => e.name));
  const onPath = new Set(exits.flatMap(e => e.path.slice(1)));
  const byQn = new Map(input.functions.map(f => [f.qn, f]));
  const callees = calleesOf(input.calls.filter(([, b]) => byQn.has(b)));
  const starts = input.functions.filter(f => f.path === parser).map(f => f.qn);
  const lines = linesByPath(input.files);
  // A function a signature macro names (`PHP_FUNCTION(strstr)`) is not the C function a parser
  // calls by that name.
  const named = (f: SourceFunction) =>
    definedBySignatureMacro(lines.get(f.path)?.[f.start - 1] ?? '', f.name);
  return [...reachable(starts, callees, BUILDER_DEPTH).keys()]
    .map(qn => byQn.get(qn) as SourceFunction)
    .filter(
      f =>
        f.path !== parser &&
        !onPath.has(f.name) &&
        !named(f) &&
        yes(input.labels.get(f.qn), 'memory') >= LABEL_P
    )
    .map(f => ({ f, n: jumpingCalls(f, lines, jumping) }))
    .filter(x => x.n >= MIN_JUMPING_CALLS)
    .sort((a, b) => b.n - a.n || (a.f.qn < b.f.qn ? -1 : 1))
    .slice(0, MAX_BUILDERS)
    .map(x => x.f);
}

/**
 * How many calls in `f`'s body can jump, counting each call, not each name. The body runs to its
 * closing brace, past an early graph end line, and leaves the signature out: a builder that is an
 * exit itself would otherwise count its own declaration as a call.
 */
function jumpingCalls(
  f: SourceFunction,
  lines: Map<string, string[]>,
  jumping: Set<string>
): number {
  const body = withoutComments(bodyAfterSignature(f, lines) ?? '');
  return [...body.matchAll(/\b([A-Za-z_]\w*)\s*\(/g)].filter(m => jumping.has(m[1] as string))
    .length;
}
