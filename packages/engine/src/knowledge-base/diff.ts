/**
 * A diff scan's knowledge base: the change, the paths through it, the threat model brought up to
 * date, and one brief per investigation packet, built before the scan as a full scan's is.
 *
 * Without it a diff runs upstream's diff workflow bare, and its helpers find the code around the
 * change themselves. Repeated source searches can spend many turns recovering caller and
 * callee relationships already held by the code graph. As for a full scan, finding and reading
 * happen here, outside the model's turns:
 *
 *   1  changes       the files changed since the base, with their hunks (git)
 *   2  graph         the code graph at HEAD (code-graph.ts): functions, calls, call references
 *   3  paths         the changed functions, and the paths through them: their callers up to entry
 *                    points (through code that passes a function on as a value, too), their
 *                    callees down to sinks
 *   4  labels        Jev's labels for the changed code and those paths; what did not change is
 *                    answered from the cache (cache.ts), so a diff asks about little
 *   5  threat model  the last full scan's review (stored-review.ts), updated by the review agent
 *                    when the change touches what the review describes (reviewGate), else reused.
 *                    With none stored, or one of a commit outside this checkout's history, the
 *                    build reviews the whole repository at HEAD itself (buildThreatModel) and
 *                    stores that review, so the next diff of this branch starts from it
 *   6  packets       one design call whose instructions are upstream's own rules for grouping a
 *                    scan into packets and for how far a diff follows supporting code
 *   7  briefs        the lead's index, a brief per packet, the reader (diff-briefing.ts)
 *
 * The graph is indexed fresh at HEAD so moved or renamed functions and their updated callers
 * reflect the current checkout.
 */
import { chmodSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { KNOWLEDGE_BASE_INDEX, KNOWLEDGE_BASE_OUTPUT } from '../constants';
import { runCommand, type Runner } from '../processes';
import type { AgentPlan } from './architecture-agent';
import {
  citedPaths,
  maintainedThreatModel,
  renderReview,
  reviewArchitecture,
  roleOf,
  type ArchitectureReview,
  type ReviewStats,
} from './architecture';
import { productRows, type BriefSummary } from './briefing';
import { AnswerCache } from './cache';
import { CodeGraph, type FunctionNode, type GraphTransport, graphTransport } from './code-graph';
import type { CynosDecisions, ReviewModel } from './cynos';
import { diffBriefing, diffTaskName, isProduct } from './diff-briefing';
import type { BuildPlan, KnowledgeBaseModels } from './index';
import { classify, inventory, type FileRow } from './inventory';
import { askMany, choice, noul, type Answers } from './jev';
import {
  DESIGN_MODEL,
  ENTRY_P,
  entryPoints,
  FILE_QUESTIONS,
  FILE_SWEEP_QUESTIONS,
  FUNCTION_QUESTIONS,
  functionStates,
  labelRepository,
  secretWindows,
  sinkFunctions,
  tokens,
  type Entry,
  type SecretWindow,
} from './plan';
import {
  loadReview,
  reuseReview,
  saveReview,
  type ReuseStats,
  type StoredReview,
} from './stored-review';

/** Where Jev's answers are kept in the cache; the full build's file, so its answers are reused. */
const ANSWERS_FILE = 'jev-answers.jsonl';
/** Callers followed up from a changed function, and callees down to a sink. */
export const PATH_DEPTH = 3;
/** Paths kept per changed function and direction; the rest are counted. */
export const MAX_PATHS = 12;
/** The change as the review agent and the packet design read it: hunks up to this many tokens. */
const DIGEST_HUNK_TOKENS = 60_000;
const DESIGN_ATTEMPTS = 3;
/** The brief of the changed files no packet reviews: CI, deployment, configuration, docs, tests. */
export const DIFF_BASELINE = 'diff-baseline';

// --------------------------------------------------------------------------- //
// 1. The change
// --------------------------------------------------------------------------- //

/** One hunk of a file's diff, with the HEAD-side lines it changed. */
export interface Hunk {
  oldStart: number;
  oldLines: number;
  newStart: number;
  newLines: number;
  /**
   * HEAD-side lines the hunk added or changed, and for a removal both lines it now sits between:
   * what a function's range must overlap to count as changed. A removal touches the line after it
   * as much as the one before: removing a decorator or a check just above a function changes that
   * function. In ascending order, each once.
   */
  changedLines: number[];
  /**
   * The lines the hunk removed, as they were at the base. Code a change removes from a file it keeps
   * (an entry point, a sensitive operation) is in no function at HEAD, and only these lines show it.
   */
  removed: string;
}

export interface Change {
  path: string;
  status: 'added' | 'modified' | 'deleted' | 'renamed';
  /** A rename's old path. */
  from?: string;
  /** The file's unified diff, header included. */
  patch: string;
  hunks: Hunk[];
  binary: boolean;
}

const HUNK = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;

/** A path without git's a/ or b/ prefix; /dev/null stays as it is. */
const unprefixed = (path: string, prefix: 'a/' | 'b/'): string =>
  path.startsWith(prefix) ? path.slice(prefix.length) : path;

/** C escapes git uses in a quoted path, by the letter after the backslash. */
const PATH_ESCAPES: Record<string, number> = {
  a: 7,
  b: 8,
  t: 9,
  n: 10,
  v: 11,
  f: 12,
  r: 13,
  '"': 34,
  '\\': 92,
};

/**
 * A path as git writes it in a diff header: bare, or, when it holds a quote, a backslash or a
 * control character, as a C string with its a/ or b/ prefix inside (`"b/a\"b.py"` for `a"b.py`),
 * any byte outside ASCII written in octal when core.quotePath is on. Taken as it stands, a quoted
 * path matches no file of the checkout and the change loses its row, functions and packet.
 */
export function headerPath(raw: string): string {
  const path = raw.trim();
  if (path.length < 2 || !path.startsWith('"') || !path.endsWith('"')) return path;
  const chars = Array.from(path.slice(1, -1));
  const bytes: number[] = [];
  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i] as string;
    if (ch !== '\\') {
      bytes.push(...Buffer.from(ch, 'utf8'));
      continue;
    }
    const octal = /^[0-3][0-7]{2}/.exec(chars.slice(i + 1, i + 4).join(''));
    if (octal) {
      bytes.push(parseInt(octal[0], 8));
      i += 3;
      continue;
    }
    const next = chars[i + 1] ?? '';
    bytes.push(
      ...(PATH_ESCAPES[next] !== undefined
        ? [PATH_ESCAPES[next] as number]
        : Buffer.from(next, 'utf8'))
    );
    i += 1;
  }
  return Buffer.from(bytes).toString('utf8');
}

/**
 * The two paths of a header line that names both, each bare or quoted (headerPath): the
 * `diff --git` line (separated by a space) and the `Binary files … differ` line (by " and ").
 * Those lines are all a mode change or a binary file has, so a quoted path there must be decoded
 * too.
 *
 * A bare path can itself hold the separator and a b/ (`foo b/run.sh`), so where a bare first path
 * ends is chosen among the places the separator could split the line, in this order: where both
 * sides name the same path (`a/X` and `b/X`: both lines name one path unless the file was added or
 * deleted, and a rename has its own lines), else where /dev/null or a quoted path follows, else the
 * first place b/ follows.
 */
export function pathPair(rest: string, separator: string): [string, string] | undefined {
  let first: string;
  if (rest.startsWith('"')) {
    let i = 1;
    while (i < rest.length && rest[i] !== '"') i += rest[i] === '\\' ? 2 : 1;
    first = rest.slice(0, i + 1);
    if (!rest.startsWith(separator, first.length)) return undefined;
  } else {
    const splits: number[] = [];
    for (let at = rest.indexOf(separator); at >= 0; at = rest.indexOf(separator, at + 1))
      splits.push(at);
    const second = (at: number): string => rest.slice(at + separator.length);
    const same = (at: number): boolean =>
      rest.startsWith('a/') &&
      second(at).startsWith('b/') &&
      rest.slice(2, at) === second(at).slice(2);
    const at =
      splits.find(same) ??
      splits.find(i => /^("|\/dev\/null$)/.test(second(i))) ??
      splits.find(i => second(i).startsWith('b/'));
    if (at === undefined) return undefined;
    first = rest.slice(0, at);
  }
  return [headerPath(first), headerPath(rest.slice(first.length + separator.length))];
}

/**
 * The files of a unified diff (`git diff -M`), each with its hunks. A deleted file is named by its
 * old path, a renamed one by its new path with the old one beside it; a binary file has no hunks.
 */
export function parseDiff(diff: string): Change[] {
  const out: Change[] = [];
  for (const block of diff.split(/^(?=diff --git )/m)) {
    if (!block.startsWith('diff --git ')) continue;
    const lines = block.split('\n');
    let status: Change['status'] = 'modified';
    let oldPath = '';
    let newPath = '';
    let from: string | undefined;
    let binary = false;
    const hunks: Hunk[] = [];
    let hunk: Hunk | undefined;
    let line = 0;
    for (const l of lines) {
      const h = HUNK.exec(l);
      if (h) {
        hunk = {
          oldStart: Number(h[1]),
          oldLines: h[2] === undefined ? 1 : Number(h[2]),
          newStart: Number(h[3]),
          newLines: h[4] === undefined ? 1 : Number(h[4]),
          changedLines: [],
          removed: '',
        };
        hunks.push(hunk);
        line = hunk.newStart;
        continue;
      }
      if (hunk) {
        if (l.startsWith('+')) hunk.changedLines.push(line++);
        else if (l.startsWith('-')) {
          hunk.changedLines.push(...[line - 1, line].filter(n => n >= 1));
          hunk.removed += `${l.slice(1)}\n`;
        } else if (l.startsWith(' ')) line++;
        continue;
      }
      if (l.startsWith('new file mode')) status = 'added';
      else if (l.startsWith('deleted file mode')) status = 'deleted';
      else if (l.startsWith('rename from ')) {
        status = 'renamed';
        from = headerPath(l.slice('rename from '.length));
      } else if (l.startsWith('rename to ')) newPath = headerPath(l.slice('rename to '.length));
      else if (l.startsWith('--- ')) oldPath = headerPath(l.slice(4)).replace(/^a\//, '');
      else if (l.startsWith('+++ ')) newPath = headerPath(l.slice(4)).replace(/^b\//, '');
      else if (l.startsWith('Binary files ') && l.endsWith(' differ')) {
        binary = true;
        const pair = pathPair(l.slice('Binary files '.length, -' differ'.length), ' and ');
        if (pair) {
          oldPath ||= unprefixed(pair[0], 'a/');
          newPath ||= unprefixed(pair[1], 'b/');
        }
      }
    }
    if (!newPath && !oldPath) {
      // A mode change or an empty file: the paths are only in the first line.
      const pair = pathPair((lines[0] ?? '').slice('diff --git '.length), ' ');
      oldPath = pair ? unprefixed(pair[0], 'a/') : '';
      newPath = pair ? unprefixed(pair[1], 'b/') : '';
    }
    const path = status === 'deleted' || newPath === '/dev/null' ? oldPath : newPath;
    if (!path || path === '/dev/null') continue;
    for (const h of hunks) h.changedLines = [...new Set(h.changedLines)].sort((a, b) => a - b);
    out.push({
      path,
      status,
      ...(from ? { from } : {}),
      patch: block.trimEnd(),
      hunks,
      binary,
    });
  }
  return out;
}

/** The changes from base to HEAD in the checkout at project; throws when git fails. */
export function gitChanges(project: string, base: string, run: Runner = runCommand): Change[] {
  if (!/^[0-9a-f]{7,64}$/.test(base)) throw new Error(`the diff base is no commit id: ${base}`);
  const result = run('git', [
    '-C',
    project,
    '-c',
    'core.quotePath=false',
    'diff',
    '--no-color',
    '--no-ext-diff',
    '--no-textconv',
    '-M',
    '-U5',
    base,
    'HEAD',
    '--',
  ]);
  if (result.status !== 0)
    throw new Error(`git diff ${base.slice(0, 12)} HEAD failed: ${result.stderr.trim()}`);
  return parseDiff(result.stdout);
}

/**
 * The changed files as they were at the base, keyed by their HEAD path. What a file was (a route
 * table, an access control, a deployment file) decides whether changing it touches the threat
 * model, and a change can remove exactly that: a deleted file has no row in this checkout, and a
 * modified one can lose its only access check, which its HEAD text no longer shows. An added file,
 * or one whose base is binary or unreadable, has no base row; a file binary only at HEAD still has
 * its text base read.
 */
export function baseRows(
  project: string,
  base: string,
  changes: Change[],
  run: Runner = runCommand
): FileRow[] {
  const out: FileRow[] = [];
  for (const c of changes) {
    if (c.status === 'added') continue;
    const shown = run('git', ['-C', project, 'show', `${base}:${c.from ?? c.path}`]);
    if (shown.status !== 0 || shown.stdout.includes('\0')) continue;
    // Classified as the file it was: a route moved into tests/ was a route at the base.
    const [kind, reason] = classify(c.from ?? c.path, shown.stdout);
    out.push({
      path: c.path,
      kind,
      reason,
      lines: shown.stdout.split('\n').length,
      text: shown.stdout,
    });
  }
  return out;
}

/** Whether sha is HEAD or one of its ancestors in the checkout at project. */
export function inHistory(project: string, sha: string, run: Runner = runCommand): boolean {
  if (!/^[0-9a-f]{7,64}$/.test(sha)) return false;
  return run('git', ['-C', project, 'merge-base', '--is-ancestor', sha, 'HEAD']).status === 0;
}

// --------------------------------------------------------------------------- //
// 3. The paths through the change
// --------------------------------------------------------------------------- //

/**
 * The functions a change touches: those whose HEAD range holds a line a hunk changed. The graph
 * is at HEAD, so the ranges are the changed file's own; a deleted file's functions are gone, and
 * its hunks speak for it.
 */
export function changedFunctions(changes: Change[], functions: FunctionNode[]): FunctionNode[] {
  const lines = new Map<string, number[]>();
  for (const c of changes)
    if (c.status !== 'deleted')
      lines.set(
        c.path,
        c.hunks.flatMap(h => h.changedLines)
      );
  return functions.filter(f =>
    (lines.get(f.path) ?? []).some(n => n >= f.start && n <= Math.max(f.end, f.start))
  );
}

/** The paths through one changed function. */
export interface FunctionPaths {
  fn: FunctionNode;
  /**
   * Paths up to the function, each from its outermost caller down to the direct one. A step can be
   * a call reference (valueEdge): code that passes the next function on as a value, a callback
   * wired into a plugin, the only link to whoever later calls it.
   */
  callers: string[][];
  /** Call paths down from the function, to be cut at sensitive operations once labelled. */
  callees: string[][];
  /** Paths left out beyond MAX_PATHS, per direction. */
  more: { callers: number; callees: number };
}

/**
 * The paths of at most PATH_DEPTH steps from `start` along `next`: one to every function within
 * reach, the shortest, ending where the walk could go no further.
 *
 * Enumerating paths cannot be bounded safely: a helper that hundreds of functions call fans out to
 * millions of paths within three steps, and any budget on them can be spent before the one path
 * that reaches an entry point. So the walk is over functions, breadth first in name order (the same
 * every build), each function reached once and remembering the function it was reached from: it is
 * linear in the graph, and every function within PATH_DEPTH, entry points included, is found. It
 * does not go on past a function `stop` says ends a path (an entry point). A path is returned for
 * each function the walk went no further from, from the first step to that function.
 */
function walk(
  start: string,
  next: Map<string, string[]>,
  stop: (qn: string) => boolean
): string[][] {
  const from = new Map<string, string>();
  const reached: string[] = [];
  let level = [start];
  for (let depth = 1; depth <= PATH_DEPTH && level.length; depth++) {
    const deeper: string[] = [];
    for (const node of level) {
      if (node !== start && stop(node)) continue;
      for (const n of next.get(node) ?? []) {
        if (n === start || from.has(n)) continue;
        from.set(n, node);
        reached.push(n);
        deeper.push(n);
      }
    }
    level = deeper;
  }
  // A function the walk went on from is a step on another path, not the end of one.
  const steps = new Set(from.values());
  const pathTo = (end: string): string[] => {
    const path = [end];
    for (let at = from.get(end); at !== undefined && at !== start; at = from.get(at))
      path.unshift(at);
    return path;
  };
  return reached.filter(n => !steps.has(n)).map(pathTo);
}

/**
 * Paths in the order worth reading: those that reach what `reaches` looks for (an entry point up,
 * a sensitive operation down) first, then the longer ones, then by name. Name order alone let a
 * dozen shallow dead ends crowd out the one path that reaches an entry point.
 */
function ranked(paths: string[][], reaches: (path: string[]) => boolean): string[][] {
  const key = (p: string[]): [number, number, string] => [
    reaches(p) ? 0 : 1,
    -p.length,
    p.join('>'),
  ];
  return [...paths].sort((x, y) => {
    const [a, b] = [key(x), key(y)];
    return a[0] - b[0] || a[1] - b[1] || (a[2] < b[2] ? -1 : a[2] > b[2] ? 1 : 0);
  });
}

/** An edge list as an adjacency map, each list sorted, self-edges and excluded nodes dropped. */
function adjacency(
  edges: [string, string][],
  from: 0 | 1,
  keep: (qn: string) => boolean
): Map<string, string[]> {
  const out = new Map<string, Set<string>>();
  for (const edge of edges) {
    const a = edge[from];
    const b = edge[1 - from] as string;
    if (a === b || !keep(a) || !keep(b)) continue;
    out.set(a, (out.get(a) ?? new Set()).add(b));
  }
  return new Map([...out].map(([k, v]) => [k, [...v].sort()]));
}

/** A call reference as a key: `a` passes `b` on as a value. */
export const valueEdge = (a: string, b: string): string => `${a}>${b}`;

/**
 * Every changed function's paths: callers up to PATH_DEPTH, through calls and call references
 * alike (stopping at an entry point once labels exist), and callees down to PATH_DEPTH, each
 * direction ranked (entry points and sensitive operations first) and cut to `keep`. Functions in
 * tests are left out: a test calling the changed code is no attacker's path. Each path is in the
 * order it is read: callers from the outermost down, callees from the first call on.
 */
export function functionPaths(
  changed: FunctionNode[],
  calls: [string, string][],
  references: [string, string][],
  functions: FunctionNode[],
  isTest: (path: string) => boolean,
  isEntry: (qn: string) => boolean = () => false,
  isSink: (qn: string) => boolean = () => false,
  keep: number = MAX_PATHS
): FunctionPaths[] {
  const pathOf = new Map(functions.map(f => [f.qn, f.path]));
  const product = (qn: string): boolean => {
    const path = pathOf.get(qn);
    return path !== undefined && !isTest(path);
  };
  const up = adjacency([...calls, ...references], 1, product);
  const down = adjacency(calls, 0, product);
  return changed.map(fn => {
    // A caller path is walked from the changed function up; it is kept outermost caller first.
    const callers = ranked(walk(fn.qn, up, isEntry), p => isEntry(p[p.length - 1] as string)).map(
      p => [...p].reverse()
    );
    const callees = ranked(
      walk(fn.qn, down, () => false),
      p => p.some(isSink)
    );
    return {
      fn,
      callers: callers.slice(0, keep),
      callees: callees.slice(0, keep),
      more: {
        callers: Math.max(callers.length - keep, 0),
        callees: Math.max(callees.length - keep, 0),
      },
    };
  });
}

/**
 * The functions the paths name, the changed ones first: every one, since which of them is an entry
 * point or a sink is what labelling them finds out, and a cap taken before that could drop the one
 * entry point that matters. Unchanged functions are answered from Jev's cache, and the build's Jev
 * spend is capped (index.ts MAX_COST_USD).
 */
export function pathFunctions(paths: FunctionPaths[]): string[] {
  const out = new Set<string>(paths.map(p => p.fn.qn));
  for (const p of paths) for (const qn of [...p.callers.flat(), ...p.callees.flat()]) out.add(qn);
  return [...out];
}

// --------------------------------------------------------------------------- //
// 5. The threat model
// --------------------------------------------------------------------------- //

/**
 * Why the stored threat model needs updating for this change, or nothing when it does not. The
 * review describes the architecture: its entry points, boundaries, controls, configuration and
 * deployment. A change touches that when it touches a file the review cites, a file with an
 * architecture role, an entry point, an access control or a sensitive operation. A change to a
 * helper the review never mentions leaves it as it is.
 */
export function reviewGate(
  review: ArchitectureReview,
  changes: Change[],
  changed: FunctionNode[],
  labels: {
    roles: Map<string, Answers>;
    fileLabels: Map<string, Answers>;
    functionLabels: Map<string, Answers>;
    /** The changed files' labels as they were at the base (baseRows), by HEAD path. */
    base?: { roles: Map<string, Answers>; fileLabels: Map<string, Answers> };
    /** The function questions' answers about each hunk's removed lines (removedCode). */
    removed?: { change: Change; answers: Answers }[];
  }
): string[] {
  const texts = [
    review.threatModel.summary,
    ...review.threatModel.assets,
    ...review.threatModel.trustBoundaries,
    ...review.threatModel.attackerCapabilities,
    ...review.threatModel.securityObjectives,
    ...review.threatModel.assumptions,
    ...review.effectiveResources.flatMap(r => Object.values(r)),
  ];
  const cited = new Set<string>();
  for (const text of texts) for (const p of citedPaths(text)) cited.add(p.replace(/^\.\//, ''));
  // A citation the full review could not repair was cut to its bare file (architecture.ts
  // cutInvalid), which is no `path:line` any more but still says the review rests on that file.
  const named = (path: string): boolean => texts.some(t => mentionsPath(t, path));
  const reasons: string[] = [];
  for (const c of changes) {
    const paths = [c.path, ...(c.from ? [c.from] : [])];
    if (paths.some(p => cited.has(p) || named(p)))
      reasons.push(`${c.path} (${c.status}) is cited by the threat model`);
    // What the file is now, else what it was at the base: a change can remove the very thing.
    const now = c.status === 'deleted' ? undefined : labels.roles.get(c.path);
    const role = roleOf(now) ?? roleOf(labels.base?.roles.get(c.path));
    if (role)
      reasons.push(
        `${c.path} (${c.status}) ${roleOf(now) ? 'has' : 'had'} the architecture role ${role.role}`
      );
    // A file can define an entry point no graph function holds: a route table, an inline handler.
    const entry = (a: Answers | undefined): boolean => noul(a, 'entry_point') >= ENTRY_P;
    const entryNow = c.status !== 'deleted' && entry(labels.fileLabels.get(c.path));
    if (entryNow || entry(labels.base?.fileLabels.get(c.path)))
      reasons.push(`${c.path} (${c.status}) ${entryNow ? 'defines' : 'defined'} an entry point`);
    const access = (a: Answers | undefined): boolean => noul(a, 'access_control') >= 0.5;
    const accessNow = c.status !== 'deleted' && access(labels.fileLabels.get(c.path));
    if (accessNow || access(labels.base?.fileLabels.get(c.path)))
      reasons.push(
        `${c.path} (${c.status}) ${accessNow ? 'decides' : 'decided'} authentication or authorization`
      );
  }
  for (const f of changed) {
    const a = labels.functionLabels.get(f.qn);
    if (noul(a, 'entry_point') >= 0.3) reasons.push(`${f.qn} is an entry point`);
    const sink = choice(a, 'sink');
    if (sink !== 'none' && sink !== 'rendering')
      reasons.push(`${f.qn} performs a sensitive operation (${sink})`);
  }
  // Code the change removed, which no function at HEAD holds any more.
  for (const { change: c, answers } of labels.removed ?? []) {
    if (noul(answers, 'entry_point') >= 0.3)
      reasons.push(`${c.path} (${c.status}) lost code that was an entry point`);
    const sink = choice(answers, 'sink');
    if (sink !== 'none' && sink !== 'rendering' && sink)
      reasons.push(
        `${c.path} (${c.status}) lost code that performed a sensitive operation (${sink})`
      );
  }
  return [...new Set(reasons)];
}

/**
 * Whether a text names a path as a whole word, written as it is or with a leading ./: not as part of
 * a longer path or name.
 */
export function mentionsPath(text: string, path: string): boolean {
  const escaped = path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(^|[^\\w./-])(?:\\./)?${escaped}(?=$|[^\\w./-]|\\.(?:$|\\s))`).test(text);
}

/**
 * The change as the review agent and the packet design read it: every changed file with its
 * status, every changed function with its labels and paths, then the hunks up to
 * DIGEST_HUNK_TOKENS (the rest named, to read from the checkout).
 */
export function changeDigest(
  base: string,
  changes: Change[],
  paths: FunctionPaths[],
  functionLabels: Map<string, Answers>,
  values: Set<string>
): string {
  const label = (qn: string): string => {
    const a = functionLabels.get(qn);
    const sink = choice(a, 'sink');
    return [
      noul(a, 'entry_point') >= 0.3 ? 'entry' : '',
      sink !== 'none' && sink !== 'rendering' && sink ? `sink:${sink}` : '',
    ]
      .filter(Boolean)
      .join(',');
  };
  const md = [
    `Change: ${base.slice(0, 12)}..HEAD, ${changes.length} files`,
    '',
    '## Changed files',
    '',
    ...changes.map(
      c =>
        `- ${c.status} \`${c.path}\`${c.from ? ` (from \`${c.from}\`)` : ''}${c.binary ? ' (binary)' : ''}`
    ),
    '',
    '## Changed functions and the paths through them',
    '',
  ];
  for (const p of paths) {
    md.push(
      `- \`${p.fn.qn}\` (${p.fn.path}:${p.fn.start}-${p.fn.end}) ${label(p.fn.qn)}`.trimEnd()
    );
    for (const c of p.callers.slice(0, 4))
      md.push(
        `  - reached from: ${c
          .map((q, i) => {
            const passes =
              i + 1 < c.length
                ? values.has(valueEdge(q, c[i + 1] as string))
                : values.has(valueEdge(q, p.fn.qn));
            return `\`${q}\` ${label(q)}${passes ? ' (passes the next on as a value)' : ''}`.trim();
          })
          .join(' -> ')}`
      );
    for (const c of p.callees.slice(0, 4))
      md.push(`  - calls: ${c.map(q => `\`${q}\` ${label(q)}`.trimEnd()).join(' -> ')}`);
  }
  md.push('', '## Hunks', '');
  let left = DIGEST_HUNK_TOKENS;
  const omitted: string[] = [];
  for (const c of changes) {
    const size = tokens(c.patch);
    if (c.binary || size > left) {
      omitted.push(c.path);
      continue;
    }
    md.push('```diff', c.patch, '```', '');
    left -= size;
  }
  if (omitted.length)
    md.push(
      `Not shown (binary or past the budget; read them from the checkout): ${omitted.join(', ')}`
    );
  return md.join('\n');
}

// --------------------------------------------------------------------------- //
// 6. The packets
// --------------------------------------------------------------------------- //

/**
 * upstream's own rules for grouping a scan's questions into packets (core-scan.md, steps 4 and 5)
 * and for how far a diff's review follows supporting code (finding-discovery), read from upstream's
 * bundled plugin at the pin (`plugin`, the runtime's bundledPlugin). Throws when a rule is no longer where it
 * was: an upstream bump that moved or rewrote them.
 */
export function packetRules(plugin: string): string[] {
  const read = (path: string): string[] => readFileSync(join(plugin, path), 'utf8').split('\n');
  const coreScan = read('references/core-scan.md');
  const discovery = read('skills/finding-discovery/SKILL.md');
  const rules = [
    coreScan.find(l => l.startsWith('4. Group promising source-backed questions')),
    coreScan.find(l => l.startsWith('5. Delegate independent packet groups')),
    discovery.find(l => l.startsWith('For a diff, inspect the actual changed behavior')),
  ];
  if (rules.some(r => r === undefined))
    throw new Error("upstream's packet and diff rules are not where the pinned plugin had them");
  return rules as string[];
}

/** One packet of a change: a helper's assignment. */
export interface DiffPacket {
  id: string;
  perspective: string;
  attacker: string;
  /** The changed product files it reviews. */
  changed: string[];
  /** Unchanged files it needs to follow the change. */
  context: string[];
  /** Bounded questions, each naming functions or call sites from the paths. */
  questions: string[];
}

/** The design's instructions: upstream's rules, then the output contract. */
export function designSystem(rules: string[]): string {
  return `You split the security review of one code change into investigation packets. Auditor agents
review the packets in parallel, one each, starting from the packet's changed files and the call
paths through them. You only design the packets; you do not look for vulnerabilities yourself.

Follow these rules, codex-security's own (the scan "parent" is the agent that starts the auditors;
you are planning its delegation):

${rules.map(r => `> ${r}`).join('\n\n')}

Output contract:
- Every changed product file the change lists belongs to at least one packet; a file may belong to
  several when it serves several boundaries.
- perspective: what the change does in this packet's code, and what an attacker would gain if it is
  wrong.
- attacker: one of the threat model's attacker capabilities, as written there. Never invent one.
- context_files: unchanged files the packet needs to follow the change (the paths name them).
- questions: the concrete questions the auditor must answer, each naming the functions or call
  sites it concerns from the paths. They bound the review: a question with no named code is too
  broad.
Return JSON: {"packets": [{"id", "perspective", "attacker", "changed_files", "context_files", "questions"}]}`;
}

const slug = (raw: unknown, n: number): string =>
  String(raw ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-') // one dash per run, so at most one at each end
    .replace(/^-|-$/g, '')
    .slice(0, 48) || `packet-${n}`;

/**
 * The design's packets, checked: changed files only from the change, context files only files of
 * the checkout, ids slugs whose task names are unique (never the diff baseline's), every packet with its questions,
 * its perspective and its attacker. A
 * changed product file no packet took joins the packet whose files share the most of its paths'
 * files, else the first, with a question of its own naming it, since a packet's questions bound
 * its helper's review; the design must give at least one packet a changed file.
 */
export function checkedDiffDesign(
  design: unknown,
  changedProduct: string[],
  files: Set<string>,
  related: Map<string, Set<string>>
): DiffPacket[] {
  const raw = (design as { packets?: unknown[] } | null)?.packets ?? [];
  const changed = new Set(changedProduct);
  const seen = new Set<string>([diffTaskName(DIFF_BASELINE)]);
  const packets: DiffPacket[] = [];
  for (const item of raw) {
    const p = (item ?? {}) as Record<string, unknown>;
    const list = (key: string, keep: (f: string) => boolean): string[] => [
      ...new Set(
        (Array.isArray(p[key]) ? (p[key] as unknown[]) : [])
          .filter((f): f is string => typeof f === 'string')
          .map(f => f.replace(/^\.\//, ''))
          .filter(keep)
      ),
    ];
    // Unique by task name, which names the helper and its result file: `auth` and `packet-auth`
    // are different ids but the same task.
    let id = slug(p['id'], packets.length + 1);
    while (seen.has(diffTaskName(id))) id += '-x';
    seen.add(diffTaskName(id));
    const mine = list('changed_files', f => changed.has(f));
    packets.push({
      id,
      perspective: String(p['perspective'] ?? ''),
      attacker: String(p['attacker'] ?? ''),
      changed: mine,
      context: list('context_files', f => files.has(f) && !mine.includes(f)),
      questions: (Array.isArray(p['questions']) ? (p['questions'] as unknown[]) : [])
        .filter((q): q is string => typeof q === 'string' && q.trim() !== '')
        .map(q => q.trim()),
    });
  }
  const kept = packets.filter(p => p.changed.length);
  if (!kept.length) throw new Error('no packet of the design reviews a changed product file');
  // The questions bound a helper's review (its brief's Scope); a packet without them is unbounded.
  const open = kept.filter(p => !p.questions.length).map(p => p.id);
  if (open.length) throw new Error(`packets with no questions: ${open.join(', ')}`);
  // The perspective and the attacker frame the helper's assignment (its brief's first lines).
  const unframed = kept.filter(p => !p.perspective.trim() || !p.attacker.trim()).map(p => p.id);
  if (unframed.length)
    throw new Error(`packets with no perspective or attacker: ${unframed.join(', ')}`);
  for (const file of changedProduct) {
    if (kept.some(p => p.changed.includes(file))) continue;
    const near = related.get(file) ?? new Set();
    const score = (p: DiffPacket): number =>
      [...p.changed, ...p.context].filter(f => near.has(f)).length;
    const best = [...kept].sort((x, y) => score(y) - score(x))[0] as DiffPacket;
    best.changed.push(file);
    best.questions.push(
      `What does the change to \`${file}\` do to this packet's boundary, and which of its callers in the paths reach the changed code?`
    );
  }
  return kept;
}

/** One design call, retried when its answer fails the check, as the full scan's design is. */
export async function designDiffPackets(
  model: ReviewModel,
  system: string,
  user: string,
  check: (design: unknown) => DiffPacket[],
  log: (message: string) => void
): Promise<DiffPacket[]> {
  let problem = '';
  for (let attempt = 1; attempt <= DESIGN_ATTEMPTS; attempt++) {
    const raw = await model.chatJson(DESIGN_MODEL, system, user);
    try {
      return check(JSON.parse(raw));
    } catch (error) {
      problem = error instanceof Error ? error.message : String(error);
      log(`packet design attempt ${attempt} rejected: ${problem}`);
    }
  }
  throw new Error(`no usable packet design after ${DESIGN_ATTEMPTS} attempts: ${problem}`);
}

// --------------------------------------------------------------------------- //
// The build
// --------------------------------------------------------------------------- //

/** A diff build: a full build's plan, with the base the change starts from. */
export interface DiffBuildPlan extends Omit<BuildPlan, 'maxHypothesisPackets'> {
  /** The diff's base commit. */
  base: string;
  /**
   * upstream's bundled plugin, whose rules the packet design follows. Asked for only when there
   * are packets to design: the docker runtime copies it out of the image (bundledPlugin).
   */
  plugin: () => string;
}

/** What the diff build made, as run.json records it. */
export interface DiffKnowledgeBaseSummary {
  kind: 'diff';
  base: string;
  changed_files: number;
  changed_functions: number;
  /** Functions the paths through the change brought in. */
  path_functions: number;
  graph: { functions: number; calls: number; call_references: number };
  /** Where the threat model came from (stored, or built), and what the update did. */
  threat_model: {
    from: ReuseStats;
    /** Why it was updated; empty when the change left it as it was. */
    gate: string[];
    updated: boolean;
    review: ReviewStats | null;
  };
  briefs: BriefSummary[];
  secret_windows: number;
  cache: { answers_reused: number };
  jev_calls: number;
  cost_usd: number;
}

/** Labels from Jev: per function, per product file, and the file sweep's. */
interface Labels {
  functionLabels: Map<string, Answers>;
  fileLabels: Map<string, Answers>;
  roles: Map<string, Answers>;
  /** The changed files as they were at the base (baseRows), by HEAD path. */
  base: { fileLabels: Map<string, Answers>; roles: Map<string, Answers> };
  /** The function questions about each hunk's removed lines, for the gate. */
  removed: { change: Change; answers: Answers }[];
  secrets: SecretWindow[];
}

/**
 * Each hunk's removed lines as the function questions' state, keyed `<path>#<hunk>`: what the
 * removed code was (an entry point, a sensitive operation), asked as of a function's code.
 */
export function removedCode(changes: Change[]): [string, unknown, Change][] {
  const out: [string, unknown, Change][] = [];
  for (const c of changes)
    c.hunks.forEach((h, i) => {
      if (!h.removed.trim()) return;
      out.push([
        `${c.path}#${i}`,
        {
          path: c.from ?? c.path,
          function: '(lines the change removed)',
          imports: '',
          decorators: '',
          code: h.removed,
        },
        c,
      ]);
    });
  return out;
}

/**
 * A change and what the knowledge base knows about it: since the diff's base for the packets, and
 * since the stored review's commit for the threat model when that is older.
 */
interface ChangeView {
  changes: Change[];
  changed: FunctionNode[];
  labels: Labels;
  /** The entry points among the labelled functions and files, and the files that hold them. */
  entries: Entry[];
  entryFiles: Map<string, number>;
  sinks: Map<string, string>;
  /** The paths through the changed functions, cut at entry points and ranked. */
  paths: FunctionPaths[];
  /** Every function the paths reach: what was labelled. */
  qns: Set<string>;
  digest: string;
}

/** What changeView reads: the build's checkout, graph and model calls. */
interface ViewInput {
  plan: DiffBuildPlan;
  client: CynosDecisions;
  rows: FileRow[];
  functions: FunctionNode[];
  calls: [string, string][];
  references: [string, string][];
  values: Set<string>;
  isTest: (path: string) => boolean;
  run: Runner;
  log: (message: string) => void;
}

/**
 * Steps 3 and 4 for a change from commit `from`: the changed functions, every path through them
 * (before labels nothing is known about entry points or sinks, so every function the paths reach
 * is labelled), Jev's labels for those functions and their files and for the changed files at
 * `from`, then the paths again, callers cut at entry points and both directions ranked by what
 * they reach, and the digest the review agent and the packet design read.
 */
async function changeView(input: ViewInput, from: string, changes: Change[]): Promise<ChangeView> {
  const { plan, client, rows, functions, calls, references, values, isTest, run, log } = input;
  const changed = changedFunctions(changes, functions);
  const walked = functionPaths(
    changed,
    calls,
    references,
    functions,
    isTest,
    () => false,
    () => false,
    Infinity
  );
  const qns = new Set(pathFunctions(walked));
  const based = baseRows(plan.project, from, changes, run);
  const labels = await labelChange(client, rows, based, functions, qns, changes, log);
  const entries = entryPoints(
    {
      rows,
      product: productRows(rows).filter(r => r.text),
      functions: functions.filter(f => qns.has(f.qn)),
      calls: [],
      tokens: new Map<string, number>(),
    },
    labels.functionLabels,
    labels.fileLabels
  );
  const entryFiles = new Map<string, number>();
  for (const e of entries) entryFiles.set(e.path, (entryFiles.get(e.path) ?? 0) + 1);
  const entryQns = new Set(entries.map(e => e.qn));
  const sinks = sinkFunctions(labels.functionLabels);
  const paths = functionPaths(
    changed,
    calls,
    references,
    functions,
    isTest,
    qn => entryQns.has(qn),
    qn => sinks.has(qn)
  );
  const digest = changeDigest(from, changes, paths, labels.functionLabels, values);
  return { changes, changed, labels, entries, entryFiles, sinks, paths, qns, digest };
}

/** Steps 1-4's labels: Jev on the changed code and the paths' functions and files. */
async function labelChange(
  client: CynosDecisions,
  rows: FileRow[],
  based: FileRow[],
  functions: FunctionNode[],
  qns: Set<string>,
  changes: Change[],
  log: (message: string) => void
): Promise<Labels> {
  const byPath = new Map(rows.map(r => [r.path, r]));
  const labelled = functions.filter(f => qns.has(f.qn));
  const files = new Set([
    ...labelled.map(f => f.path),
    ...changes.filter(c => c.status !== 'deleted').map(c => c.path),
  ]);
  const product = productRows(rows).filter(r => r.text && files.has(r.path));
  const text = [...files]
    .map(p => byPath.get(p))
    .filter((r): r is FileRow => r?.text !== undefined);
  const repo = {
    rows,
    product,
    functions: labelled,
    calls: [],
    tokens: new Map(product.map(r => [r.path, tokens(r.text ?? '')])),
  };
  const fileItems = (list: FileRow[]): [string, unknown][] =>
    list.map(r => [r.path, { path: r.path, content: r.text }]);
  const changedText = changes
    .filter(c => c.status !== 'deleted')
    .map(c => byPath.get(c.path))
    .filter((r): r is FileRow => r?.text !== undefined);
  // The changed files as they were are asked the same file questions, for the threat model's
  // gate; unchanged text is answered from the cache.
  const removedItems = removedCode(changes);
  const [
    { answers: functionLabels },
    { answers: fileLabels },
    { answers: roles },
    { answers: baseFileLabels },
    { answers: baseRoles },
    { answers: removedAnswers },
  ] = await Promise.all([
    askMany(client, functionStates(repo), FUNCTION_QUESTIONS, log),
    askMany(client, fileItems(product), FILE_QUESTIONS, log),
    askMany(client, fileItems(text), FILE_SWEEP_QUESTIONS, log),
    askMany(client, fileItems(productRows(based).filter(r => r.text)), FILE_QUESTIONS, log),
    askMany(client, fileItems(based), FILE_SWEEP_QUESTIONS, log),
    askMany(
      client,
      removedItems.map(([key, state]) => [key, state] as [string, unknown]),
      FUNCTION_QUESTIONS,
      log
    ),
  ]);
  const removed = removedItems.flatMap(([key, , change]) => {
    const answers = removedAnswers.get(key);
    return answers ? [{ change, answers }] : [];
  });
  const secrets = await secretWindows(client, changedText, new Set(), roles, log);
  return {
    functionLabels,
    fileLabels,
    roles,
    base: { fileLabels: baseFileLabels, roles: baseRoles },
    removed,
    secrets,
  };
}

/**
 * Builds a diff's knowledge base into `<work>/output` and `<work>/kb`, in the order the module
 * comment lists; throws when a step fails.
 */
export async function buildDiffKnowledgeBase(
  plan: DiffBuildPlan,
  log: (message: string) => void,
  models: KnowledgeBaseModels,
  transport: GraphTransport = graphTransport,
  run: Runner = runCommand
): Promise<DiffKnowledgeBaseSummary> {
  // 0. The last full scan's review, which step 5 brings up to date; with none usable, step 5
  // builds one.
  const stored = storedReview(plan, log, run);
  const client = models.decisions;
  const stop = (): void => {
    if (plan.signal?.aborted)
      throw new Error(`the build was stopped: ${String(plan.signal.reason)}`);
  };
  const output = join(plan.work, KNOWLEDGE_BASE_OUTPUT);
  mkdirSync(join(plan.work, 'graph'), { recursive: true, mode: 0o700 });
  mkdirSync(output, { recursive: true, mode: 0o700 });
  if (plan.cacheDir) client.cache = new AnswerCache(join(plan.cacheDir, ANSWERS_FILE));

  // 1. The change, and every file of the checkout.
  const changes = gitChanges(plan.project, plan.base, run);
  const rows = inventory(plan.project);
  const byPath = new Map(rows.map(r => [r.path, r]));
  plan.step?.('files', `${changes.length} changed files`, { changed_files: changes.length });

  // 2. The graph at HEAD; the server and its container end whatever happens.
  stop();
  const graph = new CodeGraph(
    {
      name: plan.name,
      project: plan.project,
      home: join(plan.work, 'graph'),
      runtime: plan.runtime,
      paths: plan.paths,
      ...(plan.signal ? { signal: plan.signal } : {}),
    },
    transport
  );
  let functions: FunctionNode[];
  let calls: [string, string][];
  let references: [string, string][];
  try {
    await graph.start();
    await graph.index();
    functions = await graph.functions();
    calls = await graph.calls();
    references = await graph.callReferences();
  } finally {
    await graph.stop();
  }
  plan.step?.('graph', `code graph: ${functions.length} functions, ${calls.length} calls`, {
    functions: functions.length,
    calls: calls.length,
  });

  // 3-4. The change from the base: the changed functions, the paths through them, Jev's labels.
  const isTest = (path: string): boolean => byPath.get(path)?.kind === 'test';
  const values = new Set(references.map(([a, b]) => valueEdge(a, b)));
  const viewOf = (from: string, change: Change[]): Promise<ChangeView> =>
    changeView(
      { plan, client, rows, functions, calls, references, values, isTest, run, log },
      from,
      change
    );
  stop();
  const view = await viewOf(plan.base, changes);
  const { changed, labels, entries, entryFiles, sinks, paths, qns, digest } = view;
  log(
    `${changes.length} changed files, ${changed.length} changed functions, ${qns.size} functions on their paths${client.cache ? `, ${client.cache.hits} stored answers` : ''}`
  );
  plan.step?.('labels', `${changed.length} changed functions, ${qns.size} on their paths`, {
    changed_functions: changed.length,
    path_functions: qns.size,
  });

  // 5. The threat model: the stored review, updated by the review agent when the gate opens. A
  // review older than the diff's base is read against the change since its own commit, computed
  // as the diff's is. With no stored review, the whole repository is reviewed at HEAD instead.
  stop();
  const sameCommit = (a: string, b: string): boolean => {
    const resolve = (rev: string) =>
      run('git', ['-C', plan.project, 'rev-parse', rev]).stdout.trim();
    return a === b || resolve(a) === resolve(b);
  };
  const since = async (sha: string): Promise<ChangeView> => {
    if (sameCommit(sha, plan.base)) return view;
    log(
      `the stored review is of ${sha.slice(0, 12)}, before the diff's base: its update reads every change since then`
    );
    return viewOf(sha, gitChanges(plan.project, sha, run));
  };
  const threatModel = stored
    ? await updateThreatModel(plan, stored, rows, functions, since, models, log)
    : await buildThreatModel(plan, rows, functions, calls, models, log);
  plan.step?.(
    'threat-model',
    threatModel.from.source === 'built'
      ? "threat model built: no full scan's threat model was stored"
      : threatModel.updated
        ? `threat model updated: ${threatModel.gate.length} reasons`
        : 'threat model reused: the change leaves it as it was',
    {}
  );

  // 6. The packets, from the change, the paths and the threat model, by upstream's rules.
  stop();
  const changedProduct = changes
    .filter(c => c.status !== 'deleted' && isProduct(byPath.get(c.path)))
    .map(c => c.path);
  const related = new Map<string, Set<string>>();
  const pathOf = new Map(functions.map(f => [f.qn, f.path]));
  for (const p of paths) {
    const near = related.get(p.fn.path) ?? new Set<string>();
    for (const qn of [...p.callers.flat(), ...p.callees.flat()]) {
      const path = pathOf.get(qn);
      if (path) near.add(path);
    }
    related.set(p.fn.path, near);
  }
  const review = threatModel.review;
  const packets = changedProduct.length
    ? await designDiffPackets(
        models.chat,
        designSystem(packetRules(plan.plugin())),
        `Threat model:\n\n${renderReview(review)}\n\n${digest}`,
        design => checkedDiffDesign(design, changedProduct, new Set(byPath.keys()), related),
        log
      )
    : [];
  // Logged as well as reported: a host that shows no progress events (the action) prints only the
  // log, and the packets are what the scan's helpers are given.
  const packetsLine = `${packets.length} packets${packets.length ? `: ${packets.map(p => p.id).join(', ')}` : ''}`;
  log(packetsLine);
  plan.step?.('packets', packetsLine, { packets: packets.length });

  // 7. The lead's index, every brief, the reader.
  const kb = diffBriefing({
    paths: { project: plan.paths.project, kbIndex: plan.paths.kbIndex },
    base: plan.base,
    rows,
    functions,
    calls,
    values,
    changes,
    changed,
    through: paths,
    packets,
    entries,
    sinks,
    secretWindows: labels.secrets,
    fileLabels: labels.fileLabels,
    functionLabels: labels.functionLabels,
    roles: labels.roles,
    entryFiles,
    review,
  });
  writeFileSync(join(output, 'code-graph.md'), kb.markdown);
  writeFileSync(join(output, 'threat-model.json'), `${JSON.stringify(review, null, 1)}\n`);
  const kbDir = join(plan.work, KNOWLEDGE_BASE_INDEX);
  rmSync(kbDir, { recursive: true, force: true });
  mkdirSync(join(kbDir, 'packets'), { recursive: true, mode: 0o755 });
  for (const [name, text] of kb.files) writeFileSync(join(kbDir, name), text);
  chmodSync(join(kbDir, 'kb'), 0o755);
  plan.step?.('briefs', `${kb.briefs.length} helper briefs`, { briefs: kb.briefs.length });

  return {
    kind: 'diff',
    base: plan.base,
    changed_files: changes.length,
    changed_functions: changed.length,
    path_functions: qns.size,
    graph: { functions: functions.length, calls: calls.length, call_references: references.length },
    threat_model: {
      from: threatModel.from,
      gate: threatModel.gate,
      updated: threatModel.updated,
      review: threatModel.stats,
    },
    briefs: kb.briefs,
    secret_windows: labels.secrets.length,
    cache: { answers_reused: client.cache?.hits ?? 0 },
    jev_calls: client.calls,
    cost_usd: Math.round(client.cost * 10_000) / 10_000,
  };
}

/**
 * Step 0: the last full scan's review, which the store restored into the cache, or undefined when
 * there is none to start from: none stored (no full scan yet, or its cache evicted), or one of a
 * commit outside this checkout's history (the store's newest is another branch's, or another
 * repository's), whose change since cannot be computed. Step 5 then builds one (buildThreatModel).
 */
function storedReview(
  plan: DiffBuildPlan,
  log: (message: string) => void,
  run: Runner
): StoredReview | undefined {
  const stored = plan.cacheDir ? loadReview(plan.cacheDir) : undefined;
  if (!stored) {
    log("no full scan's threat model is stored: this diff builds one of the whole repository");
    return undefined;
  }
  if (!inHistory(plan.project, stored.sha, run)) {
    log(
      `the stored threat model is of ${stored.sha.slice(0, 12)}, which is not in this checkout's history: this diff builds one of the whole repository`
    );
    return undefined;
  }
  return stored;
}

/** What step 5 made: the threat model, where it came from, and what the update did. */
interface ThreatModel {
  review: ArchitectureReview;
  from: ReuseStats;
  /** Why the stored review was updated; empty when it was reused, or built. */
  gate: string[];
  updated: boolean;
  stats: ReviewStats | null;
}

/** The review agent's plan, for both the update and a build: the scan's runtime and key. */
function reviewAgent(plan: DiffBuildPlan): AgentPlan | undefined {
  if (plan.reviewAgent === false) return undefined;
  return {
    name: `${plan.name}-review`,
    project: plan.project,
    runtime: plan.runtime,
    paths: { project: plan.paths.project, review: plan.paths.review },
    work: join(plan.work, 'review'),
    cynosKey: plan.cynosKey,
    ...(plan.modelCatalog ? { modelCatalog: plan.modelCatalog } : {}),
    ...(plan.baseUrl ? { baseUrl: plan.baseUrl } : {}),
    ...(plan.signal ? { signal: plan.signal } : {}),
  };
}

/**
 * Step 5 with no stored review: the whole repository reviewed at HEAD, as a full scan reviews it.
 *
 * The review reads every file's and function's labels, not only the change's, so the repository is
 * labelled with a full scan's own requests (labelRepository): a cache restored from an older full
 * scan answers every file the change left alone, and only changed content costs a call. The graph
 * is step 2's, already indexed at HEAD. The review describes HEAD, the change included, so it needs
 * no update. It is stored as HEAD's, so the next diff of this branch starts from it and updates it.
 */
async function buildThreatModel(
  plan: DiffBuildPlan,
  rows: FileRow[],
  functions: FunctionNode[],
  calls: [string, string][],
  models: KnowledgeBaseModels,
  log: (message: string) => void
): Promise<ThreatModel> {
  // Every product file's and function's labels, and the file sweep, as a full scan asks them.
  const product = productRows(rows).filter(r => r.text);
  const labels = await labelRepository(
    models.decisions,
    {
      rows,
      product,
      functions,
      calls,
      tokens: new Map(product.map(r => [r.path, tokens(r.text ?? '')])),
    },
    log
  );

  // The review from scratch, with the repository's own threat model when it keeps one. A diff
  // scan needs a threat model, so a failed review fails the build.
  const maintained = maintainedThreatModel(rows, plan.threatModelPath);
  const agent = reviewAgent(plan);
  const built = await reviewArchitecture(
    {
      rows,
      product,
      functions,
      fileLabels: labels.fileLabels,
      functionLabels: labels.functionLabels,
      roles: labels.roles,
      entryFiles: labels.entryFiles,
      ...(maintained ? { maintained } : {}),
      ...(agent ? { agent } : {}),
      cynos: models.chat,
    },
    log
  );

  // Stored as HEAD's, as a full build stores its own (index.ts).
  if (plan.cacheDir && plan.head) saveReview(plan.cacheDir, plan.head, built.review);
  const sha = plan.head ?? '';
  log(
    `threat model built for this diff${sha ? ` at ${sha.slice(0, 12)}` : ''}: ${built.stats.citations} citations`
  );
  return {
    review: built.review,
    from: { source: 'built', sha, citations: built.stats.citations, cut: 0, redacted: 0 },
    gate: [],
    updated: false,
    stats: built.stats,
  };
}

/**
 * Step 5: the stored review, checked against this checkout, then updated by the review agent when
 * the gate opens (reviewGate).
 */
async function updateThreatModel(
  plan: DiffBuildPlan,
  stored: StoredReview,
  rows: FileRow[],
  functions: FunctionNode[],
  since: (sha: string) => Promise<ChangeView>,
  models: KnowledgeBaseModels,
  log: (message: string) => void
): Promise<ThreatModel> {
  const { review, stats: from } = reuseReview(stored, rows);
  log(
    `threat model from the full scan of ${from.sha.slice(0, 12)}: ${from.citations} citations, ${from.cut} cut, ${from.redacted} secret literals redacted`
  );
  // The review describes its own commit, which can be older than the diff's base (a diff of the
  // changes since the last diff scan, whose own update was never stored), so the gate and the update
  // read every change since the review, not only the diff's.
  const { changes, changed, labels, entryFiles, digest } = await since(stored.sha);
  // The gate reads the stored review's own citations: the check above cuts a citation whose line
  // is gone, and a changed file cited only there would then look uncited.
  const gate = reviewGate(stored.review, changes, changed, labels);
  if (!gate.length) {
    log('threat model reused: the change touches nothing it describes');
    return { review, from, gate, updated: false, stats: null };
  }
  log(
    `threat model update: ${gate.slice(0, 5).join('; ')}${gate.length > 5 ? `; +${gate.length - 5} more` : ''}`
  );
  const agent = reviewAgent(plan);
  const updated = await reviewArchitecture(
    {
      rows,
      product: productRows(rows).filter(r => r.text),
      functions,
      fileLabels: labels.fileLabels,
      functionLabels: labels.functionLabels,
      roles: labels.roles,
      entryFiles,
      ...(agent ? { agent } : {}),
      cynos: models.chat,
      update: {
        previous: review,
        change: digest,
        changedFiles: changes.filter(c => c.status !== 'deleted').map(c => c.path),
        changedFunctions: new Set(changed.map(f => f.qn)),
      },
    },
    log
  );
  return { review: updated.review, from, gate, updated: true, stats: updated.stats };
}
