/**
 * A diff's briefs, the reader and its index, and the lead's short index of them: briefing.ts's
 * shape, sized to a change.
 *
 * A full scan's helper starts from its packet's most important files. A diff's helper reviews a
 * change, and what it needs first is the change itself and the code on either side of it: who
 * calls the changed functions (up to the entry points an attacker reaches), what passes them as
 * values, and what they call (down to sensitive operations). Those are what a diff's helper
 * otherwise spends its turns finding. So each packet's brief holds:
 *
 *   change    the hunks of its changed files
 *   paths     per changed function, its caller paths (through code that passes a function on as
 *             a value, too) and its callee paths, every function with `path:start-end` and
 *             its labels
 *   core      its changed files whole, then the functions on those paths, printed with their
 *             own line numbers, up to CORE_TOKENS
 *   map       the other files on the paths, to read when the review leads there
 *   context   the threat model, its boundaries citing the packet's files first
 *
 * The diff baseline's brief holds the changed files no packet reviews (CI, deployment,
 * configuration, documentation, tests, deleted files) and the changed files' secret windows.
 * Briefs state facts about the code only; they never say where a vulnerability is.
 */
import type { ArchitectureReview } from './architecture';
import { indexFiles, kbScript, shellWord, sinkKinds, type IndexInput } from './architecture-agent';
import {
  CORE_TOKENS,
  pieceTokens,
  printPiece,
  reading,
  SECRET_TOKENS,
  secretPieces,
  threatModelSection,
  type BriefSummary,
  type Piece,
} from './briefing';
import type { FunctionNode } from './code-graph';
import { DIFF_BASELINE, valueEdge, type Change, type DiffPacket, type FunctionPaths } from './diff';
import { PRODUCT_KINDS, type FileRow } from './inventory';
import { noul } from './jev';
import type { Entry, SecretWindow } from './plan';

/** The hunks one brief prints; a larger change is named, to read from the checkout. */
export const CHANGE_TOKENS = 30_000;
/** Rough, for numbered source. */
const CHARS_PER_TOKEN = 3.5;
/** Callee paths shown per changed function: those reaching a sensitive operation first. */
const MAX_CALLEE_PATHS = 6;

export interface DiffBriefingInput extends IndexInput {
  /** The checkout and the reader's directory, as the scanner sees them (runtime.paths). */
  paths: { project: string; kbIndex: string };
  base: string;
  calls: [string, string][];
  /** Call references as valueEdge keys: where a path step passes a function on as a value. */
  values: Set<string>;
  changes: Change[];
  changed: FunctionNode[];
  /** The paths through every changed function (diff.ts functionPaths). */
  through: FunctionPaths[];
  packets: DiffPacket[];
  entries: Entry[];
  sinks: Map<string, string>;
  secretWindows: SecretWindow[];
  review: ArchitectureReview;
}

/** What every brief draws on. */
interface Shared {
  input: DiffBriefingInput;
  byPath: Map<string, FileRow>;
  byQn: Map<string, FunctionNode>;
  sinkFiles: Map<string, Set<string>>;
  entryQns: Set<string>;
}

/**
 * A helper's task name: the name its result is saved under. The design often names its packets
 * `packet-1-…` already, which would make `packet_packet_1_…`.
 */
export function diffTaskName(id: string): string {
  return id === DIFF_BASELINE
    ? 'diff_baseline'
    : `packet_${id.replace(/^packet-/, '').replace(/-/g, '_')}`;
}

/** A function as the paths print it: name, place and labels. */
function described(qn: string, shared: Shared): string {
  const f = shared.byQn.get(qn);
  const labels = [
    shared.entryQns.has(qn) ? 'entry' : '',
    shared.input.sinks.has(qn) ? `sink:${shared.input.sinks.get(qn)}` : '',
  ].filter(Boolean);
  return f
    ? `\`${qn}\` (${f.path}:${f.start}-${f.end}${labels.length ? `, ${labels.join(',')}` : ''})`
    : `\`${qn}\``;
}

/** A file's labels, in the reader index's words. */
function fileLabels(path: string, shared: Shared): string[] {
  const a = shared.input.fileLabels.get(path);
  return [
    shared.input.entryFiles.has(path) ? `entry:${shared.input.entryFiles.get(path)}` : '',
    noul(a, 'untrusted_input') >= 0.5 ? 'input' : '',
    noul(a, 'access_control') >= 0.5 ? 'access-control' : '',
    ...[...(shared.sinkFiles.get(path) ?? [])].map(k => `sink:${k}`),
  ].filter(Boolean);
}

/**
 * Callee paths worth showing: each cut at its first sensitive operation, those reaching one first;
 * a path that reaches none is shown only when no path does, as what the function goes on to call.
 */
function calleePaths(p: FunctionPaths, shared: Shared): string[][] {
  const cut = p.callees
    .map(path => {
      const i = path.findIndex(qn => shared.input.sinks.has(qn));
      return i >= 0 ? path.slice(0, i + 1) : undefined;
    })
    .filter((x): x is string[] => !!x);
  const unique = [...new Map(cut.map(c => [c.join('>'), c])).values()];
  return (unique.length ? unique : p.callees.slice(0, 2)).slice(0, MAX_CALLEE_PATHS);
}

/** A caller path down to the changed function, each step a call or a value passed on. */
function callerChain(path: string[], fn: string, shared: Shared): string {
  const steps = [...path, fn];
  const out = [described(steps[0] as string, shared)];
  for (let i = 1; i < steps.length; i++) {
    const passes = shared.input.values.has(valueEdge(steps[i - 1] as string, steps[i] as string));
    const next = i === steps.length - 1 ? '(changed)' : described(steps[i] as string, shared);
    out.push(`${passes ? ' =passes as a value=> ' : ' -> '}${next}`);
  }
  return out.join('');
}

/** The "Paths through the change" lines for one changed function. */
function pathLines(p: FunctionPaths, shared: Shared): string[] {
  const md = [`- changed: ${described(p.fn.qn, shared)}`];
  for (const c of p.callers) md.push(`  - reached from: ${callerChain(c, p.fn.qn, shared)}`);
  if (p.more.callers)
    md.push(`  - ${p.more.callers} more caller paths (\`kb fn ${p.fn.name}\`, then its callers)`);
  if (!p.callers.length) md.push('  - no caller in product code within three steps');
  for (const c of calleePaths(p, shared))
    md.push(`  - calls: (changed) -> ${c.map(q => described(q, shared)).join(' -> ')}`);
  return md;
}

/** A function's lines as a piece of its file. */
function functionPiece(f: FunctionNode, shared: Shared): Piece | undefined {
  const row = shared.byPath.get(f.path);
  if (!row?.text || f.start < 1) return undefined;
  return {
    ...row,
    start: f.start,
    end: Math.max(f.end, f.start),
    lines: Math.max(f.end, f.start) - f.start + 1,
  };
}

/**
 * The core: the packet's changed files whole, then the functions on the paths, entry-point
 * callers first, then the code that passes a function on as a value (the wiring a callback's real
 * caller is found from), sensitive callees, other callers, up to CORE_TOKENS. A
 * changed file too large for half the core contributes its changed functions instead. A function
 * inside a file already printed is not printed again.
 */
function corePieces(changedFiles: string[], through: FunctionPaths[], shared: Shared): Piece[] {
  const out: Piece[] = [];
  const whole = new Set<string>();
  let left = CORE_TOKENS;
  const take = (piece: Piece | undefined): void => {
    if (!piece?.text || whole.has(piece.path)) return;
    if (
      out.some(
        o =>
          o.path === piece.path &&
          (o.start ?? 1) <= (piece.start ?? 1) &&
          (o.end ?? o.lines) >= (piece.end ?? piece.lines)
      )
    )
      return;
    const size = pieceTokens(piece);
    if (size > left) return;
    out.push(piece);
    if (piece.start === undefined) whole.add(piece.path);
    left -= size;
  };
  for (const path of changedFiles) {
    const row = shared.byPath.get(path);
    if (row?.text && pieceTokens(row) <= CORE_TOKENS / 2) take(row);
    else for (const p of through.filter(t => t.fn.path === path)) take(functionPiece(p.fn, shared));
  }
  const fn = (qn: string): Piece | undefined => {
    const f = shared.byQn.get(qn);
    return f ? functionPiece(f, shared) : undefined;
  };
  const callers = through.flatMap(t => t.callers);
  for (const c of callers) for (const qn of c) if (shared.entryQns.has(qn)) take(fn(qn));
  for (const t of through)
    for (const c of t.callers)
      [...c, t.fn.qn].forEach((qn, i, steps) => {
        const next = steps[i + 1];
        if (next && shared.input.values.has(valueEdge(qn, next))) take(fn(qn));
      });
  for (const t of through) for (const c of calleePaths(t, shared)) for (const qn of c) take(fn(qn));
  for (const c of callers) for (const qn of [...c].reverse()) take(fn(qn));
  return out;
}

/** The hunks of `changes` up to CHANGE_TOKENS; the rest are named, with the command to read them. */
function changeSection(changes: Change[], input: DiffBriefingInput): string[] {
  const md = ['## The change', ''];
  let left = CHANGE_TOKENS;
  const named: string[] = [];
  for (const c of changes) {
    const size = Math.ceil(c.patch.length / CHARS_PER_TOKEN);
    if (c.binary || size > left) {
      named.push(`\`${c.path}\` (${c.status}${c.binary ? ', binary' : ''})`);
      continue;
    }
    md.push('```diff', c.patch, '```', '');
    left -= size;
  }
  if (named.length)
    md.push(
      `Not printed here: ${named.join(', ')}. Read them with \`git -C ${shellWord(input.paths.project)} diff ${shellWord(input.base)} HEAD -- <path>\`.`,
      ''
    );
  return md;
}

function summarise(
  id: string,
  files: number,
  core: Piece[],
  listed: number,
  markdown: string
): BriefSummary {
  return {
    id,
    files,
    coreFiles: core.length,
    coreTokens: core.reduce((sum, p) => sum + pieceTokens(p), 0),
    listed,
    briefTokens: Math.round(markdown.length / CHARS_PER_TOKEN),
  };
}

/** Scope: the rule every diff brief states before anything else. */
const SCOPE = [
  '## Scope',
  '',
  'Your review is this change and the paths through it below. Follow supporting code as far as',
  'the affected boundary, and to sibling callers where a changed shared control affects them. A',
  'question that leads beyond them is an open question in your result, not a new investigation.',
  '',
];

/** One packet's brief: assignment, scope, threat model, reading, change, paths, map, core. */
function packetBrief(
  packet: DiffPacket,
  shared: Shared
): { markdown: string; summary: BriefSummary } {
  const { input } = shared;
  const mine = new Set(packet.changed);
  const through = input.through.filter(t => mine.has(t.fn.path));
  const core = corePieces(packet.changed, through, shared);
  const inCore = new Set(core.filter(p => p.start === undefined).map(p => p.path));
  const onPaths = new Set<string>();
  for (const t of through)
    for (const qn of [...t.callers.flat(), ...t.callees.flat()]) {
      const path = shared.byQn.get(qn)?.path;
      if (path && !mine.has(path)) onPaths.add(path);
    }
  const map = [...new Set([...onPaths, ...packet.context])].filter(p => !inCore.has(p)).sort();
  const md = [
    `# Diff packet ${packet.id}`,
    '',
    `The change ${input.base.slice(0, 12)}..HEAD in ${packet.changed.length} files, ${through.length} changed functions; ${core.length} pieces printed in the core below, ${map.length} more files on the paths.`,
    '',
  ];
  if (packet.perspective) md.push(`Perspective: ${packet.perspective}`, '');
  if (packet.attacker) md.push(`Attacker: ${packet.attacker}`, '');
  if (packet.questions.length)
    md.push('## Questions', '', ...packet.questions.map(q => `- ${q}`), '');
  md.push(
    ...SCOPE,
    ...threatModelSection(input.review, new Set([...mine, ...onPaths])),
    ...reading(input.paths.kbIndex),
    ...changeSection(
      input.changes.filter(c => mine.has(c.path)),
      input
    ),
    '## Paths through the change',
    '',
    'Callers up to an entry point (or three steps), and callees down to a sensitive operation, from',
    'the code graph at HEAD. A step marked `=passes as a value=>` hands the next function on as a',
    'value (a callback wired in): whoever later calls that value is not in the graph, so follow it',
    'from there. Labels: `entry` an entry point, `sink:<kind>` a sensitive operation.',
    '',
    ...(through.length
      ? through.flatMap(t => pathLines(t, shared))
      : ['(no function of these files changed: the change is outside functions)']),
    '',
    '## Other files on these paths',
    '',
    'Not printed. Read any of them when your review leads there.',
    '',
    ...(map.length
      ? map.map(p => {
          const labels = fileLabels(p, shared);
          return `- \`${p}\` (${shared.byPath.get(p)?.lines ?? 0} lines${labels.length ? `; ${labels.join(', ')}` : ''})`;
        })
      : ['(none: the core holds them)']),
    '',
    '## Core',
    '',
    ...core.map(printPiece),
    ''
  );
  const markdown = md.join('\n');
  return {
    markdown,
    summary: summarise(packet.id, packet.changed.length, core, map.length, markdown),
  };
}

/**
 * The diff baseline's brief: every changed file no packet reviews (a non-product file, or a
 * deleted one, read from its hunks at the base) and the changed files' secret windows.
 */
function baselineBrief(
  files: Change[],
  shared: Shared
): { markdown: string; summary: BriefSummary } {
  const { input } = shared;
  const printed: Piece[] = [];
  const listed: Piece[] = [];
  let left = SECRET_TOKENS;
  for (const piece of secretPieces(input.secretWindows, shared.byPath)) {
    const size = pieceTokens(piece);
    if (size <= left) {
      printed.push(piece);
      left -= size;
    } else listed.push(piece);
  }
  const md = [
    '# Diff baseline',
    '',
    `The changed files no packet reviews: ${files.length} (CI, deployment, configuration, documentation, tests, deleted files), and the changed files' secret windows. Review how each change affects the build, deployment or a boundary; a deleted file is shown as its hunks at the base.`,
    '',
    ...SCOPE,
    ...threatModelSection(input.review, new Set(files.map(f => f.path))),
    ...reading(input.paths.kbIndex),
    ...changeSection(files, input),
    '## Secret windows',
    '',
    `${input.secretWindows.length} line windows of the changed files that a decision model flagged as holding a password, key or token. Check each literal for a credential that grants access.` +
      (listed.length
        ? ` Read the ${listed.length} not printed below with: \`sh ${input.paths.kbIndex}/kb read ${listed.map(p => shellWord(`${p.path}:${p.start}-${p.end}`)).join(' ')}\``
        : ''),
    '',
    ...printed.map(printPiece),
    '',
  ];
  const markdown = md.join('\n');
  return {
    markdown,
    summary: summarise(DIFF_BASELINE, files.length, printed, listed.length, markdown),
  };
}

/** The knowledge base the diff scan reads: the lead's index, and the helpers' reader directory. */
export interface DiffBriefing {
  /** code-graph.md: what the lead reads. */
  markdown: string;
  /** Files of the reader directory (the scanner's paths.kbIndex), by relative path. */
  files: Map<string, string>;
  briefs: BriefSummary[];
}

/** The lead's index, every brief, the reader and its index. */
export function diffBriefing(input: DiffBriefingInput): DiffBriefing {
  const shared: Shared = {
    input,
    byPath: new Map(input.rows.map(r => [r.path, r])),
    byQn: new Map(input.functions.map(f => [f.qn, f])),
    sinkFiles: sinkKinds(input),
    entryQns: new Set(input.entries.map(e => e.qn)),
  };
  const reviewed = new Set(input.packets.flatMap(p => p.changed));
  const rest = input.changes.filter(c => !reviewed.has(c.path));
  const briefs = [
    ...input.packets.map(p => ({ id: p.id, ...packetBrief(p, shared) })),
    ...(rest.length || input.secretWindows.length
      ? [{ id: DIFF_BASELINE, ...baselineBrief(rest, shared) }]
      : []),
  ];
  const index = indexFiles(input);
  const files = new Map<string, string>([
    ['kb', kbScript(input.paths.project, input.paths.kbIndex)],
    ['files.tsv', index.files],
    ['functions.tsv', index.functions],
  ]);
  for (const b of briefs) files.set(`packets/${b.id}.md`, b.markdown);

  // The lead's index: the change, the threat model, one line per helper.
  const packetsOf = (path: string): string =>
    input.packets
      .filter(p => p.changed.includes(path))
      .map(p => p.id)
      .join(', ') || (briefs.some(b => b.id === DIFF_BASELINE) ? DIFF_BASELINE : '');
  const kind = (path: string): string => shared.byPath.get(path)?.kind ?? 'deleted';
  const md = [
    '# Knowledge base index: a diff',
    '',
    `Computed on the host before the scan, for the change ${input.base.slice(0, 12)}..HEAD: the code graph at HEAD, the paths through every changed function, and a decision model's labels for that code. Each helper has a brief at \`${input.paths.kbIndex}/packets/<id>.md\`: its part of the change, the paths through it, its core files and the threat model. You do not read the briefs or the source.`,
    '',
    '## The change',
    '',
    `${input.changes.length} files, ${input.changed.length} changed functions.`,
    '',
    '| status | file | kind | reviewed by |',
    '|---|---|---|---|',
    ...input.changes.map(
      c => `| ${c.status} | \`${c.path}\` | ${kind(c.path)} | ${packetsOf(c.path)} |`
    ),
    '',
    '## Threat model',
    '',
    'Use it unchanged.',
    '',
    '## Helpers',
    '',
    'One helper per row, all started at once.',
    '',
    '| task name | brief id | changed files | core | listed | perspective |',
    '|---|---|---|---|---|---|',
    ...briefs.map(b => {
      const p = input.packets.find(x => x.id === b.id);
      const view = p
        ? p.perspective.replace(/\|/g, '/').replace(/\s+/g, ' ').slice(0, 200)
        : 'the changed files no packet reviews, and secrets';
      return `| ${diffTaskName(b.id)} | ${b.id} | ${b.summary.files} | ${b.summary.coreFiles} | ${b.summary.listed} | ${view} |`;
    }),
    '',
  ];
  return { markdown: md.join('\n'), files, briefs: briefs.map(b => b.summary) };
}

/** Whether a path is a product file: what a packet reviews, as against the diff baseline. */
export function isProduct(row: FileRow | undefined): boolean {
  return !!row && PRODUCT_KINDS.has(row.kind) && row.lines > 0;
}
