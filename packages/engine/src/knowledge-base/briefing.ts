/**
 * The briefs the scan's helpers start from, the index and reader they load the rest with, and the
 * lead's short index of them.
 *
 * A packet can exceed a helper's context. Splitting by a fixed reading budget can create more
 * helpers than available slots, while printing the whole briefing can truncate it. As for the
 * architecture review (architecture-agent.ts), each helper gets:
 *
 *   core       its packet's most important files, printed in its brief with their own line
 *              numbers: the files the design named, then those with entry points, access
 *              control and sensitive operations, up to CORE_TOKENS
 *   map        the packet's other labelled files, each with its labelled functions, to read when
 *              the review leads there; nothing obliges the helper to read them
 *   reader     `kb` over files.tsv and functions.tsv, which label every file and function, so it
 *              loads what it needs on demand, several files per command
 *   context    the whole threat model, the boundaries and assumptions that cite its files first
 *
 * One helper per packet and one baseline auditor, whose brief holds the riskiest files and the
 * secret windows, and the hypothesis packets: packets that settle the hypotheses (hypotheses/),
 * shared out between them. The lead reads only the index: one line per helper. Briefs state facts
 * about the code only; they never say where a vulnerability is, except that a hypothesis packet's
 * brief asks its hypotheses as questions to settle.
 */
import { citedPaths, roleOf, type ArchitectureReview } from './architecture';
import { indexFiles, kbScript, shellWord, sinkKinds, type IndexInput } from './architecture-agent';
import type { FunctionNode } from './code-graph';
import { PRODUCT_KINDS, type FileRow } from './inventory';
import { noul } from './jev';
import { BASELINE, type Entry, type PacketSpec, type SecretWindow } from './plan';
import {
  briefSections,
  hypothesisPackets,
  TEMPLATES,
  type Hypothesis,
  type HypothesisInput,
} from '../hypotheses';

/** A packet helper's core, printed in its brief. */
export const CORE_TOKENS = 50_000;
/** The baseline auditor's core of riskiest files; its secret windows come on top. */
export const BASELINE_CORE_TOKENS = 40_000;
/** Secret windows printed in the baseline brief; the rest are listed to read. */
export const SECRET_TOKENS = 12_000;
/** Files the map of a brief names; a packet's other labelled files are counted by directory. */
export const MAX_LISTED = 120;
/** The budget every read exec asks for in its `// @exec:` header. */
export const READ_EXEC_TOKENS = 60_000;
export const EXEC_HEADER = `// @exec: {"yield_time_ms": 60000, "max_output_tokens": ${READ_EXEC_TOKENS}}`;
/** Rough, for numbered source. */
const CHARS_PER_TOKEN = 3.5;
/** A secret window longer than this is printed in several pieces. */
export const MAX_SECRET_WINDOW_LINES = 120;
const MAX_FILE_FUNCTIONS = 6;
const MAX_PACKET_CHAINS = 20;
const MAX_CHAIN_PATHS = 3;
const MAX_CHAIN_DEPTH = 3;
const MAX_CHAIN_SINKS = 4;
const MAX_OUTSIDE_CALLS = 25;
/** The threat model condensed into one brief. */
const MAX_THREAT_CHARS = 32_000;
export const APP_WIDE_CONTROLS =
  'rate limiting, CSRF protection, cookie flags, security headers, CORS';
/** The reader as a helper runs it, from the reader's directory as the scanner sees it. */
export function reader(kbIndex: string): string {
  return `sh ${kbIndex}/kb`;
}

/** A file, or a window of one with its own line numbers, as the reader prints it. */
export interface Piece {
  path: string;
  lines: number;
  text: string | undefined;
  start?: number;
  end?: number;
}

/** The piece's lines under the reader's header, numbered with the file's own numbers. */
export function printPiece(piece: Piece): string {
  const all = (piece.text ?? '').split('\n');
  if (all.length > 1 && all[all.length - 1] === '') all.pop();
  const a = piece.start ?? 1;
  const b = Math.min(piece.end ?? all.length, all.length);
  const body = all.slice(a - 1, b).map((l, i) => `${String(a + i).padStart(6)}\t${l}`);
  return [`==> ${piece.path} (lines ${a}-${b}) <==`, ...body].join('\n');
}

/** Tokens of a piece as the reader prints it, with line numbers. */
export function pieceTokens(piece: Piece): number {
  let text = piece.text ?? '';
  let lines = piece.lines;
  if (piece.start !== undefined && piece.end !== undefined && text) {
    text = text
      .split('\n')
      .slice(piece.start - 1, piece.end)
      .join('\n');
    lines = piece.end - piece.start + 1;
  }
  return Math.floor((text.length + 8 * lines) / CHARS_PER_TOKEN);
}

/**
 * Secret windows as pieces; a window longer than MAX_SECRET_WINDOW_LINES (a merged run through a
 * data or translation file) is cut into several.
 */
export function secretPieces(windows: SecretWindow[], byPath: Map<string, FileRow>): Piece[] {
  const out: Piece[] = [];
  for (const w of windows) {
    const row = byPath.get(w.path);
    if (!row) continue;
    for (let a = w.start; a <= w.end; a += MAX_SECRET_WINDOW_LINES) {
      const end = Math.min(a + MAX_SECRET_WINDOW_LINES - 1, w.end);
      out.push({ ...row, start: a, end, lines: end - a + 1 });
    }
  }
  return out;
}

export interface Chain {
  entry: Entry;
  /** The entry point's own sink, if it performs one. */
  own: string | undefined;
  /** Call paths after the entry point, each ending at a sink function. */
  paths: string[][];
}

/** For each entry point, the call paths (depth <= MAX_CHAIN_DEPTH) to sink functions. */
export function chains(
  entries: Entry[],
  calls: [string, string][],
  sinks: Map<string, string>
): Chain[] {
  const out = new Map<string, Set<string>>();
  for (const [a, b] of calls) if (a !== b) out.set(a, (out.get(a) ?? new Set()).add(b));
  return entries.map(entry => {
    const paths: string[][] = [];
    const stack: string[][] = [[entry.qn]];
    const seen = new Set([entry.qn]);
    while (stack.length) {
      const path = stack.pop() as string[];
      const node = path[path.length - 1] as string;
      if (path.length > 1 && sinks.has(node)) paths.push(path.slice(1));
      if (path.length > MAX_CHAIN_DEPTH) continue;
      for (const next of [...(out.get(node) ?? [])].sort()) {
        if (seen.has(next)) continue;
        seen.add(next);
        stack.push([...path, next]);
      }
    }
    return { entry, own: sinks.get(entry.qn), paths };
  });
}

export interface BriefingInput extends IndexInput {
  /** The checkout and the reader's directory, as the scanner sees them (runtime.paths). */
  paths: { project: string; kbIndex: string };
  calls: [string, string][];
  index: Record<string, unknown>;
  entries: Entry[];
  sinks: Map<string, string>;
  spec: PacketSpec[];
  baseline: string[];
  secretWindows: SecretWindow[];
  review?: ArchitectureReview;
  /** The hypothesis templates' input and hypotheses (plan.ts step 7), and the most packets for them. */
  hypotheses?: { input: HypothesisInput; computed: Hypothesis[]; packets: number };
}

/** What one helper is given, as the build reports it. */
export interface BriefSummary {
  id: string;
  files: number;
  coreFiles: number;
  coreTokens: number;
  /** Other packet files the brief's map names. */
  listed: number;
  briefTokens: number;
}

/** What every brief draws on. */
interface Shared {
  input: BriefingInput;
  byPath: Map<string, FileRow>;
  byFile: Map<string, FunctionNode[]>;
  rank: (path: string, seed: boolean) => Ranked;
  fileOf: Map<string, string>;
  packetOf: Map<string, string>;
}

// --------------------------------------------------------------------------- //
// Ranking a helper's files: what goes into its core, and its map of the rest
// --------------------------------------------------------------------------- //

/** A file with its labels, as files.tsv writes them, and the score that ranks it for a core. */
interface Ranked {
  path: string;
  labels: string[];
  score: number;
}

/** Security labels rank a file; a central architecture role and a design seed lift it. */
function ranker(input: BriefingInput): (path: string, seed: boolean) => Ranked {
  const sinks = sinkKinds(input);
  const central = new Set(['startup', 'routes', 'access_control']);
  return (path, seed) => {
    const a = input.fileLabels.get(path);
    const role = roleOf(input.roles.get(path));
    const entries = input.entryFiles.get(path) ?? 0;
    const access = noul(a, 'access_control') >= 0.5;
    const caller = noul(a, 'untrusted_input') >= 0.5;
    const kinds = [...(sinks.get(path) ?? [])];
    const labels = [
      entries ? `entry:${entries}` : '',
      caller ? 'input' : '',
      access ? 'access-control' : '',
      ...kinds.map(k => `sink:${k}`),
      role ? `role:${role.role}` : '',
    ].filter(Boolean);
    const score =
      (seed ? 20 : 0) +
      Math.min(entries, 5) * 2 +
      (access ? 6 : 0) +
      (caller ? 2 : 0) +
      kinds.length * 3 +
      (role && central.has(role.role) ? 4 : 0);
    return { path, labels, score };
  };
}

const byScore = (x: Ranked, y: Ranked): number => y.score - x.score || (x.path < y.path ? -1 : 1);

/** `ranked` with the seeds moved to its front in the order `seeds` gives them. */
function seedsInOrder(ranked: Ranked[], seeds: string[]): Ranked[] {
  const byPath = new Map(ranked.map(r => [r.path, r]));
  const first = seeds.flatMap(p => byPath.get(p) ?? []);
  const isSeed = new Set(seeds);
  return [...first, ...ranked.filter(r => !isSeed.has(r.path))];
}

/** The highest-ranked files that fit `budget` tokens, in rank order. */
function core(ranked: Ranked[], byPath: Map<string, FileRow>, budget: number): FileRow[] {
  const out: FileRow[] = [];
  let left = budget;
  for (const r of ranked) {
    const row = byPath.get(r.path);
    if (!row?.text) continue;
    const size = pieceTokens(row);
    if (size > left) continue;
    out.push(row);
    left -= size;
  }
  return out;
}

/** A file's labelled functions, entry points and sinks, as `name a-b label`. */
function fileFunctions(path: string, shared: Shared): string {
  const entry = new Set(shared.input.entries.filter(e => e.path === path).map(e => e.qn));
  const sinks = shared.input.sinks;
  const fs = (shared.byFile.get(path) ?? [])
    .map(f => ({
      f,
      label: [entry.has(f.qn) ? 'entry' : '', sinks.has(f.qn) ? `sink:${sinks.get(f.qn)}` : '']
        .filter(Boolean)
        .join(','),
    }))
    .filter(x => x.label);
  if (!fs.length) return '';
  const shown = fs.slice(0, MAX_FILE_FUNCTIONS);
  const more = fs.length - shown.length;
  return (
    ': ' +
    shown.map(x => `${x.f.qn.split('.').pop()} ${x.f.start}-${x.f.end} ${x.label}`).join(', ') +
    (more ? `, +${more} more (\`kb fn\`)` : '')
  );
}

/** The map's lines (at most MAX_LISTED files) and the count of what ranks below them. */
function mapLines(open: Ranked[], shared: Shared): { lines: string[]; paths: string[] } {
  const listed = open.slice(0, MAX_LISTED);
  const rest = open.slice(MAX_LISTED);
  const lines = listed.map(
    r =>
      `- \`${r.path}\` (${shared.byPath.get(r.path)?.lines ?? 0} lines; ${r.labels.join(', ')})${fileFunctions(r.path, shared)}`
  );
  if (rest.length) {
    const dirs = new Map<string, number>();
    for (const r of rest) {
      const d = r.path.includes('/') ? r.path.slice(0, r.path.lastIndexOf('/')) : '.';
      dirs.set(d, (dirs.get(d) ?? 0) + 1);
    }
    lines.push(
      '',
      `${rest.length} more labelled files rank below these (\`${reader(shared.input.paths.kbIndex)} files <dir>\`): ` +
        [...dirs]
          .sort((x, y) => y[1] - x[1])
          .slice(0, 20)
          .map(([d, n]) => `\`${d}/\` ${n}`)
          .join(', ')
    );
  }
  return { lines, paths: listed.map(r => r.path) };
}

/**
 * The threat model as a helper needs it: whole, because whether a finding is real depends on
 * facts outside the packet. Who can call a route is decided by middleware the packet does not
 * hold, and which requests are served at all by allow-lists and deployment defaults. A slice by
 * the packet's own files dropped exactly those boundaries: the log packet saw no "/api is
 * admin-only" boundary and reported admin reads as cross-tenant leaks. So every list is given,
 * the boundaries and assumptions that cite the packet's files first.
 */
export function threatModelSection(
  review: ArchitectureReview | undefined,
  files: Set<string>
): string[] {
  if (!review) return [];
  const tm = review.threatModel;
  const touches = (i: string): boolean => [...citedPaths(i)].some(p => files.has(p));
  const mineFirst = (items: string[]): string[] => [
    ...items.filter(touches),
    ...items.filter(i => !touches(i)),
  ];
  const list = (title: string, items: string[]): string[] =>
    items.length ? ['', `### ${title}`, '', ...items.map(i => `- ${i}`)] : [];
  const md = [
    '## Threat model',
    '',
    'Whole, as the scan submits it. Before reporting, name the attacker as one of the attacker',
    'capabilities below and confirm the boundaries in front of the code let that attacker reach it.',
    '',
    tm.summary,
    ...list('Trust boundaries', mineFirst(tm.trustBoundaries)),
    ...list('Attacker capabilities', tm.attackerCapabilities),
    ...list('Security objectives', tm.securityObjectives),
    ...list('Assumptions and discrepancies', mineFirst(tm.assumptions)),
  ];
  let text = md.join('\n');
  if (text.length > MAX_THREAT_CHARS)
    text = `${text.slice(0, MAX_THREAT_CHARS)}\n- … (cut; the whole model is in the knowledge base's threat-model file)`;
  return [text, ''];
}

/** How a helper reads: the core first, then the reader, in batches. */
export function reading(kbIndex: string): string[] {
  const KB = reader(kbIndex);
  return [
    '## Reading',
    '',
    'Your core files are printed at the end of this brief, each numbered from its own line 1.',
    'Analyse them first. Load anything else with the reader, several files or ranges per command',
    '(about 3,000 lines at most), one command per `exec` whose first line is the header below:',
    '',
    '```js',
    EXEC_HEADER,
    `const r = await tools.exec_command({cmd: \`${KB} read a.py b.py:120-180 c.py\`, yield_time_ms: 60000, max_output_tokens: ${READ_EXEC_TOKENS}}); text(r.output);`,
    '```',
    '',
    `- \`${KB} read <path>[:<start>-<end>] ...\` files or line ranges`,
    `- \`${KB} fn <name>\` one function (or the list of matches)`,
    `- \`${KB} find <text>\` search the index of files (${kbIndex}/files.tsv) and functions (${kbIndex}/functions.tsv)`,
    `- \`${KB} files <directory>\` a directory's files with their labels`,
    '- `rg -n -e A -e B` to search the code',
    '',
    'Never pipe the reader through `head` or `tail` (ask for the range instead) and never print',
    'several files with one `cat -n`. Cite every file by its full path from the repository root.',
    'Labels: `entry:<n>` entry points, `input` reads caller-controlled data, `access-control`',
    'decides authentication or authorization, `sink:<kind>` performs a sensitive operation,',
    '`role:<role>` its role in the architecture.',
    '',
  ];
}

const MAP_HEADER = [
  '## Other files in this packet',
  '',
  'Not printed. Ranked by their security labels, each with its labelled functions. Read any of',
  'them when your review leads there.',
  '',
];

// --------------------------------------------------------------------------- //
// The briefs
// --------------------------------------------------------------------------- //

interface Brief {
  markdown: string;
  summary: BriefSummary;
}

function summarise(
  id: string,
  files: number,
  coreRows: FileRow[],
  listed: string[],
  markdown: string
): BriefSummary {
  return {
    id,
    files,
    coreFiles: coreRows.length,
    coreTokens: coreRows.reduce((sum, r) => sum + pieceTokens(r), 0),
    listed: listed.length,
    briefTokens: Math.round(markdown.length / CHARS_PER_TOKEN),
  };
}

/**
 * One packet's brief: perspective, the hypotheses a hypothesis packet settles, threat model,
 * reading, map of other files, chains, core.
 */
function packetBrief(
  spec: PacketSpec,
  owner: string | undefined,
  shared: Shared,
  hypotheses: Hypothesis[] = []
): Brief {
  const { input, byPath, fileOf, packetOf } = shared;
  const members = new Set(spec.review);
  const seeds = new Set(spec.seeds);

  // The core: seeds first, then the most labelled files; the map: every other file with a security
  // label. A hypothesis packet's seeds keep their order (the files a hypothesis is about, then the
  // long lifecycle files), so a high-scoring lifecycle file cannot fill the core before them.
  const byRank = spec.review.map(p => shared.rank(p, seeds.has(p))).sort(byScore);
  const ranked = hypotheses.length ? seedsInOrder(byRank, spec.seeds) : byRank;
  const coreRows = core(ranked, byPath, CORE_TOKENS);
  const inCore = new Set(coreRows.map(r => r.path));
  const open = ranked.filter(
    r => !inCore.has(r.path) && r.labels.some(l => !l.startsWith('role:'))
  );
  const { lines, paths } = mapLines(open, shared);
  const total = spec.review.reduce((sum, p) => sum + (byPath.get(p)?.lines ?? 0), 0);

  const md = [
    `# Packet ${spec.id}`,
    '',
    `${spec.review.length} files, ${total} lines: ${coreRows.length} core files printed below, ${paths.length} more listed by label, ${spec.review.length - coreRows.length - paths.length} others without a security label.`,
    '',
  ];
  if (spec.perspective) md.push(`Perspective: ${spec.perspective}`, '');
  if (spec.attacker) md.push(`Attacker: ${spec.attacker}`, '');
  md.push(...hypothesesToSettle(hypotheses));
  // One packet owns application-wide controls, so packets whose perspective touches headers or
  // cookies do not each report the same missing control.
  if (owner)
    md.push(
      `Application-wide controls (${APP_WIDE_CONTROLS}): ` +
        (spec.id === owner
          ? 'this packet reports each one that is missing, once.'
          : `reported by packet \`${owner}\`; do not report them here.`),
      ''
    );
  md.push(
    ...threatModelSection(input.review, members),
    ...reading(input.paths.kbIndex),
    ...MAP_HEADER
  );
  md.push(...(lines.length ? lines : ['(none: your core holds every labelled file)']), '');
  if (spec.context.length)
    md.push(
      `Context files (read only to follow a call or a control): ${spec.context.map(c => `\`${c}\``).join(', ')}`,
      ''
    );

  // Where a value leaves the packet: its calls into other packets, and the chains from its entry
  // points to sensitive operations.
  const outside = [
    ...new Set(
      input.calls
        .filter(
          ([a, b]) =>
            members.has(fileOf.get(a) ?? '') && fileOf.has(b) && !members.has(fileOf.get(b) ?? '')
        )
        .map(([, b]) => b)
    ),
  ]
    .sort()
    .slice(0, MAX_OUTSIDE_CALLS)
    .map(b => `\`${b}\` (${fileOf.get(b)}, ${packetOf.get(fileOf.get(b) ?? '') ?? 'no packet'})`);
  if (outside.length) md.push(`Calls into other packets: ${outside.join(', ')}`, '');
  const loc = new Map(input.functions.map(f => [f.qn, f]));
  const mine = chains(
    input.entries.filter(e => members.has(e.path)),
    input.calls,
    input.sinks
  ).filter(c => c.own || c.paths.length);
  if (mine.length) {
    md.push(
      '## Entry point to sink chains',
      '',
      `Call paths from this packet's entry points to functions labelled as performing a sensitive operation (depth <= ${MAX_CHAIN_DEPTH}).`,
      ''
    );
    for (const c of mine.slice(0, MAX_PACKET_CHAINS)) {
      md.push(`- \`${c.entry.qn}\` (\`${c.entry.path}:${c.entry.line}\`): own: ${c.own ?? 'none'}`);
      for (const path of c.paths.slice(0, MAX_CHAIN_PATHS)) {
        const steps = path.slice(0, MAX_CHAIN_SINKS).map(qn => {
          const f = loc.get(qn);
          return f
            ? `\`${qn}\` (${f.path}:${f.start}, ${input.sinks.get(qn) ?? 'call'})`
            : `\`${qn}\``;
        });
        md.push(`  - -> ${steps.join(' -> ')}`);
      }
    }
    md.push('');
  }

  md.push(...codeFacts(input, members));
  md.push('## Core files', '', ...coreRows.map(printPiece), '');
  const markdown = md.join('\n');
  return {
    markdown,
    summary: summarise(spec.id, spec.review.length, coreRows, paths, markdown),
  };
}

/** The hypothesis templates' facts about a brief's files (hypotheses/): where its code can be interrupted. */
function codeFacts(input: BriefingInput, files: Set<string>): string[] {
  return input.hypotheses ? briefSections(TEMPLATES, input.hypotheses.input, files) : [];
}

/**
 * The hypothesis packets: the hypotheses shared out between at most `packets` of them
 * (hypotheses/ hypothesisPackets), each built from its hypotheses' briefs: their seeds first, the
 * files they name beside them, and the rest of every packet that reviews a hypothesis's first
 * seed as the map.
 */
function hypothesisPacketSpecs(
  input: BriefingInput
): { spec: PacketSpec; hypotheses: Hypothesis[] }[] {
  const { computed = [], packets = 0 } = input.hypotheses ?? {};
  return hypothesisPackets(computed, packets).map((hypotheses, i) => {
    const briefs = [...new Set(hypotheses.map(h => h.brief))];
    const seeds = [...new Set(briefs.flatMap(b => b.seeds))];
    const owners = input.spec.filter(s => briefs.some(b => s.review.includes(b.seeds[0] ?? '')));
    return {
      spec: {
        id: `hypotheses-${i + 1}`,
        perspective: [...new Set(briefs.map(b => b.perspective))].join(' '),
        attacker: [...new Set(briefs.map(b => b.attacker))].join(' '),
        review: [
          ...new Set([
            ...seeds,
            ...briefs.flatMap(b => b.related),
            ...owners.flatMap(s => s.review),
          ]),
        ].sort(),
        seeds,
        context: [],
        ownsAppWide: false,
      },
      hypotheses,
    };
  });
}

/** A hypothesis packet's hypotheses, as questions: each claim, where it starts, what would settle it. */
function hypothesesToSettle(hypotheses: Hypothesis[]): string[] {
  if (!hypotheses.length) return [];
  return [
    '## Hypotheses to settle',
    '',
    "This packet's job is the hypotheses below: questions computed from the code before the scan,",
    "from facts no single packet's files show. A hypothesis is not a finding. Settle each one either",
    "way: follow the path it names beyond this brief's files where it leads (an error, a limit or a",
    'non-local exit part-way; a second request on the same worker; a callback another component',
    'installs), then report a finding with its evidence, or record in `resolved_questions` why it',
    'does not hold, with the lines that show it.',
    '',
    ...hypotheses.flatMap((h, i) => [
      `${i + 1}. ${h.claim}`,
      `   - where: ${h.where}`,
      `   - what would settle it: ${h.check}`,
    ]),
    '',
  ];
}

/**
 * The baseline auditor's brief: the riskiest files an attacker's path could run through as its
 * core, the secret windows (configuration, tests and documentation included), and a map of the
 * other files with an entry point, an access control or a sensitive operation.
 */
function baselineBrief(shared: Shared): Brief {
  const { input, byPath } = shared;
  const ranked = input.baseline.map(p => shared.rank(p, false)).sort(byScore);
  const coreRows = core(ranked, byPath, BASELINE_CORE_TOKENS);
  const inCore = new Set(coreRows.map(r => r.path));
  const open = ranked.filter(
    r =>
      !inCore.has(r.path) &&
      r.labels.some(l => l.startsWith('entry') || l === 'access-control' || l.startsWith('sink'))
  );
  const { lines, paths } = mapLines(open, shared);

  // Secret windows: printed up to SECRET_TOKENS, the rest named in one reader command.
  const printed: Piece[] = [];
  const listed: Piece[] = [];
  let left = SECRET_TOKENS;
  for (const piece of secretPieces(input.secretWindows, byPath)) {
    const size = pieceTokens(piece);
    if (size <= left) {
      printed.push(piece);
      left -= size;
    } else listed.push(piece);
  }

  const md = [
    '# Baseline auditor',
    '',
    `The independent second look across packets: ${input.baseline.length} files a decision model judged to lie on an attacker's path; ${coreRows.length} core files printed below, ${paths.length} more listed by label. Every file is also reviewed by a packet.`,
    '',
    ...threatModelSection(input.review, new Set(input.baseline)),
    ...reading(input.paths.kbIndex),
    ...MAP_HEADER,
    ...(lines.length ? lines : ['(none: your core holds every labelled file)']),
    '',
    '## Secret windows',
    '',
    `${input.secretWindows.length} line windows (in configuration, tests, documentation and data as well as code) that a decision model flagged as holding a password, key or token. Check each literal for a credential that grants access.` +
      (listed.length
        ? ` ${printed.length} are printed at the end; read the other ${listed.length} with this command:`
        : ''),
    '',
  ];
  if (listed.length)
    md.push(
      '```',
      `${reader(input.paths.kbIndex)} read ${listed.map(p => shellWord(`${p.path}:${p.start}-${p.end}`)).join(' ')}`,
      '```',
      ''
    );
  md.push(...codeFacts(input, new Set(input.baseline)));
  md.push('## Core files', '', ...coreRows.map(printPiece), '');
  if (printed.length) md.push('## Secret windows, printed', '', ...printed.map(printPiece), '');
  const markdown = md.join('\n');
  return {
    markdown,
    summary: summarise(BASELINE, input.baseline.length, coreRows, paths, markdown),
  };
}

// --------------------------------------------------------------------------- //
// The lead's index, and everything together
// --------------------------------------------------------------------------- //

/** The knowledge base the scan reads: the lead's index, and the helpers' reader directory. */
export interface Briefing {
  /** code-graph.md: what the lead reads. */
  markdown: string;
  /** Files of the reader directory (the scanner's paths.kbIndex), by relative path. */
  files: Map<string, string>;
  briefs: BriefSummary[];
}

/** A helper's task name: the name its result is saved under. */
export function taskName(id: string): string {
  return id === BASELINE ? 'baseline_auditor' : `packet_${id.replace(/-/g, '_')}`;
}

/** The lead's index, every brief, the reader and its index. */
export function briefing(input: BriefingInput): Briefing {
  const { rows, functions, spec } = input;
  const byFile = new Map<string, FunctionNode[]>();
  for (const f of [...functions].sort((a, b) => a.start - b.start))
    byFile.set(f.path, [...(byFile.get(f.path) ?? []), f]);
  const packetOf = new Map<string, string>();
  for (const s of spec) for (const p of s.review) if (!packetOf.has(p)) packetOf.set(p, s.id);
  const shared: Shared = {
    input,
    byPath: new Map(rows.map(r => [r.path, r])),
    byFile,
    rank: ranker(input),
    fileOf: new Map(functions.map(f => [f.qn, f.path])),
    packetOf,
  };

  // The briefs: the packets', the hypothesis packets' and the baseline auditor's.
  const owner = spec.find(s => s.ownsAppWide)?.id;
  const hypothesis = hypothesisPacketSpecs(input);
  const specs = [...spec, ...hypothesis.map(h => h.spec)];
  const briefs = [
    ...spec.map(s => ({ id: s.id, ...packetBrief(s, owner, shared) })),
    ...hypothesis.map(h => ({
      id: h.spec.id,
      ...packetBrief(h.spec, owner, shared, h.hypotheses),
    })),
    { id: BASELINE, ...baselineBrief(shared) },
  ];
  const index = indexFiles(input);
  const files = new Map<string, string>([
    ['kb', kbScript(input.paths.project, input.paths.kbIndex)],
    ['files.tsv', index.files],
    ['functions.tsv', index.functions],
  ]);
  for (const b of briefs) {
    files.set(`packets/${b.id}.md`, b.markdown);
  }

  // The lead's index: one line per helper, and what the scan leaves out.
  const lines = new Map<string, number>();
  const count = new Map<string, number>();
  for (const r of rows) {
    lines.set(r.kind, (lines.get(r.kind) ?? 0) + r.lines);
    count.set(r.kind, (count.get(r.kind) ?? 0) + 1);
  }
  const md = [
    '# Knowledge base index',
    '',
    'Computed on the host before the scan: a code graph (functions and calls) and a decision model',
    'that read every file and function once. Each helper has a brief at',
    `\`${input.paths.kbIndex}/packets/<id>.md\`: its core files, a map of its other files and the threat`,
    'model; it loads everything else on demand. You do not read the briefs or the source.',
    '',
    '## Summary',
    '',
    `- ${functions.length} functions, ${input.entries.length} entry points, ${input.sinks.size} functions performing a sensitive operation; graph ${input.index['nodes'] ?? '?'} nodes, ${input.index['edges'] ?? '?'} edges`,
    '- lines by kind: ' +
      [...lines]
        .sort((x, y) => (x[0] < y[0] ? -1 : 1))
        .map(([k, v]) => `${k} ${v} (${count.get(k)} files)`)
        .join(', '),
    '',
    '## Helpers',
    '',
    'One helper per row, all started at once: the baseline auditor in your first reply, the',
    'packets in your second.',
    '',
    '| task name | brief id | files | core | listed | perspective |',
    '|---|---|---|---|---|---|',
    ...briefs.map(b => {
      const s = specs.find(x => x.id === b.id);
      const view = s
        ? s.perspective.replace(/\|/g, '/').replace(/\s+/g, ' ').slice(0, 200)
        : 'the independent second look, and secrets';
      return `| ${taskName(b.id)} | ${b.id} | ${b.summary.files} | ${b.summary.coreFiles} | ${b.summary.listed} | ${view} |`;
    }),
    '',
    '## Not reviewed (explicit exclusions)',
    '',
    'Vendored, minified, generated, lock and binary files, tests, data files and documentation',
    '(the baseline auditor still checks them for secrets). Each line names the files it covers:',
    '',
    ...notReviewed(rows),
    '',
  ];
  return { markdown: md.join('\n'), files, briefs: briefs.map(b => b.summary) };
}

/** What the files of a kind are, in words. A skipped file says why instead (whatSkipped). */
const KIND_WORDS: Record<string, string> = {
  test: 'test files',
  data: 'data files',
  docs: 'documentation',
  other: 'stylesheets and repository metadata',
};

/**
 * The index's "Not reviewed" lines, which the lead copies into upstream's coverage as its
 * explicit exclusions, and so into the scan's report. A line must therefore say exactly which
 * files it covers: grouped as `terraform/ (skip)`, one lock file read in the report as "terraform/
 * excluded from review" while every .tf file beside it was reviewed.
 *
 *   a few files     each path, with what it is      `terraform/.terraform.lock.hcl` (lock file)
 *   more            the kind and its directory      test files under `src/`: 30 files
 *
 * Groups are by top-level directory and what the files are; the largest come first, at most 40.
 */
/** A skip reason as words: "in node_modules/" names a directory, which the line names already. */
function whatSkipped(reason: string): string {
  return reason.startsWith('in ') ? 'vendored or build output' : reason;
}

export function notReviewed(rows: FileRow[], maxListed = 3): string[] {
  const groups = new Map<string, { dir: string; what: string; paths: string[] }>();
  for (const r of rows) {
    if (PRODUCT_KINDS.has(r.kind)) continue;
    const dir = r.path.includes('/') ? (r.path.split('/')[0] as string) : '';
    const what =
      r.kind === 'skip' ? whatSkipped(r.reason) : (KIND_WORDS[r.kind] ?? `${r.kind} files`);
    const key = `${dir}\0${what}`;
    const group = groups.get(key) ?? { dir, what, paths: [] };
    group.paths.push(r.path);
    groups.set(key, group);
  }
  return [...groups.values()]
    .sort((x, y) => y.paths.length - x.paths.length || (x.dir < y.dir ? -1 : 1))
    .slice(0, 40)
    .flatMap(({ dir, what, paths }) =>
      paths.length <= maxListed
        ? paths.map(p => `- \`${p}\` (${what})`)
        : [`- ${what} ${dir ? `under \`${dir}/\`` : 'at the top level'}: ${paths.length} files`]
    );
}

/** Product rows of the inventory: the files packets and the baseline review. */
export function productRows(rows: FileRow[]): FileRow[] {
  return rows.filter(r => PRODUCT_KINDS.has(r.kind) && r.lines);
}
