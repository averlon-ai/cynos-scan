/**
 * The scan plan: which functions an outside caller can invoke, which perform a sensitive
 * operation, where secrets sit, and how the product files split into investigation packets.
 *
 * Pattern rules for entry points and sinks only know the frameworks someone wrote rules for, and
 * miss the rest without an error. So a decision model (Jev) reads every function and every file
 * once and answers a few fixed questions with a probability, in any language; the code graph
 * supplies the functions, their line ranges and the calls between them; one strong-model call
 * designs the packets from a digest of those answers:
 *
 *   1  functions     Jev per function: entry point? which sink? and the hypothesis templates'
 *                    questions (hypotheses/): exits without returning? state a later request uses?
 *                    then, of the functions that touch such state, when they run
 *   2  files         Jev per product file: entry point? untrusted input? access control? could an
 *                    attacker's path run through it (the baseline auditors' files)?
 *   3  secrets       Jev per text file of every kind; a flagged file the baseline does not read
 *                    whole is narrowed to line windows by asking again per window
 *   4  design        a digest (identity, directory map, route table, hubs, file cards) and one
 *                    strong-model call through cynos, router and judge off: packets with seed
 *                    files, context files, membership criteria
 *   5  membership    Jev per product file: one yes/no question per packet, does the file meet its
 *                    criteria
 *   6  assembly      each file to every packet it meets at MEMBER_P (its likeliest packet when it
 *                    meets none, so no file is left unreviewed); one helper
 *                    per packet and one baseline auditor, however many files each has, since they
 *                    start from a core of their most important files and load the rest on demand
 *                    (briefing.ts)
 *   7  hypotheses    the hypothesis templates' hypotheses (hypotheses/), from the labels and the
 *                    graph, for the hypothesis packets that settle them (briefing.ts)
 *
 * If more than MAX_FAILED_SHARE of the per-function calls fail, Jev cannot be trusted for entry
 * points, and the plan fails rather than guess.
 */
import { basename } from 'node:path';
import { KNOWLEDGE_BASE_MODEL } from '../constants';
import type { FunctionNode } from './code-graph';
import type { AgentPlan } from './architecture-agent';
import type { CynosDecisions, ReviewModel } from './cynos';
import { renderReview, reviewArchitecture } from './architecture';
import { MANIFESTS, type FileRow } from './inventory';
import { askMany, choice, noul, type Answers, type Questions } from './jev';
import {
  computeHypotheses,
  labelQuestions,
  TEMPLATES,
  type Hypothesis,
  type LabelQuestion,
  type HypothesisInput,
} from '../hypotheses';

/** Recall first: a false entry point costs one route-table line. */
export const ENTRY_P = 0.3;
/** Recall first: a false yes costs one more file in the baseline. */
export const ATTACK_PATH_P = 0.3;
export const SECRET_P = 0.3;
/** A file joins every packet whose criteria it meets with at least this probability. */
export const MEMBER_P = 0.5;
export const MAX_PACKETS = 8;
/** The baseline auditor's brief; no packet may take its name. */
export const BASELINE = 'baseline';
const MAX_SEEDS = 15;
const MAX_CONTEXT = 10;
const MAX_FUNCTION_CHARS = 60_000;
const MAX_FAILED_SHARE = 0.2;
/** Rough, for code. */
export const CHARS_PER_TOKEN = 3.5;
const WINDOW_LINES = 40;
const WINDOW_PAD = 3;
const MAX_ROUTES_IN_DIGEST = 600;
const MAX_HUBS = 30;
/** The packet design's model: the knowledge base's (KNOWLEDGE_BASE_MODEL, the only copy). */
export const DESIGN_MODEL = KNOWLEDGE_BASE_MODEL;
const DESIGN_ATTEMPTS = 3;

export const FUNCTION_QUESTIONS: Questions = {
  entry_point: {
    type: 'noul',
    instructions:
      'Is this function itself something an outside caller can invoke directly: an HTTP route handler, RPC or GraphQL resolver, WebSocket or message handler, CLI command, scheduled job, or public library API?',
    criteria: {
      true: 'An outside caller can invoke it directly.',
      false: 'It is only called by other code in the application.',
    },
  },
  sink: {
    type: 'choice',
    instructions: 'Which sensitive operation does this function itself perform most prominently?',
    criteria: {
      none: 'No sensitive operation.',
      database: 'Builds or runs database queries or ORM writes.',
      filesystem: 'Reads, writes or serves files or paths.',
      execution: 'Runs commands, evaluates code, or deserializes untrusted data.',
      network:
        "Makes a request from the server to another service or URL, or redirects the client. A browser-side call to the application's own backend is not this.",
      rendering: 'Renders HTML, templates or other output interpreted by a browser.',
      crypto: 'Handles passwords, keys, tokens, hashing, signing or secrets.',
    },
  },
};

/**
 * The hypothesis templates' questions (hypotheses/). Those asked of every function go into the same call as
 * FUNCTION_QUESTIONS, so a function is read once; those a template asks only where earlier answers
 * make them matter (`askIf`) follow, of those functions only.
 */
const HYPOTHESIS_QUESTIONS = labelQuestions(TEMPLATES);

/** Questions as the decision model takes them. */
function decisionQuestions(questions: LabelQuestion[]): Questions {
  return Object.fromEntries(
    questions.map(({ name, type, instructions, criteria }) => [
      name,
      { type, instructions, criteria },
    ])
  );
}

export const FILE_QUESTIONS: Questions = {
  entry_point: {
    type: 'noul',
    instructions:
      'Does this file define or register something an outside caller can invoke directly: an HTTP route or handler, RPC or GraphQL resolver, WebSocket or message handler, CLI command, scheduled job, or a public library API?',
    criteria: {
      true: 'It registers or implements at least one such entry point.',
      false:
        'It only holds helpers, models, types, configuration, styles or tests. Documentation, API specifications (OpenAPI/Swagger), examples and tests that describe routes do not count: only code that serves them.',
    },
  },
  untrusted_input: {
    type: 'noul',
    instructions:
      'Does code in this file read data that an outside caller controls (request body, query, params, headers, cookies, uploaded files, messages, CLI arguments)?',
    criteria: {
      true: 'It reads caller-controlled data.',
      false: 'It does not read caller-controlled data.',
    },
  },
  access_control: {
    type: 'noul',
    instructions:
      'Does this file decide, or contain code that should decide, whether a caller is authenticated or allowed to act on a specific resource (guards, middleware, decorators, permission, role or ownership checks, session or token validation)?',
    criteria: {
      true: 'It contains authentication or authorization logic, or a handler that reads or changes per-user or per-tenant data.',
      false: 'It has no authentication or authorization role.',
    },
  },
  attack_path: {
    type: 'noul',
    instructions:
      "Could an attacker's path to a vulnerability run through code in this file? That is: it reads data an outside caller controls, makes an authentication or authorization decision, or performs a sensitive operation (database query, file or path access, command or code execution, outbound request or redirect, rendering of user-supplied data, cryptography or token handling) on behalf of a caller.",
    criteria: {
      true: 'Code in this file is on such a path.',
      false:
        'It only holds types, constants, styles, static content, pure helpers on trusted data, or wiring with no such operation.',
    },
  },
};

const SECRET_QUESTION: Questions = {
  embedded_secret: {
    type: 'noul',
    instructions:
      "Does this file contain a hardcoded secret that grants access to something beyond reading this source: a password for an account, an API key, a signing, encryption or session key, a token, a private key, or a connection string with a password? A default or fallback value the application really uses to log in, sign or encrypt counts, even if it looks simple (for example 'secret' or 'admin123').",
    criteria: {
      true: 'The file holds at least one such secret value.',
      false:
        'No such value: only placeholders (changeme, xxx, <your-key>), environment-variable or secret-store references, public keys, identifiers, hashes of unknown passwords, or CTF/game flags.',
    },
  },
};

/**
 * Every text file's role in the security architecture: what the architecture review's evidence
 * and checklist are built from, in place of guessing from file names.
 */
const ARCHITECTURE_ROLE_QUESTION: Questions = {
  architecture_role: {
    type: 'choice',
    instructions:
      "What role does this file play in the application's security architecture? Judge from its content and its path.",
    criteria: {
      startup:
        'Process entry point or server bootstrap: creates the application, wires its components, middleware or plugins together, or starts its listeners.',
      routes:
        'Registers or mounts the routes, handlers, RPC methods or commands that outside callers reach (a router, URL map or controller registration), not a single handler.',
      access_control:
        'Decides authentication, sessions, authorization, roles or tenancy for requests: middleware, guards, policies, token or key validation.',
      configuration:
        'Loads, merges, validates or defines the settings and secrets the running code consumes: config loaders, settings modules, environment handling, default configuration.',
      deployment:
        'Defines how the application is built, packaged, exposed or run: Dockerfiles, compose files, Helm charts and values, Kubernetes manifests, proxy or server configuration, deploy steps.',
      data_integrations:
        'Owns a data store or an external integration: database or storage setup, queues, clients for other services.',
      architecture_docs:
        "Documentation that explains the application's components, deployment, configuration or security posture: README, SECURITY, architecture or deployment guides.",
      none: 'Anything else: a feature module or a single handler, a helper, model or UI component, a test, example or data file, generated code, or documentation of something else (an API reference, a changelog, a user guide).',
    },
  },
};

/** The questions every text file is asked once: does it hold a secret, and what is its role. */
export const FILE_SWEEP_QUESTIONS: Questions = {
  ...SECRET_QUESTION,
  ...ARCHITECTURE_ROLE_QUESTION,
};

export function designSystem(maxPackets: number): string {
  return `You design the work split for a static security audit of one repository. Several
auditor agents run in parallel, one per packet; each starts from its packet's most important
files, loads the rest of the packet on demand, and reports vulnerabilities. You only design the
packets; you do not look for vulnerabilities yourself.

Rules:
- Group by attacker goal and trust boundary (for example: authorization and ownership of user
  data, authentication and sessions, file handling, outbound requests, rendering/XSS,
  administration), not by directory. A route file belongs with the controls that should protect it.
- Design as many packets as the repository's distinct attacker goals need, at most ${maxPackets}.
  A packet may hold many files: its auditor reads the important ones and loads the rest on
  demand. Do not merge unrelated concerns to save packets, and do not split one concern into
  several packets.
- List at most ${MAX_SEEDS} seed_review_files (the files that certainly belong) and ${MAX_CONTEXT}
  context_files (shared helpers the packet's code depends on, read only to understand a call or a
  control) per packet. A classifier asks of every other file, packet by packet, whether it meets
  membership_criteria; a file can belong to several packets.
- Write membership_criteria so that a classifier that sees ONE file at a time, and nothing else,
  can decide whether that file belongs in the packet. Describe what the file's code does, not
  its path.
- Ground the packets in the architecture review (section 0 of the digest) when there is one: every
  trust boundary and sensitive resource it names should be the concern of at least one packet, and
  a packet's perspective names the boundaries it covers.
- A packet's attacker is one of the review's attacker capabilities, entering through the gate that
  guards the packet's code (for example "a tenant holding a virtual key, through the inference
  surface"). Never invent an actor the review does not list: when the review says a surface is
  reachable only by the administrator, its packet's attacker is an outside caller trying to pass
  that gate, not a tenant already inside it.
- Mark exactly one packet with "owns_application_wide_controls": true. It alone reports controls
  that are missing for the whole application (rate limiting, CSRF protection, cookie flags,
  security headers, CORS); usually the packet about authentication and sessions. No other
  packet's perspective mentions those controls.
Return JSON: {"packets": [{"id", "perspective", "attacker", "seed_review_files", "context_files",
"membership_criteria", "owns_application_wide_controls"}]}`;
}

export function tokens(text: string): number {
  return Math.ceil(text.length / CHARS_PER_TOKEN);
}

export interface Entry {
  qn: string;
  path: string;
  line: number;
  how: 'function' | 'file';
  p: number;
  /** `[p=0.92] <the handler's first line>` */
  text: string;
}

export interface SecretWindow {
  path: string;
  start: number;
  end: number;
}

export interface Packet {
  id: string;
  perspective: string;
  attacker: string;
  seeds: string[];
  criteria: string;
  context: string[];
  ownsAppWide: boolean;
}

/** One packet as the briefing renders it: one helper each. */
export interface PacketSpec {
  id: string;
  perspective: string;
  attacker: string;
  review: string[];
  /** The files the design named for it: first in its core. */
  seeds: string[];
  context: string[];
  ownsAppWide: boolean;
}

export interface Repository {
  rows: FileRow[];
  product: FileRow[];
  functions: FunctionNode[];
  calls: [string, string][];
  /** Tokens per product file. */
  tokens: Map<string, number>;
}

export interface Plan {
  /** The architecture review, when it succeeded: the scan's threat model. */
  review: Awaited<ReturnType<typeof reviewArchitecture>> | undefined;
  entries: Entry[];
  sinks: Map<string, string>;
  spec: PacketSpec[];
  /** The baseline auditor's files: those an attacker's path could run through. */
  baseline: string[];
  secretWindows: SecretWindow[];
  digest: string;
  /** The labels behind the index and the briefs (briefing.ts). */
  fileLabels: Map<string, Answers>;
  functionLabels: Map<string, Answers>;
  /** The file sweep's answers: every text file's architecture role and secret. */
  roles: Map<string, Answers>;
  entryFiles: Map<string, number>;
  /** What the hypothesis templates read, for the briefs' facts (briefing.ts). */
  hypothesisInput: HypothesisInput;
  /** The hypotheses the templates computed, for the hypothesis packets. */
  hypotheses: Hypothesis[];
}

// --------------------------------------------------------------------------- //
// 1. Per-function labels: entry points and sinks
// --------------------------------------------------------------------------- //

/** What Jev reads about a function: its code, the lines above it (decorators), the file's imports. */
export function functionStates(repo: Repository): [string, unknown][] {
  const text = new Map(repo.product.map(r => [r.path, (r.text ?? '').split('\n')]));
  const out: [string, unknown][] = [];
  for (const f of repo.functions) {
    const lines = text.get(f.path);
    if (!lines) continue;
    const body = lines.slice(Math.max(f.start - 1, 0), Math.max(f.end, f.start)).join('\n');
    out.push([
      f.qn,
      {
        path: f.path,
        function: f.qn,
        imports: lines.slice(0, 40).join('\n'),
        decorators: lines.slice(Math.max(f.start - 4, 0), Math.max(f.start - 1, 0)).join('\n'),
        code: body.slice(0, MAX_FUNCTION_CHARS),
      },
    ]);
  }
  return out;
}

/**
 * Functions Jev calls entry points, plus files Jev calls entry points where no function is.
 *
 * The file-level case is real, not a fallback: a file-based router (a Next.js page, a PHP
 * script), an inline arrow handler the graph does not name, or a registration-only module has
 * its entry point in the file, not in a named function. Those get line 1 and qn = path.
 */
export function entryPoints(
  repo: Repository,
  functionLabels: Map<string, Answers>,
  fileLabels: Map<string, Answers>
): Entry[] {
  const lines = new Map(repo.product.map(r => [r.path, (r.text ?? '').split('\n')]));
  const out: Entry[] = [];
  const filesWithEntry = new Set<string>();
  for (const f of repo.functions) {
    const p = noul(functionLabels.get(f.qn), 'entry_point');
    const fileLines = lines.get(f.path);
    if (p < ENTRY_P || !fileLines) continue;
    const first = f.start >= 1 ? (fileLines[f.start - 1] ?? '').trim().slice(0, 120) : '';
    out.push({
      qn: f.qn,
      path: f.path,
      line: f.start,
      how: 'function',
      p,
      text: `[p=${p.toFixed(2)}] ${first}`,
    });
    filesWithEntry.add(f.path);
  }
  for (const [path, answers] of fileLabels) {
    const p = noul(answers, 'entry_point');
    if (p < ENTRY_P || filesWithEntry.has(path)) continue;
    const first =
      (lines.get(path) ?? [])
        .find(l => l.trim())
        ?.trim()
        .slice(0, 120) ?? '';
    out.push({ qn: path, path, line: 1, how: 'file', p, text: `[p=${p.toFixed(2)}] ${first}` });
  }
  return out.sort((a, b) => (a.path === b.path ? a.line - b.line : a.path < b.path ? -1 : 1));
}

/**
 * Function -> the sensitive operation it performs: the ends of the entry-to-sink chains.
 * Rendering is left out: every UI component renders, so as an end it marks nothing.
 */
export function sinkFunctions(functionLabels: Map<string, Answers>): Map<string, string> {
  const out = new Map<string, string>();
  for (const [qn, answers] of functionLabels) {
    const kind = choice(answers, 'sink');
    if (kind !== 'none' && kind !== 'rendering') out.set(qn, kind);
  }
  return out;
}

// --------------------------------------------------------------------------- //
// 3. Secret windows
// --------------------------------------------------------------------------- //

/**
 * Line windows that may hold an embedded secret, in files `whole` does not hold.
 *
 * Asked per file over every text file, because codex-security wants credentials in
 * configuration, tests, documentation and inactive code found too; a flagged file is then asked
 * again per WINDOW_LINES-line window, so the baseline auditor reads a few windows instead of a
 * whole test file or blog post.
 */
export async function secretWindows(
  client: CynosDecisions,
  rows: FileRow[],
  whole: Set<string>,
  /** The file sweep's answers: whether each file holds a secret. */
  answers: Map<string, Answers>,
  log: (message: string) => void
): Promise<SecretWindow[]> {
  const files = rows.filter(r => r.text !== undefined);
  const windows: SecretWindow[] = [];
  const items: [string, unknown][] = [];
  const spans = new Map<string, [string, number, number, number]>();
  for (const r of files) {
    if (whole.has(r.path) || noul(answers.get(r.path), 'embedded_secret') < SECRET_P) continue;
    const lines = (r.text ?? '').split('\n');
    if (lines.length <= WINDOW_LINES * 1.5) {
      windows.push({ path: r.path, start: 1, end: Math.max(lines.length, 1) });
      continue;
    }
    for (let a = 0; a < lines.length; a += WINDOW_LINES) {
      const b = Math.min(a + WINDOW_LINES, lines.length);
      const key = `${r.path}:${a + 1}`;
      items.push([
        key,
        { path: r.path, lines: `${a + 1}-${b}`, content: lines.slice(a, b).join('\n') },
      ]);
      spans.set(key, [r.path, a + 1, b, lines.length]);
    }
  }
  const { answers: windowAnswers } = await askMany(client, items, SECRET_QUESTION, log);
  // Adjacent flagged windows of one file merge; each keeps a few lines of context either side.
  const flagged = [...windowAnswers]
    .filter(([, a]) => noul(a, 'embedded_secret') >= SECRET_P)
    .map(([key]) => spans.get(key) as [string, number, number, number])
    .sort((x, y) => (x[0] === y[0] ? x[1] - y[1] : x[0] < y[0] ? -1 : 1));
  const merged: SecretWindow[] = [];
  for (const [path, a0, b0, n] of flagged) {
    const a = Math.max(a0 - WINDOW_PAD, 1);
    const b = Math.min(b0 + WINDOW_PAD, n);
    const last = merged[merged.length - 1];
    if (last && last.path === path && a <= last.end + 1) last.end = Math.max(last.end, b);
    else merged.push({ path, start: a, end: b });
  }
  return [...windows, ...merged].sort((x, y) =>
    x.path === y.path ? x.start - y.start : x.path < y.path ? -1 : 1
  );
}

// --------------------------------------------------------------------------- //
// 4. The digest and the packet design
// --------------------------------------------------------------------------- //

/** Functions that at least two entry points reach within two calls, by count then name. */
export function callGraphHubs(
  entries: Entry[],
  functions: FunctionNode[],
  calls: [string, string][]
): [string, number, string][] {
  const out = new Map<string, Set<string>>();
  for (const [a, b] of calls) if (a !== b) out.set(a, (out.get(a) ?? new Set()).add(b));
  const loc = new Map(functions.map(f => [f.qn, f]));
  const entryQns = new Set(entries.map(e => e.qn).filter(qn => loc.has(qn)));
  const reach = new Map<string, number>();
  for (const h of entryQns) {
    const seen = new Set(out.get(h) ?? []);
    for (const b of [...seen]) for (const c of out.get(b) ?? []) seen.add(c);
    for (const s of seen) if (!entryQns.has(s)) reach.set(s, (reach.get(s) ?? 0) + 1);
  }
  // A call can name a class or an unresolved symbol; only functions with a location are hubs.
  // Ties sort by name, so the digest is the same on every build of one snapshot.
  return [...reach]
    .filter(([qn, n]) => n >= 2 && loc.has(qn))
    .sort((x, y) => y[1] - x[1] || (x[0] < y[0] ? -1 : 1))
    .slice(0, MAX_HUBS)
    .map(([qn, n]) => [qn, n, (loc.get(qn) as FunctionNode).path]);
}

/** The designer's input: identity, directory map, route table, hubs, one card per product file. */
export function digest(
  repo: Repository,
  entries: Entry[],
  hubs: [string, number, string][],
  fileLabels: Map<string, Answers>,
  functionLabels: Map<string, Answers>
): string {
  const parts = ['## 1. Identity'];
  for (const name of ['README.md', 'README.rst', 'README', 'SECURITY.md']) {
    const row = repo.rows.find(r => r.path === name);
    if (row?.text !== undefined) parts.push(`### ${name}\n${row.text.slice(0, 6000)}`);
  }
  for (const r of repo.rows)
    if (MANIFESTS.has(basename(r.path)) && r.text && r.path.split('/').length <= 2)
      parts.push(`### ${r.path}\n${r.text.slice(0, 3000)}`);
  const dirs = new Map<string, [number, number]>();
  for (const r of repo.product) {
    const d = r.path.split('/').slice(0, 3).slice(0, -1).join('/') || '.';
    const e = dirs.get(d) ?? [0, 0];
    dirs.set(d, [e[0] + 1, e[1] + (repo.tokens.get(r.path) ?? 0)]);
  }
  parts.push('## 2. Directory map (product files: count, approximate tokens)');
  for (const [d, [n, t]] of [...dirs].sort((x, y) => (x[0] < y[0] ? -1 : 1)))
    parts.push(`${d}/  ${n} files  ~${t} tokens`);
  parts.push('## 3. Route table (entry point, handler, [entry-point probability] first line)');
  for (const e of entries.slice(0, MAX_ROUTES_IN_DIGEST))
    parts.push(`${e.path}:${e.line}  ${e.qn}  ${e.text}`);
  if (entries.length > MAX_ROUTES_IN_DIGEST)
    parts.push(`... ${entries.length - MAX_ROUTES_IN_DIGEST} more entry points not shown`);
  parts.push('## 4. Call-graph hubs (function, entry points reaching it within 2 calls, file)');
  for (const [qn, n, path] of hubs) parts.push(`${qn}  ${n}  ${path}`);
  parts.push(
    '## 5. File cards\npath | ~tokens | top functions | E=entry point I=untrusted input G=access control | most common sink of its functions'
  );
  const entryFiles = new Set(entries.map(e => e.path));
  const byFile = new Map<string, FunctionNode[]>();
  for (const f of [...repo.functions].sort((a, b) => a.start - b.start))
    byFile.set(f.path, [...(byFile.get(f.path) ?? []), f]);
  for (const r of repo.product) {
    const a = fileLabels.get(r.path);
    const codes =
      (entryFiles.has(r.path) ? 'E' : '-') +
      (noul(a, 'untrusted_input') >= 0.5 ? 'I' : '-') +
      (noul(a, 'access_control') >= 0.5 ? 'G' : '-');
    const sinks = new Map<string, number>();
    for (const f of byFile.get(r.path) ?? []) {
      const kind = choice(functionLabels.get(f.qn), 'sink');
      if (kind !== 'none') sinks.set(kind, (sinks.get(kind) ?? 0) + 1);
    }
    const sink = [...sinks].sort((x, y) => y[1] - x[1])[0]?.[0] ?? '';
    const names = (byFile.get(r.path) ?? [])
      .slice(0, 6)
      .map(f => f.qn.split('.').pop())
      .join(',');
    parts.push(`${r.path} | ~${repo.tokens.get(r.path) ?? 0} | ${names} | ${codes} | ${sink}`);
  }
  return parts.join('\n');
}

/**
 * The design's packets, checked: every packet needs membership criteria, and the design needs at
 * least one seed that is a product file (the model sometimes answers with well-formed but empty
 * JSON: one packet, seed files given as numbers). Seeds that are not product files are dropped;
 * ids become unique slugs because they name files and helpers. Exactly one packet owns
 * application-wide controls: the one the design marked, else the one about authentication or
 * sessions, else the first.
 */
export function checkedDesign(design: unknown, maxPackets: number, product: Set<string>): Packet[] {
  const raw = ((design as { packets?: unknown[] } | null)?.packets ?? []).slice(0, maxPackets);
  const seen = new Set<string>([BASELINE]);
  const packets: Packet[] = [];
  for (const item of raw) {
    const p = (item ?? {}) as Record<string, unknown>;
    const files = (key: string, max: number): string[] =>
      (Array.isArray(p[key]) ? (p[key] as unknown[]) : [])
        .filter((f): f is string => typeof f === 'string')
        .map(f => f.replace(/^\.\//, ''))
        .filter(f => product.has(f))
        .slice(0, max);
    const criteria = p['membership_criteria'];
    if (typeof criteria !== 'string' || !criteria.trim())
      throw new Error(`packet ${JSON.stringify(p['id'])} has no membership criteria`);
    let id =
      String(p['id'] ?? '')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 48) || `packet-${packets.length + 1}`;
    while (seen.has(id)) id += '-x';
    seen.add(id);
    packets.push({
      id,
      perspective: String(p['perspective'] ?? ''),
      attacker: String(p['attacker'] ?? ''),
      seeds: files('seed_review_files', MAX_SEEDS),
      criteria,
      context: files('context_files', MAX_CONTEXT),
      ownsAppWide: p['owns_application_wide_controls'] === true,
    });
  }
  if (!packets.length) throw new Error('the design has no packets');
  if (!packets.some(p => p.seeds.length))
    throw new Error('no seed file of the design is a product file');
  const owner =
    packets.find(p => p.ownsAppWide) ??
    packets.find(p => /auth|session|login/.test(`${p.id} ${p.perspective}`.toLowerCase())) ??
    (packets[0] as Packet);
  for (const p of packets) p.ownsAppWide = p === owner;
  return packets;
}

/**
 * One strong-model call designs the packets; a reply that fails the check is retried. The call goes
 * to cynos with router and judge off, like the architecture review's own calls.
 */
export async function designPackets(
  model: ReviewModel,
  text: string,
  maxPackets: number,
  product: Set<string>,
  log: (message: string) => void
): Promise<Packet[]> {
  let problem = '';
  for (let attempt = 1; attempt <= DESIGN_ATTEMPTS; attempt++) {
    const raw = await model.chatJson(
      DESIGN_MODEL,
      designSystem(maxPackets),
      `Repository digest follows.\n\n${text}`
    );
    try {
      return checkedDesign(JSON.parse(raw), maxPackets, product);
    } catch (error) {
      problem = error instanceof Error ? error.message : String(error);
      log(`packet design attempt ${attempt} rejected: ${problem}`);
    }
  }
  throw new Error(`no usable packet design after ${DESIGN_ATTEMPTS} attempts: ${problem}`);
}

// --------------------------------------------------------------------------- //
// 5-6. Membership and assembly
// --------------------------------------------------------------------------- //

/** The membership question that asks about one packet: a name Jev's answers can be keyed by. */
export const memberQuestion = (id: string): string => `in_${id.replace(/[^a-z0-9]/g, '_')}`;

/**
 * One yes/no question per packet. A single "which packet fits best" choice gave every file one
 * perspective: oauth2/discovery.go is OAuth code that makes outbound requests, went only to the
 * inbound OAuth packet, and its SSRF never reached the outbound reviewer. Asked per packet, a file
 * joins every packet whose criteria it meets.
 */
export function membershipQuestions(packets: Packet[]): Questions {
  return Object.fromEntries(
    packets.map(p => [
      memberQuestion(p.id),
      {
        type: 'noul',
        instructions: `Does this file belong in this review packet? Judge from what its code does. The packet: ${p.criteria}`,
        criteria: {
          true: 'The file meets the packet description.',
          false: 'The file does not meet the packet description.',
        },
      },
    ])
  );
}

/**
 * Review sets per packet.
 *
 * Each file joins every packet it meets at MEMBER_P or more. A file that meets none goes to the
 * packet it is likeliest to belong to, and a file with no usable answer to the smallest packet,
 * so every product file is reviewed. Seed files are always in their packet.
 */
export function assignFiles(
  packets: Packet[],
  member: Map<string, Answers>,
  filesTokens: Map<string, number>
): Map<string, Set<string>> {
  const review = new Map(packets.map(p => [p.id, new Set(p.seeds)]));
  const size = (id: string): number =>
    [...(review.get(id) ?? [])].reduce((sum, f) => sum + (filesTokens.get(f) ?? 0), 0);
  for (const path of filesTokens.keys()) {
    const answers = member.get(path);
    const ranked = packets
      .map(p => [p.id, noul(answers, memberQuestion(p.id))] as [string, number])
      .sort((x, y) => y[1] - x[1]);
    let chosen = ranked.filter(([, p]) => p >= MEMBER_P).map(([id]) => id);
    if (!chosen.length && (ranked[0]?.[1] ?? 0) > 0) chosen = [ranked[0]?.[0] as string];
    if (!chosen.length && ![...review.values()].some(files => files.has(path)))
      chosen = [packets.map(p => p.id).sort((x, y) => size(x) - size(y))[0] as string];
    for (const id of chosen) review.get(id)?.add(path);
  }
  return review;
}

/** The packets as the briefing renders them, each with its review set. */
export function packetSpec(packets: Packet[], review: Map<string, Set<string>>): PacketSpec[] {
  return packets
    .map(p => {
      const files = [...(review.get(p.id) ?? [])].sort();
      return {
        id: p.id,
        perspective: p.perspective,
        attacker: p.attacker,
        review: files,
        seeds: p.seeds,
        context: p.context.filter(c => !files.includes(c)),
        ownsAppWide: p.ownsAppWide,
      };
    })
    .filter(s => s.review.length);
}

// --------------------------------------------------------------------------- //
// The plan
// --------------------------------------------------------------------------- //

/** Steps 1-7 for one repository; `maintained` is the repository's own threat model, if any. */
export async function planScan(
  client: CynosDecisions,
  cynos: ReviewModel,
  repo: Repository,
  log: (message: string) => void,
  maintained?: { path: string; text: string },
  agent?: AgentPlan,
  maxPackets = MAX_PACKETS
): Promise<Plan> {
  const fileItems = repo.product.map(
    r => [r.path, { path: r.path, content: r.text }] as [string, unknown]
  );
  const progress = (step: string): void => log(`${step} ($${client.cost.toFixed(4)} so far)`);

  // 1. Per-function labels; entry points are trusted only when most were answered. Then the
  // hypothesis templates' follow-up questions, each of the functions whose answers make it matter.
  const states = functionStates(repo);
  const { answers: functionLabels, failed } = await askMany(
    client,
    states,
    { ...FUNCTION_QUESTIONS, ...decisionQuestions(HYPOTHESIS_QUESTIONS.filter(q => !q.askIf)) },
    log
  );
  if (states.length && failed / states.length > MAX_FAILED_SHARE)
    throw new Error(`Jev could not label ${failed} of ${states.length} functions`);
  for (const q of HYPOTHESIS_QUESTIONS.filter(q => q.askIf)) {
    const asked = states.filter(([qn]) => q.askIf?.(functionLabels.get(qn)));
    const { answers } = await askMany(client, asked, decisionQuestions([q]), log);
    for (const [qn, a] of answers) functionLabels.set(qn, { ...functionLabels.get(qn), ...a });
  }
  // 2. Per-file labels.
  const { answers: fileLabels } = await askMany(client, fileItems, FILE_QUESTIONS, log);
  const entries = entryPoints(repo, functionLabels, fileLabels);
  const sinks = sinkFunctions(functionLabels);
  progress(`${entries.length} entry points, ${sinks.size} sink functions`);

  // 3. The file sweep: every text file's architecture role and whether it holds a secret. Then the
  // baseline from the attack-path answers and the secret windows, with the architecture review
  // alongside, since both read only the labels and the sweep.
  const { answers: sweep } = await askMany(
    client,
    repo.rows
      .filter(r => r.text !== undefined)
      .map(r => [r.path, { path: r.path, content: r.text }] as [string, unknown]),
    FILE_SWEEP_QUESTIONS,
    log
  );
  const baseline = [...repo.tokens.keys()]
    .sort()
    .filter(p => !fileLabels.has(p) || noul(fileLabels.get(p), 'attack_path') >= ATTACK_PATH_P);
  const entryFiles = new Map<string, number>();
  for (const e of entries) entryFiles.set(e.path, (entryFiles.get(e.path) ?? 0) + 1);
  const [windows, review] = await Promise.all([
    secretWindows(client, repo.rows, new Set(), sweep, log),
    reviewArchitecture(
      {
        rows: repo.rows,
        product: repo.product,
        functions: repo.functions,
        fileLabels,
        functionLabels,
        roles: sweep,
        entryFiles,
        maintained,
        agent,
        cynos,
      },
      log
    ).catch(error => {
      // The scan can run without it: the lead then writes the threat model from the briefing.
      log(
        `architecture review failed, packets are designed without it: ${error instanceof Error ? error.message : String(error)}`
      );
      return undefined;
    }),
  ]);
  progress(`baseline ${baseline.length} files, ${windows.length} secret windows`);

  // 4. Digest and packet design, grounded in the architecture review.
  const hubs = callGraphHubs(entries, repo.functions, repo.calls);
  const text =
    (review
      ? `## 0. Architecture review (verified citations)\n${renderReview(review.review)}\n\n`
      : '') + digest(repo, entries, hubs, fileLabels, functionLabels);
  const product = new Set(repo.tokens.keys());
  const packets = await designPackets(cynos, text, maxPackets, product, log);
  // 5. Membership of every product file.
  const { answers: member } = await askMany(client, fileItems, membershipQuestions(packets), log);
  // 6. Assembly: one helper per packet, however large.
  const spec = packetSpec(packets, assignFiles(packets, member, repo.tokens));
  // 7. Hypotheses, from the labels and the code graph, for the hypothesis packets.
  const hypothesisInput: HypothesisInput = {
    files: repo.rows
      .filter(r => r.text !== undefined)
      .map(r => ({ path: r.path, text: r.text as string })),
    functions: repo.functions,
    calls: repo.calls,
    labels: functionLabels,
  };
  const hypotheses = computeHypotheses(TEMPLATES, hypothesisInput);
  progress(`${spec.length} packets, ${hypotheses.length} hypotheses`);
  return {
    review,
    entries,
    sinks,
    spec,
    baseline,
    secretWindows: windows,
    digest: text,
    fileLabels,
    functionLabels,
    roles: sweep,
    entryFiles,
    hypothesisInput,
    hypotheses,
  };
}
