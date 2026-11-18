/**
 * The architecture review as one Codex agent: a small core of evidence in its prompt, an index of
 * every file and function, and a reader that loads the rest on demand.
 *
 * A review has to see the whole architecture, but its evidence can exceed one prompt.
 * Separate partial reviews can miss relationships across components, while rediscovering the
 * repository turn by turn delays planning. So this agent:
 *
 *   1  starts with the core     identity documents, manifests, deployment, startup and route
 *                               registration, access controls: what every review needs, about
 *                               CORE_TOKENS, in its first prompt
 *   2  loads the rest by index  files.tsv and functions.tsv label every file and function (entry
 *                               point, access control, sensitive operation); `kb` prints a file, a
 *                               range or a function with the file's own line numbers
 *   3  works a checklist        every component (directory) with an entry point, an access
 *                               control, a sensitive operation or configuration: each is read
 *                               from a representative file or dismissed with a reason, since an
 *                               architecture review needs every component, not every file
 *   4  is checked in code       its final message must be the review's JSON object: one that is
 *                               not (a quote left unescaped inside a string) is asked for again
 *                               in the same session once. What it read comes from the line
 *                               numbers its commands printed; a component it neither read nor
 *                               dismissed, or a citation of a line it never saw, goes back to the
 *                               same session once, and what is still invalid is cut
 *
 * It runs through cynos with the router and the quality judge switched off for this agent alone
 * (`x-cy-eh-task-route: off`, `x-cy-eh-domain-expert-judge: off`), as `codex exec` in Codex's
 * read-only sandbox, on the runtime the scan runs on: in the scanner image with the checkout
 * mounted read-only (docker), or the pinned Codex on the host (native). The runtime builds the
 * command (runtime.reviewAgentCommand) from the arguments here, at the paths the agent sees.
 */
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { BASE_URL, KEY_NOT_IN_COMMANDS, PROVIDER_ID, SHELL_SNAPSHOT_OFF } from '../constants';
import type { ReviewAgentPlan, ScanPaths, ScanRuntime } from '../runtime';
import type { FunctionNode } from './code-graph';
import type { FileRow } from './inventory';
import { choice, noul, type Answers } from './jev';
import {
  NON_PRODUCT,
  normalise,
  REVIEW_MODEL,
  REVIEWER_TASK,
  roleOf,
  type ArchitectureReview,
} from './architecture';

/** One agent session's hard limit; the follow-up gets the same. */
export const AGENT_TIMEOUT_MS = 20 * 60_000;
/** Commands the prompt allows beyond the core. */
export const AGENT_COMMANDS = 250;
/** The variable the provider table names as its key; the runtime sets it in the agent's env. */
export const AGENT_KEY_VARIABLE = 'CODEX_API_KEY';
/** cynos switches, for this agent only: no task routing, no quality judge. */
export const AGENT_HEADERS = { 'x-cy-eh-task-route': 'off', 'x-cy-eh-domain-expert-judge': 'off' };
const SINK_KINDS = ['database', 'filesystem', 'execution', 'network', 'crypto'];

/** The agent's run: what the runtime needs to start it, and the paths the agent sees. */
export interface AgentPlan extends ReviewAgentPlan {
  runtime: ScanRuntime;
  /** The checkout and the agent's directory (plan.work), as the agent sees them. */
  paths: Pick<ScanPaths, 'project' | 'review'>;
  /** The run's signal: no session starts after it fires, and the one running is stopped. */
  signal?: AbortSignal;
}

export interface AgentStats {
  seconds: number;
  sessions: number;
  turns: number;
  commands: number;
  inputTokens: number;
  cachedInputTokens: number;
  outputTokens: number;
  checklist: number;
  /** Checklist files the agent read or named in its review. */
  checklistCovered: number;
  filesRead: number;
  exitCode: number | null;
  timedOut: boolean;
}

/** What the agent is given: its core, and the labels behind the index and the checklist. */
export interface AgentInput {
  core: string;
  /** Lines the core printed, per file: readable without a command. */
  corePrinted: Map<string, [number, number][]>;
  rows: FileRow[];
  functions: FunctionNode[];
  fileLabels: Map<string, Answers>;
  functionLabels: Map<string, Answers>;
  /** The file sweep's answers, with each file's architecture role. */
  roles: Map<string, Answers>;
  entryFiles: Map<string, number>;
  maintained: string;
  /**
   * An update's changed files: the checklist keeps only the components that hold one, since the
   * starting review already accounts for the rest.
   */
  scope?: Set<string>;
}

// --------------------------------------------------------------------------- //
// 2. The index and the reader
// --------------------------------------------------------------------------- //

/** Sensitive-operation kinds per file, from the function labels. */
export function sinkKinds(
  input: Pick<AgentInput, 'functions' | 'functionLabels'>
): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  for (const f of input.functions) {
    const kind = choice(input.functionLabels.get(f.qn), 'sink');
    if (SINK_KINDS.includes(kind)) out.set(f.path, (out.get(f.path) ?? new Set()).add(kind));
  }
  return out;
}

/** The labels behind the index: the architecture review's and every scan helper's. */
export type IndexInput = Pick<
  AgentInput,
  'rows' | 'functions' | 'fileLabels' | 'functionLabels' | 'roles' | 'entryFiles'
>;

/** files.tsv and functions.tsv: every readable file and every function, with their labels. */
export function indexFiles(input: IndexInput): { files: string; functions: string } {
  const sinks = sinkKinds(input);
  const fileLabels = (path: string): string => {
    const a = input.fileLabels.get(path);
    return [
      roleOf(input.roles.get(path)) ? `role:${roleOf(input.roles.get(path))?.role}` : '',
      input.entryFiles.has(path) ? `entry:${input.entryFiles.get(path)}` : '',
      noul(a, 'untrusted_input') >= 0.5 ? 'input' : '',
      noul(a, 'access_control') >= 0.5 ? 'access-control' : '',
      ...[...(sinks.get(path) ?? [])].map(k => `sink:${k}`),
    ]
      .filter(Boolean)
      .join(',');
  };
  const files = input.rows
    .filter(r => r.text !== undefined)
    .map(r => [r.path, r.kind, r.lines, fileLabels(r.path)].join('\t'));
  const functions = input.functions.map(f => {
    const kind = choice(input.functionLabels.get(f.qn), 'sink');
    const labels = [
      noul(input.functionLabels.get(f.qn), 'entry_point') >= 0.3 ? 'entry' : '',
      SINK_KINDS.includes(kind) ? `sink:${kind}` : '',
    ];
    return [f.qn, f.path, f.start, f.end, labels.filter(Boolean).join(',')].join('\t');
  });
  return {
    files: ['path\tkind\tlines\tlabels', ...files].join('\n') + '\n',
    functions: ['function\tpath\tstart\tend\tlabels', ...functions].join('\n') + '\n',
  };
}

/** A path as one shell word: as it is when it needs no quoting (every docker path), else quoted. */
export function shellWord(path: string): string {
  // A leading ~ is the shell's home directory, so it is quoted like any other special character.
  return /^[A-Za-z0-9_./@%+=:,-][A-Za-z0-9_./@%+=:,~-]*$/.test(path)
    ? path
    : `'${path.replace(/'/g, `'\\''`)}'`;
}

/**
 * The reader, for the checkout at `project` and an index kept in `indexDir`, both as the agent
 * sees them. Every print starts with `==> path (lines a-b) <==` and numbers each line with the
 * file's own number, so an agent cites real lines and the build can tell from the command log
 * exactly which lines it read.
 */
export function kbScript(project: string, indexDir: string): string {
  return `#!/bin/sh
# kb: read the repository by the knowledge base's index, each file with its own line numbers.
#   kb read <path>[:<start>-<end>] ...   print files or line ranges
#   kb fn <name>                         print a function (or list the matches)
#   kb find <text>                       search the file and function index
#   kb files <directory>                 list a directory's files with their labels
R=${shellWord(project)}
I=${shellWord(indexDir)}
show() {
  f="$R/$1"
  if [ ! -f "$f" ]; then echo "kb: no such file: $1"; return; fi
  n=$(awk 'END {print NR}' "$f")
  a=\${2:-1}; b=\${3:-$n}
  if [ -z "$2" ] && [ "$n" -gt 1500 ]; then b=1500; echo "kb: $1 has $n lines; showing 1-1500, read the rest by range"; fi
  [ "$b" -gt "$n" ] && b=$n
  printf '==> %s (lines %s-%s) <==\\n' "$1" "$a" "$b"
  awk -v a="$a" -v b="$b" 'NR>=a && NR<=b {printf "%6d\\t%s\\n", NR, $0}' "$f"
}
case "$1" in
  read)
    shift
    for spec in "$@"; do
      p=\${spec%%:*}; r=\${spec#"$p"}; r=\${r#:}
      if [ -n "$r" ]; then show "$p" "\${r%-*}" "\${r#*-}"; else show "$p"; fi
    done ;;
  fn)
    m=$(awk -F'\\t' -v q="$2" 'NR>1 && index($1, q) {print}' "$I/functions.tsv")
    c=$(printf '%s\\n' "$m" | grep -c .)
    if [ "$c" -eq 1 ]; then
      set -- $(printf '%s\\n' "$m" | awk -F'\\t' '{print $2, $3, $4}')
      show "$1" "$2" "$3"
    else
      printf '%s\\n' "$m" | head -40
      [ "$c" -gt 40 ] && echo "kb: $c matches; narrow the name"
      [ "$c" -eq 0 ] && echo "kb: no function matches $2"
    fi ;;
  find) grep -i -- "$2" "$I/files.tsv" "$I/functions.tsv" | head -80 ;;
  files) awk -F'\\t' -v d="$2" 'NR>1 && index($1, d) == 1' "$I/files.tsv" | head -200 ;;
  *) sed -n '2,6p' "$0" ;;
esac
`;
}

// --------------------------------------------------------------------------- //
// 3. The checklist
// --------------------------------------------------------------------------- //

/** One component of the checklist: a directory of architecture files, with the files to start from. */
export interface ChecklistItem {
  component: string;
  files: number;
  /** What its files are, by architecture role and security label. */
  labels: string;
  /** Its most important files: the most probable role files, then the most labelled. */
  examples: string[];
  /** Every architecture file of the component: reading any of them accounts for it. */
  members: string[];
}

/** Above this many files a directory with several subdirectories is split into them. */
const SPLIT_FILES = 25;
/** A subdirectory with this many files or fewer stays in its parent's component. */
const MERGE_FILES = 3;
/**
 * A directory with more subdirectories than this is a family of similar modules (providers,
 * plugins of one kind): one component, read from a representative member.
 */
const MAX_PARTS = 8;

/**
 * Components from the directory tree, sized by the architecture files in each directory. Every
 * top-level directory is one; below the top, a directory with more than SPLIT_FILES files spread
 * over several subdirectories is split into them, a subdirectory of MERGE_FILES or fewer stays with
 * its parent, a directory with more than MAX_PARTS sizeable subdirectories is a family of similar
 * modules and stays one, and a directory whose files all sit in one subdirectory is skipped
 * through. So a whole HTTP server becomes its handlers, its server and its library, while 23
 * near-identical provider adapters stay one component and a few UI folders stay one.
 */
export function components(paths: string[]): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const add = (dir: string, files: string[]): void => {
    if (files.length) out.set(dir || '.', [...(out.get(dir || '.') ?? []), ...files]);
  };
  const place = (dir: string, files: string[], top: boolean): void => {
    const depth = dir ? dir.split('/').length : 0;
    const direct: string[] = [];
    const children = new Map<string, string[]>();
    for (const f of files) {
      const parts = f.split('/');
      if (parts.length - 1 > depth) {
        const child = parts.slice(0, depth + 1).join('/');
        children.set(child, [...(children.get(child) ?? []), f]);
      } else direct.push(f);
    }
    if (!top && children.size === 1 && !direct.length) {
      place([...children.keys()][0] as string, files, false);
      return;
    }
    const parts = [...children.values()].filter(m => m.length > MERGE_FILES).length;
    if (!top && (files.length <= SPLIT_FILES || parts === 0 || parts > MAX_PARTS)) {
      add(dir, files);
      return;
    }
    const keep = [...direct];
    for (const [child, members] of children) {
      if (!top && members.length <= MERGE_FILES) keep.push(...members);
      else place(child, members, false);
    }
    add(dir, keep);
  };
  place('', paths, true);
  return out;
}

/**
 * The components the review must account for: those of the files with an architecture role
 * (startup, routes, access control, configuration, data and integrations, deployment,
 * architecture documentation) or a security label (entry points, access control, sensitive
 * operations). An architecture review need not read every file, since most repeat a pattern, but
 * it must not miss a component; so each is read from a representative file or dismissed with a
 * reason, which costs nothing. A component the core printed a file of is covered already. An
 * update's checklist is only the components that hold a changed file (input.scope).
 */
export function checklist(input: AgentInput): ChecklistItem[] {
  const sinks = sinkKinds(input);
  const access = (p: string): boolean => noul(input.fileLabels.get(p), 'access_control') >= 0.5;
  const role = (p: string): { role: string; p: number } | undefined => roleOf(input.roles.get(p));
  const score = (p: string): number =>
    (role(p)?.p ?? 0) * 10 +
    (input.entryFiles.get(p) ?? 0) * 2 +
    (access(p) ? 6 : 0) +
    (sinks.get(p)?.size ?? 0) * 2;
  // Components are made of code and deployment: a file with such a role, outside documentation,
  // examples, tests and CI. Security labels only rank the files within a component.
  const files = input.rows
    .filter(r => r.text !== undefined && !NON_PRODUCT.test(r.path))
    .filter(r => {
      const rr = role(r.path);
      return rr !== undefined && rr.role !== 'architecture_docs';
    })
    .map(r => r.path);
  const items: ChecklistItem[] = [];
  const scope = input.scope ? [...input.scope] : undefined;
  const touched = (component: string, members: string[]): boolean =>
    !scope ||
    scope.some(p => members.includes(p) || (component !== '.' && p.startsWith(`${component}/`)));
  for (const [component, members] of components(files)) {
    if (members.some(p => input.corePrinted.has(p)) || !touched(component, members)) continue;
    const counts = new Map<string, number>();
    const bump = (k: string): void => {
      counts.set(k, (counts.get(k) ?? 0) + 1);
    };
    for (const p of members) {
      const r = role(p);
      if (r) bump(r.role.replace('_', ' '));
      if (input.entryFiles.has(p)) bump('with entry points');
      if (access(p) && r?.role !== 'access_control') bump('access-control labelled');
      for (const k of sinks.get(p) ?? []) bump(`sink:${k}`);
    }
    const labels = [...counts]
      .sort((x, y) => y[1] - x[1])
      .map(([k, n]) => `${n} ${k}`)
      .join(', ');
    const examples = [...members].sort((x, y) => score(y) - score(x)).slice(0, 3);
    items.push({ component, files: members.length, labels, examples, members });
  }
  return items.sort((x, y) => y.files - x.files || (x.component < y.component ? -1 : 1));
}

// --------------------------------------------------------------------------- //
// 1 and 4. The sessions, and what they read
// --------------------------------------------------------------------------- //

const line = (i: ChecklistItem): string =>
  `- ${i.component} (${i.files} architecture files: ${i.labels}; start with ${i.examples.join(', ')})`;

function prompt(input: AgentInput, items: ChecklistItem[], paths: AgentPlan['paths']): string {
  const KB = `${paths.review}/kb`;
  return `${REVIEWER_TASK}

You are a Codex agent in ${paths.project}, the repository's checkout, read-only. The core evidence
below is already read for you. Everything else you load on demand with the reader, which prints
each file with its own line numbers:

  ${KB} read <path>[:<start>-<end>] ...    files or line ranges
  ${KB} fn <name>                          one function (or the list of matching functions)
  ${KB} find <text>                        search the index of files and functions
  ${KB} files <directory>                  a directory's files with their labels

The index lists every file (${paths.review}/files.tsv: path, kind, lines, labels) and function
(${paths.review}/functions.tsv: function, path, start, end, labels). Labels: role:<role> the file's
role in the architecture (startup, routes, access_control, configuration, data_integrations,
deployment, architecture_docs), entry:<n> entry points, input reads caller-controlled data,
access-control decides authentication or authorization, sink:<kind> performs a sensitive
operation. rg is there for searching.

Reading rules:
- Read with the reader, not cat or sed, and never pipe it through head or tail: ask for the
  range you want instead. A line you cite must be one the reader or rg printed, or one in the core.
- Cite every file by its full path from the repository root, exactly as the index lists it.

You do not need to read every file: most files of a component repeat its pattern. But account for
every component in the checklist below: read one to three representative files (start with the
ones listed), or name the component in resolvedQuestions as "<component>: <reason>" when it does
not change the architecture (documentation, tests, examples, UI widgets with no security role).
Use at most ${AGENT_COMMANDS} commands; batch several reads into one command. Do not delegate,
edit files or use the network.

When you are done, your final message is the JSON object alone, with no prose around it.

Checklist (${items.length} components):
${items.map(line).join('\n')}

${input.maintained}Core evidence:

${input.core}`;
}

/** The follow-up for a final message that holds no review: the whole review again, as valid JSON. */
function resendReview(problem: string): string {
  return `Your final message holds no review this run can read: ${problem}.\n\nAnswer with the whole review again: the JSON object alone, valid JSON, with every double quote inside a string escaped as \\".`;
}

function followUp(missing: ChecklistItem[], invalid: string[]): string {
  const lists = [
    missing.length
      ? `You did not account for these components. Read a representative file of each, or name it in resolvedQuestions as "<component>: <reason>":\n${missing.map(line).join('\n')}`
      : '',
    invalid.length
      ? `These citations are not lines the reader or rg printed. Read them and correct the citation (full path from the repository root), or remove it:\n${invalid.map(c => `- ${c}`).join('\n')}`
      : '',
  ].filter(Boolean);
  return `Your review is not complete yet.\n\n${lists.join('\n\n')}\n\nThen answer with the whole corrected review: the JSON object alone.`;
}

/**
 * Codex's settings for this agent: cynos without router or judge, read-only, no apps or plugins,
 * no shell snapshot (it would hold the key, and outlive a stopped session), no key in the
 * environment of the commands it runs (they would print it into its session), and the run's model
 * catalog at the path the agent sees it, when the run wrote one.
 *
 * With plugins on, Codex clones OpenAI's plugin marketplace (93 MB: Shopify, Gmail, Figma and
 * sixty more) into its home at startup. The agent's home is in the run dir, so every scan
 * downloaded it again and kept it: most of a run dir's size, and of a debug bundle's files. The
 * review reads the checkout with the shell alone and needs none of them.
 */
export function agentOverrides(modelCatalog?: string, baseUrl = BASE_URL): string[] {
  const headers = Object.entries(AGENT_HEADERS)
    .map(([k, v]) => `"${k}"="${v}"`)
    .join(',');
  return [
    `model_provider="${PROVIDER_ID}"`,
    `model_providers.${PROVIDER_ID}={name="cynos",base_url="${baseUrl}",env_key="${AGENT_KEY_VARIABLE}",wire_api="responses",http_headers={${headers}}}`,
    `model="${REVIEW_MODEL}"`,
    'model_reasoning_effort="xhigh"',
    'sandbox_mode="read-only"',
    'tool_output_token_limit=60000',
    'features.apps=false',
    'features.plugins=false',
    SHELL_SNAPSHOT_OFF,
    KEY_NOT_IN_COMMANDS,
    'analytics.enabled=false',
    // Without the catalog Codex uses fallback metadata for this model and caps its context.
    ...(modelCatalog ? [`model_catalog_json="${modelCatalog}"`] : []),
  ];
}

/**
 * `codex exec`'s arguments for the agent (a new session, or `resume` of the last), at the paths
 * the agent sees: the checkout, its directory (where the answer goes) and the model catalog.
 * The prompt goes on stdin; the runtime puts these after its own Codex command.
 */
export function agentExecArguments(
  paths: { project: string; review: string; modelCatalog?: string },
  baseUrl: string | undefined,
  resume: boolean
): string[] {
  return [
    'exec',
    ...(resume
      ? ['resume', '--last']
      : ['--sandbox', 'read-only', '-C', paths.project, '--color', 'never']),
    '--skip-git-repo-check',
    '--ignore-user-config',
    '--json',
    '-o',
    `${paths.review}/answer.txt`,
    ...agentOverrides(paths.modelCatalog, baseUrl).flatMap(o => ['-c', o]),
    '-',
  ];
}

function events(jsonl: string): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  for (const line of jsonl.split('\n')) {
    try {
      out.push(JSON.parse(line) as Record<string, unknown>);
    } catch {
      // not an event
    }
  }
  return out;
}

/** Turns, commands and tokens from the agent's JSONL event stream. */
export function agentEvents(
  jsonl: string
): Pick<AgentStats, 'turns' | 'commands' | 'inputTokens' | 'cachedInputTokens' | 'outputTokens'> {
  const out = { turns: 0, commands: 0, inputTokens: 0, cachedInputTokens: 0, outputTokens: 0 };
  for (const event of events(jsonl)) {
    const item = (event['item'] ?? {}) as Record<string, unknown>;
    if (event['type'] === 'item.completed' && item['type'] === 'command_execution')
      out.commands += 1;
    if (event['type'] === 'turn.completed') {
      out.turns += 1;
      const usage = (event['usage'] ?? {}) as Record<string, number>;
      out.inputTokens += usage['input_tokens'] ?? 0;
      out.cachedInputTokens += usage['cached_input_tokens'] ?? 0;
      out.outputTokens += usage['output_tokens'] ?? 0;
    }
  }
  return out;
}

const READ_HEADER = /^==> (.+?) \(lines \d+-\d+\) <==$/;
const NUMBERED = /^\s*(\d+)\t/;
/** An rg hit, `path:line:`, its path relative to the checkout or absolute under it. */
function rgLine(project: string): RegExp {
  const prefix = `${project}/`.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  return new RegExp(`^(?:${prefix}|\\./)?([^\\s:]+\\.[A-Za-z0-9]+):(\\d+):`);
}

/**
 * Lines the agent read: the core, the numbered lines the reader printed under each of its headers
 * (the line numbers themselves, so a read cut short by a pipe counts only what it showed), and
 * rg's hits.
 */
export function linesRead(
  jsonl: string,
  core: Map<string, [number, number][]>,
  project: string
): Map<string, [number, number][]> {
  const RG_LINE = rgLine(project);
  const out = new Map(core);
  const add = (path: string, a: number, b: number): void => {
    const ranges = out.get(path) ?? [];
    const last = ranges[ranges.length - 1];
    if (last && a === last[1] + 1) last[1] = b;
    else ranges.push([a, b]);
    out.set(path, ranges);
  };
  for (const event of events(jsonl)) {
    const item = (event['item'] ?? {}) as Record<string, unknown>;
    if (event['type'] !== 'item.completed' || item['type'] !== 'command_execution') continue;
    let file = '';
    for (const text of String(item['aggregated_output'] ?? '').split('\n')) {
      const header = READ_HEADER.exec(text);
      if (header) {
        file = header[1] as string;
        out.set(file, out.get(file) ?? []);
        continue;
      }
      const numbered = NUMBERED.exec(text);
      if (file && numbered) {
        add(file, Number(numbered[1]), Number(numbered[1]));
        continue;
      }
      file = numbered ? file : '';
      const hit = RG_LINE.exec(text);
      if (hit) add(hit[1] as string, Number(hit[2]), Number(hit[2]));
    }
  }
  return out;
}

/**
 * The first complete JSON object in a text: models wrap it in prose or fences, and sometimes
 * close it with a stray extra brace, so the object ends where its own braces balance.
 */
export function firstJsonObject(text: string): unknown {
  const start = text.indexOf('{');
  if (start < 0) return undefined;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === '"') inString = false;
    } else if (c === '"') inString = true;
    else if (c === '{') depth += 1;
    else if (c === '}' && --depth === 0) {
      try {
        return JSON.parse(text.slice(start, i + 1));
      } catch {
        return undefined;
      }
    }
  }
  return undefined;
}

/** The review in the agent's final message, or undefined when it holds none. */
export function answerJson(text: string): ArchitectureReview | undefined {
  const raw = firstJsonObject(text);
  if (!raw) return undefined;
  const review = normalise(raw);
  return review.threatModel.summary ? review : undefined;
}

/**
 * Why a final message holds no review, for the agent to correct: the parser's error when its
 * object does not parse (models leave a quote inside a string unescaped), or what it lacks.
 */
function answerProblem(text: string): string {
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start < 0 || end < start) return 'it holds no JSON object';
  try {
    JSON.parse(text.slice(start, end + 1));
  } catch (error) {
    return `its JSON object does not parse (${error instanceof Error ? error.message : String(error)})`;
  }
  return 'its JSON object has no threatModel.summary';
}

interface Session {
  status: number | null;
  events: string;
  answer: string;
  timedOut: boolean;
}

/**
 * One session: the prompt on stdin, the event stream and the final message back. A session past
 * AGENT_TIMEOUT_MS is stopped through the runtime (its container, or its process group), and so
 * is one whose run is stopped (plan.signal), as the scan itself is (scan-run.ts). A stopped run
 * starts no session: it has no answer, and the review's fallback calls stop too (cynos.ts).
 */
function session(plan: AgentPlan, text: string, resume: boolean): Promise<Session> {
  if (plan.signal?.aborted)
    return Promise.resolve({ status: null, events: '', answer: '', timedOut: false });
  const command = plan.runtime.reviewAgentCommand(plan, resume);
  return new Promise(resolve => {
    const child = plan.runtime.spawn(command, ['pipe', 'pipe', 'pipe']);
    let stdout = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      void plan.runtime.stop(command.name);
    }, AGENT_TIMEOUT_MS);
    const onAbort = (): void => void plan.runtime.stop(command.name);
    plan.signal?.addEventListener('abort', onAbort);
    child.stdout?.on('data', chunk => (stdout += chunk));
    child.stderr?.on('data', () => {});
    let finished = false;
    const done = (status: number | null): void => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      plan.signal?.removeEventListener('abort', onAbort);
      let answer = '';
      try {
        answer = readFileSync(join(plan.work, 'answer.txt'), 'utf8');
      } catch {
        answer = '';
      }
      resolve({ status, events: stdout, answer, timedOut });
    };
    child.on('close', done);
    child.on('error', () => done(1));
    child.stdin?.end(text);
  });
}

/** A component is accounted for when the agent read one of its files or dismissed it with a reason. */
function accounted(
  item: ChecklistItem,
  read: Map<string, [number, number][]>,
  review: ArchitectureReview
): boolean {
  const readOne = item.members.some(p => (read.get(p) ?? []).length > 0);
  // A dismissal names the component in resolvedQuestions; a passing mention elsewhere is not one.
  return readOne || review.resolvedQuestions.some(q => q.includes(item.component));
}

/**
 * Steps 1-4: the review from one agent, with a follow-up in the same session when its final
 * message holds no review, and one when the review skipped checklist files or cited lines it did
 * not read. `invalidOf` returns a review's citations that are not among the lines read.
 */
export async function agentReview(
  plan: AgentPlan,
  input: AgentInput,
  invalidOf: (review: ArchitectureReview, read: Map<string, [number, number][]>) => string[]
): Promise<{
  review: ArchitectureReview | undefined;
  read: Map<string, [number, number][]>;
  stats: AgentStats;
}> {
  mkdirSync(join(plan.work, 'home'), { recursive: true, mode: 0o700 });
  const index = indexFiles(input);
  writeFileSync(join(plan.work, 'files.tsv'), index.files);
  writeFileSync(join(plan.work, 'functions.tsv'), index.functions);
  writeFileSync(join(plan.work, 'kb'), kbScript(plan.paths.project, plan.paths.review));
  chmodSync(join(plan.work, 'kb'), 0o755);
  const items = checklist(input);
  writeFileSync(join(plan.work, 'checklist.json'), `${JSON.stringify(items, null, 1)}\n`);
  const started = Date.now();

  // 1-3. The session with the core, the index and the checklist.
  const first = await session(plan, prompt(input, items, plan.paths), false);
  let log = first.events;
  let review = first.timedOut ? undefined : answerJson(first.answer);
  let read = linesRead(log, input.corePrinted, plan.paths.project);
  let last = first;
  let sessions = 1;
  // 4. A session that finished without a readable review is asked for it once more: the review
  // is in its context, and starting over would lose every command it ran.
  if (!review && first.status === 0 && !first.timedOut) {
    last = await session(plan, resendReview(answerProblem(first.answer)), true);
    sessions += 1;
    log += last.events;
    read = linesRead(log, input.corePrinted, plan.paths.project);
    review = last.timedOut ? undefined : answerJson(last.answer);
  }
  // One follow-up in the same session when the review skipped checklist files or cites
  // lines the agent never read.
  if (review) {
    const missing = items.filter(i => !accounted(i, read, review as ArchitectureReview));
    const invalid = invalidOf(review, read);
    if (missing.length || invalid.length) {
      last = await session(plan, followUp(missing, invalid), true);
      sessions += 1;
      log += last.events;
      read = linesRead(log, input.corePrinted, plan.paths.project);
      review = (last.timedOut ? undefined : answerJson(last.answer)) ?? review;
    }
  }
  writeFileSync(join(plan.work, 'events.jsonl'), log);
  return {
    review,
    read,
    stats: {
      seconds: Math.round((Date.now() - started) / 1000),
      sessions,
      ...agentEvents(log),
      checklist: items.length,
      checklistCovered: review
        ? items.filter(i => accounted(i, read, review as ArchitectureReview)).length
        : 0,
      filesRead: read.size,
      exitCode: last.status,
      timedOut: last.timedOut,
    },
  };
}
