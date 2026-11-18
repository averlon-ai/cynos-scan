/**
 * Fakes for the knowledge-base tests: cynos's calls, the code graph's server, git checkouts. Kept
 * beside the tests so the full build's and the diff build's suites drive the same fakes.
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ArchitectureReview } from '../knowledge-base/architecture';
import type { McpConnector, ProcessRunner } from '../knowledge-base/code-graph';
import type { Decision, DecisionRequest } from '../knowledge-base/cynos';
import type { FileRow } from '../knowledge-base/inventory';
import type { Answer } from '../knowledge-base/jev';

export const yes = (p: number) => ({ type: 'noul' as const, noul: p });
export const pick = (choice: string, probabilities: Record<string, number> = { [choice]: 1 }) => ({
  type: 'choice' as const,
  choice,
  probabilities,
});

export function row(path: string, text: string, kind = 'code', reason = ''): FileRow {
  return { path, lines: text.split('\n').length, kind, reason, text };
}

/** A fetch that answers every cynos call from `answer`, recording each request body. */
export function fakeFetch(
  answer: (url: string, body: Record<string, unknown>) => unknown,
  bodies: Record<string, unknown>[] = []
) {
  return async (url: string, init: RequestInit): Promise<Response> => {
    const body = JSON.parse(String(init.body)) as Record<string, unknown>;
    bodies.push(body);
    return new Response(JSON.stringify(answer(url, body)), { status: 200 });
  };
}

/**
 * cynos's Decision for a decisions request: each question answered as Jev would (`answer`, given
 * the question's name and the state asked about), in OpenAI's shape; none is a refusal.
 */
export function decisionFor(
  body: Record<string, unknown>,
  answer: (name: string, state: Record<string, unknown>) => Answer | undefined
): Decision {
  const request = body as unknown as DecisionRequest;
  const state =
    typeof request.input === 'string'
      ? { content: request.input }
      : (request.input[0]?.content[0]?.data as Record<string, unknown>);
  return {
    model: 'typesafe/jev-1.14',
    answers: request.questions.map(({ name }) => {
      const a = answer(name, state);
      if (!a) return { type: 'refusal', name };
      if (a.type === 'noul') return { type: 'predicate', name, probability: a.noul };
      const probabilities = Object.entries(a.probabilities ?? { [a.choice]: 1 });
      return {
        type: 'choice',
        name,
        choice: a.choice,
        probabilities: probabilities.map(([value, probability]) => ({ value, probability })),
      };
    }),
    usage: { input_tokens: 1000, output_tokens: 0 },
  };
}

/**
 * A fake codebase-memory-mcp server: it answers MCP's handshake, and each tool call with what
 * `answer` returns for it (an Error is a tool error). Every server it starts is logged by argv.
 */
export function fakeServer(
  answer: (tool: string, args: Record<string, unknown>) => unknown,
  started: string[][] = []
): McpConnector {
  return command => {
    started.push(command.argv);
    let deliver: (message: Record<string, unknown>) => void = () => {};
    let exited: (detail: string) => void = () => {};
    let open = true;
    const result = (message: Record<string, unknown>): unknown => {
      if (message['method'] === 'initialize') return { protocolVersion: '2024-11-05' };
      const { name, arguments: args } = message['params'] as {
        name: string;
        arguments: Record<string, unknown>;
      };
      const out = answer(name, args);
      return out instanceof Error
        ? { isError: true, content: [{ type: 'text', text: out.message }] }
        : { content: [{ type: 'text', text: JSON.stringify(out) }] };
    };
    return {
      send: message => {
        if (!open || message['id'] === undefined) return;
        const answered = result(message);
        queueMicrotask(() => deliver({ jsonrpc: '2.0', id: message['id'], result: answered }));
      },
      onMessage: listener => (deliver = listener),
      onExit: listener => (exited = listener),
      close: async () => {
        open = false;
      },
      kill: () => {
        open = false;
        exited('killed');
      },
    };
  };
}

/** A function as the graph stores it: its qualified name carries the project, e.g. `scan.app.a`. */
export interface FakeFunction {
  qn: string;
  name: string;
  path: string;
  start: number;
  end: number;
}

/** An edge as the graph stores it: the caller's file is the one the graph reads it by. */
export interface FakeEdge {
  caller: string;
  callerPath: string;
  callee: string;
  calleePath: string;
}

/** A code graph for fakeGraphTool to answer from. */
export interface FakeGraph {
  /** What index_repository answers; its `project` is the name later queries must use. */
  index?: Record<string, unknown>;
  functions?: FakeFunction[];
  calls?: FakeEdge[];
  callReferences?: FakeEdge[];
  /** The File nodes' paths; by default every file a function or an edge names. */
  files?: string[];
  /** Rows per response page (the real tool's are bounded by output tokens); all by default. */
  pageRows?: number;
}

/**
 * codebase-memory-mcp's query_graph over a fake graph, for fakeServer, with the real tool's limits:
 * a query whose whole result reaches 100k rows is refused however it is paged, and the rows that
 * fit come back in pages joined by a cursor. It reads the queries CodeGraph writes (functions by
 * label, edges by kind, File nodes, `<file> IN [...]`, a `count(*)`) and fails on any other.
 */
export function fakeGraphTool(
  graph: FakeGraph
): (tool: string, args: Record<string, unknown>) => unknown {
  const project = String(graph.index?.['project'] ?? 'scan');
  const fileNodes =
    graph.files ??
    [
      ...new Set([
        ...(graph.functions ?? []).map(f => f.path),
        ...[...(graph.calls ?? []), ...(graph.callReferences ?? [])].flatMap(e => [
          e.callerPath,
          e.calleePath,
        ]),
      ]),
    ].filter(path => !path.startsWith('<'));
  return (tool, args) => {
    if (tool === 'index_repository') return { project, ...graph.index };
    if (tool !== 'query_graph' || args['project'] !== project)
      return new Error(`unexpected call: ${tool} ${JSON.stringify(args)}`);
    const query = String(args['query']);
    // The rows the pattern matches, each with the file it belongs to.
    const kind = /^MATCH \(a\)-\[:(CALLS|CALL_REFERENCE)\]->\(b\)/.exec(query)?.[1];
    const functions = /^MATCH \(f\) WHERE f\.label IN \['Function', 'Method'\]/.test(query);
    const files = /^MATCH \(f:File\)/.test(query);
    if (!kind && !functions && !files) return new Error(`unexpected query: ${query}`);
    const matched = kind
      ? (kind === 'CALLS' ? graph.calls : graph.callReferences)?.map(e => ({
          file: e.callerPath,
          row: [e.caller, e.callee, e.calleePath],
        }))
      : functions
        ? graph.functions?.map(f => ({ file: f.path, row: [f.qn, f.name, f.path, f.start, f.end] }))
        : fileNodes.map(path => ({ file: path, row: [path] }));
    // The files the query is limited to, its string literals unescaped as the tool's lexer does.
    const list = /\.file_path IN \[(.*)\] RETURN/.exec(query)?.[1];
    const among =
      list === undefined
        ? undefined
        : new Set(
            [...list.matchAll(/'((?:\\.|[^'\\])*)'/g)].map(m => m[1]!.replace(/\\(.)/g, '$1'))
          );
    const selected = (matched ?? []).filter(({ file }) => !among || among.has(file));
    // A count is one row, as a string the way the real tool's json answers it, or none for no rows.
    const result = / RETURN count\(\*\)$/.test(query)
      ? selected.length
        ? [[String(selected.length)]]
        : []
      : selected.map(({ row }) => row);
    if (result.length >= 100_000)
      return new Error('result exceeded 100k rows — use narrower filters or add LIMIT');
    const offset = Number(args['cursor'] ?? 0);
    const end = offset + Math.min(Number(args['max_rows']), graph.pageRows ?? Infinity);
    return {
      rows: result.slice(offset, end),
      has_more: end < result.length,
      ...(end < result.length ? { next_cursor: String(end) } : {}),
    };
  };
}

/** A runner for the graph container's start and stop that only records them. */
export const recordingRunner =
  (commands: string[][]): ProcessRunner =>
  async (_, args) => {
    commands.push(args);
    return { status: 0, stdout: '', stderr: '' };
  };

/**
 * git in a checkout, as a fixed author and without the developer's own git configuration (commit
 * signing, hooks, a default branch), which would otherwise decide whether a commit is made.
 * Throws when git fails, so a fixture never goes on without its commit.
 */
export function git(project: string, ...args: string[]): string {
  const result = spawnSync(
    'git',
    [
      '-C',
      project,
      '-c',
      'user.name=t',
      '-c',
      'user.email=t@t',
      '-c',
      'commit.gpgsign=false',
      ...args,
    ],
    {
      encoding: 'utf8',
      env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' },
    }
  );
  if (result.status !== 0)
    throw new Error(`git ${args.join(' ')} failed: ${(result.stderr || result.stdout).trim()}`);
  return result.stdout.trim();
}

/** Writes files into a checkout; null deletes one. */
export function writeFiles(project: string, files: Record<string, string | null>): void {
  for (const [path, text] of Object.entries(files)) {
    if (text === null) {
      git(project, 'rm', '-q', path);
      continue;
    }
    mkdirSync(join(project, path, '..'), { recursive: true });
    writeFileSync(join(project, path), text);
  }
}

/** A git checkout holding files, with one commit. */
export function gitCheckout(files: Record<string, string>): string {
  const project = mkdtempSync(join(tmpdir(), 'kb-diff-project-'));
  git(project, 'init', '-q');
  writeFiles(project, files);
  git(project, 'add', '-A');
  git(project, 'commit', '-qm', 'files');
  return project;
}

/** Commits changes to a checkout and returns the new HEAD. */
export function gitCommit(project: string, files: Record<string, string | null>): string {
  writeFiles(project, files);
  git(project, 'add', '-A');
  git(project, 'commit', '-qm', 'change');
  return gitHead(project);
}

export function gitHead(project: string): string {
  return git(project, 'rev-parse', 'HEAD');
}

/** A stored review with these trust boundaries and assumptions. */
export const reviewOf = (boundaries: string[], assumptions: string[] = []): ArchitectureReview =>
  ({
    threatModel: {
      origin: 'generated',
      summary: 'A gateway.',
      scope: { includePaths: ['.'], summary: 'Whole repository.' },
      assets: [],
      trustBoundaries: boundaries,
      attackerCapabilities: ['A tenant holding a virtual key, through the inference surface'],
      securityObjectives: [],
      assumptions,
    },
    effectiveResources: [],
    resolvedQuestions: [],
  }) as ArchitectureReview;
