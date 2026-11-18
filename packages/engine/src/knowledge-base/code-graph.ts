/**
 * The code graph: every function and method with its line range, the calls between them, and the
 * call references (a function passed as a value, such as a callback wired into a plugin).
 *
 * codebase-memory-mcp (a pinned release, code-graph-binary.ts) parses the checkout with tree-sitter
 * and answers Cypher queries. The runtime decides where it runs: the docker runtime starts one
 * container for the whole build (the scanner image, no network, the checkout read-only, only the
 * graph's home writable) and the server runs in it; the native runtime runs the pinned binary on
 * the host, with its home in the stage. The calls and their answers are the same.
 *
 * The tool runs as one MCP server for the whole build, and every call is a JSON-RPC request over
 * its stdin and stdout. Starting a separate CLI process for each call repeatedly starts and
 * stops the daemon; keeping one server avoids that overhead.
 *
 * Three of its behaviours shape the code here:
 *   - it renames a project on indexing (it collapses `--`, for one), so later queries use the
 *     name it reports back;
 *   - one response holds about a tenth of a large repository's functions, so queries are paged
 *     until `has_more` is false; a call the tool answers with an error is retried with backoff,
 *     as one can fail with no message right after indexing;
 *   - it refuses a query whose whole result reaches 100k rows, however it is paged, so a large
 *     result is read in pieces, a set of files at a time (query()).
 */
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { pause } from '../processes';
import type { RuntimeCommand, ScanPaths, ScanRuntime } from '../runtime';

const PROJECT = 'scan';
/**
 * The tool's ceiling on one query's whole result: it refuses a result of this many rows
 * (`CYPHER_RESULT_CEILING` in its cypher.c), whatever page size or cursor the call asks for.
 */
const RESULT_CAP = 100_000;
/**
 * The most files one piece of a larger result names. The tool tests each node it scans against the
 * list one name at a time, so a short list keeps a piece's read cheap.
 */
const PIECE_FILES = 2_000;
/**
 * The most bytes of file names one piece names. The tool reads a request of at most 10 MiB
 * (`MCP_MAX_MESSAGE_SIZE` in its mcp.c) and closes the connection on a longer one.
 */
const PIECE_BYTES = 256 * 1024;
const ATTEMPTS = 8;
const CALL_TIMEOUT_MS = 600_000;
/** How long a closed server gets to exit on its own before it is killed. */
const CLOSE_GRACE_MS = 5_000;
/** The MCP protocol version the client offers; the tool answers with the one it speaks. */
const MCP_PROTOCOL = '2024-11-05';

export interface FunctionNode {
  /** Qualified name without the project prefix, e.g. app.views.login. */
  qn: string;
  name: string;
  path: string;
  start: number;
  end: number;
}

/** What the runtime needs to serve the graph: its name, the checkout and its home on this machine. */
export interface CodeGraphPlan {
  /** The name the runtime knows the graph by (its container's), so a stopped run can remove it. */
  name: string;
  /** The caller's checkout. */
  project: string;
  /** The graph's home on this machine. */
  home: string;
}

export interface GraphPlan extends CodeGraphPlan {
  runtime: ScanRuntime;
  /** The checkout as the graph sees it: the path it indexes. */
  paths: Pick<ScanPaths, 'project'>;
  /** The run's signal: no call starts after it fires, and the server is killed. */
  signal?: AbortSignal;
}

export interface ProcessResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

/**
 * Runs a command with input on stdin, in the environment and directory it is given. A signal
 * kills it when it fires, as CALL_TIMEOUT_MS does.
 */
export type ProcessRunner = (
  command: string,
  args: string[],
  input: string,
  options?: { env?: NodeJS.ProcessEnv; cwd?: string; signal?: AbortSignal }
) => Promise<ProcessResult>;

export const runProcess: ProcessRunner = (command, args, input, options) =>
  new Promise(resolve => {
    const child = spawn(command, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      ...(options?.env ? { env: options.env } : {}),
      ...(options?.cwd ? { cwd: options.cwd } : {}),
    });
    let stdout = '';
    let stderr = '';
    const kill = (): void => void child.kill('SIGKILL');
    const timer = setTimeout(kill, CALL_TIMEOUT_MS);
    options?.signal?.addEventListener('abort', kill);
    const done = (result: ProcessResult): void => {
      clearTimeout(timer);
      options?.signal?.removeEventListener('abort', kill);
      resolve(result);
    };
    child.stdout.on('data', chunk => (stdout += chunk));
    child.stderr.on('data', chunk => (stderr += chunk));
    child.on('close', status => done({ status, stdout, stderr }));
    child.on('error', error => done({ status: 1, stdout, stderr: String(error) }));
    child.stdin.end(input);
  });

/** Runs one of the runtime's commands through the runner, stopped by the signal when given one. */
function runCommandWith(
  run: ProcessRunner,
  command: RuntimeCommand,
  input: string,
  signal?: AbortSignal
): Promise<ProcessResult> {
  const [program, ...args] = command.argv;
  return run(program ?? '', args, input, {
    env: command.env,
    ...(command.cwd ? { cwd: command.cwd } : {}),
    ...(signal ? { signal } : {}),
  });
}

// --------------------------------------------------------------------------- //
// The MCP server: one process, newline-delimited JSON-RPC on its stdin and stdout
// --------------------------------------------------------------------------- //

/** A running MCP server as the graph talks to it. */
export interface McpChannel {
  /** Writes one JSON-RPC message, a request or a notification. */
  send(message: Record<string, unknown>): void;
  /** Called with every message the server writes, in order. */
  onMessage(listener: (message: Record<string, unknown>) => void): void;
  /** Called once when the server's process ends or cannot start, with what it said on stderr. */
  onExit(listener: (detail: string) => void): void;
  /** Closes its stdin and waits for it to exit, killing it after CLOSE_GRACE_MS. */
  close(): Promise<void>;
  /** Ends it at once. */
  kill(): void;
}

/** Starts the server a runtime command describes. */
export type McpConnector = (command: RuntimeCommand, runtime: ScanRuntime) => McpChannel;

/**
 * The server as a child of this process, through the runtime's own spawn so a cancelled run's
 * process registry (native) or container (docker) stops it too.
 */
export const spawnMcpServer: McpConnector = (command, runtime) => {
  const child = runtime.spawn(command, ['pipe', 'pipe', 'pipe']);
  let stderr = '';
  let exited = false;
  const exitListeners: ((detail: string) => void)[] = [];
  const exit = (detail: string): void => {
    if (exited) return;
    exited = true;
    for (const listener of exitListeners) listener(detail);
  };
  child.stderr?.on('data', chunk => (stderr = `${stderr}${String(chunk)}`.slice(-2000)));
  child.on('error', error => exit(String(error)));
  // A write to a server that has exited fails on its stdin (EPIPE): the server is gone, which the
  // graph learns as an exit, rather than an unhandled stream error that would end this process.
  child.stdin?.on('error', error => exit(`stopped reading its input: ${String(error)}`));
  child.on('close', status => exit(`exited with ${status}: ${stderr.trim().slice(-300)}`));
  const lines = child.stdout ? createInterface({ input: child.stdout }) : undefined;
  return {
    send: message => void child.stdin?.write(`${JSON.stringify(message)}\n`),
    onMessage: listener =>
      void lines?.on('line', line => {
        try {
          listener(JSON.parse(line) as Record<string, unknown>);
        } catch {
          // A line that is not JSON-RPC (a log line) answers no request.
        }
      }),
    onExit: listener => {
      if (exited) listener(`exited: ${stderr.trim().slice(-300)}`);
      else exitListeners.push(listener);
    },
    close: () =>
      new Promise(resolve => {
        if (exited) return resolve();
        const timer = setTimeout(() => child.kill('SIGKILL'), CLOSE_GRACE_MS);
        exitListeners.push(() => {
          clearTimeout(timer);
          resolve();
        });
        child.stdin?.end();
      }),
    kill: () => void child.kill('SIGKILL'),
  };
};

/** How a graph reaches the tool: a runner for the container's start and stop, and its server. */
export interface GraphTransport {
  run: ProcessRunner;
  connect: McpConnector;
}

export const graphTransport: GraphTransport = { run: runProcess, connect: spawnMcpServer };

/** A request waiting for its response. */
interface Pending {
  resolve: (result: Record<string, unknown>) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

export class CodeGraph {
  private project = PROJECT;
  private channel: McpChannel | undefined;
  private nextId = 1;
  private readonly pending = new Map<number, Pending>();
  /** Why the server can no longer answer: it exited, or the run was stopped. */
  private broken: string | undefined;

  constructor(
    private readonly plan: GraphPlan,
    private readonly transport: GraphTransport = graphTransport,
    /** A backoff's wait: ms, or less when the run's signal fires first (processes.ts pause). */
    private readonly sleep: (ms: number, signal?: AbortSignal) => Promise<void> = pause
  ) {}

  /**
   * Starts what serves the calls: the docker runtime's container first, then the server, with
   * MCP's handshake. A stopped run kills the server, which fails the request in flight.
   */
  async start(): Promise<void> {
    const container = this.plan.runtime.codeGraphStart(this.plan);
    if (container) {
      this.stopIfAborted();
      const result = await runCommandWith(this.transport.run, container, '', this.plan.signal);
      if (result.status !== 0)
        throw new Error(`the code graph did not start: ${result.stderr.trim().slice(-300)}`);
    }
    this.stopIfAborted();
    const channel = this.transport.connect(
      this.plan.runtime.codeGraphServer(this.plan),
      this.plan.runtime
    );
    this.channel = channel;
    channel.onMessage(message => this.answer(message));
    channel.onExit(detail => this.fail(`the code graph's server ${detail}`));
    this.plan.signal?.addEventListener('abort', this.abort);
    await this.request('initialize', {
      protocolVersion: MCP_PROTOCOL,
      capabilities: {},
      clientInfo: { name: 'cynos-scan', version: '1' },
    });
    channel.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
  }

  /**
   * Ends the server and removes what start() started; it runs whatever stopped the build, so it
   * takes no signal.
   */
  async stop(): Promise<void> {
    this.plan.signal?.removeEventListener('abort', this.abort);
    await this.channel?.close();
    this.channel = undefined;
    const container = this.plan.runtime.codeGraphStop(this.plan);
    if (container) await runCommandWith(this.transport.run, container, '');
  }

  /** The run was stopped: the server is killed and every request in flight fails with the reason. */
  private readonly abort = (): void => {
    this.fail(`the code graph was stopped: ${String(this.plan.signal?.reason)}`);
    this.channel?.kill();
  };

  /** Fails every request in flight, and every later one, with why. */
  private fail(why: string): void {
    this.broken ??= why;
    for (const [id, pending] of this.pending) {
      clearTimeout(pending.timer);
      this.pending.delete(id);
      pending.reject(new Error(this.broken));
    }
  }

  /** Settles the request a response answers; anything else the server writes is ignored. */
  private answer(message: Record<string, unknown>): void {
    const pending = typeof message['id'] === 'number' ? this.pending.get(message['id']) : undefined;
    if (!pending) return;
    clearTimeout(pending.timer);
    this.pending.delete(message['id'] as number);
    const error = message['error'] as { message?: string } | undefined;
    if (error) pending.reject(new Error(error.message ?? JSON.stringify(error)));
    else pending.resolve((message['result'] ?? {}) as Record<string, unknown>);
  }

  /** One JSON-RPC request, failed after CALL_TIMEOUT_MS or when the server ends. */
  private request(
    method: string,
    params: Record<string, unknown>
  ): Promise<Record<string, unknown>> {
    const channel = this.channel;
    if (this.broken) return Promise.reject(new Error(this.broken));
    if (!channel) return Promise.reject(new Error('the code graph was not started'));
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`codebase-memory-mcp ${method} timed out after ${CALL_TIMEOUT_MS} ms`));
      }, CALL_TIMEOUT_MS);
      this.pending.set(id, { resolve, reject, timer });
      channel.send({ jsonrpc: '2.0', id, method, params });
    });
  }

  /**
   * One tool call; the result is the MCP envelope's first text block. A call the tool answers
   * with an error is retried with backoff; a server that ended or a stopped run fails it at once.
   */
  private async call(
    tool: string,
    args: Record<string, unknown>
  ): Promise<Record<string, unknown>> {
    let problem = '';
    for (let attempt = 0; attempt < ATTEMPTS; attempt++) {
      this.stopIfAborted();
      const result = await this.request('tools/call', { name: tool, arguments: args });
      const text = (result['content'] as { text?: string }[] | undefined)?.[0]?.text ?? '';
      if (!result['isError']) {
        try {
          return JSON.parse(text) as Record<string, unknown>;
        } catch {
          problem = `not JSON: ${text.slice(0, 300)}`;
        }
      } else problem = text.trim().slice(-300);
      this.stopIfAborted();
      if (attempt < ATTEMPTS - 1)
        await this.sleep(Math.min(3000 * 2 ** attempt, 30000), this.plan.signal);
    }
    throw new Error(`codebase-memory-mcp ${tool} failed: ${problem}`);
  }

  /** Throws once the run's signal has fired: a stopped run starts no graph command. */
  private stopIfAborted(): void {
    if (this.plan.signal?.aborted)
      throw new Error(`the code graph was stopped: ${String(this.plan.signal.reason)}`);
  }

  /** Indexes the checkout; later queries use the project name the tool reports back. */
  async index(): Promise<Record<string, unknown>> {
    const info = await this.call('index_repository', {
      repo_path: this.plan.paths.project,
      name: PROJECT,
      mode: 'fast',
    });
    if (typeof info['project'] === 'string' && info['project']) this.project = info['project'];
    return info;
  }

  /**
   * Every row of a query, however many the graph holds.
   *
   * The tool evaluates a query in full before it pages the answer, and refuses one whose whole
   * result reaches RESULT_CAP rows ("result exceeded 100k rows"): its cursor only pages a result
   * that already fits. SKIP and LIMIT do not get past the cap either: the engine keeps the first
   * RESULT_CAP rows before it skips, so a page past them comes back short, with no error.
   * A large repository can exceed that limit even when each page is small.
   *
   * So a result that reaches the cap is read a set of files at a time. Every row belongs to one
   * file (`query.file`: the function's, or the caller's for an edge), and the engine filters on it
   * exactly and before it follows the pattern's edges:
   *
   *   count   the query's rows, `count(*)`; a result under RESULT_CAP is read whole
   *   files   the graph's files, one File node each, packed into sets of PIECE_FILES names and
   *           PIECE_BYTES bytes at most
   *   pieces  each set's rows counted, `WHERE <file> IN [...]`; a set that reaches RESULT_CAP is
   *           halved until each fits
   *   check   the pieces' rows add up to the query's count, so no row lies outside the files
   *   read    each piece, paged by the tool's cursor, returns the rows counted for it
   *
   * Every count is one group: the tool groups a `count(*)` per file by a linear search, rows times
   * files under its 30-second deadline, and cuts a grouped value to 511 bytes, so a long path
   * would come back as a name no filter matches. A File node's path comes back in full.
   *
   * A file holding RESULT_CAP rows on its own, a graph of RESULT_CAP files, or a count the reads do
   * not match fails the build, as the refused query did: briefs built on part of the call graph
   * would have holes.
   */
  private async query(query: GraphQuery): Promise<unknown[][]> {
    const total = await this.count(query);
    if (total < RESULT_CAP) return this.read(query, { rows: total });
    const pieces: GraphPiece[] = [];
    for (const files of fileSets(await this.files()))
      pieces.push(...(await this.piecesUnderCap(query, files)));
    // A row on a file the graph has no File node for would be in no piece.
    const counted = pieces.reduce((sum, piece) => sum + piece.rows, 0);
    if (counted !== total)
      throw new Error(
        `codebase-memory-mcp counted ${total} rows of MATCH ${query.match}, and ${counted} of them on the graph's files: the code graph cannot be read completely`
      );
    const rows: unknown[][] = [];
    for (const piece of pieces) rows.push(...(await this.read(query, piece)));
    return rows;
  }

  /**
   * How many rows a query holds, on some files when given them. A query with no rows answers its
   * count with no row at all, rather than a zero.
   */
  private async count(query: GraphQuery, files?: string[]): Promise<number> {
    const [row] = await this.pages(pieceCypher({ ...query, returns: 'count(*)' }, files));
    return Number(row?.[0] ?? 0);
  }

  /** The path of every file the graph holds, in full. */
  private async files(): Promise<string[]> {
    const files: GraphQuery = { match: '(f:File)', returns: 'f.file_path', file: 'f.file_path' };
    const count = await this.count(files);
    if (count >= RESULT_CAP)
      throw new Error(
        `codebase-memory-mcp cannot list the code graph's ${count} files: the tool refuses a result of ${RESULT_CAP} rows`
      );
    return (await this.pages(pieceCypher(files))).map(([path]) => String(path ?? ''));
  }

  /**
   * A set of files as pieces under RESULT_CAP: the set itself when its rows fit, else its halves,
   * each split again as needed. Files with no rows make no piece, and are not read.
   */
  private async piecesUnderCap(query: GraphQuery, files: string[]): Promise<GraphPiece[]> {
    const rows = await this.count(query, files);
    if (rows < RESULT_CAP) return rows ? [{ files, rows }] : [];
    if (files.length === 1)
      throw new Error(
        `codebase-memory-mcp cannot read ${files[0]}: it holds ${rows} rows of the code graph, and the tool refuses a result of ${RESULT_CAP}`
      );
    const half = Math.ceil(files.length / 2);
    return [
      ...(await this.piecesUnderCap(query, files.slice(0, half))),
      ...(await this.piecesUnderCap(query, files.slice(half))),
    ];
  }

  /** A piece's rows; a number other than its count means the filter missed rows or caught others'. */
  private async read(query: GraphQuery, piece: GraphPiece): Promise<unknown[][]> {
    const rows = await this.pages(pieceCypher(query, piece.files));
    if (rows.length !== piece.rows)
      throw new Error(
        `codebase-memory-mcp query_graph returned ${rows.length} rows of MATCH ${query.match} for ${piece.files ? `${piece.files.length} files` : 'every file'}, where it counted ${piece.rows}: the code graph cannot be read completely`
      );
    return rows;
  }

  /** Every row of one Cypher query whose whole result fits under RESULT_CAP, page by page. */
  private async pages(query: string): Promise<unknown[][]> {
    const rows: unknown[][] = [];
    let cursor: string | undefined;
    do {
      const result = await this.call('query_graph', {
        project: this.project,
        query,
        format: 'json',
        max_rows: 50000,
        max_output_tokens: 200000,
        ...(cursor ? { cursor } : {}),
      });
      rows.push(...((result['rows'] as unknown[][] | undefined) ?? []));
      cursor = result['has_more'] ? (result['next_cursor'] as string | undefined) : undefined;
    } while (cursor);
    return rows;
  }

  private short(qn: unknown): string {
    const name = typeof qn === 'string' ? qn : '';
    const prefix = `${this.project}.`;
    return name.startsWith(prefix) ? name.slice(prefix.length) : name;
  }

  /** Every function and method defined in the repository, with its line range. */
  async functions(): Promise<FunctionNode[]> {
    const rows = await this.query({
      match: '(f)',
      where: "f.label IN ['Function', 'Method']",
      returns: 'f.qualified_name, f.name, f.file_path, f.start_line, f.end_line',
      file: 'f.file_path',
    });
    const out: FunctionNode[] = [];
    for (const [qn, name, path, start, end] of rows) {
      // Builtins and externals have no file.
      if (typeof path !== 'string' || !path || path.startsWith('<')) continue;
      const first = Number(start) || 0;
      out.push({
        qn: this.short(qn),
        name: String(name ?? ''),
        path,
        start: first,
        end: Number(end) || first,
      });
    }
    return out;
  }

  /** (caller, callee) pairs, the callee limited to repository code. */
  async calls(): Promise<[string, string][]> {
    return this.edges('CALLS');
  }

  /**
   * (referrer, function) pairs where a function is passed as a value rather than called: a callback
   * handed to a plugin, a handler registered by name. Who calls such a function is no CALLS edge,
   * so the place that wires it in is the only link to it.
   */
  async callReferences(): Promise<[string, string][]> {
    return this.edges('CALL_REFERENCE');
  }

  /** Edges of one kind, the target limited to repository code. */
  private async edges(kind: 'CALLS' | 'CALL_REFERENCE'): Promise<[string, string][]> {
    const rows = await this.query({
      match: `(a)-[:${kind}]->(b)`,
      returns: 'a.qualified_name, b.qualified_name, b.file_path',
      file: 'a.file_path',
    });
    return rows
      .filter(([, , path]) => typeof path === 'string' && path && !path.startsWith('<'))
      .map(([a, b]) => [this.short(a), this.short(b)]);
  }
}

/** A query the graph reads a set of files at a time (CodeGraph.query). */
interface GraphQuery {
  /** The pattern, e.g. `(a)-[:CALLS]->(b)`. */
  match: string;
  /** What every row meets, if anything, e.g. `f.label IN ['Function', 'Method']`. */
  where?: string;
  /** The columns of a row. */
  returns: string;
  /**
   * The file a row belongs to, one per row, on the pattern's first node so the engine filters on
   * it before it follows edges: `f.file_path`, or `a.file_path` for an edge's caller.
   */
  file: string;
}

/** Some of a query's files and the rows they hold; no files is every file. */
interface GraphPiece {
  files?: string[];
  rows: number;
}

/**
 * The files packed, in order, into sets of at most PIECE_FILES names and PIECE_BYTES bytes of
 * them as the query names them.
 */
function fileSets(files: string[]): string[][] {
  const sets: string[][] = [];
  let bytes = 0;
  for (const file of files) {
    const size = Buffer.byteLength(cypherString(file)) + 2;
    const last = sets.at(-1);
    if (last && last.length < PIECE_FILES && bytes + size <= PIECE_BYTES) {
      last.push(file);
      bytes += size;
    } else {
      sets.push([file]);
      bytes = size;
    }
  }
  return sets;
}

/** The query limited to some files, when given them: its own condition and the files, both. */
function pieceCypher(query: GraphQuery, files?: string[]): string {
  const among = files && `${query.file} IN [${files.map(cypherString).join(', ')}]`;
  return cypher(query, [query.where, among].filter(Boolean).join(' AND ') || undefined);
}

/** `MATCH <pattern> [WHERE <where>] RETURN <columns>`. */
function cypher(query: Pick<GraphQuery, 'match' | 'returns'>, where: string | undefined): string {
  return `MATCH ${query.match}${where ? ` WHERE ${where}` : ''} RETURN ${query.returns}`;
}

/** A Cypher string literal: the tool's lexer reads a backslash as escaping the next character. */
function cypherString(text: string): string {
  return `'${text.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
}
