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
 * Two of its behaviours shape the code here:
 *   - it renames a project on indexing (it collapses `--`, for one), so later queries use the
 *     name it reports back;
 *   - one response holds about a tenth of a large repository's functions, so queries are paged
 *     until `has_more` is false; a call the tool answers with an error is retried with backoff,
 *     as one can fail with no message right after indexing.
 */
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { pause } from '../processes';
import type { RuntimeCommand, ScanPaths, ScanRuntime } from '../runtime';

const PROJECT = 'scan';
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

  /** Every row of a Cypher query, page by page. */
  async query(cypher: string): Promise<unknown[][]> {
    const rows: unknown[][] = [];
    let cursor: string | undefined;
    do {
      const result = await this.call('query_graph', {
        project: this.project,
        query: cypher,
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
    const rows = await this.query(
      "MATCH (f) WHERE f.label IN ['Function', 'Method'] RETURN f.qualified_name, f.name, f.file_path, f.start_line, f.end_line"
    );
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
    const rows = await this.query(
      `MATCH (a)-[:${kind}]->(b) RETURN a.qualified_name, b.qualified_name, b.file_path`
    );
    return rows
      .filter(([, , path]) => typeof path === 'string' && path && !path.startsWith('<'))
      .map(([a, b]) => [this.short(a), this.short(b)]);
  }
}
