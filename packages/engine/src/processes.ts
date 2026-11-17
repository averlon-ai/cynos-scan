/**
 * The processes a scan starts on this machine, and how they are stopped.
 *
 * The docker runtime's work runs in containers, which the Docker daemon owns: stopping one is
 * `docker kill <name>`, from this process or from the action's post step. The native runtime's
 * work runs as this process's children instead, and each of them starts more: upstream starts
 * Codex, Codex starts its sandboxed shells and helpers. Killing the child alone would leave its
 * descendants running. So each child starts in a process group of its own (detached), and
 * stopping it means stopping that group:
 *
 *   spawn     spawnTracked: a detached group, recorded in a ProcessRegistry under a name
 *   stop      SIGTERM to the group, then SIGKILL once STOP_GRACE_MS has passed and it is still there
 *
 * A child that must read the terminal (upstream's interactive dashboard) stays in this process's
 * group instead: a background group that reads the terminal is stopped by SIGTTIN. Such a child is
 * stopped on its own pid, never the group, which this process belongs to as well.
 *
 * The registry can also be kept in a file, so another process (the action's post step) can stop
 * what a cancelled run left behind, as `docker kill` does for containers.
 */
import {
  spawn,
  spawnSync,
  type ChildProcess,
  type SpawnOptions,
  type StdioOptions,
} from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';

/** How long a stopped process group has to exit after SIGTERM before it gets SIGKILL. */
export const STOP_GRACE_MS = 10_000;

export interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
}

/** Runs a short command to completion and returns its output. */
export type Runner = (command: string, args: string[], env?: NodeJS.ProcessEnv) => Run;

/** Runs a short command to completion and returns its output. */
export const runCommand: Runner = (command, args, env) => {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    env: env ?? process.env,
    maxBuffer: 64 * 1024 * 1024,
  });
  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? (result.error ? String(result.error) : ''),
  };
};

/** One process this run started: its pid, and whether it leads a process group of its own. */
export interface TrackedProcess {
  name: string;
  pid: number;
  /** Started detached: the pid is also its process group's id, and the group is what stops. */
  group: boolean;
}

/**
 * The processes a run has started and not yet seen exit, by name. With a file, every change is
 * written to it, so another process can load the registry and stop what is left.
 */
export class ProcessRegistry {
  private readonly entries = new Map<string, TrackedProcess>();

  constructor(private readonly file?: string) {}

  /** The registry another process wrote to file; empty when there is none. */
  static load(file: string): ProcessRegistry {
    const registry = new ProcessRegistry(file);
    try {
      for (const entry of JSON.parse(readFileSync(file, 'utf8')) as TrackedProcess[])
        registry.entries.set(entry.name, entry);
    } catch {
      // No file yet, or one cut short: nothing to stop.
    }
    return registry;
  }

  add(entry: TrackedProcess): void {
    this.entries.set(entry.name, entry);
    this.persist();
  }

  remove(name: string, pid: number): void {
    // A later process may have taken the name; only this one's exit removes it.
    if (this.entries.get(name)?.pid !== pid) return;
    this.entries.delete(name);
    this.persist();
  }

  get(name: string): TrackedProcess | undefined {
    return this.entries.get(name);
  }

  list(): TrackedProcess[] {
    return [...this.entries.values()];
  }

  private persist(): void {
    if (this.file)
      writeFileSync(this.file, `${JSON.stringify(this.list(), null, 1)}\n`, { mode: 0o600 });
  }
}

export interface TrackedSpawn {
  /** The name the registry and stop() know the process by. */
  name: string;
  registry?: ProcessRegistry;
  env: NodeJS.ProcessEnv;
  stdio: StdioOptions;
  cwd?: string;
  /** Start in a process group of its own (default); false for a child that reads the terminal. */
  detached?: boolean;
}

/**
 * Spawns argv in a process group of its own and records it in the registry until it exits.
 * The group lets stopProcess reach every process it starts (upstream's Codex and its shells).
 */
export function spawnTracked(argv: string[], options: TrackedSpawn): ChildProcess {
  const [program, ...args] = argv;
  if (!program) throw new Error('spawnTracked needs a command');
  const detached = options.detached ?? true;
  const spawnOptions: SpawnOptions = {
    env: options.env,
    stdio: options.stdio,
    detached,
    ...(options.cwd ? { cwd: options.cwd } : {}),
  };
  const child = spawn(program, args, spawnOptions);
  // A spawn that fails (no such program) has no pid and reports through 'error'.
  const pid = child.pid;
  if (pid !== undefined) {
    options.registry?.add({ name: options.name, pid, group: detached });
    child.once('exit', () => options.registry?.remove(options.name, pid));
  }
  return child;
}

/** Whether a process (or, for a group, its leader) still exists. */
function alive(target: number): boolean {
  try {
    process.kill(target, 0);
    return true;
  } catch (error) {
    // EPERM: it exists but belongs to someone else, so it is not this run's to stop.
    return (error as NodeJS.ErrnoException).code === 'EPERM';
  }
}

function signal(target: number, name: NodeJS.Signals): void {
  try {
    process.kill(target, name);
  } catch {
    // Gone already.
  }
}

/**
 * Stops one tracked process: SIGTERM to its group (or to it alone, when it shares this process's
 * group), then SIGKILL if it is still there after graceMs. Resolves once it is gone or killed.
 */
export async function stopProcess(
  entry: TrackedProcess,
  graceMs: number = STOP_GRACE_MS
): Promise<void> {
  const target = entry.group ? -entry.pid : entry.pid;
  if (!alive(target)) return;
  signal(target, 'SIGTERM');
  const deadline = Date.now() + graceMs;
  while (Date.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, Math.min(200, graceMs)));
    if (!alive(target)) return;
  }
  signal(target, 'SIGKILL');
}

/** Stops every process in the registry at once, each as stopProcess does. */
export async function stopProcesses(
  registry: ProcessRegistry,
  graceMs: number = STOP_GRACE_MS
): Promise<void> {
  await Promise.all(registry.list().map(entry => stopProcess(entry, graceMs)));
}

/**
 * A wait of ms (a retry's backoff) that ends early when the run's signal fires, so a stop takes
 * effect at once rather than when the backoff runs out. The timer is cleared then too: a pending
 * one would keep the process alive for the rest of the backoff after the run has stopped. The
 * caller checks the signal after it.
 */
export function pause(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) return Promise.resolve();
  return new Promise(resolve => {
    const done = (): void => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal?.addEventListener('abort', done);
  });
}

/** stdio for a child: stdin ignored, stdout and stderr piped (the headless default). */
export const PIPED: StdioOptions = ['ignore', 'pipe', 'pipe'];
