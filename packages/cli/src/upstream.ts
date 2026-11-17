/**
 * Running upstream's own CLI (`codex-security`) for history, logs and exports.
 *
 * History is upstream's: its workbench.sqlite3 in its state dir, which `cs` reads too. So
 * `cynos scans list` is upstream's `scans list`, run as the engine runs upstream (the
 * pinned package from node_modules, through upstreamCommand) with this process's environment:
 * the same state dir, keys already removed, and CODEX_SECURITY_LOG_LEVEL when -v or
 * CYNOS_LOG_LEVEL asked for it.
 *
 *   passThrough   stdio inherited: upstream's output and exit code are the command's own
 *   capture       stdout read back, for the CLI's own use of upstream's JSON
 */
import { spawn, spawnSync } from 'node:child_process';
import { engine } from './engine';

export interface Captured {
  status: number | null;
  stdout: string;
  stderr: string;
}

/** Runs upstream with args and returns what it printed; injected so tests need no upstream. */
export type UpstreamCapture = (args: string[], cwd?: string) => Promise<Captured>;

export const captureUpstream: UpstreamCapture = async (args, cwd) => {
  const [command, ...rest] = engine().upstreamCommand(args);
  const run = spawnSync(command!, rest, {
    encoding: 'utf8',
    cwd: cwd ?? process.cwd(),
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 256 * 1024 * 1024,
  });
  return {
    status: run.error ? null : run.status,
    stdout: run.stdout ?? '',
    stderr: run.stderr ?? run.error?.message ?? '',
  };
};

/** upstream's JSON output for args (with --json), or undefined when it failed. */
export async function upstreamJson(
  args: string[],
  capture: UpstreamCapture = captureUpstream,
  cwd?: string
): Promise<{ value: unknown; error?: undefined } | { value?: undefined; error: string }> {
  const run = await capture([...args, '--json'], cwd);
  if (run.status !== 0)
    return { error: run.stderr.trim().split('\n').slice(-3).join(' ') || `exit ${run.status}` };
  try {
    return { value: JSON.parse(run.stdout) };
  } catch {
    return { error: 'upstream printed no JSON' };
  }
}

/**
 * Runs upstream with the terminal: its output and exit code become the command's. Ctrl-C reaches
 * upstream through the terminal (same process group); this process only waits for it.
 */
export function passThrough(args: string[]): Promise<number> {
  const [command, ...rest] = engine().upstreamCommand(args);
  return new Promise((resolve, reject) => {
    const child = spawn(command!, rest, { stdio: 'inherit' });
    const ignore = (): void => {};
    process.on('SIGINT', ignore);
    child.on('error', reject);
    child.on('exit', (code, signal) => {
      process.off('SIGINT', ignore);
      if (signal === 'SIGINT') resolve(130);
      else if (signal === 'SIGTERM') resolve(143);
      else resolve(code ?? 2);
    });
  });
}
