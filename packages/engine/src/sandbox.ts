/**
 * Proves the scan can start before any model call is made.
 *
 * codex-security reports a failed preparation as "The API key ... cannot access the configured
 * model" whenever the underlying error mentions a 403 or "permission denied", and does not print
 * it: a sandbox Bubblewrap refused and a key cynos does not recognise read the same. So two
 * checks run first, each printing its real error: upstream's own sandbox check (Codex's sandbox
 * runs /usr/bin/true: runtime.sandboxCheck), then the scan itself, with the scan's settings and a
 * placeholder key, until it starts scanning. The second is what catches a sandbox that fails
 * only with the scan's configuration (it caught the /home/node/.codex permission error) and a
 * diff target that cannot resolve.
 *
 * The preflight scan must not reach a model: the docker runtime runs it with no network, the
 * native runtime against a port nothing listens on (PREFLIGHT_BASE_URL). Either way a scan that
 * gets through preparation stops at its first model request.
 */
import type { RuntimeCommand, ScanRuntime } from './runtime';

/** codex-security's progress line once preparation is over and scanning has begun. */
export const SCANNING = 'Running scan';
/** The preflight's key: it never reaches a model, which the preflight cannot reach. */
export const PREFLIGHT_KEY = 'preflight-without-network';
const PREFLIGHT_TIMEOUT_MS = 180_000;

export interface PreflightResult {
  reached: boolean;
  lines: string[];
}

/**
 * Runs the preflight until codex-security starts scanning, then stops it.
 *
 * Cut off from the model, a scan that gets through preparation stops at its first model request;
 * one that does not fails before that with its real error. The run's signal stops it as its own
 * deadline does.
 */
export function scanReachesScanning(
  command: RuntimeCommand,
  runtime: Pick<ScanRuntime, 'spawn' | 'stop'>,
  signal?: AbortSignal
): Promise<PreflightResult> {
  return new Promise((resolve, reject) => {
    const child = runtime.spawn(command, ['ignore', 'ignore', 'pipe']);
    const lines: string[] = [];
    let pending = '';
    let reached = false;
    const stop = (): void => void runtime.stop(command.name);
    const deadline = setTimeout(stop, PREFLIGHT_TIMEOUT_MS);
    signal?.addEventListener('abort', stop);
    child.stderr?.on('data', (chunk: Buffer) => {
      if (reached) return;
      pending += chunk.toString('utf8');
      const parts = pending.split('\n');
      pending = parts.pop() ?? '';
      for (const line of parts) {
        lines.push(line);
        if (line.includes(SCANNING)) {
          reached = true;
          void runtime.stop(command.name);
          break;
        }
      }
    });
    child.on('error', reject);
    child.on('close', () => {
      clearTimeout(deadline);
      signal?.removeEventListener('abort', stop);
      if (!reached && pending) lines.push(pending);
      resolve({ reached, lines });
    });
  });
}

/** The last meaningful stderr lines, without debug and Node warning noise. */
export function stderrTail(stderr: string, count = 3): string {
  const kept = stderr
    .trim()
    .split('\n')
    .map(line => line.trim())
    .filter(
      line =>
        line &&
        !line.includes('debug:') &&
        !line.includes('ExperimentalWarning') &&
        !line.includes('--trace-warnings')
    );
  return kept.slice(-count).join(' | ');
}
