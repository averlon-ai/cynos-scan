/**
 * Runs upstream's scan on its runtime: streams its output, reports progress, stops it when the
 * job is cancelled, and counts the tokens it used.
 *
 * The scan has no time limit of its own: the job's timeout-minutes is the caller's limit, as
 * with upstream's action, and on cancellation this process, and the post step after it, stop the
 * scan through its runtime (`docker kill` by name, or the native process group). A benchmark's
 * time limit arrives the same way, as an abort signal.
 *
 * In interactive mode upstream draws its own dashboard on the terminal and reads its keys, so
 * the terminal belongs to it: stderr (and, for `docker run -it`, everything) is not captured,
 * and a first Ctrl-C reaches upstream directly, which stops gracefully and keeps the partial
 * scan, as `codex-security` does. Only a second one makes this process stop it.
 *
 * codex-security reports usage only in its --json result, which a failed or killed scan never
 * writes, so the tokens are read from Codex's own records once the scan ends: each thread's
 * rollout under the state directory carries its running total. A shared state dir (the native
 * runtime's, upstream's default) holds every scan's sessions, so there only the sessions that ran
 * in this scan's scan dir count.
 */
import { createWriteStream, readdirSync, readFileSync, statSync } from 'node:fs';
import { constants as osConstants } from 'node:os';
import { join } from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import { safeLogLines } from './log-lines';
import type { ScanEvent } from './progress';
import type { RuntimeCommand, ScanRuntime } from './runtime';
import { SCANNING } from './sandbox';

/** With verbose off, upstream prints elapsed-time messages only; one every five minutes. */
const HEARTBEAT_INTERVAL_MS = 5 * 60_000;
/** How often a heartbeat event carries the elapsed time to a live display. */
const HEARTBEAT_EVENT_MS = 10_000;

export interface Usage {
  input_tokens: number;
  cached_input_tokens: number;
  output_tokens: number;
  reasoning_output_tokens: number;
}

/** How upstream's scan ended, on either runtime. */
export interface ScannerRun {
  /** upstream's exit code (0 completed, 1 policy failed, 2 failure, 130/143 interrupted). */
  exitCode: number | null;
  /** 'cancelled' when the job was cancelled and the scan stopped; empty otherwise. */
  stopStatus: '' | 'cancelled';
  stopReason: string;
  usage: Usage;
  elapsedSeconds: number;
}

/** The docker runtime's name for a ScannerRun, kept for the action. */
export type ContainerRun = ScannerRun;

function* rollouts(directory: string): Generator<string> {
  let entries;
  try {
    entries = readdirSync(directory, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) yield* rollouts(path);
    else if (/^rollout-.*\.jsonl$/.test(entry.name) && path.includes('/sessions/')) yield path;
  }
}

/** The working directory a rollout's session_meta records, or '' when it has none. */
function rolloutCwd(text: string): string {
  const end = text.indexOf('\n');
  try {
    const meta = JSON.parse(end < 0 ? text : text.slice(0, end)) as {
      type?: string;
      payload?: { cwd?: string };
    };
    return meta.type === 'session_meta' ? (meta.payload?.cwd ?? '') : '';
  } catch {
    return '';
  }
}

/**
 * Sums the final token usage of every Codex thread (root and workers) in this scan.
 *
 * codex-security reports usage only in its --json result, which a failed or killed scan never
 * writes. Each rollout's last token_count event carries that thread's running total. A state
 * directory that belongs to this one scan counts every rollout in it; a shared one (cwd given)
 * counts only the sessions upstream started in this scan's scan dir, its threads' working
 * directory.
 */
export function sessionUsage(state: string, cwd?: string): Usage {
  const totals: Usage = {
    input_tokens: 0,
    cached_input_tokens: 0,
    output_tokens: 0,
    reasoning_output_tokens: 0,
  };
  for (const rollout of rollouts(state)) {
    let last: Partial<Usage> = {};
    let text: string;
    try {
      text = readFileSync(rollout, 'utf8');
    } catch {
      continue;
    }
    if (cwd !== undefined && rolloutCwd(text) !== cwd) continue;
    for (const line of text.split('\n')) {
      if (!line.includes('"token_count"')) continue;
      try {
        const usage = JSON.parse(line)?.payload?.info?.total_token_usage;
        if (usage) last = usage;
      } catch {
        // A line cut off when the scan was killed carries no usable total.
      }
    }
    for (const key of Object.keys(totals) as (keyof Usage)[]) totals[key] += Number(last[key] ?? 0);
  }
  return totals;
}

export interface ScanRunPlan {
  /** The scan as the runtime built it (runtime.scanCommand). */
  command: RuntimeCommand;
  runtime: Pick<ScanRuntime, 'spawn' | 'stop'>;
  /** Receives stdout.json and stderr.log. */
  stage: string;
  /** Where Codex's sessions are, and the scan dir that scopes them in a shared state dir. */
  usage: { state: string; cwd?: string };
  verbose: boolean;
  /** upstream owns the terminal (its dashboard): a first Ctrl-C is its own to handle. */
  interactive?: boolean;
  log: (line: string) => void;
  progress?: (event: ScanEvent) => void;
  /** Stops the scan as a cancellation does, with the signal's reason (a benchmark's timeout). */
  signal?: AbortSignal;
}

/** Runs the scan to its end, or until the job is cancelled. */
export function runScan(plan: ScanRunPlan): Promise<ScannerRun> {
  const run: ScannerRun = {
    exitCode: null,
    stopStatus: '',
    stopReason: '',
    usage: {
      input_tokens: 0,
      cached_input_tokens: 0,
      output_tokens: 0,
      reasoning_output_tokens: 0,
    },
    elapsedSeconds: 0,
  };
  const started = Date.now();
  const name = plan.command.name;

  return new Promise((resolve, reject) => {
    const stdout = createWriteStream(join(plan.stage, 'stdout.json'));
    const stderr = createWriteStream(join(plan.stage, 'stderr.log'));
    const child = plan.runtime.spawn(plan.command);
    child.stdout?.pipe(stdout);
    // The diagnostics are model- and repository-derived text: logged only as safe lines, and
    // only whole lines, so a chunk boundary cannot split a character or a command prefix.
    const decoder = new StringDecoder('utf8');
    let pending = '';
    const lines = (text: string): void => {
      for (const line of text.split('\n'))
        if (line.includes(SCANNING)) plan.progress?.({ type: 'upstream', message: line.trim() });
      if (plan.verbose) for (const safe of safeLogLines(text)) plan.log(safe);
    };
    child.stderr?.on('data', (chunk: Buffer) => {
      stderr.write(chunk);
      pending += decoder.write(chunk);
      const boundary = pending.lastIndexOf('\n');
      if (boundary < 0) return;
      lines(pending.slice(0, boundary + 1));
      pending = pending.slice(boundary + 1);
    });
    const stop = (reason: string): void => {
      if (run.stopStatus) return;
      run.stopStatus = 'cancelled';
      run.stopReason = reason;
      plan.log(`codex-security: stopping ${name}: ${run.stopReason}`);
      void plan.runtime.stop(name);
    };
    // Interactive: the terminal's Ctrl-C reached upstream too, which stops on its own and keeps
    // the partial scan; only a second signal is this process's to act on.
    let signals = 0;
    const onSignal = (signal: NodeJS.Signals): void => {
      signals += 1;
      if (plan.interactive && signal === 'SIGINT' && signals === 1) {
        plan.log('codex-security: upstream is stopping the scan; press Ctrl-C again to kill it.');
        return;
      }
      stop(`job cancelled (${signal})`);
    };
    const onAbort = (): void => stop(String(plan.signal?.reason ?? 'aborted'));
    process.on('SIGINT', onSignal);
    process.on('SIGTERM', onSignal);
    if (plan.signal?.aborted) onAbort();
    plan.signal?.addEventListener('abort', onAbort);
    const heartbeat = plan.verbose
      ? undefined
      : setInterval(() => {
          const minutes = Math.floor((Date.now() - started) / 60_000);
          plan.log(`Security scan is still running; elapsed: ${minutes}m.`);
        }, HEARTBEAT_INTERVAL_MS);
    const beat = setInterval(
      () =>
        plan.progress?.({
          type: 'heartbeat',
          phase: 'scan',
          elapsedSeconds: Math.round((Date.now() - started) / 1000),
        }),
      HEARTBEAT_EVENT_MS
    );
    const settle = (): void => {
      clearInterval(heartbeat);
      clearInterval(beat);
      process.off('SIGINT', onSignal);
      process.off('SIGTERM', onSignal);
      plan.signal?.removeEventListener('abort', onAbort);
    };
    child.on('error', error => {
      settle();
      reject(error);
    });
    child.on('close', (code, signal) => {
      settle();
      lines(pending + decoder.end());
      stdout.end();
      stderr.end(() => {
        run.exitCode = exitCodeOf(code, signal);
        // The dashboard's own stop (Ctrl-C, or a second one that kills it): upstream exits as
        // interrupted.
        if (plan.interactive && !run.stopStatus && (run.exitCode === 130 || run.exitCode === 143)) {
          run.stopStatus = 'cancelled';
          run.stopReason = `upstream was interrupted (exit ${run.exitCode})`;
        }
        run.elapsedSeconds = Math.round((Date.now() - started) / 100) / 10;
        run.usage = sessionUsage(plan.usage.state, plan.usage.cwd);
        resolve(run);
      });
    });
  });
}

/**
 * upstream's exit code for how its process ended. A process killed by a signal has no exit code
 * of its own (Node reports null and the signal), and upstream's second Ctrl-C ends it that way;
 * a shell reports it as 128 plus the signal's number, the code upstream gives an interrupted
 * (130) or terminated (143) scan.
 */
export function exitCodeOf(code: number | null, signal: NodeJS.Signals | null): number | null {
  if (code !== null || signal === null) return code;
  const number = osConstants.signals[signal];
  return number === undefined ? null : 128 + number;
}

/** Whether a file exists and is a regular file. */
export function isFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}
