/**
 * The CLI's ScanIO: what the engine reports a scan through on this machine.
 *
 * A scan reports through log lines and progress events, and on a laptop they have three readers
 * with different needs: the person at the terminal (the renderer: a live view or plain lines),
 * a script reading stdout (--format jsonl: one event per line), and whoever debugs the run later
 * (the run dir's cli.log and events.jsonl, which `scans logs` and `debug bundle` read). Every line is
 * redacted with the run's keys before any of them sees it.
 *
 * It also owns how the scan is stopped. A run stops for one of three reasons: Ctrl-C, SIGTERM, or
 * --timeout running out. Each aborts the scan through the AbortSignal, so the engine stops upstream
 * and keeps the partial scan. On the docker runtime it also kills every container the run may
 * have started. The engine names those containers before any starts (ScanIO.containers), and only
 * the scan's own container watches the signal; the knowledge base's would keep running, because
 * the Docker daemon owns them, not this process. A signal after the stop exits at once (130 for
 * Ctrl-C, 143 for SIGTERM).
 */
import { appendFileSync } from 'node:fs';
import { join } from 'node:path';
import type { KnowledgeBaseStore, ScanEvent, ScanIO } from './engine';
import { EXIT } from './exit-codes';
import type { ProgressRenderer } from './progress/renderers';
import { PhaseTimings } from './progress/timings';
import { RUN_FILES } from './settings';
import type { Terminal } from './terminal';

/** Why a run was stopped: a signal, or --timeout running out. */
export type StopCause = 'SIGINT' | 'SIGTERM' | 'timeout';

export interface LocalIO {
  io: ScanIO;
  timings: PhaseTimings;
  /** What stopped the scan, if anything did. */
  stoppedBy(): StopCause | undefined;
  /** The stop's reason as the engine was given it ("timed out after 2h"), if the scan was stopped. */
  stopReason(): string | undefined;
  /** Removes the signal handlers and gives the terminal back. */
  close(): void;
}

export interface LocalIOOptions {
  terminal: Terminal;
  renderer: ProgressRenderer;
  timings: PhaseTimings;
  /** The run dir: cli.log and events.jsonl go there. */
  runDir: string;
  /** Every key value of this run, replaced with *** wherever a line goes. */
  keys: (string | undefined)[];
  knowledgeBaseStore?: KnowledgeBaseStore;
  /** --format jsonl: each event as a line on stdout. */
  onEvent?: (event: ScanEvent) => void;
  /** --timeout in seconds: the run is stopped once it has run this long. */
  timeoutSeconds?: number;
  /** docker runtime: kills a container by name (the engine's killContainer). */
  killContainer?: (name: string) => void;
  /** process.exit, injected for tests. */
  exit?: (code: number) => void;
  signals?: Pick<NodeJS.Process, 'on' | 'off'>;
}

/** text with every key replaced. */
export function redact(text: string, keys: (string | undefined)[]): string {
  return keys.reduce<string>((out, key) => (key ? out.split(key).join('***') : out), text);
}

export function createLocalIO(options: LocalIOOptions): LocalIO {
  const { terminal, renderer, timings, runDir, keys } = options;
  const controller = new AbortController();
  const record = (file: string, line: string): void => {
    try {
      appendFileSync(join(runDir, file), `${line}\n`, { mode: 0o600 });
    } catch {
      // A run dir removed under us (gc) loses the line; the terminal still shows it.
    }
  };
  const line = (level: string, message: string): string => {
    const clean = redact(message, keys);
    record(RUN_FILES.log, `${new Date().toISOString()} ${level} ${clean}`);
    return clean;
  };

  // The stop: the scan aborted, and on docker every container of the run killed.
  let stoppedBy: StopCause | undefined;
  let containers: string[] = [];
  const stop = (cause: StopCause, reason: string): void => {
    stoppedBy = cause;
    controller.abort(reason);
    for (const name of containers) options.killContainer?.(name);
    renderer.close();
  };

  // Signals: the first stops the scan, keeping what it has; one after any stop exits at once.
  const exit = options.exit ?? ((code: number) => process.exit(code));
  const signals = options.signals ?? process;
  const onSignal = (signal: 'SIGINT' | 'SIGTERM'): void => {
    if (stoppedBy) {
      renderer.close();
      exit(signal === 'SIGTERM' ? EXIT.terminated : EXIT.interrupted);
      return;
    }
    stop(signal, signal === 'SIGINT' ? 'interrupted (Ctrl-C)' : 'terminated (SIGTERM)');
    terminal.warn(
      'Stopping the scan and keeping what it has so far; press Ctrl-C again to exit now.'
    );
  };
  const onInterrupt = (): void => onSignal('SIGINT');
  const onTerminate = (): void => onSignal('SIGTERM');
  signals.on('SIGINT', onInterrupt);
  signals.on('SIGTERM', onTerminate);

  // --timeout: the same stop, once the run has taken that long.
  const timeout = options.timeoutSeconds;
  const timer = timeout
    ? setTimeout(() => {
        if (stoppedBy) return;
        stop('timeout', `timed out after ${formatDuration(timeout)}`);
        terminal.warn(
          `The scan ran past --timeout ${formatDuration(timeout)}: stopping it and keeping what it has so far.`
        );
      }, timeout * 1000)
    : undefined;

  const io: ScanIO = {
    log: message => renderer.log(line('info', message)),
    warn: message => renderer.warn(line('warn', message)),
    error: message => renderer.error(line('error', message)),
    progress: event => {
      const clean = JSON.parse(redact(JSON.stringify(event), keys)) as ScanEvent;
      timings.record(clean);
      record(RUN_FILES.events, JSON.stringify({ at: new Date().toISOString(), ...clean }));
      renderer.event(clean);
      options.onEvent?.(clean);
    },
    containers: names => {
      containers = names;
    },
    signal: controller.signal,
    ...(options.knowledgeBaseStore ? { knowledgeBaseStore: options.knowledgeBaseStore } : {}),
  };
  return {
    io,
    timings,
    stoppedBy: () => stoppedBy,
    stopReason: () => (controller.signal.aborted ? String(controller.signal.reason) : undefined),
    close: () => {
      clearTimeout(timer);
      signals.off('SIGINT', onInterrupt);
      signals.off('SIGTERM', onTerminate);
      renderer.close();
    },
  };
}

/** Seconds as the largest whole unit: 7200 → 2h, 5400 → 90m, 90 → 90s. */
export function formatDuration(seconds: number): string {
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}
