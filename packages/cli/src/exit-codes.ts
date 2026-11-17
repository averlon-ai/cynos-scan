/**
 * Exit codes: upstream's, unchanged, so a script or CI job reads cynos as it reads `cs`.
 *
 *   0         completed, or passes the severity policy
 *   1         severity policy violation (--fail-on-severity)
 *   2         every failure: invalid input, auth, a spent budget, a model cynos cannot serve,
 *             cynos unreachable or failing, host check, knowledge base, runtime error, target
 *             change, a scan upstream stopped short, required-output failure, a scan stopped by
 *             --timeout
 *   130 / 143 interrupted (Ctrl-C) / terminated (SIGTERM)
 *
 * Our own failures are many, but they all map onto 2; what went wrong is the error's kind, on
 * stderr and as error.kind in --format json, never a new exit code.
 */
import { EngineUnavailable, type KeyRefusal } from './engine';
import type { StopCause } from './local-io';

export const EXIT = {
  ok: 0,
  policy: 1,
  failure: 2,
  interrupted: 130,
  terminated: 143,
} as const;

/** What went wrong, for --format json's error.kind and the error line's hint. */
export type ErrorKind =
  | 'usage'
  | 'auth'
  | 'budget'
  | 'model'
  | 'network'
  | 'gateway'
  | 'host-check'
  | 'knowledge-base'
  | 'engine'
  | 'upstream'
  | 'interrupted'
  | 'terminated'
  | 'timed-out'
  | 'internal';

/** A failure the CLI explains itself: a kind, a message, and what to do about it. */
export class CliError extends Error {
  constructor(
    readonly kind: ErrorKind,
    message: string,
    readonly hint?: string
  ) {
    super(message);
  }
}

/**
 * The engine reports failures as plain errors; their messages name the step that failed
 * (pipeline.ts), which is all there is to classify them by. Anything unrecognised is internal.
 */
const ENGINE_FAILURES: [RegExp, ErrorKind][] = [
  [/The scan was stopped: timed out/i, 'timed-out'],
  [/The scan was stopped/i, 'interrupted'],
  [/reasoning effort must be one of/i, 'usage'],
  [/refused the key|needs the cynos key/i, 'auth'],
  // The key check's other refusals, in the wording of keyCheckFailure (the engine's key-check.ts).
  [/the key's budget is spent/i, 'budget'],
  [/cannot serve the model/i, 'model'],
  [/cynos is unreachable/i, 'network'],
  [/could not answer the key check/i, 'gateway'],
  [/knowledge base could not be built/i, 'knowledge-base'],
  [/sandbox could not start|stopped before scanning began|host check/i, 'host-check'],
];

/** A run that was stopped, failed: its kind is the stop's, and `stopped` its reason. */
export class StoppedError extends CliError {
  constructor(
    kind: ErrorKind,
    message: string,
    readonly stopped: string
  ) {
    super(kind, message);
  }
}

/** What each stop is, as error.kind: its exit code follows (exitCodeFor). */
const STOP_KINDS: Record<StopCause, ErrorKind> = {
  SIGINT: 'interrupted',
  SIGTERM: 'terminated',
  timeout: 'timed-out',
};

/**
 * A stopped run fails wherever the stop caught it, and rarely with the stop's own words: a killed
 * code-graph container fails the knowledge base, a killed preflight fails the host check. The stop
 * is what happened, so the error becomes the stop's (130 for Ctrl-C, 143 for SIGTERM, 2 for
 * --timeout), with the step's own message kept after it. Any other error passes through.
 */
export function stopError(
  error: unknown,
  stoppedBy: StopCause | undefined,
  reason: string | undefined
): unknown {
  if (!stoppedBy) return error;
  const stopped = reason ?? stoppedBy;
  const message = error instanceof Error ? error.message : String(error);
  return new StoppedError(
    STOP_KINDS[stoppedBy],
    message.startsWith('The scan was stopped')
      ? message
      : `The scan was stopped: ${stopped}. ${message}`,
    stopped
  );
}

/** The kind of any thrown value. */
export function errorKind(error: unknown): ErrorKind {
  if (error instanceof CliError) return error.kind;
  if (error instanceof EngineUnavailable) return 'engine';
  if (isCommanderError(error)) return 'usage';
  const message = error instanceof Error ? error.message : String(error);
  return ENGINE_FAILURES.find(([pattern]) => pattern.test(message))?.[1] ?? 'internal';
}

/** The kind of a refused key check, for a failure the CLI reports itself (login). */
export function refusalKind(refusal: KeyRefusal | undefined): ErrorKind {
  const kinds: Record<KeyRefusal, ErrorKind> = {
    key: 'auth',
    budget: 'budget',
    model: 'model',
    unreachable: 'network',
    gateway: 'gateway',
  };
  return kinds[refusal ?? 'key'];
}

/** The exit code for a thrown value: 130 or 143 for a stop, 2 for every other failure. */
export function exitCodeFor(error: unknown): number {
  if (isCommanderError(error) && error.exitCode === 0) return EXIT.ok;
  const kind = errorKind(error);
  if (kind === 'interrupted') return EXIT.interrupted;
  if (kind === 'terminated') return EXIT.terminated;
  return EXIT.failure;
}

/**
 * A finished scan's exit code, from the engine's outcome (results.ts, upstream's vocabulary):
 *
 *   completed   upstream's own 0 or 1 passes through (the severity policy)
 *   skipped     a dry run that validated: 0
 *   failed      2, unless upstream itself was interrupted or terminated (130 / 143)
 *
 * A scan the user stopped is 130 (Ctrl-C) or 143 (SIGTERM) unless it completed anyway. One that
 * --timeout stopped is a failure, 2, whatever upstream exited with when it was stopped.
 */
export function scanExitCode(
  result: { exitCode: number | null; outcome: { scanStatus: string } },
  stoppedBy?: StopCause
): number {
  const status = result.outcome.scanStatus;
  if (stoppedBy && status !== 'completed')
    return { SIGINT: EXIT.interrupted, SIGTERM: EXIT.terminated, timeout: EXIT.failure }[stoppedBy];
  if (status === 'completed') return result.exitCode === EXIT.policy ? EXIT.policy : EXIT.ok;
  if (status === 'skipped') return result.exitCode === EXIT.ok ? EXIT.ok : EXIT.failure;
  if (result.exitCode === EXIT.interrupted || result.exitCode === EXIT.terminated)
    return result.exitCode;
  return EXIT.failure;
}

interface CommanderErrorLike {
  code: string;
  exitCode: number;
}

function isCommanderError(error: unknown): error is CommanderErrorLike {
  return (
    error instanceof Error &&
    typeof (error as Partial<CommanderErrorLike>).code === 'string' &&
    (error as Partial<CommanderErrorLike>).code!.startsWith('commander.')
  );
}
