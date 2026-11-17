/**
 * What a scan is doing, as structured events beside its log lines.
 *
 * A host shows a scan's progress its own way: the action logs plain lines, the CLI draws a live
 * screen of phases with their current step until upstream's own dashboard takes the terminal. So
 * the engine reports each phase's start and end, the steps inside it and the running usage as
 * events (ScanIO.progress), and the log line for the same moment as before (ScanIO.log). `say`
 * emits both at once, so the two cannot drift apart.
 *
 *   stage → preflight → knowledge → brief → scan → report
 */
import type { JsonObject } from './json';

/** The scan's phases, in the order scanCheckout runs them. */
export const SCAN_PHASES = ['stage', 'preflight', 'knowledge', 'brief', 'scan', 'report'] as const;
export type ScanPhase = (typeof SCAN_PHASES)[number];

/** A step inside a phase: the preflight's three checks and the knowledge base's build steps. */
export type ScanStep =
  | 'sandbox'
  | 'preparation'
  | 'key'
  | 'files'
  | 'graph'
  | 'labels'
  | 'review'
  | 'packets'
  | 'briefs'
  | 'threat-model';

export interface TokenUsage {
  input_tokens: number;
  cached_input_tokens: number;
  output_tokens: number;
  reasoning_output_tokens: number;
}

export type ScanEvent =
  | {
      type: 'phase';
      phase: ScanPhase;
      status: 'start' | 'end' | 'failed' | 'skipped' | 'cancelled';
      seconds?: number;
      detail?: string;
    }
  | { type: 'step'; phase: ScanPhase; step: ScanStep; message: string; data?: JsonObject }
  /** upstream's own progress line, `Running scan: <phase>`, in headless mode. */
  | { type: 'upstream'; message: string }
  | { type: 'usage'; source: 'scan' | 'review'; tokens: TokenUsage }
  /** The knowledge base's Jev spend, at cynos's catalog rate (jev.ts). */
  | { type: 'cost'; source: 'knowledge-base'; usd: number }
  | { type: 'heartbeat'; phase: ScanPhase; elapsedSeconds: number }
  /**
   * upstream is about to take the terminal for its own dashboard (interactive mode): a host that
   * draws a live screen must release the terminal before this returns.
   */
  | { type: 'handoff'; phase: 'scan' }
  | { type: 'outcome'; scanStatus: string; scanId: string | null; scanDir: string | null };

/** The part of ScanIO these helpers need. */
export interface ProgressIO {
  log(message: string): void;
  progress?(event: ScanEvent): void;
}

/** Emits a step's event and its log line together. */
export function say(
  io: ProgressIO,
  phase: ScanPhase,
  step: ScanStep,
  message: string,
  data?: JsonObject
): void {
  io.progress?.({ type: 'step', phase, step, message, ...(data ? { data } : {}) });
  io.log(message);
}

/**
 * Runs one phase of the scan between its start and end events. A step that throws ends the
 * phase as failed (cancelled when the scan was stopped) and the error goes on to the caller.
 */
export async function phase<T>(
  io: ProgressIO & { signal?: AbortSignal },
  name: ScanPhase,
  step: () => T | Promise<T>
): Promise<T> {
  const started = Date.now();
  const seconds = (): number => Math.round((Date.now() - started) / 100) / 10;
  io.progress?.({ type: 'phase', phase: name, status: 'start' });
  try {
    const result = await step();
    io.progress?.({ type: 'phase', phase: name, status: 'end', seconds: seconds() });
    return result;
  } catch (error) {
    io.progress?.({
      type: 'phase',
      phase: name,
      status: io.signal?.aborted ? 'cancelled' : 'failed',
      seconds: seconds(),
      detail: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
}

/** Marks a phase that did not run for this scan (a diff's knowledge base, a dry run's report). */
export function skipped(io: ProgressIO, name: ScanPhase, detail: string): void {
  io.progress?.({ type: 'phase', phase: name, status: 'skipped', detail });
}
