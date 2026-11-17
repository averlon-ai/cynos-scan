/**
 * How long each phase of a scan took, and what it used, from the scan's progress events.
 *
 * The live view and the headless lines both end with the same summary, and the debug bundle
 * keeps it, so the phases are recorded once here rather than by each renderer:
 *
 *   stage 0.4s · preflight 12s · knowledge 3m02s · brief 0.1s · scan 14m10s · report 2.1s
 */
import { SCAN_PHASES, type ScanEvent, type ScanPhase, type TokenUsage } from '../engine';
import { duration, type Colors } from '../terminal';

export type PhaseStatus = 'pending' | 'running' | 'done' | 'failed' | 'skipped' | 'cancelled';

export interface PhaseRecord {
  status: PhaseStatus;
  startedAt?: number;
  seconds?: number;
  /** The phase's latest step message, or why it failed or was skipped. */
  detail?: string;
}

const STATUS_OF: Record<string, PhaseStatus> = {
  start: 'running',
  end: 'done',
  failed: 'failed',
  skipped: 'skipped',
  cancelled: 'cancelled',
};

export class PhaseTimings {
  readonly phases = new Map<ScanPhase, PhaseRecord>(
    SCAN_PHASES.map(phase => [phase, { status: 'pending' }])
  );
  readonly usage: Partial<Record<'scan' | 'review', TokenUsage>> = {};
  /** The knowledge base's Jev spend, at cynos's catalog rate. */
  knowledgeBaseUsd = 0;
  private readonly started: number;

  constructor(private readonly now: () => number = Date.now) {
    this.started = now();
  }

  record(event: ScanEvent): void {
    if (event.type === 'phase') {
      const record = this.phases.get(event.phase) ?? { status: 'pending' };
      record.status = STATUS_OF[event.status] ?? record.status;
      if (event.status === 'start') record.startedAt = this.now();
      if (event.seconds !== undefined) record.seconds = event.seconds;
      if (event.detail) record.detail = event.detail;
      this.phases.set(event.phase, record);
    } else if (event.type === 'step') {
      const record = this.phases.get(event.phase);
      if (record) record.detail = event.message;
    } else if (event.type === 'usage') this.usage[event.source] = event.tokens;
    else if (event.type === 'cost') this.knowledgeBaseUsd = event.usd;
  }

  /** A running phase's seconds so far, or a finished one's. */
  elapsed(phase: ScanPhase): number | undefined {
    const record = this.phases.get(phase);
    if (!record) return undefined;
    if (record.seconds !== undefined) return record.seconds;
    return record.startedAt !== undefined ? (this.now() - record.startedAt) / 1000 : undefined;
  }

  totalSeconds(): number {
    return (this.now() - this.started) / 1000;
  }

  toJSON(): Record<string, unknown> {
    return {
      phases: Object.fromEntries(
        [...this.phases].map(([phase, record]) => [
          phase,
          { status: record.status, seconds: record.seconds ?? null, detail: record.detail ?? null },
        ])
      ),
      total_seconds: Math.round(this.totalSeconds() * 10) / 10,
      usage: this.usage,
      knowledge_base_usd: this.knowledgeBaseUsd,
    };
  }

  /**
   * One line per phase that ran, then the total, then the tokens: the scan's last lines on stderr.
   *
   * upstream prints its own TOKENS line after a scan that reached its summary, on the terminal it
   * had (interactive); `upstreamPrintedTokens` leaves the scan's out then. Everywhere else
   * (headless, where its stderr is captured, or a scan it never finished) ours is the only count.
   * The architecture review's are always ours: upstream never sees them.
   */
  summary(c: Colors, options: { upstreamPrintedTokens?: boolean } = {}): string {
    const lines = [c.bold('Timings')];
    for (const [phase, record] of this.phases) {
      if (record.status === 'pending') continue;
      const seconds = record.seconds !== undefined ? duration(record.seconds) : '';
      const note = record.status === 'done' ? '' : c.dim(` ${record.status}`);
      lines.push(`  ${phase.padEnd(10)} ${seconds.padStart(7)}${note}`);
    }
    lines.push(`  ${'total'.padEnd(10)} ${duration(this.totalSeconds()).padStart(7)}`);
    // A source that used no tokens (a mock or dry run) has no line.
    const sources = (['scan', 'review'] as const).filter(
      source =>
        usedTokens(this.usage[source]) && !(source === 'scan' && options.upstreamPrintedTokens)
    );
    if (sources.length) lines.push(c.bold('Tokens'));
    for (const source of sources)
      lines.push(`  ${source.padEnd(10)} ${tokenLine(this.usage[source] as TokenUsage)}`);
    // A small repository's knowledge base costs fractions of a cent; $0.00 would read as free.
    const usd = this.knowledgeBaseUsd;
    if (usd) lines.push(c.dim(`  Knowledge base (Jev): $${usd.toFixed(usd < 0.01 ? 4 : 2)}`));
    return lines.join('\n');
  }
}

function usedTokens(tokens: TokenUsage | undefined): tokens is TokenUsage {
  return !!tokens && tokens.input_tokens + tokens.output_tokens > 0;
}

/** `2,495,756 in (1,958,656 cached) · 88,286 out (35,413 reasoning)` */
function tokenLine(tokens: TokenUsage): string {
  const count = (n: number): string => n.toLocaleString('en-US');
  const reasoning = tokens.reasoning_output_tokens
    ? ` (${count(tokens.reasoning_output_tokens)} reasoning)`
    : '';
  return `${count(tokens.input_tokens)} in (${count(tokens.cached_input_tokens)} cached) · ${count(tokens.output_tokens)} out${reasoning}`;
}
