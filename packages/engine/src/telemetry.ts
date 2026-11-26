/**
 * Scan telemetry: each scan reports its start and finish to cynos, so a scan that fails or slows
 * down on a customer's machine is seen without the customer telling us.
 *
 * A scan runs where its logs never reach us: a laptop, a GitHub runner. What reaches us is a
 * summary the host sends to cynos's `POST /v1/scan-events/{repo_hash}` with the scan's own key, two events a
 * run: `run_started` before the scan, `run_finished` once scanCheckout returns or throws. A run
 * with a start and no finish crashed. The summary is built from what the scan already reports:
 *
 *   phases   the engine's phase events (progress.ts): each phase's status and duration
 *   cache    the knowledge-base store's restore and save (measureStore), with the failures a
 *            store that keeps its own errors reports through cacheFailed, so a failed restore is
 *            not taken for a miss
 *   outcome  the host's: completed, failed (with the phase that failed and the error's kind),
 *            or cancelled
 *
 * The repository is sent only as a hash of its identity (repositoryIdentity), and an error's
 * message without the key, the checkout's path or the home directory. Nothing else of the
 * repository, its findings or the scan's output is sent.
 *
 * Telemetry never changes the scan: each event is one attempt with a 3-second timeout, and every
 * failure to send is dropped. It sends nothing when the host disables it (a scan that makes no
 * model calls) or without a key.
 */
import { createHash, randomUUID } from 'node:crypto';
import { BASE_URL } from './constants';
import type { Fetch } from './key-check';
import type { ScanKind } from './knowledge-base';
import type { KnowledgeBaseStore } from './knowledge-base/store';
import type { ScanEvent, ScanPhase } from './progress';
import type { RuntimeName } from './runtime';
import { withoutTrailing } from './text.js';

/** The knowledge-base store's two steps, beside the scan's phases. */
export type CacheStep = 'cache_restore' | 'cache_save';

/**
 * A step's status. A phase ends ok, failed, skipped or cancelled; a restore is a hit or a miss, a
 * save ok; either cache step is an error when the store failed, which never fails the scan.
 */
export type StepStatus = 'ok' | 'failed' | 'skipped' | 'cancelled' | 'hit' | 'miss' | 'error';

/** How one step ended; its name is its key in the run's steps. */
export interface TelemetryStep {
  status: StepStatus;
  ms: number;
}

/** How the run ended, as the host decided it. */
export interface RunFinish {
  outcome: 'completed' | 'failed' | 'cancelled';
  /** The host's name for what went wrong (the CLI's error.kind); failed runs only. */
  errorKind?: string;
  /** What was thrown, when the run failed; its message is sent redacted. */
  error?: unknown;
  /** A diff's changed files, or a full scan's product files: the size the duration depends on. */
  changedFiles?: number;
  productFiles?: number;
}

export interface TelemetryOptions {
  /** The scan's cynos key; without one nothing is sent. */
  key: string | undefined;
  /** cynos's endpoint, BASE_URL unless the scan runs against another gateway. */
  baseUrl?: string;
  client: 'cli' | 'action';
  clientVersion: string;
  kind: ScanKind;
  runtime: RuntimeName;
  /** The repository's identity (repositoryIdentity); only its hash is sent. */
  repository: string;
  /** Paths replaced in an error's message: the checkout's, and the home directory. */
  checkout?: string;
  home?: string;
  /** False when the host sends nothing for this run, such as a scan that makes no model calls. */
  enabled?: boolean;
  /** The run's id; the action's post step passes the main step's, to finish the same run. */
  runId?: string;
  fetch?: Fetch;
  now?: () => number;
}

/** Each event is one attempt; a runner that cannot reach cynos loses the event and nothing else. */
export const TELEMETRY_TIMEOUT_MS = 3_000;
/** How much of an error's message is sent. */
export const ERROR_MESSAGE_LIMIT = 500;
/**
 * The shortest start of the key that is redacted when it appears cut short: the key's prefix
 * (`sk-cy-`) and two characters. Anything shorter tells nothing of the key.
 */
export const KEY_FRAGMENT_MIN = 8;

/**
 * A repository's identity, `<host>/<owner>/<repo>` lowercased, from a git remote URL in any of its
 * spellings, so the CLI's checkout and the action's run of one repository hash the same:
 *
 *   git@github.com:Acme/API.git, https://github.com/acme/api, ssh://git@github.com/acme/api.git
 *     → github.com/acme/api
 *
 * Undefined when the URL is not one of those (a local path, a bundle).
 */
export function repositoryIdentity(remoteUrl: string): string | undefined {
  const url = remoteUrl.trim();
  const scp = /^[\w.-]+@([\w.-]+):(?!\/)(.+)$/.exec(url);
  const standard = /^(?:https?|ssh|git):\/\/(?:[^@/]+@)?([\w.-]+)(?::\d+)?\/(.+)$/.exec(url);
  const [, host, path] = scp ?? standard ?? [];
  if (!host || !path) return undefined;
  const name = withoutTrailing(path.replace(/\.git\/?$/, ''), '/');
  return name ? `${host}/${name}`.toLowerCase() : undefined;
}

/** What the server finds runs of one repository by: the identity's SHA-256, 32 hex characters. */
export function repoHash(identity: string): string {
  return createHash('sha256').update(identity).digest('hex').slice(0, 32);
}

/**
 * An error's message as it may leave the machine: no key, no checkout path, no home directory.
 *
 * The key goes first (keyFragmentsRedacted). The checkout goes before the home directory, which
 * usually holds it: the other way round, the checkout's path would no longer match. The cut to 500
 * comes last, so it can never leave part of anything above.
 */
export function telemetryMessage(
  message: string,
  secrets: { key?: string | undefined; checkout?: string | undefined; home?: string | undefined }
): string {
  let text = message;
  if (secrets.key) text = keyFragmentsRedacted(text, secrets.key);
  if (secrets.checkout) text = text.split(secrets.checkout).join('<checkout>');
  if (secrets.home) text = text.split(secrets.home).join('~');
  return text.slice(0, ERROR_MESSAGE_LIMIT);
}

/**
 * text with every piece of the key replaced by `***`: the whole key, and the key cut short.
 *
 * A message can reach telemetry already cut by the code that made it (upstream's reason at 500
 * characters, a cynos error body at 300), and a key cut at that boundary no longer matches whole.
 * So each place the key's first KEY_FRAGMENT_MIN characters appear is redacted for as far as the
 * text goes on matching the key: to the key's end, or to where it was cut.
 */
function keyFragmentsRedacted(text: string, key: string): string {
  const start = key.slice(0, KEY_FRAGMENT_MIN);
  let redacted = '';
  let from = 0;
  for (let at = text.indexOf(start); at >= 0; at = text.indexOf(start, from)) {
    let end = at + start.length;
    while (end < text.length && end - at < key.length && text[end] === key[end - at]) end++;
    redacted += `${text.slice(from, at)}***`;
    from = end;
  }
  return redacted + text.slice(from);
}

/** One scan's telemetry: listens to the scan, then sends its start and its finish. */
export class ScanTelemetry {
  readonly runId: string;
  readonly enabled: boolean;
  /**
   * The run's steps, keyed by name: cynos's queries follow one phase across runs by its name
   * (steps.knowledge.ms), which an array would number by position instead. A scan runs each phase
   * and cache step once.
   */
  private readonly steps: Partial<Record<ScanPhase | CacheStep, TelemetryStep>> = {};
  private readonly cacheFailures = new Set<CacheStep>();
  private failedPhase: { name: ScanPhase; detail: string } | undefined;
  private startedAt: number | undefined;
  private finishSent = false;
  private readonly now: () => number;

  constructor(private readonly options: TelemetryOptions) {
    this.runId = options.runId ?? randomUUID();
    this.now = options.now ?? Date.now;
    this.enabled = options.enabled !== false && Boolean(options.key);
  }

  /** ScanIO.progress: records each phase as it ends. */
  progress(event: ScanEvent): void {
    if (event.type !== 'phase' || event.status === 'start') return;
    const status = event.status === 'end' ? 'ok' : event.status;
    this.steps[event.phase] = { status, ms: Math.round((event.seconds ?? 0) * 1000) };
    if (event.status === 'failed')
      this.failedPhase = { name: event.phase, detail: event.detail ?? '' };
  }

  /**
   * The store, with its restore and save timed and their result recorded. A store that throws is
   * recorded as an error and the error goes on to the scan as before; one that keeps its own
   * errors reports them through cacheFailed while the call runs.
   */
  measureStore(store: KnowledgeBaseStore): KnowledgeBaseStore {
    return {
      restore: (dir, sha, preferred, inHistory) =>
        this.measure('cache_restore', () => store.restore(dir, sha, preferred, inHistory)),
      save: (dir, sha, restored) =>
        this.measure('cache_save', () => store.save(dir, sha, restored)),
    };
  }

  /** A store's own failure, which it logged and did not throw (the action's GitHub cache). */
  cacheFailed(step: CacheStep): void {
    this.cacheFailures.add(step);
  }

  /** Sends run_started; the run's duration counts from here. */
  async started(): Promise<void> {
    this.startedAt = this.now();
    await this.send({ event: 'run_started', ...this.runContext() });
  }

  /** Sends run_finished, once: the action's post step sends one only if the main step did not. */
  async finished(finish: RunFinish): Promise<void> {
    if (this.finishSent) return;
    this.finishSent = true;
    await this.send({
      event: 'run_finished',
      ...this.runContext(),
      outcome: finish.outcome,
      ...(this.startedAt === undefined ? {} : { duration_ms: this.now() - this.startedAt }),
      ...(finish.changedFiles === undefined ? {} : { changed_files: finish.changedFiles }),
      ...(finish.productFiles === undefined ? {} : { product_files: finish.productFiles }),
      steps: this.steps,
      ...(finish.outcome === 'failed' ? { error: this.errorOf(finish) } : {}),
    });
  }

  /** Runs one cache step, recording hit or miss (restore), ok (save), or error. */
  private async measure<T>(step: CacheStep, call: () => Promise<T>): Promise<T> {
    const started = this.now();
    this.cacheFailures.delete(step);
    const record = (status: StepStatus): void => {
      this.steps[step] = { status, ms: this.now() - started };
    };
    try {
      const result = await call();
      if (this.cacheFailures.has(step)) record('error');
      else if (step === 'cache_save') record('ok');
      else record(result === undefined ? 'miss' : 'hit');
      return result;
    } catch (error) {
      record('error');
      throw error;
    }
  }

  /**
   * The failure as sent: the phase that failed and its message, else what the host caught (a
   * failure before the first phase, or after the last, is the run's own: step `run`).
   */
  private errorOf(finish: RunFinish): { step: string; kind: string; message: string } {
    const thrown =
      finish.error instanceof Error ? finish.error.message : String(finish.error ?? '');
    return {
      step: this.failedPhase?.name ?? 'run',
      kind: finish.errorKind ?? 'internal',
      message: telemetryMessage(this.failedPhase?.detail || thrown, {
        key: this.options.key,
        checkout: this.options.checkout,
        home: this.options.home,
      }),
    };
  }

  private runContext() {
    return {
      run_id: this.runId,
      client: this.options.client,
      client_version: this.options.clientVersion,
      kind: this.options.kind,
      runtime: this.options.runtime,
    };
  }

  /**
   * One attempt, bounded by TELEMETRY_TIMEOUT_MS; any failure is dropped. The repository is in
   * the path, where cynos limits events per repository without reading the body.
   */
  private async send(event: Record<string, unknown>): Promise<void> {
    if (!this.enabled) return;
    const fetch = this.options.fetch ?? globalThis.fetch;
    const base = withoutTrailing(this.options.baseUrl ?? BASE_URL, '/');
    try {
      await fetch(`${base}/scan-events/${repoHash(this.options.repository)}`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${this.options.key}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify(event),
        signal: AbortSignal.timeout(TELEMETRY_TIMEOUT_MS),
      });
    } catch {
      // Telemetry never changes the scan: an event that cannot be sent is lost.
    }
  }
}
