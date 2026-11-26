/**
 * The CLI's one door into the scan engine (@averlon-ai/cynos-scan-engine).
 *
 * The engine is bundled into the CLI, and it is being reshaped around a runtime seam (native or
 * docker) while the CLI is written against that new interface. Two problems follow: a named
 * import of an export that is not there yet fails the build, and a missing function must not crash
 * commands that never need it (`info`, `doctor`, `--help`). So the engine is imported as a
 * namespace and every export is looked up by name when it is used:
 *
 *   engine().scanCheckout(...)    the export, or EngineUnavailable naming the missing export
 *   hasEngine('checkHost')        whether this engine build has it, for checks that degrade
 *
 * The types below are the contract the CLI codes against (scanCheckout, checkHost, fixHost,
 * resolveStateDir, resolveUpstream, LocalKnowledgeBaseStore, checkKey,
 * keyCheckFailure, killContainer, plain and the constants). They mirror the engine's own; once the
 * engine's index.ts exports all of them, the local copies can become re-exports. Tests mock this
 * module rather than the engine.
 */
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as engineModule from '@averlon-ai/cynos-scan-engine';

/** Where a scan runs upstream: on the host under Codex's OS sandbox, or in the hardened container. */
export type Runtime = 'native' | 'docker';
export const RUNTIMES: readonly Runtime[] = ['native', 'docker'];

/** The scan's phases, in the order scanCheckout runs them (the engine's progress.ts). */
export const SCAN_PHASES = ['stage', 'preflight', 'knowledge', 'brief', 'scan', 'report'] as const;
export type ScanPhase = (typeof SCAN_PHASES)[number];

export interface TokenUsage {
  input_tokens: number;
  cached_input_tokens: number;
  output_tokens: number;
  reasoning_output_tokens: number;
}

/** What a scan is doing, beside its log lines (the engine's progress.ts ScanEvent). */
export type ScanEvent =
  | {
      type: 'phase';
      phase: ScanPhase;
      status: 'start' | 'end' | 'failed' | 'skipped' | 'cancelled';
      seconds?: number;
      detail?: string;
    }
  | {
      type: 'step';
      phase: ScanPhase;
      step: string;
      message: string;
      data?: Record<string, unknown>;
    }
  | { type: 'upstream'; message: string }
  | { type: 'usage'; source: 'scan' | 'review'; tokens: TokenUsage }
  | { type: 'cost'; source: 'knowledge-base'; usd: number }
  | { type: 'heartbeat'; phase: ScanPhase; elapsedSeconds: number }
  | { type: 'handoff'; phase: 'scan' }
  | { type: 'outcome'; scanStatus: string; scanId: string | null; scanDir: string | null };

/** Carries the knowledge-base cache between scans (the engine's knowledge-base/store.ts). */
export interface KnowledgeBaseStore {
  restore(dir: string, sha: string, preferred: string[]): Promise<string | undefined>;
  save(dir: string, sha: string, restored: string | undefined): Promise<void>;
}

/** What to scan, where, and with which keys: the fields the CLI sets. */
export interface ScanConfig {
  runtime: Runtime;
  /** upstream's own state dir (the CLI never sets CODEX_SECURITY_STATE_DIR), or a path. */
  stateDir: 'upstream-default' | string;
  /** upstream draws its own dashboard on the terminal instead of running headless. */
  interactive: boolean;
  /** Whether the host publishes the results (the key-leak check); the CLI never does. */
  publishes: boolean;
  /** This run's private directory: <state>/averlon/scans/<runName>/. */
  stage: string;
  /** The engine's assets (profiles, prompt, image context), copied beside the bundle. */
  assets: string;
  kind: 'full' | 'diff';
  diffBase: string;
  project: string;
  runName: string;
  scannedSha: string;
  /** A diff's repository-relative threat-model file, or empty. */
  knowledgeBase: string;
  /** false for CYNOS_SCAN_NO_KNOWLEDGE_BASE: a full scan on upstream's own threat model. */
  buildKnowledgeBase: boolean;
  /** CYNOS_SCAN_HYPOTHESES: the most hypothesis packets; unset for the engine's default. */
  maxHypothesisPackets?: number;
  cynosKey?: string;
  model: string;
  effort: string;
  mode: string;
  paths: string[];
  cyberAccessProgram: string;
  maxTimeHours: number | undefined;
  failOnSeverity: string;
  verbose: boolean;
  dryRun: boolean;
  mock: boolean;
  judge: boolean;
  taskRouting: boolean;
  baseUrl?: string;
  /** docker runtime only. */
  buildImage: boolean;
  /** docker runtime only. */
  loadAppArmor: boolean;
  /** Appended to the scan prompt (--scan-prompt-file's text). */
  promptAddendum?: string;
  /** --rubric: the severity rubric file; upstream's default when unset. */
  rubricFile?: string;
  /** --false-positives: a JSON file of the findings reviewers dismissed, and why. */
  falsePositivesFile?: string;
  /** docker runtime only: [here, on the Docker host] for each bind-mount source (--host-path). */
  hostPaths?: [string, string][];
}

/** The caller's inputs as the engine read them (the engine's scan-inputs.ts). */
export interface ScanInputs {
  rubric?: string;
  falsePositives: unknown[];
}

export interface ScanIO {
  log(message: string): void;
  warn(message: string): void;
  error(message: string): void;
  progress?(event: ScanEvent): void;
  /** docker: every container the run may start, before any starts, so a stop can kill them. */
  containers?(names: string[]): void;
  knowledgeBaseStore?: KnowledgeBaseStore;
  signal?: AbortSignal;
}

/** The parts of the engine's ScanResult the CLI reads. */
export interface ScanResult {
  scanId: string | null;
  scanDir: string | null;
  /** upstream's exit code; null when it never exited on its own. */
  exitCode: number | null;
  outcome: { scanStatus: string; policyStatus: string; reason: string; skipReason: string };
  counts: Record<string, number> | undefined;
  sarif: string;
  /** A full scan's or a diff's summary, told apart by its `kind`. */
  knowledgeBase: Record<string, unknown> | undefined;
  diffThreatModel: Record<string, unknown> | undefined;
  usage: TokenUsage;
  seconds: number;
  cost: { scan_usd: number | null; knowledge_base_usd: number | null };
  versions: Record<string, unknown>;
}

export interface HostCheck {
  id: string;
  group: 'common' | 'native' | 'docker';
  status: 'ok' | 'warn' | 'fail';
  title: string;
  detail: string;
  fix?: string;
}

export interface CheckHostOptions {
  scope: 'doctor' | 'scan';
  runtime: Runtime;
  assets?: string;
  project?: string;
  stateDir?: string;
  cynosKey?: string;
  baseUrl?: string;
  model?: string;
  quick?: boolean;
}

export interface UpstreamInstall {
  root: string;
  bin: string;
  version: string;
  codex: { executable: string; toolsDir?: string; version: string };
}

/** Why cynos refused a key check (the engine's key-check.ts). */
export type KeyRefusal = 'key' | 'budget' | 'model' | 'unreachable' | 'gateway';

export interface KeyCheck {
  accepted: boolean;
  answer: string;
  refusal?: KeyRefusal;
}

export type Fetch = (url: string, init: RequestInit) => Promise<Response>;

/** How a run ended, for its telemetry (the engine's telemetry.ts). */
export interface RunFinish {
  outcome: 'completed' | 'failed' | 'cancelled';
  errorKind?: string;
  error?: unknown;
  changedFiles?: number;
  productFiles?: number;
}

export interface TelemetryOptions {
  key: string | undefined;
  baseUrl?: string;
  client: 'cli' | 'action';
  clientVersion: string;
  kind: 'full' | 'diff';
  runtime: Runtime;
  repository: string;
  checkout?: string;
  home?: string;
  enabled?: boolean;
  fetch?: Fetch;
}

/** One scan's telemetry: its start and finish, reported to cynos (the engine's telemetry.ts). */
export interface ScanTelemetry {
  readonly enabled: boolean;
  progress(event: ScanEvent): void;
  measureStore(store: KnowledgeBaseStore): KnowledgeBaseStore;
  cacheFailed(step: 'cache_restore' | 'cache_save'): void;
  started(): Promise<void>;
  finished(finish: RunFinish): Promise<void>;
}

/** The engine as the CLI uses it. */
export interface Engine {
  scanCheckout(config: ScanConfig, io: ScanIO): Promise<ScanResult>;
  /** The caller's rubric and dismissals, read and checked; throws on one it cannot use. */
  readScanInputs(config: Pick<ScanConfig, 'rubricFile' | 'falsePositivesFile'>): ScanInputs;
  checkHost(options: CheckHostOptions): Promise<HostCheck[]>;
  /** Repairs one of FIXABLE_CHECKS and returns it checked again; throws for any other. */
  fixHost(id: string, options: CheckHostOptions & { allowSudo?: boolean }): Promise<HostCheck>;
  FIXABLE_CHECKS: readonly string[];
  resolveStateDir(env: NodeJS.ProcessEnv): string;
  resolveUpstream(): UpstreamInstall;
  LocalKnowledgeBaseStore: new (
    root: string,
    log?: (message: string) => void,
    failed?: (step: 'cache_save') => void
  ) => KnowledgeBaseStore;
  checkKey(key: string, model: string, fetcher?: Fetch, baseUrl?: string): Promise<KeyCheck>;
  /** A refused check's failure, naming its cause, and that cause's fix. */
  keyCheckFailure(
    check: KeyCheck,
    model: string,
    baseUrl?: string
  ): { failure: string; fix: string };
  /** `docker kill` by name: the Docker daemon, not this process, owns a scan's containers. */
  killContainer(name: string): void;
  ScanTelemetry: new (options: TelemetryOptions) => ScanTelemetry;
  /** A git remote URL as `<host>/<owner>/<repo>`, or undefined for one that is not a URL. */
  repositoryIdentity(remoteUrl: string): string | undefined;
  /** External text (model output, upstream's files) without control or bidi-override characters. */
  plain(value: string, limit?: number): string;
  DEFAULT_MODEL: string;
  /** Most severe first. */
  SEVERITIES: readonly string[];
  BASE_URL: string;
  ENGINE_VERSION: string;
  UPSTREAM_PIN: { package: string; version: string; codexPackage: string; codexVersion: string };
}

export type EngineExport = keyof Engine;

/** A command needs an engine export this build does not have. */
export class EngineUnavailable extends Error {
  constructor(readonly exportName: string) {
    super(
      `This cynos build's engine has no ${exportName} export; reinstall cynos, or report it with \`cynos debug bundle\`.`
    );
  }
}

let exports: Record<string, unknown> = engineModule as unknown as Record<string, unknown>;

/** Whether this engine build has an export (a check can then say so instead of failing). */
export function hasEngine(name: EngineExport): boolean {
  return exports[name] !== undefined;
}

/** The engine; reading an export it lacks throws EngineUnavailable. */
export function engine(): Engine {
  return new Proxy({} as Engine, {
    get(_target, name: string) {
      const value = exports[name];
      if (value === undefined) throw new EngineUnavailable(name);
      return value;
    },
  });
}

/** Tests replace the engine with a partial fake; returns a function restoring the real one. */
export function useEngineForTests(fake: Partial<Engine>): () => void {
  const real = exports;
  exports = fake as Record<string, unknown>;
  return () => {
    exports = real;
  };
}

/**
 * The engine's assets. The bundle cannot find them in the engine package (it is bundled, not
 * installed), so the build copies them beside dist/cynos.mjs; running from source, they are
 * the engine package's own.
 */
export function assetsDir(): string {
  const candidates = [
    fileURLToPath(new URL('./assets', import.meta.url)),
    fileURLToPath(new URL('../../engine/assets', import.meta.url)),
  ];
  return candidates.find(existsSync) ?? candidates[0];
}
