/**
 * `cynos scan [PATH]`: one scan of a checkout on this machine, through the engine.
 *
 * The engine runs the scan wherever it is hosted (scanCheckout); what the CLI decides is
 * everything a laptop adds around it, and most of it must be settled before the engine starts,
 * because a scan that fails ten minutes in for a missing key or a bad revision is the worst
 * outcome a CLI can have:
 *
 *   plan      the checkout and its HEAD, the runtime, what to scan (full, --diff REV, or
 *             --since-last-scan from the run dirs), the cynos key (a scan that calls the
 *             model needs it, its knowledge base included: checked here, before any call)
 *   run dir   <state>/averlon/scans/<run name>/, the engine's stage, private to this user
 *   scan      scanCheckout with the CLI's ScanIO: a live view or plain lines, Ctrl-C and
 *             --timeout, the local knowledge-base store
 *   link      upstream's scan id, a link to the run dir, so `scans` commands find it by the id
 *   report    the result on stdout (pretty, or one JSON object), timings on stderr, and
 *             upstream's exit code
 */
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { Option, type Command } from 'commander';
import { cynosBaseUrl, cynosKey } from '../auth/keys';
import { CLI_NAME, CLI_VERSION, defaultModel, engineBaseUrl, type Context } from '../context';
import {
  assetsDir,
  engine,
  EngineUnavailable,
  type KnowledgeBaseStore,
  type RunFinish,
  type Runtime,
  type ScanConfig,
  type ScanResult,
  type ScanTelemetry,
} from '../engine';
import { CliError, errorKind, EXIT, scanExitCode, stopError } from '../exit-codes';
import { withExamples } from '../help';
import { createLocalIO, type StopCause } from '../local-io';
import { HeadlessRenderer, LiveRenderer, type ProgressRenderer } from '../progress/renderers';
import { PhaseTimings } from '../progress/timings';
import {
  defaultRuntime,
  inCI,
  knowledgeBaseCacheDir,
  maxHypothesisPackets,
  MOCK_STATE_DIR,
  parseRuntime,
  RUN_FILES,
  runsDir,
  scanSwitches,
} from '../settings';
import type { Terminal } from '../terminal';
import { findingRows, readFindings } from './scans';
import { sinceLastScan, type SinceLastScanDeps } from './since-last-scan';
import { withoutTrailing } from '../text.js';

export type ScanFormat = 'pretty' | 'json' | 'jsonl';

export interface ScanOptions {
  diff?: string;
  sinceLastScan?: boolean;
  path?: string[];
  failOnSeverity: string;
  dryRun?: boolean;
  runtime?: string;
  headless?: boolean;
  format: ScanFormat;
  buildImage: boolean;
  scanPromptFile?: string;
  timeout?: string;
  hostPath?: string[];
  rubric?: string;
  falsePositives?: string;
}

/** What the plan settled: everything scanCheckout needs except the run dir and the IO. */
export interface ScanPlan {
  project: string;
  head: string;
  runtime: Runtime;
  kind: 'full' | 'diff';
  diffBase: string;
  /** upstream's mock scan (CYNOS_SCAN_MOCK=1): synthetic findings, no model call, no key. */
  mock: boolean;
  callsModel: boolean;
  buildKnowledgeBase: boolean;
  interactive: boolean;
  verbose: boolean;
  /** --since-last-scan found HEAD scanned already: the scan id, and nothing to do. */
  upToDate?: string;
  cynosKey?: string;
  model: string;
  baseUrl: string;
  /** cynos's quality judge and task routing (CYNOS_SCAN_NO_JUDGE, CYNOS_SCAN_NO_ROUTING turn them off). */
  judge: boolean;
  routing: boolean;
  /** --scan-prompt-file: the file, and its text for the end of the scan prompt. */
  scanPrompt?: { file: string; text: string };
  /** --timeout in seconds. */
  timeoutSeconds?: number;
  /** --rubric and --false-positives, checked: the files and what they hold. */
  inputs: PlannedInputs;
  /** --host-path: [here, on the Docker host] pairs. */
  hostPaths: [string, string][];
  /** Said before the scan starts: what is scanned, and why (since-last-scan's choice). */
  notes: string[];
}

/** The caller's inputs as the plan settled them: the files' absolute paths, and what they hold. */
export interface PlannedInputs {
  rubric: { file: string; sha256: string } | null;
  falsePositives: { file: string; count: number } | null;
}

/**
 * Every scan runs in upstream's standard mode at xhigh reasoning effort: the workflow and the
 * knowledge base are tuned for them, so the CLI offers no other.
 */
const SCAN_MODE = 'standard';
const SCAN_EFFORT = 'xhigh';

export function registerScan(program: Command, ctx: Context): void {
  const command = program
    .command('scan')
    .description('Scan a repository, selected paths, or the changes since a revision.')
    .argument('[path]', 'the checkout to scan', '.')
    .option('--diff <rev>', 'scan only the changes from REV to HEAD')
    .option('--since-last-scan', "scan the changes since this repository's last completed scan")
    .option('--path <path>', 'limit the scan to a file or directory (repeatable)', collect)
    .option('--rubric <file>', "grade findings with the severity rubric in FILE, not upstream's")
    .option(
      '--false-positives <file>',
      'a JSON file of findings reviewers dismissed, each with a reason; the scan drops a finding whose reason still holds'
    )
    .option(
      '--timeout <duration>',
      'stop the whole run after DURATION and keep what it has: hours, or 90s / 30m / 2h (max 96h)'
    )
    .option('--scan-prompt-file <file>', 'append scan instructions from FILE')
    .addOption(
      new Option('--fail-on-severity <level>', 'exit 1 for findings at or above LEVEL')
        .choices(['none', 'critical', 'high', 'medium', 'low'])
        .default('none')
    )
    .option('--dry-run', 'validate the configuration only; no scan')
    .addOption(
      new Option(
        '--runtime <runtime>',
        'where upstream runs (default: CYNOS_SCAN_RUNTIME or native)'
      ).choices(['native', 'docker'])
    )
    .option('--headless', "plain progress lines instead of the live view and upstream's dashboard")
    .addOption(
      new Option('--format <format>', 'result format on stdout')
        .choices(['pretty', 'json', 'jsonl'])
        .default('pretty')
    )
    .option('--no-build-image', 'docker runtime: use the scanner image already present')
    .option(
      '--host-path <here=host>',
      'docker runtime, from inside a container: the directory HERE is HOST on the Docker host (repeatable)',
      collect
    )
    .action(async (path: string, options: ScanOptions) => {
      process.exitCode = await scanCommand(ctx, path, options);
    });
  withExamples(command, [
    `${CLI_NAME} scan .`,
    `${CLI_NAME} scan . --diff origin/main`,
    `${CLI_NAME} scan . --since-last-scan`,
    `${CLI_NAME} scan . --headless --format json`,
    `${CLI_NAME} scan ~/code/api --runtime docker --fail-on-severity high`,
    `${CLI_NAME} scan . --path src`,
    `${CLI_NAME} scan . --rubric severity.md --false-positives dismissed.json`,
    `${CLI_NAME} scan /out/repo --runtime docker --host-path /out=/srv/arm/out --timeout 2h --headless --format json`,
  ]);
}

function collect(value: string, previous: string[] = []): string[] {
  return [...previous, value];
}

export async function scanCommand(
  ctx: Context,
  path: string,
  options: ScanOptions,
  deps: SinceLastScanDeps = {}
): Promise<number> {
  const { terminal } = ctx;
  ctx.output = options.format;

  // 1. The plan: everything that can fail before the engine starts.
  const plan = await planScan(ctx, path, options, deps);
  for (const note of plan.notes) terminal.info(note);
  if (plan.upToDate) {
    const summary = {
      scanId: plan.upToDate,
      scanStatus: 'up-to-date',
      scanDir: null,
      exitCode: 0,
      counts: null,
    };
    if (options.format !== 'pretty')
      terminal.result(JSON.stringify(summary, null, options.format === 'json' ? 2 : 0));
    return 0;
  }

  // 2. The run dir and the CLI's ScanIO.
  const stateDir = engine().resolveStateDir(ctx.env);
  const runName = newRunName();
  const runDir = join(runsDir(stateDir), runName);
  mkdirSync(runDir, { recursive: true, mode: 0o700 });
  const timings = new PhaseTimings();
  const keys = [plan.cynosKey];
  const title = `${plan.kind === 'diff' ? `diff scan since ${plan.diffBase.slice(0, 12)}` : 'full scan'} of ${plan.project} · ${plan.runtime} runtime`;
  const renderer = progressRenderer(terminal, timings, title, plan.interactive);
  // The run's start and finish, reported to cynos: it listens to the phases and the cache.
  const telemetry = scanTelemetry(ctx, plan);
  const store = knowledgeBaseStore(plan, stateDir, terminal, telemetry);
  const local = createLocalIO({
    terminal,
    renderer,
    timings,
    runDir,
    keys,
    ...(plan.timeoutSeconds ? { timeoutSeconds: plan.timeoutSeconds } : {}),
    ...(plan.runtime === 'docker'
      ? { killContainer: (name: string) => engine().killContainer(name) }
      : {}),
    ...(store ? { knowledgeBaseStore: telemetry.measureStore(store.knowledgeBaseStore) } : {}),
    onEvent: event => {
      telemetry.progress(event);
      if (options.format === 'jsonl') terminal.result(JSON.stringify(event));
    },
  });

  // 3. The scan.
  let result: ScanResult;
  await telemetry.started();
  try {
    result = await engine().scanCheckout(scanConfig(plan, options, runDir, runName), local.io);
  } catch (error) {
    // A failed run keeps its log and timings for `scans logs` and `debug bundle`; a stopped one fails as
    // its stop, whichever step the stop cut short.
    writePrivate(join(runDir, RUN_FILES.timings), timings.toJSON());
    const stopped = stopError(error, local.stoppedBy(), local.stopReason());
    await telemetry.finished(failedRunFinish(stopped));
    throw stopped;
  } finally {
    local.close();
  }

  // 4. upstream's scan id names the run dir too, then the result and the timings are written to it.
  linkScanId(runDir, result.scanId);
  const exitCode = scanExitCode(result, local.stoppedBy());
  const summary = resultSummary(result, plan, exitCode, runDir, timings, local.stopReason());
  writePrivate(join(runDir, RUN_FILES.timings), timings.toJSON());
  writePrivate(join(runDir, RUN_FILES.result), summary);

  // 5. The result on stdout, the timings on stderr.
  if (options.format === 'json') terminal.json(summary);
  else if (options.format === 'jsonl')
    terminal.result(JSON.stringify({ type: 'result', ...summary }));
  else printResult(terminal, summary);
  // upstream printed its TOKENS line on the terminal it had, after a scan it completed.
  const upstreamPrintedTokens = plan.interactive && result.outcome.scanStatus === 'completed';
  terminal.info(`\n${timings.summary(terminal.c, { upstreamPrintedTokens })}`);
  // 6. The run's finish, reported last: the signal handlers are gone by now, so a Ctrl-C while
  // the report waits (up to its 3-second timeout) must find the scan's result already saved.
  await telemetry.finished(scannedRunFinish(result, local.stoppedBy()));
  return exitCode;
}

/**
 * Settles what to scan and with which keys. Everything here is checked before the engine starts,
 * so a mistake costs a second, not a scan.
 */
export async function planScan(
  ctx: Context,
  path: string,
  options: ScanOptions,
  deps: SinceLastScanDeps = {}
): Promise<ScanPlan> {
  const { env } = ctx;
  const notes: string[] = [];
  const project = checkout(path);
  const head = gitHead(project);
  const runtime = options.runtime ? parseRuntime(options.runtime) : defaultRuntime(env);
  const mock = mockScan(env);
  const callsModel = !mock && !options.dryRun;

  // What to scan: --diff REV, --since-last-scan's choice, or the whole repository.
  if (options.diff && options.sinceLastScan)
    throw new CliError('usage', '--diff and --since-last-scan cannot be combined');
  let kind: 'full' | 'diff' = 'full';
  let diffBase = '';
  let upToDate: string | undefined;
  if (options.diff || options.sinceLastScan) {
    if (!head)
      throw new CliError(
        'usage',
        `${options.diff ? '--diff' : '--since-last-scan'} needs a git checkout with a commit: ${project}`
      );
  }
  if (options.diff) {
    kind = 'diff';
    diffBase = resolveRevision(project, options.diff);
    if (diffBase === head)
      throw new CliError(
        'usage',
        `--diff ${options.diff} is HEAD itself: there are no changes to scan`
      );
  } else if (options.sinceLastScan) {
    const since = sinceLastScan(project, head, engine().resolveStateDir(env), deps);
    if (since.kind === 'up-to-date') {
      notes.push(`Nothing to scan: the last completed scan (${since.scanId}) was of HEAD.`);
      upToDate = since.scanId;
    } else if (since.kind === 'diff') {
      kind = 'diff';
      diffBase = since.base;
      notes.push(
        `Scanning the changes since the last completed scan (${since.scanId}, ${since.base.slice(0, 12)}).`
      );
    } else notes.push(`A full scan: ${since.reason}.`);
  }

  // The cynos key whenever the model is called: the scan's and its knowledge base's calls.
  const cynos = callsModel ? cynosKey(ctx.envKeys.cynos, ctx.credentials) : undefined;
  if (callsModel && !cynos)
    throw new CliError(
      'auth',
      'No cynos key: a scan that calls the model needs one.',
      `Run \`${CLI_NAME} login\`, or set CYNOS_API_KEY.`
    );
  const switches = scanSwitches(env);
  const buildKnowledgeBase = switches.knowledgeBase;

  // What surrounds the scan: its prompt's addendum, the caller's inputs, its time limit, the
  // Docker host's paths.
  const scanPrompt = options.scanPromptFile ? readScanPrompt(options.scanPromptFile) : undefined;
  const inputs = planInputs(options);
  const timeoutSeconds = parseTimeout(options.timeout);
  const hostPaths = parseHostPaths(options.hostPath ?? []);
  if (hostPaths.length && runtime !== 'docker')
    throw new CliError(
      'usage',
      '--host-path maps bind mounts for the Docker daemon; it needs --runtime docker'
    );

  return {
    project,
    head,
    runtime,
    kind,
    diffBase,
    mock,
    callsModel,
    buildKnowledgeBase,
    interactive: interactiveScan({
      stdinTTY: Boolean(process.stdin.isTTY),
      stderrTTY: ctx.terminal.stderrIsTTY,
      headless: Boolean(options.headless),
      verbose: ctx.terminal.verbose,
      ci: inCI(env),
      quiet: ctx.terminal.quiet,
      format: options.format,
    }),
    verbose: ctx.terminal.verbose,
    ...(upToDate ? { upToDate } : {}),
    ...(cynos ? { cynosKey: cynos.value } : {}),
    model: defaultModel(env),
    baseUrl: cynosBaseUrl(env, engineBaseUrl()),
    judge: switches.judge,
    routing: switches.routing,
    ...(scanPrompt ? { scanPrompt } : {}),
    ...(timeoutSeconds ? { timeoutSeconds } : {}),
    inputs,
    hostPaths,
    notes,
  };
}

/**
 * --rubric and --false-positives, read and checked by the engine's own rules now, so a file the
 * scan cannot use fails as a usage error before anything runs.
 */
export function planInputs(options: Pick<ScanOptions, 'rubric' | 'falsePositives'>): PlannedInputs {
  const rubricFile = options.rubric ? resolve(options.rubric) : undefined;
  const falsePositivesFile = options.falsePositives ? resolve(options.falsePositives) : undefined;
  if (!rubricFile && !falsePositivesFile) return { rubric: null, falsePositives: null };
  let read;
  try {
    read = engine().readScanInputs({
      ...(rubricFile ? { rubricFile } : {}),
      ...(falsePositivesFile ? { falsePositivesFile } : {}),
    });
  } catch (error) {
    if (error instanceof EngineUnavailable) throw error;
    throw new CliError('usage', error instanceof Error ? error.message : String(error));
  }
  return {
    rubric:
      rubricFile && read.rubric !== undefined
        ? { file: rubricFile, sha256: createHash('sha256').update(read.rubric).digest('hex') }
        : null,
    falsePositives: falsePositivesFile
      ? { file: falsePositivesFile, count: read.falsePositives.length }
      : null,
  };
}

/**
 * Interactive when someone is at the terminal (stdin and stderr are TTYs) and nothing asked for
 * plain lines: --headless, --verbose, --quiet, CI, or a machine-readable --format.
 */
export function interactiveScan(conditions: {
  stdinTTY: boolean;
  stderrTTY: boolean;
  headless: boolean;
  verbose: boolean;
  ci: boolean;
  quiet?: boolean;
  format: ScanFormat;
}): boolean {
  const { stdinTTY, stderrTTY, headless, verbose, ci, quiet, format } = conditions;
  return stdinTTY && stderrTTY && !headless && !verbose && !ci && !quiet && format === 'pretty';
}

function progressRenderer(
  terminal: Terminal,
  timings: PhaseTimings,
  title: string,
  interactive: boolean
): ProgressRenderer {
  if (!interactive) return new HeadlessRenderer(terminal, timings);
  const live = new LiveRenderer(terminal, timings, title);
  live.start();
  return live;
}

/** The local store: a full scan saves its snapshot, a diff restores its base's review. */
function knowledgeBaseStore(
  plan: ScanPlan,
  stateDir: string,
  terminal: Terminal,
  telemetry: ScanTelemetry
): { knowledgeBaseStore: KnowledgeBaseStore } | undefined {
  if (!plan.buildKnowledgeBase || !plan.callsModel) return undefined;
  // The store logs a save it could not make and carries on; telemetry is told, so it records an
  // error rather than a save.
  const store = new (engine().LocalKnowledgeBaseStore)(
    knowledgeBaseCacheDir(stateDir),
    message => terminal.debug(`knowledge-base cache: ${message}`),
    step => telemetry.cacheFailed(step)
  );
  return { knowledgeBaseStore: store };
}

/**
 * The run's telemetry (the engine's telemetry.ts): sent with the scan's own key, and only for a
 * scan that calls the model, so a mock scan or a dry run sends nothing.
 */
export function scanTelemetry(ctx: Context, plan: ScanPlan): ScanTelemetry {
  return new (engine().ScanTelemetry)({
    key: plan.cynosKey,
    baseUrl: plan.baseUrl,
    client: 'cli',
    clientVersion: CLI_VERSION,
    kind: plan.kind,
    runtime: plan.runtime,
    repository: checkoutIdentity(plan.project),
    checkout: plan.project,
    home: homedir(),
    enabled: plan.callsModel,
    fetch: ctx.fetch,
  });
}

/**
 * The checkout's repository identity: its origin remote's `<host>/<owner>/<repo>`, as the action
 * reports the same repository, else the checkout's path, so a laptop's runs of one directory still
 * group together.
 */
export function checkoutIdentity(project: string, remote = originRemote(project)): string {
  return (remote && engine().repositoryIdentity(remote)) || project;
}

function originRemote(project: string): string {
  const remote = spawnSync('git', ['-C', project, 'remote', 'get-url', 'origin'], {
    encoding: 'utf8',
  });
  return remote.status === 0 ? remote.stdout.trim() : '';
}

/**
 * A run that returned, in scanExitCode's order:
 *
 *   completed            upstream completed the scan (a policy failure included)
 *   the CLI's own stop   --timeout fails it as timed out; Ctrl-C or SIGTERM cancels it
 *   upstream's own stop  the dashboard's Ctrl-C is a keypress to upstream, not a signal to the CLI,
 *                        so upstream stops itself and exits 130 or 143: cancelled too
 *   anything else        failed in upstream
 */
export function scannedRunFinish(result: ScanResult, stoppedBy: StopCause | undefined): RunFinish {
  const size = runSize(result.knowledgeBase);
  if (result.outcome.scanStatus === 'completed') return { outcome: 'completed', ...size };
  if (stoppedBy === 'timeout')
    return { outcome: 'failed', errorKind: 'timed-out', error: result.outcome.reason, ...size };
  if (stoppedBy) return { outcome: 'cancelled', ...size };
  if (result.exitCode === EXIT.interrupted || result.exitCode === EXIT.terminated)
    return { outcome: 'cancelled', ...size };
  return { outcome: 'failed', errorKind: 'upstream', error: result.outcome.reason, ...size };
}

/** A run that threw: a Ctrl-C or SIGTERM is cancelled; anything else, --timeout too, failed. */
export function failedRunFinish(error: unknown): RunFinish {
  const kind = errorKind(error);
  if (kind === 'interrupted' || kind === 'terminated') return { outcome: 'cancelled' };
  return { outcome: 'failed', errorKind: kind, error };
}

/** What the duration depends on: a diff's changed files, or a full scan's product files. */
function runSize(summary: Record<string, unknown> | undefined): Partial<RunFinish> {
  const count = (name: string): number | undefined =>
    typeof summary?.[name] === 'number' ? summary[name] : undefined;
  const changedFiles = count('changed_files');
  const productFiles = count('product_files');
  return {
    ...(changedFiles === undefined ? {} : { changedFiles }),
    ...(productFiles === undefined ? {} : { productFiles }),
  };
}

/**
 * Whether this run is upstream's mock scan: CYNOS_SCAN_MOCK=1. A mock scan's findings are
 * synthetic, so it is not a scan option a user should find: it exists to test the CLI and its
 * runtimes end to end with no key and no model call (scripts/e2e.sh, the install smoke test), and
 * is deliberately missing from the help, `help env` and the READMEs.
 */
export function mockScan(env: NodeJS.ProcessEnv): boolean {
  return env['CYNOS_SCAN_MOCK'] === '1';
}

export function scanConfig(
  plan: ScanPlan,
  options: ScanOptions,
  runDir: string,
  runName: string
): ScanConfig {
  const hypothesisPackets = maxHypothesisPackets();
  return {
    runtime: plan.runtime,
    // upstream saves a mock scan's synthetic findings in the history it is given: in the user's own,
    // they appeared in upstream's `findings list` beside real ones. A mock scan gets a history of
    // its own, in its run dir, which gc removes.
    stateDir: plan.mock ? join(runDir, MOCK_STATE_DIR) : 'upstream-default',
    interactive: plan.interactive,
    publishes: false,
    stage: runDir,
    assets: assetsDir(),
    kind: plan.kind,
    diffBase: plan.diffBase,
    project: plan.project,
    runName,
    scannedSha: plan.head,
    knowledgeBase: '',
    buildKnowledgeBase: plan.buildKnowledgeBase,
    ...(hypothesisPackets !== undefined ? { maxHypothesisPackets: hypothesisPackets } : {}),
    ...(plan.cynosKey ? { cynosKey: plan.cynosKey } : {}),
    model: plan.model,
    effort: SCAN_EFFORT,
    mode: SCAN_MODE,
    paths: options.path ?? [],
    cyberAccessProgram: '',
    maxTimeHours: undefined,
    failOnSeverity: options.failOnSeverity,
    verbose: plan.verbose,
    dryRun: Boolean(options.dryRun),
    mock: plan.mock,
    judge: plan.judge,
    taskRouting: plan.routing,
    baseUrl: plan.baseUrl,
    buildImage: plan.runtime === 'docker' && options.buildImage,
    // The docker runtime uses upstream's AppArmor profile once `doctor --fix` has loaded it: a scan
    // never runs sudo.
    loadAppArmor: false,
    ...(plan.scanPrompt ? { promptAddendum: plan.scanPrompt.text } : {}),
    ...(plan.inputs.rubric ? { rubricFile: plan.inputs.rubric.file } : {}),
    ...(plan.inputs.falsePositives ? { falsePositivesFile: plan.inputs.falsePositives.file } : {}),
    ...(plan.hostPaths.length ? { hostPaths: plan.hostPaths } : {}),
  };
}

function writePrivate(path: string, value: unknown): void {
  try {
    writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  } catch {
    // The run dir is gone (a failed stage); the result still reaches stdout.
  }
}

/**
 * A duration in hours: a bare number of hours (1.5), or a number in one of `units` (90m, 2h,
 * and 45s where seconds are allowed); NaN for anything else.
 */
function durationHours(value: string, units: readonly ('h' | 'm' | 's')[]): number {
  const match = /^(\d+(?:\.\d+)?)\s*([a-z])?$/i.exec(value.trim());
  const unit = (match?.[2] ?? 'h').toLowerCase() as 'h' | 'm' | 's';
  if (!match || !units.includes(unit)) return NaN;
  return Number(match[1]) / { h: 1, m: 60, s: 3600 }[unit];
}

/**
 * --timeout in whole seconds: hours (2), or 90s / 30m / 2h. Its bound is upstream's deep-scan limit, 96
 * hours: upstream stops discovery by then, and a longer timer would overflow Node's (~24.8
 * days) and fire at once.
 */
export function parseTimeout(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const seconds = Math.round(durationHours(value, ['h', 'm', 's']) * 3600);
  if (!Number.isFinite(seconds) || seconds <= 0 || seconds > 96 * 3600)
    throw new CliError(
      'usage',
      `--timeout takes hours (2) or a duration (90s, 30m, 2h) up to 96h, not ${value}`
    );
  return seconds;
}

/** --scan-prompt-file: the file's text, appended to the scan prompt; it must say something. */
function readScanPrompt(path: string): { file: string; text: string } {
  const file = resolve(path);
  let text: string;
  try {
    text = readFileSync(file, 'utf8');
  } catch {
    throw new CliError('usage', `--scan-prompt-file ${path} is not a readable file`);
  }
  if (!text.trim()) throw new CliError('usage', `--scan-prompt-file ${path} is empty`);
  return { file, text };
}

/**
 * --host-path HERE=HOST, for a CLI in a container that drives the host's Docker through its
 * socket. The daemon resolves a bind mount's source on the host, where this process's paths do
 * not exist, and `docker run -v` would then mount an empty directory it creates there; so each
 * source under HERE is given to Docker as the same path under HOST.
 */
export function parseHostPaths(values: string[]): [string, string][] {
  return values.map(value => {
    const [here, host, ...rest] = value.split('=');
    if (!here || !host || !isAbsolute(here) || !isAbsolute(host) || rest.length)
      throw new CliError('usage', `--host-path takes /path/here=/path/on/host, not ${value}`);
    // Trailing slashes go, but the root stays the root.
    return [withoutTrailing(here, '/') || '/', withoutTrailing(host, '/') || '/'];
  });
}

/** A run's name: sortable by time, unique, and valid as a container name. */
export function newRunName(now = new Date()): string {
  const stamp = now.toISOString().replace(/[-:T]/g, '').slice(0, 14);
  return `cynos-scan-${stamp}-${randomBytes(3).toString('hex')}`;
}

/** The checkout's real path; it must be a directory. */
function checkout(path: string): string {
  const absolute = resolve(path);
  if (!existsSync(absolute) || !statSync(absolute).isDirectory())
    throw new CliError('usage', `Not a directory: ${absolute}`);
  return realpathSync(absolute);
}

/** HEAD's commit, or '' for a directory that is not a git checkout (upstream scans it as files). */
function gitHead(project: string): string {
  const head = spawnSync('git', ['-C', project, 'rev-parse', '--verify', 'HEAD'], {
    encoding: 'utf8',
  });
  return head.status === 0 ? head.stdout.trim() : '';
}

function resolveRevision(project: string, revision: string): string {
  const resolved = spawnSync(
    'git',
    ['-C', project, 'rev-parse', '--verify', '--end-of-options', `${revision}^{commit}`],
    {
      encoding: 'utf8',
    }
  );
  if (resolved.status !== 0)
    throw new CliError(
      'usage',
      `--diff ${revision} is not a commit in ${project}`,
      'Fetch it first (git fetch), or name a branch or sha that exists here.'
    );
  return resolved.stdout.trim();
}

/**
 * Names the run dir by upstream's scan id, with a link beside it, so a scan's run dir is found by
 * the id `scans list` prints.
 *
 * The run dir keeps its run name: by the time the id is known, paths into it are recorded where
 * they cannot be rewritten (the result's SARIF, and the knowledge base and prompt that upstream's
 * history keeps for the scan), and a rename would leave each pointing at nothing. A link that
 * cannot be made leaves the extras where they are, found by their run name.
 */
export function linkScanId(runDir: string, scanId: string | null): void {
  if (!scanId || !/^[A-Za-z0-9._-]+$/.test(scanId) || basename(runDir) === scanId) return;
  const link = join(dirname(runDir), scanId);
  if (!existsSync(runDir) || lexists(link)) return;
  try {
    symlinkSync(basename(runDir), link, 'dir');
  } catch {
    // No link: `scans` and `debug bundle` take the run name instead.
  }
}

/** Whether a path exists, a dangling link included. */
function lexists(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch {
    return false;
  }
}

/** The result as --format json prints it: one object, the fields e2e and scripts read first. */
export function resultSummary(
  result: ScanResult,
  plan: Pick<
    ScanPlan,
    | 'kind'
    | 'diffBase'
    | 'head'
    | 'runtime'
    | 'project'
    | 'model'
    | 'judge'
    | 'routing'
    | 'scanPrompt'
    | 'timeoutSeconds'
    | 'inputs'
  >,
  exitCode: number,
  runDir: string,
  timings: PhaseTimings,
  stopped?: string
): Record<string, unknown> {
  return {
    scanId: result.scanId,
    scanStatus: result.outcome.scanStatus,
    policyStatus: result.outcome.policyStatus,
    reason: result.outcome.reason || null,
    scanDir: result.scanDir,
    exitCode,
    upstreamExitCode: result.exitCode,
    counts: result.counts ?? null,
    kind: plan.kind,
    diffBase: plan.diffBase || null,
    scannedSha: plan.head || null,
    runtime: plan.runtime,
    project: plan.project,
    model: plan.model,
    sarif: result.sarif || null,
    knowledgeBase: result.knowledgeBase ?? null,
    diffThreatModel: result.diffThreatModel ?? null,
    usage: result.usage ?? null,
    cost: result.cost ?? null,
    seconds: result.seconds ?? null,
    judge: plan.judge,
    routing: plan.routing,
    timeout: plan.timeoutSeconds ?? null,
    scanPromptFile: plan.scanPrompt?.file ?? null,
    rubric: plan.inputs.rubric,
    falsePositives: plan.inputs.falsePositives,
    stopped: stopped ?? null,
    runDir,
    timings: timings.toJSON(),
  };
}

/** How many findings the pretty result lists; `scans findings` and the report have them all. */
const LISTED_FINDINGS = 10;

/** The pretty result's findings: the most severe LISTED_FINDINGS, then where the rest are. */
function findingLines(terminal: Terminal, scanDir: string, total: number, id: unknown): string[] {
  const c = terminal.out;
  const findings = readFindings(scanDir) ?? [];
  if (!findings.length) return [];
  const listed = findingRows(c, findings.slice(0, LISTED_FINDINGS));
  const more = Math.max(total, findings.length) - listed.length;
  const all = id ? `${CLI_NAME} scans findings ${String(id)}` : 'the report';
  return [
    '',
    c.dim('Findings:'),
    ...listed,
    ...(more > 0 ? [c.dim(`  … and ${more} more: ${all}`)] : []),
  ];
}

function printResult(terminal: Terminal, summary: Record<string, unknown>): void {
  const c = terminal.out;
  const status = String(summary['scanStatus']);
  const counts = (summary['counts'] ?? {}) as Record<string, number>;
  const total = Object.values(counts).reduce((sum, n) => sum + n, 0);
  const bySeverity = Object.entries(counts)
    .filter(([, n]) => n)
    .map(([level, n]) => `${n} ${level}`)
    .join(', ');
  const headline =
    {
      completed: `${c.green('✓')} Scan completed: ${total} finding${total === 1 ? '' : 's'}${bySeverity ? ` (${bySeverity})` : ''}`,
      skipped: `${c.green('✓')} ${String(summary['reason'] ?? 'Skipped')}`,
    }[status] ??
    `${c.red('✗')} Scan ${status}: ${String(summary['reason'] ?? 'see the log above')}`;
  const lines = [headline];
  const row = (label: string, value: unknown): void => {
    if (value) lines.push(`  ${c.dim(label.padEnd(9))} ${String(value)}`);
  };
  const scanDir = typeof summary['scanDir'] === 'string' ? summary['scanDir'] : undefined;
  const report = scanDir ? join(scanDir, 'report.md') : undefined;
  row('scan id', summary['scanId']);
  row('report', report && existsSync(report) ? report : undefined);
  row('results', scanDir);
  row('SARIF', summary['sarif']);
  if (summary['policyStatus'] === 'failed') row('policy', `failed: ${String(summary['reason'])}`);
  row('extras', summary['runDir']);
  const id = summary['scanId'];
  if (status === 'completed' && scanDir) lines.push(...findingLines(terminal, scanDir, total, id));
  if (id && status === 'completed')
    lines.push(
      '',
      c.dim('Next:'),
      `  ${CLI_NAME} scans findings ${String(id)}`,
      `  ${CLI_NAME} scans export ${String(id)} --format sarif --output results.sarif`
    );
  else if (status === 'failed')
    lines.push(
      '',
      c.dim(
        `Debug it: ${CLI_NAME} scans logs${id ? ` ${String(id)}` : ''} · ${CLI_NAME} debug bundle${id ? ` ${String(id)}` : ''}`
      )
    );
  terminal.result(lines.join('\n'));
}
