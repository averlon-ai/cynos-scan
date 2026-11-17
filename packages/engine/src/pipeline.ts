/**
 * One scan of a checkout, from the scanner to validated reports: the part of a run that does not
 * depend on who runs it.
 *
 * The GitHub action, the cynos CLI and a benchmark run the same scan, and differ only
 * around it. The action decides what to scan from the event and the run history, and afterwards
 * publishes reports, issues and the threat model; the CLI keeps the results on the user's
 * machine, as `codex-security` does; a benchmark stages a repository and scores the findings. So
 * the caller hands over a checkout, a private stage directory and a runtime (runtime/), and gets
 * the outcome and the reports back:
 *
 *   1  stage       the stage's directories, the model catalog, the runtime prepared (docker: the
 *                  profiles, the image, AppArmor; native: upstream's pins, the code-graph
 *                  binary), the versions it runs
 *   2  preflight   the host check, upstream's sandbox check, the scan cut off from the model,
 *                  and the key check
 *   3  knowledge   the knowledge base: a full scan's, or a diff's (the change, the paths
 *                  through it, the threat model brought up to date, packets and briefs)
 *   4  brief       the scan's instructions: the scan prompt for the kind of scan and the
 *                  runtime's paths, a caller's addendum, the helper sections
 *   5  scan        upstream's scan on the runtime; upstream's outcome rules; run.json
 *   6  report      strict SARIF; the key-leak check when the caller publishes
 *
 * Each phase is reported as progress events (progress.ts) beside the log. Everything stays in the
 * stage and the scan dir: the caller decides what to keep (the action discards all of it but the
 * reports, a benchmark keeps it as evidence, the CLI leaves it in upstream's history).
 */
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { DEFAULT_HYPOTHESIS_PACKETS, REASONING_EFFORTS, type Severity } from './constants';
import { checkHost } from './host-check';
import { at, type JsonObject } from './json';
import { checkKey, keyCheckFailure } from './key-check';
import {
  buildDiffKnowledgeBase,
  buildKnowledgeBase,
  cynosModels,
  type DiffKnowledgeBaseSummary,
  type KnowledgeBaseSummary,
  type ScanKind,
} from './knowledge-base';
import type { KnowledgeBaseStore } from './knowledge-base/store';
import type { ReuseStats } from './knowledge-base/stored-review';
import {
  engineAssets,
  HELPER_CONTEXT_FILE,
  KNOWLEDGE_BASE_CACHE_DIR,
  KNOWLEDGE_BASE_DIR,
  MODEL_CATALOG_FILE,
  PLUGIN_DIR,
  PREFLIGHT_DIR,
  prepareWorkspace,
  RUN_PROMPT_FILE,
  type ScanLayout,
} from './layout';
import { runCommand, type ProcessRegistry } from './processes';
import { phase, say, skipped, type ScanEvent, type ScanStep } from './progress';
import {
  promptVariables,
  readScanPrompt,
  renderParts,
  renderPrompt,
  runPrompt,
  type RunPrompt,
} from './prompt-template';
import { validateReports, validateSarif, type ValidatedReports } from './reports';
import { classify, cliEstimatedCost, severityCounts, type Outcome } from './results';
import { createRuntime, type RuntimeCommand, type RuntimeName, type ScanRuntime } from './runtime';
import type { HostPaths } from './runtime/docker';
import { PREFLIGHT_KEY, scanReachesScanning, stderrTail } from './sandbox';
import { exportSarif } from './sarif';
import { makesModelCalls, writeModelCatalog, type ScanOptions } from './scan-command';
import {
  readFalsePositives,
  readRubric,
  scanInputInstructions,
  stageScanInputs,
  type ScanInputs,
} from './scan-inputs';
import { stagePlugin } from './scan-plugin';
import { isFile, runScan, type ScannerRun, type Usage } from './scan-run';

/** The scan's settings that pass to codex-security unchanged (scan-command.ts). */
export type ScanSettings = Pick<
  ScanOptions,
  | 'paths'
  | 'model'
  | 'effort'
  | 'mode'
  | 'cyberAccessProgram'
  | 'maxTimeHours'
  | 'failOnSeverity'
  | 'verbose'
  | 'dryRun'
  | 'mock'
  | 'judge'
  | 'taskRouting'
  | 'baseUrl'
>;

/** What to scan, where, on which runtime, and with which keys. */
export interface ScanConfig extends ScanSettings {
  /** A full repository scan, or the changes since diffBase. */
  kind: ScanKind;
  /** A diff's base commit; empty for a full scan. */
  diffBase: string;
  /** The checkout; the scanner reads it and never writes it. */
  project: string;
  /** This run's private directory: prompt, model catalog, reports, knowledge base, run.json. */
  stage: string;
  /** Where upstream runs: on the host as upstream does (native), or in the hardened container. */
  runtime: RuntimeName;
  /**
   * native: upstream's state dir, or 'upstream-default' for upstream's own (resolveStateDir); the
   * runtime sets CODEX_SECURITY_STATE_DIR only for a path. docker: always <stage>/state.
   */
  stateDir: 'upstream-default' | string;
  /** upstream draws its own dashboard on the terminal: no --headless or --json. */
  interactive: boolean;
  /** The caller publishes the outputs (the action): every file is checked for a key first. */
  publishes: boolean;
  /** native: where upstream is resolved from (resolveUpstream); the running script's by default. */
  upstream?: string;
  /** native: where the code-graph binary is kept (code-graph-binary.ts). */
  toolCache?: string;
  /**
   * The image's build context, profiles and prompt: the package's assets/. A host that bundles
   * the engine passes its copy; the engine's own is the default for unbundled use.
   */
  assets?: string;
  /** Every container's or tracked process's name starts with it. */
  runName: string;
  /** The commit the checkout is at; the scan must record scanning it. */
  scannedSha: string;
  /** A diff's --knowledge-base: a repository-relative threat-model file, or empty. */
  knowledgeBase: string;
  /** A full scan's: the repository's own threat model (repository-relative), when it keeps one. */
  threatModelPath?: string;
  /** The caller's severity rubric, a file on this machine; upstream's default when unset. */
  rubricFile?: string;
  /**
   * The findings the caller's reviewers dismissed: a JSON file on this machine, each entry a reason,
   * the finding's title and a location, and its fingerprint when known (scan-inputs.ts).
   */
  falsePositivesFile?: string;
  /**
   * cynos's key; needed whenever the scan calls the model (not a mock or dry run), and the only
   * key: a full scan's knowledge base makes its model calls through cynos too.
   */
  cynosKey?: string;
  /**
   * A scan builds its knowledge base first (default true). False runs it on upstream's own
   * threat model and workflow.
   */
  buildKnowledgeBase?: boolean;
  /**
   * The most hypothesis packets a full scan with a knowledge base starts with its other packets,
   * the hypotheses shared out between them (default DEFAULT_HYPOTHESIS_PACKETS); 0 turns them off.
   */
  maxHypothesisPackets?: number;
  /** docker: build (or pull) the image; false when the caller has it already (bench build-image). */
  buildImage: boolean;
  /** docker: load upstream's AppArmor profile when Docker uses AppArmor (needs sudo on the host). */
  loadAppArmor: boolean;
  /** Text appended to the scan prompt (a benchmark's own rules); its marked sections reach helpers. */
  promptAddendum?: string;
  /** docker: mount sources on the Docker host, when this process is not on it. */
  hostPaths?: HostPaths;
  /** Fields run.json starts with, such as the caller's name for what it scanned and why. */
  runRecord?: JsonObject;
}

/** Where the scan reports progress, and the caller's hooks into it. */
export interface ScanIO {
  log(message: string): void;
  warn(message: string): void;
  error(message: string): void;
  /** Each phase, step, usage and the outcome as they happen (progress.ts). */
  progress?(event: ScanEvent): void;
  /** docker: every container the run may start, before any starts, so a cancelled caller can stop them. */
  containers?(names: string[]): void;
  /** native: where the run's processes are tracked, so a cancelled caller can stop them. */
  processes?: ProcessRegistry;
  /**
   * Carries the knowledge-base cache between scans; none means no cache. The scan works in
   * <stage>/knowledge-base-cache, which the store fills and saves.
   */
  knowledgeBaseStore?: KnowledgeBaseStore;
  /** Called once the outcome is known, before the reports are checked (the action sets its outputs). */
  scanned?(scan: ScannedRun): void;
  /** Stops the run: the scan as a cancellation does, any later step before it starts. */
  signal?: AbortSignal;
}

/** The scan's outcome, before SARIF and the leak check. */
export interface ScannedRun {
  outcome: Outcome;
  scannerRun: ScannerRun;
  /** The CLI's own estimate; undefined means unavailable, not zero (an unpriced model). */
  estimatedCost: number | undefined;
  counts: Record<Severity, number> | undefined;
}

export interface ScanResult extends ScannedRun {
  /** upstream's scan id (its manifest's), or null when the scan recorded none. */
  scanId: string | null;
  /** The scan dir on this machine: upstream's artifacts for this scan. */
  scanDir: string;
  /** upstream's exit code (0, 1 policy failed, 2 failure, 130/143 interrupted), null if killed. */
  exitCode: number | null;
  reports: ValidatedReports;
  findings: JsonObject | undefined;
  /** The validated SARIF's path, or empty when it is missing or unsafe. */
  sarif: string;
  /** Files under the stage and scan dir (outside Codex's state) holding a key; nothing may be published then. */
  leaked: string[];
  /** Whether the scan read a knowledge base: a full scan's, or a diff's. */
  knowledgeBaseBuilt: boolean;
  /** What the knowledge base built: a full scan's or a diff's summary, told apart by `kind`. */
  knowledgeBase: KnowledgeBaseSummary | DiffKnowledgeBaseSummary | undefined;
  /** The last full scan's threat model a diff started from, and what the diff's update did to it. */
  diffThreatModel: ReuseStats | undefined;
  versions: Record<string, unknown>;
  usage: Usage;
  seconds: number;
  /** What the run cost: the CLI's estimate of the scan, and Jev's labels at cynos's catalog rate. */
  cost: { scan_usd: number | null; knowledge_base_usd: number | null };
  /** run.json as written. */
  runJson: JsonObject;
  /** Codex's state directories: the scan's, and the architecture agent's when it ran. */
  stateDirs: string[];
}

/**
 * Codex's own state under a stage, never published: session transcripts, which can quote
 * anything a session saw. The scan's and the preflight's state dirs (docker, and a native run
 * whose caller keeps its state in the stage), and the architecture review agent's home.
 */
const CODEX_STATE_DIRS = [
  'state',
  join(PREFLIGHT_DIR, 'state'),
  join(KNOWLEDGE_BASE_DIR, 'review', 'home'),
];

/**
 * Files under stage, outside Codex's state, and under any of `also` (a scan dir outside the
 * stage), that contain the key; values are never printed.
 *
 * The whole stage, not a list of what is published today: the reports, the action's records,
 * and the knowledge base the action uploads as evidence and a benchmark keeps all live there,
 * and the review agent writes its command log and answer into it freely.
 */
export function filesContaining(stage: string, key: string, also: string[] = []): string[] {
  const found: string[] = [];
  const skipped = new Set(CODEX_STATE_DIRS.map(directory => join(stage, directory)));
  const walk = (directory: string): void => {
    let entries;
    try {
      entries = readdirSync(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!skipped.has(path)) walk(path);
      } else if (entry.isFile() && readFileSync(path).includes(key)) found.push(path);
    }
  };
  walk(stage);
  for (const directory of also) walk(directory);
  return found;
}

/** text with the keys replaced, for anything shown outside a masked log. */
export function redact(text: string, keys: (string | undefined)[]): string {
  return keys.reduce<string>((out, key) => (key ? out.split(key).join('***') : out), text);
}

/** The run's containers (or tracked processes), in the order they start; the post step stops any still running. */
export function containerNames(runName: string): string[] {
  return [
    `${runName}-preflight`,
    `${runName}-knowledge-base`,
    `${runName}-knowledge-base-review`,
    runName,
  ];
}

function readJson(path: string): JsonObject | undefined {
  try {
    const value: unknown = JSON.parse(readFileSync(path, 'utf8'));
    return value && typeof value === 'object' && !Array.isArray(value)
      ? (value as JsonObject)
      : undefined;
  } catch {
    return undefined;
  }
}

// --------------------------------------------------------------------------- //
// The scan, phase by phase
// --------------------------------------------------------------------------- //

/** The keys the scan holds, and what they are needed for. */
export interface Keys {
  cynos: string;
  /** Not a mock or dry run: the scan calls the model, with the cynos key. */
  callsModel: boolean;
  /** A scan that calls the model reads a knowledge base built first, with the same key. */
  buildsBase: boolean;
  /** Every key, for redaction and the leak check. */
  all: string[];
}

/** What the knowledge phase gave the scan. */
export interface Knowledge {
  summary: KnowledgeBaseSummary | undefined;
  diff?: DiffKnowledgeBaseSummary | undefined;
  diffThreatModel: ReuseStats | undefined;
}

/** What the stage phase made. */
interface Staged {
  /** The scan's layout: its scan dir is known once runUpstreamScan creates it. */
  layout: ScanLayout;
  versions: Record<string, unknown>;
}

/** What the brief phase wrote: the scan prompt as the scan reads it. */
interface Brief {
  text: string;
  /** The helper sections were written for every helper (a scan that calls the model). */
  helperContext: boolean;
}

/** What the scan phase left for the report phase. */
interface Scanned {
  scanned: ScannedRun;
  layout: ScanLayout;
  reports: ValidatedReports;
  result: JsonObject;
  knowledge: Knowledge;
  runJson: JsonObject;
}

/**
 * Runs one scan of config.project in config.stage on config.runtime; throws when a step before
 * the outcome fails. Each phase is wrapped in its progress events, in the order the module
 * comment lists them.
 */
export async function scanCheckout(config: ScanConfig, io: ScanIO): Promise<ScanResult> {
  requireEffort(config.effort);
  const keys = requireKeys(config);
  checkHypothesisPackets(config);
  const inputs = readScanInputs(config);
  const runtime = scanRuntime(config, io);
  const { layout, versions } = await phase(io, 'stage', () => stageRun(config, runtime, keys, io));
  await phase(io, 'preflight', () => preflight(config, layout, runtime, keys, inputs, io));
  const knowledge = await knowledgePhase(config, layout, runtime, keys, io);
  const brief = await phase(io, 'brief', () => writeBrief(config, layout, runtime, keys, inputs));
  const scanned = await phase(io, 'scan', () =>
    runUpstreamScan(config, layout, runtime, brief, knowledge, keys, inputs, io)
  );
  return phase(io, 'report', () => reportScan(config, runtime, scanned, versions, keys, io));
}

/** The reasoning effort, checked before anything is touched: nothing downstream rejects a typo. */
export function requireEffort(effort: string): void {
  if (!(REASONING_EFFORTS as readonly string[]).includes(effort))
    throw new Error(
      `The reasoning effort must be one of ${REASONING_EFFORTS.join(', ')}, not "${effort}".`
    );
}

/** The keys this scan needs, checked before anything is touched. */
export function requireKeys(config: ScanConfig): Keys {
  const callsModel = makesModelCalls(config);
  const cynos = config.cynosKey ?? '';
  // A scan that calls the model reads a knowledge base built first, a full scan's or a diff's,
  // unless the caller turned it off.
  const buildsBase = callsModel && config.buildKnowledgeBase !== false;
  if (callsModel && !cynos) throw new Error('A scan that calls the model needs the cynos key.');
  return { cynos, callsModel, buildsBase, all: [cynos] };
}

/**
 * The most hypothesis packets must be a whole number: the hypotheses are shared out between
 * that many packets.
 */
export function checkHypothesisPackets(config: ScanConfig): void {
  const n = config.maxHypothesisPackets;
  if (n !== undefined && !(Number.isInteger(n) && n >= 0))
    throw new Error(`maxHypothesisPackets must be a whole number, not ${n}.`);
}

/**
 * The caller's rubric and dismissals, read and checked before anything is touched
 * (scan-inputs.ts): a file that cannot be used fails in a second, not after the knowledge base.
 */
export function readScanInputs(
  config: Pick<ScanConfig, 'rubricFile' | 'falsePositivesFile'>
): ScanInputs {
  return {
    ...(config.rubricFile ? { rubric: readRubric(config.rubricFile) } : {}),
    falsePositives: config.falsePositivesFile ? readFalsePositives(config.falsePositivesFile) : [],
  };
}

/** The runtime config names, with the caller's process registry. */
function scanRuntime(config: ScanConfig, io: ScanIO): ScanRuntime {
  return createRuntime({
    runtime: config.runtime,
    assets: config.assets ?? engineAssets(),
    runName: config.runName,
    stateDir: config.stateDir,
    ...(config.upstream ? { upstream: config.upstream } : {}),
    ...(config.toolCache ? { toolCache: config.toolCache } : {}),
    ...(io.processes ? { processes: io.processes } : {}),
    ...(config.hostPaths ? { hostPaths: config.hostPaths } : {}),
  });
}

/** Throws when the caller stopped the run. */
function stopped(io: ScanIO): void {
  if (io.signal?.aborted) throw new Error(`The scan was stopped: ${String(io.signal.reason)}`);
}

/**
 * 1. The stage, the model catalog and the runtime. Each invocation gets its own private
 * directory, so a second scan in the same job never reads the first one's reports.
 */
async function stageRun(
  config: ScanConfig,
  runtime: ScanRuntime,
  keys: Keys,
  io: ScanIO
): Promise<Staged> {
  const assets = config.assets ?? engineAssets();
  prepareWorkspace(config.stage);
  writeModelCatalog(assets, config.stage, config.model);
  await runtime.prepare({
    buildImage: config.buildImage,
    loadAppArmor: config.loadAppArmor,
    codeGraph: keys.buildsBase,
    log: io.log,
  });
  const versions = runtime.versions(join(config.stage, 'versions.json'));
  io.containers?.(containerNames(config.runName));
  return { layout: runtime.layout(config.stage, config.project, 'scan'), versions };
}

/**
 * The prompt for a layout: the kind's workflow and the helper rules at the runtime's paths; the
 * addendum, then where the caller's dismissals are, as its instruction (scan-inputs.ts).
 */
function renderRunPrompt(
  config: ScanConfig,
  layout: ScanLayout,
  runtime: ScanRuntime,
  inputs: ScanInputs
): RunPrompt {
  const paths = runtime.paths(layout);
  const variables = promptVariables(paths, paths.promptScanDir, inputs.rubric !== undefined);
  const render = (text: string): string => renderPrompt(text, variables, runtime.foreignPaths);
  const parts = readScanPrompt(config.assets ?? engineAssets(), config.kind);
  const addendum = [config.promptAddendum, scanInputInstructions(inputs, paths.falsePositives)]
    .filter(text => text?.trim())
    .join('\n\n');
  return runPrompt(renderParts(parts, render), addendum || undefined);
}

/**
 * The run's workflow and prompt, written into its workspace: the scan prompt, the caller's staged
 * inputs, and upstream's plugin with our edited workflow files in place of upstream's
 * (scan-plugin.ts).
 */
function writeRunFiles(
  config: ScanConfig,
  layout: ScanLayout,
  runtime: ScanRuntime,
  inputs: ScanInputs
): RunPrompt {
  const prompt = renderRunPrompt(config, layout, runtime, inputs);
  writeFileSync(join(layout.workspace, RUN_PROMPT_FILE), prompt.text, { mode: 0o600 });
  stageScanInputs(layout.workspace, inputs);
  stagePlugin(
    runtime.bundledPlugin(layout.stage),
    join(layout.workspace, PLUGIN_DIR),
    config.kind,
    prompt.workflow
  );
  return prompt;
}

/** Runs a short command a runtime built, to completion. */
function runToEnd(command: RuntimeCommand): { status: number | null; stderr: string } {
  const [program, ...args] = command.argv;
  return runCommand(program ?? '', args, command.env);
}

/**
 * 2. Preflight: the host check, upstream's sandbox check, the scan cut off from the model, the
 * key. Each prints its real error, which upstream itself reports as a key it cannot use.
 */
async function preflight(
  config: ScanConfig,
  layout: ScanLayout,
  runtime: ScanRuntime,
  keys: Keys,
  inputs: ScanInputs,
  io: ScanIO
): Promise<void> {
  stopped(io);
  // The host first: a missing tool fails here with its fix, not as a sandbox error later.
  const failed = (
    await checkHost({
      scope: 'scan',
      runtime: config.runtime,
      project: config.project,
      ...(config.runtime === 'native' ? { stateDir: layout.stateDir } : {}),
      ...(config.upstream ? { upstream: config.upstream } : {}),
      ...(config.assets ? { assets: config.assets } : {}),
      ...(config.toolCache ? { toolCache: config.toolCache } : {}),
    })
  ).filter(check => check.status === 'fail');
  if (failed.length)
    throw new Error(
      `This machine cannot run the ${config.runtime} runtime: ${failed
        .map(check => `${check.title}: ${check.detail}${check.fix ? ` (fix: ${check.fix})` : ''}`)
        .join('; ')}`
    );
  if (!config.dryRun) {
    const check = runToEnd(runtime.sandboxCheck());
    if (check.status !== 0)
      throw new Error(
        `Codex's sandbox could not start (upstream's sandbox check): ${stderrTail(check.stderr)}`
      );
    say(io, 'preflight', 'sandbox', "Codex's sandbox runs a command.");

    // The scan itself, until it starts scanning; in its own workspace, out of upstream's history.
    stopped(io);
    const preflightLayout = runtime.layout(config.stage, config.project, 'preflight');
    prepareWorkspace(preflightLayout.workspace);
    writeRunFiles(config, preflightLayout, runtime, inputs);
    const result = await scanReachesScanning(
      runtime.scanCommand(
        preflightLayout,
        {
          ...scanOptions(config, undefined, false, inputs),
          // The plugin the scan will run with, if its knowledge base is built.
          plugin: keys.buildsBase,
          mock: false,
          interactive: false,
        },
        'preflight',
        PREFLIGHT_KEY
      ),
      runtime,
      io.signal
    );
    if (!result.reached)
      throw new Error(
        `The scan stopped before scanning began: ${stderrTail(result.lines.join('\n'), 2)}`
      );
    say(
      io,
      'preflight',
      'preparation',
      "The scan got through preparation; Codex's sandbox starts with its configuration."
    );
  }
  if (keys.callsModel) {
    stopped(io);
    const answer = await checkKey(keys.cynos, config.model, fetch, config.baseUrl, io.signal);
    if (!answer.accepted) {
      const { failure, fix } = keyCheckFailure(answer, config.model, config.baseUrl);
      throw new Error(`${failure}. ${fix}`);
    }
    say(io, 'preflight', 'key', `cynos accepted the key for ${config.model} (${answer.answer}).`);
  }
}

/**
 * 3, as a phase: skipped when the scan reads no knowledge base (a mock or dry run, or
 * buildKnowledgeBase off).
 */
export async function knowledgePhase(
  config: ScanConfig,
  layout: ScanLayout,
  runtime: ScanRuntime,
  keys: Keys,
  io: ScanIO
): Promise<Knowledge> {
  if (!keys.buildsBase) {
    const why = !keys.callsModel ? 'the scan makes no model call' : 'disabled';
    skipped(io, 'knowledge', why);
    return { summary: undefined, diffThreatModel: undefined };
  }
  return phase(io, 'knowledge', () => buildKnowledge(config, layout, runtime, keys, io));
}

/**
 * 3. The knowledge base. The scan prompt plans the scan around it, so a failed build fails the
 * run. Jev's answers, the code graph and the last full scan's review come from the store when
 * the caller keeps one, restored into the stage's working copy and saved from it.
 */
async function buildKnowledge(
  config: ScanConfig,
  layout: ScanLayout,
  runtime: ScanRuntime,
  keys: Keys,
  io: ScanIO
): Promise<Knowledge> {
  stopped(io);
  const store = io.knowledgeBaseStore;
  const cacheDir = store ? join(config.stage, KNOWLEDGE_BASE_CACHE_DIR) : undefined;
  const work = join(config.stage, KNOWLEDGE_BASE_DIR);
  const kbLog = (message: string): void => io.log(`knowledge base: ${redact(message, keys.all)}`);

  if (config.kind === 'diff') return buildDiffKnowledge(config, layout, runtime, keys, io);

  // A full scan builds it: graph, labels, review, packets, briefs.
  io.log(
    'Building the knowledge base: code graph, Jev labels, architecture review, packet design, helper briefs.'
  );
  const restored =
    store && cacheDir ? await store.restore(cacheDir, config.scannedSha, []) : undefined;
  let summary: KnowledgeBaseSummary;
  try {
    summary = await buildKnowledgeBase(
      {
        name: `${config.runName}-knowledge-base`,
        project: config.project,
        runtime,
        paths: runtime.paths(layout),
        work,
        // Jev's decisions, the review agent and the strong-model calls all use this key.
        cynosKey: keys.cynos,
        modelCatalog: join(config.stage, MODEL_CATALOG_FILE),
        head: config.scannedSha,
        step: (step, message, data) =>
          io.progress?.({
            type: 'step',
            phase: 'knowledge',
            step,
            message: redact(message, keys.all),
            ...(data ? { data } : {}),
          }),
        ...(cacheDir ? { cacheDir } : {}),
        ...(config.threatModelPath ? { threatModelPath: config.threatModelPath } : {}),
        ...(config.baseUrl ? { baseUrl: config.baseUrl } : {}),
        ...(io.signal ? { signal: io.signal } : {}),
        maxHypothesisPackets: config.maxHypothesisPackets ?? DEFAULT_HYPOTHESIS_PACKETS,
      },
      kbLog
    );
  } catch (error) {
    throw new Error(
      `The knowledge base could not be built, so no scan was started: ${error instanceof Error ? error.message : String(error)}`
    );
  }
  io.log(`Knowledge base built: ${JSON.stringify(summary)}`);
  io.progress?.({ type: 'cost', source: 'knowledge-base', usd: summary.cost_usd });
  const agent = summary.architecture_review?.agent;
  if (agent)
    io.progress?.({
      type: 'usage',
      source: 'review',
      tokens: {
        input_tokens: agent.inputTokens,
        cached_input_tokens: agent.cachedInputTokens,
        output_tokens: agent.outputTokens,
        reasoning_output_tokens: 0,
      },
    });
  // The cache holds answers and the graph, never a key; checked like every published file,
  // whatever the store.
  if (store && cacheDir) {
    if (keys.all.some(k => k && filesContaining(cacheDir, k).length))
      io.warn('A key was found in the knowledge-base cache; it is not saved.');
    else await store.save(cacheDir, config.scannedSha, restored);
  }
  return { summary, diffThreatModel: undefined };
}

/**
 * 3, for a diff: the change, the paths through it, the threat model brought up to date, packets
 * and briefs (knowledge-base/diff.ts). The store gives it the last full scan's review and Jev's
 * answers: the base commit's snapshot first, since that full scan stored the review. A diff never
 * saves, so it cannot shrink what the next full scan restores. As for a full scan, the prompt
 * plans the scan around the knowledge base, so a failed build, a missing stored review included,
 * fails the run.
 */
async function buildDiffKnowledge(
  config: ScanConfig,
  layout: ScanLayout,
  runtime: ScanRuntime,
  keys: Keys,
  io: ScanIO
): Promise<Knowledge> {
  const store = io.knowledgeBaseStore;
  const cacheDir = store ? join(config.stage, KNOWLEDGE_BASE_CACHE_DIR) : undefined;
  const kbLog = (message: string): void => io.log(`knowledge base: ${redact(message, keys.all)}`);
  if (store && cacheDir) await store.restore(cacheDir, config.scannedSha, [config.diffBase]);
  io.log(
    'Building the knowledge base for the change: paths, labels, threat model, packets, briefs.'
  );
  const plan = {
    name: `${config.runName}-knowledge-base`,
    project: config.project,
    runtime,
    paths: runtime.paths(layout),
    work: join(config.stage, KNOWLEDGE_BASE_DIR),
    cynosKey: keys.cynos,
    modelCatalog: join(config.stage, MODEL_CATALOG_FILE),
    base: config.diffBase,
    plugin: () => runtime.bundledPlugin(config.stage),
    step: (step: ScanStep, message: string, data?: JsonObject) =>
      io.progress?.({
        type: 'step',
        phase: 'knowledge',
        step,
        message: redact(message, keys.all),
        ...(data ? { data } : {}),
      }),
    ...(cacheDir ? { cacheDir } : {}),
    ...(config.baseUrl ? { baseUrl: config.baseUrl } : {}),
    ...(io.signal ? { signal: io.signal } : {}),
  };
  let diff: DiffKnowledgeBaseSummary;
  try {
    diff = await buildDiffKnowledgeBase(plan, kbLog, cynosModels(plan));
  } catch (error) {
    throw new Error(
      `The knowledge base could not be built, so no scan was started: ${error instanceof Error ? error.message : String(error)}`
    );
  }
  io.log(`Knowledge base built: ${JSON.stringify(diff)}`);
  io.progress?.({ type: 'cost', source: 'knowledge-base', usd: diff.cost_usd });
  const agent = diff.threat_model?.review?.agent;
  if (agent)
    io.progress?.({
      type: 'usage',
      source: 'review',
      tokens: {
        input_tokens: agent.inputTokens,
        cached_input_tokens: agent.cachedInputTokens,
        output_tokens: agent.outputTokens,
        reasoning_output_tokens: 0,
      },
    });
  const tm = diff.threat_model;
  return {
    summary: undefined,
    diff,
    diffThreatModel: { ...tm.from, update: { gate: tm.gate, updated: tm.updated } },
  };
}

/**
 * 4. The brief: the workflow and the prompt at the runtime's paths, and the rules every agent
 * follows for every helper to print first.
 */
function writeBrief(
  config: ScanConfig,
  layout: ScanLayout,
  runtime: ScanRuntime,
  keys: Keys,
  inputs: ScanInputs
): Brief {
  const prompt = writeRunFiles(config, layout, runtime, inputs);
  if (!keys.callsModel) return { text: prompt.text, helperContext: false };
  writeFileSync(join(config.stage, HELPER_CONTEXT_FILE), prompt.helperContext, { mode: 0o600 });
  return { text: prompt.text, helperContext: true };
}

/** upstream's scan options for this config, with what the knowledge phase gave it. */
export function scanOptions(
  config: ScanConfig,
  knowledge: Knowledge | undefined,
  writtenHelperContext: boolean,
  inputs: Pick<ScanInputs, 'rubric' | 'falsePositives'> = { falsePositives: [] }
): ScanOptions {
  const knowledgeBaseBuilt = Boolean(knowledge?.summary || knowledge?.diff);
  return {
    paths: config.paths,
    diffBase: config.diffBase,
    // A diff's knowledge base holds the threat model, in place of the repository's file; a diff
    // without one (--no-knowledge-base) gives upstream the file as it is.
    knowledgeBase: knowledge?.diff ? '' : config.knowledgeBase,
    model: config.model,
    effort: config.effort,
    mode: config.mode,
    cyberAccessProgram: config.cyberAccessProgram,
    maxTimeHours: config.maxTimeHours,
    failOnSeverity: config.failOnSeverity,
    verbose: config.verbose,
    dryRun: config.dryRun,
    mock: config.mock,
    knowledgeBaseBuilt,
    helperContext: writtenHelperContext,
    // Every run, the preflight's too, has its plugin written (writeRunFiles), but our workflow reads
    // the knowledge base's index, threat model and briefs: without one (--no-knowledge-base, a mock
    // or a dry run) upstream runs its own.
    plugin: knowledgeBaseBuilt,
    rubric: inputs.rubric !== undefined,
    falsePositives: inputs.falsePositives.length > 0,
    judge: config.judge,
    taskRouting: config.taskRouting,
    interactive: config.interactive,
    ...(config.baseUrl ? { baseUrl: config.baseUrl } : {}),
  };
}

/**
 * upstream's result. Headless, it is the --json result on stdout. With the dashboard there is
 * none, so the parts classify() reads are rebuilt from the scan dir upstream wrote: its manifest,
 * and the review summary the manifest carries, are the result's own (dist/result.js toJSON).
 */
function upstreamResult(stage: string, scanDir: string): JsonObject {
  const printed = readJson(join(stage, 'stdout.json'));
  if (printed) return printed;
  const manifest = readJson(join(scanDir, 'scan-manifest.json'));
  if (!manifest) return {};
  const review = at(manifest, 'scan', 'review');
  return { manifest, ...(review ? { review } : {}), scanDir };
}

/** 5. The scan on the runtime; upstream's outcome rules; run.json. */
async function runUpstreamScan(
  config: ScanConfig,
  staged: ScanLayout,
  runtime: ScanRuntime,
  brief: Brief,
  knowledge: Knowledge,
  keys: Keys,
  inputs: ScanInputs,
  io: ScanIO
): Promise<Scanned> {
  stopped(io);
  // The scan dir, where the runtime creates it before upstream starts (native).
  const layout = runtime.createScanDir(staged);
  const options = scanOptions(config, knowledge, brief.helperContext, inputs);
  const command = runtime.scanCommand(
    layout,
    options,
    'scan',
    keys.callsModel ? keys.cynos : undefined
  );
  io.log(`Starting ${config.dryRun ? 'CLI configuration validation' : 'security scan'}.`);
  // upstream takes the terminal now: a live display must let go of it first.
  if (config.interactive) io.progress?.({ type: 'handoff', phase: 'scan' });
  const scannerRun = await runScan({
    command,
    runtime,
    stage: config.stage,
    // A shared state dir holds other scans' sessions: count only this scan dir's.
    usage: layout.privateState
      ? { state: layout.stateDir }
      : { state: join(layout.stateDir, 'codex-home'), cwd: layout.scanDir },
    verbose: config.verbose,
    interactive: config.interactive,
    log: io.log,
    ...(io.progress ? { progress: (event: ScanEvent) => io.progress?.(event) } : {}),
    ...(io.signal ? { signal: io.signal } : {}),
  });
  io.progress?.({ type: 'usage', source: 'scan', tokens: scannerRun.usage });

  // The outcome, by upstream's rules, from the validated reports.
  const reports = validateReports(config.stage, layout.scanDir);
  const findings = reports.findings;
  const result = upstreamResult(config.stage, layout.scanDir);
  // Empty means unavailable, not zero: the CLI prices no cynos model id.
  const estimatedCost = cliEstimatedCost(result);
  const stderr = isFile(join(config.stage, 'stderr.log'))
    ? readFileSync(join(config.stage, 'stderr.log'), 'utf8')
    : '';
  const outcome: Outcome = classify(
    scannerRun,
    result,
    reports.findingsProblem,
    stderr,
    config.scannedSha,
    config.dryRun
  );
  const counts = outcome.scanStatus === 'completed' ? severityCounts(findings) : undefined;
  const runJson: JsonObject = {
    ...config.runRecord,
    runtime: config.runtime,
    diff_base: config.diffBase,
    knowledge_base: config.knowledgeBase,
    knowledge_base_build: knowledge.summary ?? knowledge.diff ?? null,
    scan_inputs: scanInputsRecord(inputs),
    diff_threat_model: config.kind === 'diff' ? (knowledge.diffThreatModel ?? null) : undefined,
    scanned_sha: config.scannedSha,
    scan_dir: layout.scanDir,
    outcome,
    exit_code: scannerRun.exitCode,
    counts,
    elapsed_seconds: scannerRun.elapsedSeconds,
    tokens: scannerRun.usage,
    estimated_cost_usd: estimatedCost ?? null,
    command: command.argv,
  };
  writeFileSync(join(config.stage, 'run.json'), `${JSON.stringify(runJson, null, 2)}\n`);
  const scanned: ScannedRun = { outcome, scannerRun, estimatedCost, counts };
  io.scanned?.(scanned);
  return { scanned, layout, reports, result, knowledge, runJson };
}

/** What run.json says of the caller's inputs: the rubric by its hash, the dismissals by count. */
export function scanInputsRecord(inputs: ScanInputs): JsonObject {
  return {
    rubric_sha256:
      inputs.rubric === undefined
        ? null
        : createHash('sha256').update(inputs.rubric, 'utf8').digest('hex'),
    false_positives: inputs.falsePositives.length,
  };
}

/** upstream's scan id: the manifest's, from the result or the scan dir. */
function scanIdOf(result: JsonObject): string | null {
  const manifest = result['manifest'] as { scan?: { id?: unknown } } | undefined;
  return typeof manifest?.scan?.id === 'string' ? manifest.scan.id : null;
}

/**
 * 6. Reports: SARIF, then, when the caller publishes, the key-leak check over everything that
 * could be published (the stage, and a scan dir outside it).
 */
async function reportScan(
  config: ScanConfig,
  runtime: ScanRuntime,
  run: Scanned,
  versions: Record<string, unknown>,
  keys: Keys,
  io: ScanIO
): Promise<ScanResult> {
  const { scanned, layout, reports, knowledge } = run;
  const available = scanned.outcome.scanStatus === 'completed';

  // The strict SARIF export, validated like every other report.
  const sarif =
    available && exportSarif(runtime, layout) ? validateSarif(config.stage, reports) : '';
  if (available && !sarif)
    io.warn(
      'SARIF report is missing, unsafe, or unreadable; scan results and other reports are still available.'
    );
  for (const problem of reports.problems) io.warn(`Report withheld: ${problem}`);

  // The leak check guards what is published; a caller that keeps results local skips it.
  // stage/out holds the docker runtime's scan dir; a native scan dir lives in a state dir.
  const inOut = !relative(join(config.stage, 'out'), layout.scanDir).startsWith('..');
  const outside = layout.scanDir && !inOut ? [layout.scanDir] : [];
  const leaked =
    config.publishes && keys.callsModel ? filesContaining(config.stage, keys.cynos, outside) : [];
  if (leaked.length)
    io.error(`A key was found in scan outputs (${leaked.join(', ')}); no report is published.`);

  const scanId = scanIdOf(run.result);
  io.progress?.({
    type: 'outcome',
    scanStatus: scanned.outcome.scanStatus,
    scanId,
    scanDir: layout.scanDir || null,
  });
  return {
    ...scanned,
    scanId,
    scanDir: layout.scanDir,
    exitCode: scanned.scannerRun.exitCode,
    reports,
    findings: reports.findings,
    sarif,
    leaked,
    knowledgeBaseBuilt: Boolean(knowledge.summary || knowledge.diff),
    knowledgeBase: knowledge.summary ?? knowledge.diff,
    diffThreatModel: knowledge.diffThreatModel,
    versions,
    usage: scanned.scannerRun.usage,
    seconds: scanned.scannerRun.elapsedSeconds,
    cost: {
      scan_usd: scanned.estimatedCost ?? null,
      knowledge_base_usd: (knowledge.summary ?? knowledge.diff)?.cost_usd ?? null,
    },
    runJson: run.runJson,
    stateDirs: [
      layout.privateState ? layout.stateDir : join(layout.stateDir, 'codex-home'),
      ...(knowledge.summary || knowledge.diff?.threat_model?.updated
        ? [join(config.stage, KNOWLEDGE_BASE_DIR, 'review', 'home')]
        : []),
    ],
  };
}
