/**
 * The benchmark CLI: one codex-security scan of a staged checkout, outside GitHub.
 *
 * A benchmark (RealVuln's kbcodexsecurity lane) runs the action's own pipeline (image, knowledge
 * base, prompt, hardening) on many staged repositories and scores the findings. It needs none of
 * the GitHub around the scan, and three things the action never needs:
 *
 *   - Docker through the host's socket: the harness runs in its own container, so a bind mount's
 *     source must be the host's path of a directory this process sees elsewhere (--host-path);
 *   - a time limit per scan that stops its containers (--timeout);
 *   - everything kept as evidence, and one result.json to read (the action deletes its stage).
 *
 *   build-image   builds (or pulls) the scanner image once, before the first scan
 *   scan          one full scan of --project into --out, then <out>/result.json; on the docker
 *                 runtime by default, or natively (--runtime native) with upstream's state dir
 *                 kept under --out as evidence
 *   doctor        whether this machine can scan on a runtime (host-check.ts), and --fix
 *
 * The key comes from the environment only (CYNOS_API_KEY), and is removed from it once
 * read, so a child process gets it only where the scanner needs it. Nothing under --out is deleted. Before result.json is written, every file under --out is
 * searched for the keys and any value found is replaced in place, so the evidence can be kept.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { DEFAULT_MODEL, KEY_VARIABLE } from '../constants';
import { checkHost, fixHost, FIXABLE_CHECKS, type HostCheck } from '../host-check';
import type { JsonObject } from '../json';
import { LocalKnowledgeBaseStore } from '../knowledge-base/store';
import { safeLogLines } from '../log-lines';
import { containerNames, redact, scanCheckout, type ScanResult } from '../pipeline';
import { ProcessRegistry, stopProcesses } from '../processes';
import { RUNTIMES, type RuntimeName } from '../runtime';
import { killContainer, provideImage, verifyProfiles, type HostPaths } from '../runtime/docker';
import type { Usage } from '../scan-run';

/** A usage error: the arguments or the environment are wrong, and nothing ran. */
export class UsageError extends Error {}

/** The scan's settings from the command line (keys are never among them). */
export interface BenchScanArgs {
  project: string;
  out: string;
  name: string;
  model: string;
  effort: string;
  baseUrl?: string;
  judge: boolean;
  routing: boolean;
  cacheDir?: string;
  timeoutSeconds: number;
  promptAddendum?: string;
  hostPaths: HostPaths;
  apparmor: boolean;
  /** USD per 1M tokens: uncached input, cached input, output. */
  price?: [number, number, number];
  assets: string;
  /** Where upstream runs: the hardened container (default), or natively on the host. */
  runtime: RuntimeName;
}

/** The package's assets beside the script node runs (dist/bench.js, so dist/assets). */
export function assetsBeside(script = process.argv[1] ?? ''): string {
  return resolve(dirname(script), 'assets');
}

/** --runtime native|docker (|all where allowed). */
function parseRuntime(value: string | undefined, all = false): RuntimeName | 'all' {
  if (value === undefined) return 'docker';
  if ((RUNTIMES as readonly string[]).includes(value) || (all && value === 'all'))
    return value as RuntimeName | 'all';
  throw new UsageError(`--runtime takes ${RUNTIMES.join(', ')}${all ? ' or all' : ''}`);
}

function onOff(name: string, value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  if (value !== 'on' && value !== 'off') throw new UsageError(`--${name} takes on or off`);
  return value === 'on';
}

/** --host-path C=H: the directory C here is H on the Docker host. */
export function parseHostPaths(values: string[]): HostPaths {
  return values.map(value => {
    const [here, host, ...rest] = value.split('=');
    if (!here?.startsWith('/') || !host?.startsWith('/') || rest.length)
      throw new UsageError(`--host-path takes /path/here=/path/on/host, not ${value}`);
    // Trailing slashes go, but the root stays the root.
    return [here.replace(/\/+$/, '') || '/', host.replace(/\/+$/, '') || '/'];
  });
}

/** --price IN,CACHED,OUT in USD per 1M tokens. */
export function parsePrice(value: string | undefined): [number, number, number] | undefined {
  if (value === undefined) return undefined;
  const parts = value.split(',').map(Number);
  if (parts.length !== 3 || parts.some(p => !Number.isFinite(p) || p < 0))
    throw new UsageError('--price takes three USD amounts per 1M tokens: input,cached,output');
  return parts as [number, number, number];
}

/** The scan command's arguments; throws UsageError on anything missing or malformed. */
export function parseScanArgs(argv: string[], script = process.argv[1] ?? ''): BenchScanArgs {
  const { values } = parseArgs({
    args: argv,
    strict: true,
    options: {
      project: { type: 'string' },
      out: { type: 'string' },
      name: { type: 'string' },
      model: { type: 'string', default: DEFAULT_MODEL },
      effort: { type: 'string', default: 'xhigh' },
      'base-url': { type: 'string' },
      judge: { type: 'string' },
      routing: { type: 'string' },
      'cache-dir': { type: 'string' },
      timeout: { type: 'string', default: '0' },
      'prompt-addendum': { type: 'string' },
      'host-path': { type: 'string', multiple: true, default: [] },
      apparmor: { type: 'boolean', default: false },
      price: { type: 'string' },
      assets: { type: 'string' },
      runtime: { type: 'string' },
    },
  });
  for (const required of ['project', 'out', 'name'] as const)
    if (!values[required]) throw new UsageError(`--${required} is required`);
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(values.name ?? ''))
    throw new UsageError('--name must be a Docker container name: letters, digits, _ . -');
  const timeoutSeconds = Number(values.timeout);
  if (!Number.isInteger(timeoutSeconds) || timeoutSeconds < 0)
    throw new UsageError('--timeout takes whole seconds (0 = no limit)');
  const baseUrl = values['base-url']?.replace(/\/+$/, '');
  if (baseUrl !== undefined && !/^https?:\/\/[^\s"]+$/.test(baseUrl))
    throw new UsageError('--base-url must be an http(s) URL');
  const price = parsePrice(values.price);
  return {
    project: resolve(values.project ?? ''),
    out: resolve(values.out ?? ''),
    name: values.name ?? '',
    model: values.model ?? DEFAULT_MODEL,
    effort: values.effort ?? 'xhigh',
    judge: onOff('judge', values.judge, true),
    routing: onOff('routing', values.routing, true),
    timeoutSeconds,
    hostPaths: parseHostPaths(values['host-path'] ?? []),
    apparmor: values.apparmor ?? false,
    assets: resolve(values.assets ?? assetsBeside(script)),
    runtime: parseRuntime(values.runtime) as RuntimeName,
    ...(baseUrl ? { baseUrl } : {}),
    ...(values['cache-dir'] ? { cacheDir: resolve(values['cache-dir']) } : {}),
    ...(values['prompt-addendum'] ? { promptAddendum: resolve(values['prompt-addendum']) } : {}),
    ...(price ? { price } : {}),
  };
}

/** Reads a key from the environment and removes it there, so no child process inherits it. */
export function takeKey(name: string, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const value = env[name];
  delete env[name];
  if (value !== undefined && (!value || /[\r\n\u0000]/.test(value)))
    throw new UsageError(`${name} is empty or holds a line break`);
  return value;
}

/**
 * Replaces every key value found in a file under root with ***, and returns those files. Codex's
 * state is included: unlike the action, a benchmark keeps it.
 */
export function scrubKeys(root: string, keys: (string | undefined)[]): string[] {
  const present = keys.filter((key): key is string => !!key);
  const scrubbed: string[] = [];
  const walk = (directory: string): void => {
    let entries;
    try {
      entries = readdirSync(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (entry.isFile()) {
        let content: Buffer;
        try {
          content = readFileSync(path);
        } catch {
          continue;
        }
        if (!present.some(key => content.includes(key))) continue;
        let text = content.toString('latin1');
        for (const key of present)
          text = text.split(Buffer.from(key).toString('latin1')).join('***');
        writeFileSync(path, Buffer.from(text, 'latin1'));
        scrubbed.push(path);
      }
    }
  };
  if (present.length) walk(root);
  return scrubbed;
}

/** The checkout's commit: the scan must record scanning it. */
function headCommit(project: string): string {
  const head = spawnSync('git', ['-C', project, 'rev-parse', 'HEAD'], { encoding: 'utf8' });
  if (head.status !== 0)
    throw new UsageError(`--project must be a git checkout with a commit: ${head.stderr.trim()}`);
  return head.stdout.trim();
}

/** Tokens priced in USD per 1M: uncached input, cached input, output. */
export function priced(
  tokens: { input: number; cached: number; output: number },
  price: [number, number, number]
): number {
  const uncached = Math.max(0, tokens.input - tokens.cached);
  const usd = (uncached * price[0] + tokens.cached * price[1] + tokens.output * price[2]) / 1e6;
  return Math.round(usd * 10_000) / 10_000;
}

/**
 * What the run cost, and how each part is known. codex-security prices no cynos model id, so the
 * scan's own estimate is usually missing; with --price, the scan's tokens and the architecture
 * agent's are priced at the scan model's rate (exact when the scan model is the review model).
 * Jev's labels are priced at cynos's catalog rate (jev.ts).
 */
export function runCost(
  scan: Pick<ScanResult, 'cost' | 'usage' | 'knowledgeBase'>,
  price: [number, number, number] | undefined
): JsonObject {
  const scanUsage: Usage = scan.usage;
  // The review agent ran for a full scan's architecture review, or for a diff's threat-model update.
  const kb = scan.knowledgeBase;
  const review = kb?.kind === 'diff' ? kb.threat_model?.review : kb?.architecture_review;
  const agent = review?.agent ?? null;
  const scanUsd =
    scan.cost.scan_usd ??
    (price
      ? priced(
          {
            input: scanUsage.input_tokens,
            cached: scanUsage.cached_input_tokens,
            output: scanUsage.output_tokens,
          },
          price
        )
      : null);
  const reviewUsd =
    agent && price
      ? priced(
          {
            input: agent.inputTokens,
            cached: agent.cachedInputTokens,
            output: agent.outputTokens,
          },
          price
        )
      : agent
        ? null
        : 0;
  const jevUsd = scan.cost.knowledge_base_usd ?? 0;
  const parts = [scanUsd, reviewUsd, jevUsd];
  return {
    scan_usd: scanUsd,
    scan_source: scan.cost.scan_usd !== null ? 'cli-estimate' : price ? 'tokens-x-price' : null,
    review_agent_usd: reviewUsd,
    jev_usd: jevUsd,
    total_usd: parts.every(p => p !== null)
      ? Math.round(parts.reduce<number>((a, p) => a + (p ?? 0), 0) * 10_000) / 10_000
      : null,
  };
}

/**
 * result.json's status: a key in the outputs first (nothing may be used), then a run that was
 * stopped before it completed (the scan itself reports a stop as a failed, cancelled scan), then
 * the scan's own status; `error` when it never got that far.
 */
export function resultStatus(
  scan: Pick<ScanResult, 'leaked' | 'outcome'> | undefined,
  aborted: boolean
): string {
  if (scan?.leaked.length) return 'key-leak';
  if (aborted && scan?.outcome.scanStatus !== 'completed') return 'stopped';
  return scan ? scan.outcome.scanStatus : 'error';
}

/** The scan command: one full scan, then result.json. Returns the process exit code. */
export async function benchScan(args: BenchScanArgs, log = console.log): Promise<number> {
  const started = Date.now();
  const cynosKey = takeKey(KEY_VARIABLE);
  if (!cynosKey) throw new UsageError(`${KEY_VARIABLE} must be set in the environment`);
  const keys = [cynosKey];
  if (existsSync(args.out) && readdirSync(args.out).length)
    throw new UsageError(`--out must be a new or empty directory: ${args.out}`);
  mkdirSync(args.out, { recursive: true, mode: 0o700 });
  const out = realpathSync(args.out);
  const project = realpathSync(args.project);
  const scannedSha = headCommit(project);
  const addendum = args.promptAddendum ? readFileSync(args.promptAddendum, 'utf8') : undefined;

  // The time limit and a stop from outside both abort the run and stop its containers, or its
  // native process groups.
  const controller = new AbortController();
  const processes = new ProcessRegistry();
  const stop = (reason: string): void => {
    if (controller.signal.aborted) return;
    controller.abort(reason);
    if (args.runtime === 'docker')
      for (const name of containerNames(args.name)) killContainer(name);
    else void stopProcesses(processes);
  };
  const timer = args.timeoutSeconds
    ? setTimeout(() => stop(`timed out after ${args.timeoutSeconds}s`), args.timeoutSeconds * 1000)
    : undefined;
  const onSignal = (signal: NodeJS.Signals): void => stop(`stopped (${signal})`);
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);
  const say = (message: string): void => {
    for (const line of safeLogLines(redact(message, keys))) log(line);
  };

  let scan: ScanResult | undefined;
  let error = '';
  try {
    scan = await scanCheckout(
      {
        kind: 'full',
        diffBase: '',
        project,
        stage: out,
        assets: args.assets,
        runName: args.name,
        runtime: args.runtime,
        // upstream's state stays under --out with the rest of the evidence.
        stateDir: join(out, 'state'),
        interactive: false,
        // result.json reports a key found in the outputs as key-leak.
        publishes: true,
        scannedSha,
        knowledgeBase: '',
        cynosKey,
        buildImage: false,
        loadAppArmor: args.apparmor,
        runRecord: { kind: 'repository', reason: 'benchmark scan' },
        paths: [],
        model: args.model,
        effort: args.effort,
        mode: 'standard',
        cyberAccessProgram: '',
        maxTimeHours: undefined,
        failOnSeverity: 'none',
        verbose: false,
        dryRun: false,
        mock: false,
        judge: args.judge,
        taskRouting: args.routing,
        hostPaths: args.hostPaths,
        ...(args.baseUrl ? { baseUrl: args.baseUrl } : {}),
        ...(addendum ? { promptAddendum: addendum } : {}),
      },
      {
        log: say,
        warn: message => say(`warning: ${message}`),
        error: message => say(`error: ${message}`),
        processes,
        ...(args.cacheDir
          ? { knowledgeBaseStore: new LocalKnowledgeBaseStore(args.cacheDir, say) }
          : {}),
        signal: controller.signal,
      }
    );
  } catch (thrown) {
    error = redact(thrown instanceof Error ? thrown.message : String(thrown), keys);
  } finally {
    clearTimeout(timer);
    process.off('SIGINT', onSignal);
    process.off('SIGTERM', onSignal);
  }

  const scrubbed = scrubKeys(out, keys);
  const findings = join(out, 'reports', 'findings.json');
  const result = {
    status: resultStatus(scan, controller.signal.aborted),
    error: error || null,
    stopped: controller.signal.aborted ? String(controller.signal.reason) : null,
    outcome: scan?.outcome ?? null,
    scanned_sha: scannedSha,
    findings: scan && existsSync(findings) && !scan.leaked.length ? findings : null,
    reports_dir: join(out, 'reports'),
    sarif: scan?.sarif || null,
    run_json: scan ? join(out, 'run.json') : null,
    state_dirs: scan?.stateDirs ?? [join(out, 'state')],
    scan_id: scan?.scanId ?? null,
    scan_dir: scan?.scanDir || null,
    exit_code: scan?.exitCode ?? null,
    counts: scan?.counts ?? null,
    knowledge_base: scan?.knowledgeBase ?? null,
    usage: scan?.usage ?? null,
    cost: scan ? runCost(scan, args.price) : null,
    seconds: Math.round((Date.now() - started) / 100) / 10,
    scan_seconds: scan?.seconds ?? null,
    versions: scan?.versions ?? null,
    leaked: scan?.leaked ?? [],
    keys_scrubbed: scrubbed,
    settings: {
      model: args.model,
      effort: args.effort,
      base_url: args.baseUrl ?? null,
      judge: args.judge,
      routing: args.routing,
      timeout_seconds: args.timeoutSeconds,
      cache_dir: args.cacheDir ?? null,
      prompt_addendum_sha256: addendum ? createHash('sha256').update(addendum).digest('hex') : null,
      price_per_mtok: args.price ?? null,
      apparmor: args.apparmor,
      runtime: args.runtime,
    },
  };
  writeFileSync(join(out, 'result.json'), `${redact(JSON.stringify(result, null, 1), keys)}\n`);
  say(`result: ${result.status}${error ? `: ${error}` : ''} (${join(out, 'result.json')})`);
  return 0;
}

/**
 * The build-image command: verifies the vendored profiles, then builds the scanner image (or
 * pulls the release's, when assets/image.json names one).
 */
export function benchBuildImage(argv: string[], script = process.argv[1] ?? ''): number {
  const { values } = parseArgs({
    args: argv,
    strict: true,
    options: { assets: { type: 'string' } },
  });
  const assets = resolve(values.assets ?? assetsBeside(script));
  verifyProfiles(assets);
  const image = provideImage(assets);
  console.log(`${image} ready from ${assets}`);
  return 0;
}

/** One check as a line: its status, title and detail, then its fix. */
export function checkLine(check: HostCheck): string {
  const mark = { ok: 'ok  ', warn: 'warn', fail: 'FAIL' }[check.status];
  return `${mark}  [${check.group}] ${check.title}: ${check.detail}${check.status !== 'ok' && check.fix ? `\n        fix: ${check.fix}` : ''}`;
}

/**
 * The doctor command: the host checks for a runtime (or both), as lines or JSON; --fix repairs
 * the fixable failures first (never with sudo: --allow-sudo for the AppArmor profile). Exit 1
 * when any check fails.
 */
export async function benchDoctor(
  argv: string[],
  script = process.argv[1] ?? '',
  out: (line: string) => void = console.log
): Promise<number> {
  const { values } = parseArgs({
    args: argv,
    strict: true,
    options: {
      runtime: { type: 'string' },
      project: { type: 'string' },
      json: { type: 'boolean', default: false },
      fix: { type: 'boolean', default: false },
      'allow-sudo': { type: 'boolean', default: false },
      quick: { type: 'boolean', default: false },
      assets: { type: 'string' },
      'base-url': { type: 'string' },
      model: { type: 'string' },
    },
  });
  const selected = parseRuntime(values.runtime, true);
  const runtimes: RuntimeName[] = selected === 'all' ? [...RUNTIMES] : [selected];
  const cynosKey = takeKey(KEY_VARIABLE);
  const keys = [cynosKey];
  const report: Record<string, HostCheck[]> = {};
  for (const runtime of runtimes) {
    const options = {
      scope: 'doctor' as const,
      runtime,
      assets: resolve(values.assets ?? assetsBeside(script)),
      quick: values.quick ?? false,
      ...(values.project ? { project: resolve(values.project) } : {}),
      ...(cynosKey ? { cynosKey } : {}),
      ...(values['base-url'] ? { baseUrl: values['base-url'] } : {}),
      ...(values.model ? { model: values.model } : {}),
    };
    let checks = await checkHost(options);
    if (values.fix)
      for (const check of checks.filter(
        c => c.status !== 'ok' && (FIXABLE_CHECKS as readonly string[]).includes(c.id)
      )) {
        try {
          const fixed = await fixHost(check.id, {
            ...options,
            allowSudo: values['allow-sudo'] ?? false,
          });
          checks = checks.map(c => (c.id === check.id ? fixed : c));
        } catch (error) {
          checks = checks.map(c =>
            c.id === check.id
              ? { ...c, detail: `${c.detail}; not fixed: ${(error as Error).message}` }
              : c
          );
        }
      }
    report[runtime] = checks;
  }
  if (values.json) out(redact(JSON.stringify(report, null, 1), keys));
  else
    for (const [runtime, checks] of Object.entries(report)) {
      out(`${runtime} runtime:`);
      for (const check of checks) out(redact(checkLine(check), keys));
    }
  return Object.values(report).some(checks => checks.some(c => c.status === 'fail')) ? 1 : 0;
}

const USAGE = `usage:
  bench.js build-image [--assets DIR]
  bench.js scan --project DIR --out DIR --name NAME [--runtime docker|native] [--model ID]
                [--effort LEVEL] [--base-url URL] [--judge on|off] [--routing on|off]
                [--cache-dir DIR] [--timeout SECONDS] [--prompt-addendum FILE]
                [--host-path HERE=HOST]... [--price IN,CACHED,OUT] [--apparmor] [--assets DIR]
  bench.js doctor [--runtime docker|native|all] [--project DIR] [--json] [--fix [--allow-sudo]]
                [--quick] [--assets DIR] [--base-url URL] [--model ID]
key: CYNOS_API_KEY from the environment`;

/** The CLI's entry point; returns the exit code (2 for a usage error). */
export async function benchMain(argv: string[] = process.argv.slice(2)): Promise<number> {
  const [command, ...rest] = argv;
  try {
    if (command === 'build-image') return benchBuildImage(rest);
    if (command === 'scan') return await benchScan(parseScanArgs(rest));
    if (command === 'doctor') return await benchDoctor(rest);
    throw new UsageError(command ? `unknown command ${command}` : 'no command');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`bench: ${message}`);
    if (
      error instanceof UsageError ||
      (error as { code?: string }).code?.startsWith('ERR_PARSE_ARGS')
    ) {
      console.error(USAGE);
      return 2;
    }
    return 1;
  }
}
