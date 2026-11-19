/**
 * The CLI's settings from the environment, and where it keeps its files.
 *
 * Storage follows upstream: a native scan's history and scan dir live in upstream's state dir
 * (CODEX_SECURITY_STATE_DIR, else $CODEX_HOME/state/plugins/codex-security), which the CLI
 * never overrides for it. Everything else lives beside them, under <state>/averlon/:
 *
 *   <state>/averlon/scans/<run name>/    a scan's run dir, on either runtime: its result, the
 *                                        engine's validated reports and run.json, the briefs,
 *                                        the CLI's log, events and timings (what `scans` reads)
 *   <state>/averlon/scans/<scan id>      a link to it, once upstream's scan id is known
 *   <state>/averlon/knowledge-base-cache/  the knowledge-base snapshots between scans
 *
 * The saved login, where no keychain holds it, is the CLI's own, under ~/.config/averlon/cynos/;
 * the update check's cache is under ~/.cache/averlon/cynos/.
 */
import { homedir } from 'node:os';
import { join } from 'node:path';
import { RUNTIMES, type Runtime } from './engine';
import { CliError } from './exit-codes';

/** Every environment variable the CLI reads, for `help env`, the README and --llms. */
export const ENVIRONMENT: [name: string, effect: string][] = [
  ['CYNOS_API_KEY', 'The cynos key; takes precedence over the saved login.'],
  ['CYNOS_BASE_URL', 'The cynos endpoint (default: https://api.cynos.averlon.ai/v1).'],
  ['CYNOS_SCAN_RUNTIME', 'The default runtime: native (default) or docker.'],
  ['CYNOS_LOG_LEVEL', 'debug for diagnostics; passed to upstream as CODEX_SECURITY_LOG_LEVEL.'],
  ['CYNOS_CREDENTIAL_STORE', 'keychain (default where available) or file.'],
  ['CYNOS_NO_UPDATE_NOTICE', 'Set to turn off the daily update notice.'],
  ['NO_UPDATE_NOTIFIER', 'Set to turn off the daily update notice.'],
  ['CI', 'Set in CI: no prompts, no live view, no update notice.'],
  ['NO_COLOR', 'Set to turn off colour.'],
  [
    'CODEX_SECURITY_STATE_DIR',
    "upstream's state dir: native scans' history, and every scan's run dir under averlon/.",
  ],
  [
    'CODEX_HOME',
    "Codex's home; the state dir defaults to $CODEX_HOME/state/plugins/codex-security.",
  ],
];

/**
 * The most hypothesis packets a full scan with a knowledge base starts, the hypotheses shared out
 * between them: CYNOS_SCAN_HYPOTHESES, else unset for the engine's default. Undocumented on purpose
 * (not in ENVIRONMENT): an experiment's setting until hypotheses are measured beyond php-src.
 */
export function maxHypothesisPackets(env: NodeJS.ProcessEnv = process.env): number | undefined {
  const value = env['CYNOS_SCAN_HYPOTHESES'] || undefined;
  if (value === undefined) return undefined;
  if (!/^\d+$/.test(value.trim()))
    throw new CliError('usage', `CYNOS_SCAN_HYPOTHESES takes a whole number, not ${value}`);
  return Number(value);
}

/**
 * cynos's switches a scan can turn off, each with CYNOS_SCAN_NO_<SWITCH>=1: the quality judge, the
 * task routing, and the knowledge base (a scan on upstream's own threat model). Undocumented on
 * purpose (not in ENVIRONMENT), like CYNOS_SCAN_MODEL: they exist for benchmarks and debugging, and
 * a user's scan should run with all three.
 */
export function scanSwitches(env: NodeJS.ProcessEnv = process.env): {
  judge: boolean;
  routing: boolean;
  knowledgeBase: boolean;
} {
  return {
    judge: !switchedOff(env, 'CYNOS_SCAN_NO_JUDGE'),
    routing: !switchedOff(env, 'CYNOS_SCAN_NO_ROUTING'),
    knowledgeBase: !switchedOff(env, 'CYNOS_SCAN_NO_KNOWLEDGE_BASE'),
  };
}

/**
 * Set to 1 turns the switch off; any other value is a typo that would run the scan with it on, so
 * it is refused. Empty is unset, as for every variable the CLI reads (CYNOS_SCAN_RUNTIME, NO_COLOR):
 * a workflow that maps an optional input to the variable sets it to "" when the input is not given.
 */
function switchedOff(env: NodeJS.ProcessEnv, name: string): boolean {
  const value = env[name];
  if (!value) return false;
  if (value === '1') return true;
  throw new CliError('usage', `${name} takes 1, not ${value}`);
}

/** The runtime a scan uses unless --runtime says otherwise: CYNOS_SCAN_RUNTIME, else native. */
export function defaultRuntime(env: NodeJS.ProcessEnv = process.env): Runtime {
  return parseRuntime(env['CYNOS_SCAN_RUNTIME'] || 'native', 'CYNOS_SCAN_RUNTIME');
}

export function parseRuntime(value: string, source = '--runtime'): Runtime {
  if ((RUNTIMES as readonly string[]).includes(value)) return value as Runtime;
  throw new CliError('usage', `${source} must be native or docker, not ${value}`);
}

/**
 * upstream's log level for this run: CYNOS_LOG_LEVEL, else debug for --verbose. upstream
 * reads it as CODEX_SECURITY_LOG_LEVEL, which every child process inherits.
 */
export function upstreamLogLevel(env: NodeJS.ProcessEnv, verbose: boolean): string | undefined {
  return env['CYNOS_LOG_LEVEL'] || (verbose ? 'debug' : undefined);
}

/** In CI: no prompts, no live view, no update notice. */
export function inCI(env: NodeJS.ProcessEnv = process.env): boolean {
  return Boolean(env['CI']) && env['CI'] !== 'false' && env['CI'] !== '0';
}

export function configDir(env: NodeJS.ProcessEnv = process.env, home = homedir()): string {
  return join(env['XDG_CONFIG_HOME'] || join(home, '.config'), 'averlon', 'cynos');
}

export function cacheDir(env: NodeJS.ProcessEnv = process.env, home = homedir()): string {
  return join(env['XDG_CACHE_HOME'] || join(home, '.cache'), 'averlon', 'cynos');
}

/** Our part of upstream's state dir. */
export function averlonDir(stateDir: string): string {
  return join(stateDir, 'averlon');
}

/**
 * The run dirs: one per scan, under its run name, with a link named by upstream's scan id
 * beside it once the id is known (linkScanId).
 */
export function runsDir(stateDir: string): string {
  return join(averlonDir(stateDir), 'scans');
}

export function knowledgeBaseCacheDir(stateDir: string): string {
  return join(averlonDir(stateDir), 'knowledge-base-cache');
}

/**
 * A native mock scan's own upstream state dir, inside its run dir (scanConfig): its synthetic
 * findings stay out of upstream's history.
 */
export const MOCK_STATE_DIR = 'mock-state';

/** The files the CLI writes into a run dir, beside the engine's own. */
export const RUN_FILES = {
  log: 'cli.log',
  events: 'events.jsonl',
  timings: 'timings.json',
  result: 'cli-result.json',
} as const;
