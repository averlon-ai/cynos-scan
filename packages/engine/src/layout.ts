/**
 * Where a scan's files live on this machine: the stage, upstream's state dir and the scan dir.
 *
 * A scan has three places, and the runtime decides two of them:
 *
 *   stage      the caller's private directory for this run: the prompt, the model catalog, the
 *              knowledge base, the reports, run.json. The same files for both runtimes.
 *   state dir  upstream's own: its history (workbench.sqlite3), its Codex home, and by default
 *              its scan dirs. The docker runtime keeps one inside the stage (<stage>/state), as
 *              the action always has; the native runtime uses upstream's default
 *              (resolveStateDir) or the caller's path, as `codex-security` does on a laptop.
 *   scan dir   the directory upstream writes one scan's artifacts to (--output-dir). The docker
 *              runtime gives <stage>/out/scan, which upstream creates. The native runtime creates
 *              it where upstream would have (createScanDir), so the engine knows it before the
 *              scan starts and history lists the scan as upstream's own.
 *
 * The preflight is a run of upstream too, with a workspace of its own under the stage
 * (<stage>/preflight): its state dir and scan dir always stay there, so a check that is stopped
 * on purpose never reaches upstream's history.
 */
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CODEX_TMP_DIR } from './constants';
import { runCommand, type Runner } from './processes';

/** This run's scan prompt, the caller's addendum, written into its workspace (pipeline.ts). */
export const RUN_PROMPT_FILE = 'prompt.md';
/** upstream's plugin with this scan's skill (scan-plugin.ts), copied into the run's workspace. */
export const PLUGIN_DIR = 'plugin';
/** upstream's package.json and bundled plugin, copied out of the scanner image (docker runtime). */
export const UPSTREAM_PLUGIN_DIR = 'upstream-plugin';
/** The prompt's helper sections, written into the stage for a scan that calls the model. */
export const HELPER_CONTEXT_FILE = 'helper-context.md';
/** Where the knowledge base is built, under the stage; the scan reads its output/ and kb/. */
export const KNOWLEDGE_BASE_DIR = 'knowledge-base';
/** The model catalog's name in a workspace. */
export const MODEL_CATALOG_FILE = 'model-catalog.json';
/** The knowledge-base cache's working directory under the stage, which a store fills and saves. */
export const KNOWLEDGE_BASE_CACHE_DIR = 'knowledge-base-cache';
/** The preflight's workspace under the stage. */
export const PREFLIGHT_DIR = 'preflight';

/**
 * The engine's own assets/, for unbundled use (the tests, a checkout). A host that bundles the
 * engine passes its copy as ScanConfig.assets instead: in a bundle this module's URL is the
 * bundle's, not the engine's.
 */
export function engineAssets(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), '..', 'assets');
}

/** One run of upstream on this machine: the scan, or the preflight. */
export interface ScanLayout {
  /** The checkout. */
  project: string;
  /** This run's private directory. */
  stage: string;
  /** Holds this run's prompt (and, for the docker runtime, out/ and state/): the stage or <stage>/preflight. */
  workspace: string;
  /** upstream's state dir for this run. */
  stateDir: string;
  /** Whether the runtime hands stateDir to upstream as CODEX_SECURITY_STATE_DIR. */
  setsStateDir: boolean;
  /** stateDir belongs to this run alone (in the stage); else other scans' sessions share it. */
  privateState: boolean;
  /** The scan dir: set once it is known (createScanDir), else where upstream will create it. */
  scanDir: string;
}

/** value with a leading ~ or ~/ taken as the home directory, as upstream's expandHome reads it. */
export function expandHome(value: string, env: NodeJS.ProcessEnv = process.env): string {
  const home = env['HOME']?.trim() || homedir();
  if (value === '~') return home;
  if (value.startsWith('~/')) return join(home, value.slice(2));
  return value;
}

/** An environment variable as upstream reads one: unset when empty or blank. */
function setting(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const value = env[name];
  return value !== undefined && value.trim() !== '' ? value : undefined;
}

/**
 * upstream's state dir: CODEX_SECURITY_STATE_DIR, else $CODEX_HOME/state/plugins/codex-security,
 * CODEX_HOME defaulting to ~/.codex (codexSecurityStateDirectory in dist/runtime.js).
 */
export function resolveStateDir(env: NodeJS.ProcessEnv = process.env): string {
  const configured = setting(env, 'CODEX_SECURITY_STATE_DIR');
  if (configured !== undefined) return resolve(expandHome(configured, env));
  const codexHome = setting(env, 'CODEX_HOME') ?? join(homedir(), '.codex');
  return resolve(expandHome(codexHome, env), 'state', 'plugins', 'codex-security');
}

/** A repository name as upstream puts it in a path (safePrefix in dist/runtime.js). */
export function safePrefix(value: string): string {
  return basename(value).replace(/[^A-Za-z0-9._-]/g, '-') || 'repository';
}

/**
 * Creates this scan's scan dir where upstream would have made it without --output-dir:
 * <state dir>/scans/<repository>/codex-security-<repository>-XXXXXX, private to this user
 * (preparePersistentOutputRoot and prepareOutputDir in dist/runtime.js). Returns its real path.
 */
export function createScanDir(stateDir: string, project: string): string {
  const name = safePrefix(project);
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  let root = realpathSync(stateDir);
  for (const directory of ['scans', name]) {
    root = join(root, directory);
    mkdirSync(root, { recursive: true, mode: 0o700 });
  }
  const scanDir = mkdtempSync(join(root, `codex-security-${name}-`));
  // upstream refuses a scan dir others can read; mkdtemp honours the umask only.
  chmodSync(scanDir, 0o700);
  return realpathSync(scanDir);
}

/**
 * Creates out/, state/home/ and state/codex-home/tmp/ under workspace, private to this user. The
 * last is where the docker runtime mounts a tmpfs (runtime/docker.ts, mounts); Docker would
 * otherwise create the mountpoint, and on Linux the Codex home above it, as root.
 */
export function prepareWorkspace(workspace: string): void {
  mkdirSync(join(workspace, 'out'), { recursive: true, mode: 0o700 });
  mkdirSync(join(workspace, 'state', 'home'), { recursive: true, mode: 0o700 });
  mkdirSync(join(workspace, 'state', CODEX_TMP_DIR), { recursive: true, mode: 0o700 });
}

/**
 * Deletes what the run staged, except the validated reports when keepReports is set: later steps
 * read those through the action's outputs (upload-sarif, for one). Everything else goes: Codex's
 * state (session transcripts, which can hold credentials), the scanner's raw output and the
 * logs. A run whose outputs held the key passes keepReports false.
 */
export function discardWorkspace(
  stage: string,
  keepReports: boolean,
  run: Runner = runCommand
): void {
  if (!existsSync(stage)) return;
  // Codex's sandbox can leave read-only directories.
  run('chmod', ['-R', 'u+w', stage]);
  for (const entry of readdirSync(stage))
    if (!(keepReports && entry === 'reports'))
      rmSync(join(stage, entry), { recursive: true, force: true });
  if (!keepReports) rmSync(stage, { recursive: true, force: true });
}
