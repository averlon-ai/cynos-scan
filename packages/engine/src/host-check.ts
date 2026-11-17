/**
 * Whether this machine can run a scan on a runtime, and what to do when it cannot.
 *
 * A scan that fails on the host fails late and says the wrong thing: upstream reports a sandbox
 * Bubblewrap refused, or a Python it could not use, as a model it cannot access, after the stage
 * and often the knowledge base have run. So the same checks answer two questions:
 *
 *   doctor   "will my next scan work?": every check, grouped as the output is (common, then the
 *            runtime's), with the exact fix for each failure
 *   scan     the scan's preflight: the checks that are not the preflight's own steps (it runs
 *            upstream's sandbox check and the key check itself) and need no network; any
 *            failure stops the scan with its fix
 *
 *   common   Node (in upstream's engines range, and Node rather than Bun), upstream and its pins,
 *            upstream's state dir (private, outside the checkout, not under /tmp on macOS), the
 *            checkout (a git work tree, clean, shallow or not), and with the key, cynos reachable
 *            and the key valid
 *   native   Python 3.10+ (tomli on 3.10), git, upstream's sandbox probe (`codex sandbox --
 *            /usr/bin/true`: Seatbelt on macOS, Bubblewrap on Linux), the code-graph binary
 *   docker   the daemon and its version, the scanner image, the seccomp profile accepted
 *            (upstream's container check), AppArmor on Linux
 *
 * Every external call (commands, HTTP, the file system, upstream's resolution) goes through
 * HostDeps, so the checks are tested without the machine they describe. fixHost repairs what
 * can be repaired without a decision: the code-graph binary, the image, the state dir, and
 * upstream's AppArmor profile, which needs sudo and so only runs when the caller allows it.
 */
import { lstatSync, mkdirSync, readFileSync, realpathSync, chmodSync } from 'node:fs';
import { relative, resolve } from 'node:path';
import { APPARMOR_PROFILE_NAME, DEFAULT_MODEL } from './constants';
import { checkKey, keyCheckFailure, type Fetch } from './key-check';
import {
  codeGraphBinaryState,
  codeGraphPin,
  defaultToolCache,
  ensureCodeGraphBinary,
  platformKey,
  type CodeGraphState,
} from './knowledge-base/code-graph-binary';
import { engineAssets, resolveStateDir } from './layout';
import { runCommand, type Runner } from './processes';
import type { RuntimeName } from './runtime';
import {
  appArmorProfileLoaded,
  dockerEnvironment,
  dockerPlatform,
  foreignImage,
  imageReference,
  loadAppArmor,
  provideImage,
  upstreamSandboxCheck,
} from './runtime/docker';
import { stderrTail } from './sandbox';
import {
  nodeExecutable,
  resolveUpstream,
  UPSTREAM_PIN,
  verifyUpstream,
  type Upstream,
} from './upstream';

export type HostCheckGroup = 'common' | 'native' | 'docker';
export type HostCheckStatus = 'ok' | 'warn' | 'fail';

export interface HostCheck {
  id: string;
  group: HostCheckGroup;
  status: HostCheckStatus;
  title: string;
  detail: string;
  /** What to do about a warn or fail: a command or a setting. */
  fix?: string;
}

export interface HostCheckOptions {
  scope: 'doctor' | 'scan';
  runtime: RuntimeName;
  /** The checkout the scan reads. */
  project?: string;
  /** upstream's state dir; resolveStateDir's by default. */
  stateDir?: string;
  cynosKey?: string;
  baseUrl?: string;
  model?: string;
  /** Skip what is slow: the network, the sandbox probes. */
  quick?: boolean;
  /** The engine's assets (docker: the image and profiles); the engine's own by default. */
  assets?: string;
  /** Where upstream is resolved from (resolveUpstream). */
  upstream?: string;
  /** Where the code-graph binary is kept. */
  toolCache?: string;
}

/** The checks fixHost can repair. */
export const FIXABLE_CHECKS = [
  'state-dir',
  'code-graph',
  'docker-image',
  'docker-apparmor',
] as const;

/** Everything a check reaches outside this process. */
export interface HostDeps {
  run: Runner;
  fetch: Fetch;
  env: NodeJS.ProcessEnv;
  platform: NodeJS.Platform;
  /** This process runs on Bun (the engine's tests), not Node. */
  isBun: boolean;
  /** The version of the Node that runs upstream (nodeExecutable). */
  nodeVersion: () => string;
  resolveUpstream: (from?: string) => Upstream;
  /** A path's mode and owner, or undefined when it does not exist. */
  stat: (path: string) => { mode: number; uid: number; isDirectory: boolean } | undefined;
  realpath: (path: string) => string;
  readFile: (path: string) => string | undefined;
  codeGraphState: (toolCache: string) => CodeGraphState;
  uid: number | undefined;
}

const realDeps = (): HostDeps => ({
  run: runCommand,
  fetch: (url, init) => fetch(url, init),
  env: process.env,
  platform: process.platform,
  isBun: Boolean(process.versions['bun']),
  nodeVersion: () =>
    process.versions['bun']
      ? runCommand(nodeExecutable(), ['--version']).stdout.trim()
      : process.version,
  resolveUpstream,
  stat: path => {
    try {
      const s = lstatSync(path);
      return { mode: s.mode, uid: s.uid, isDirectory: s.isDirectory() };
    } catch {
      return undefined;
    }
  },
  realpath: path => {
    try {
      return realpathSync(path);
    } catch {
      return path;
    }
  },
  readFile: path => {
    try {
      return readFileSync(path, 'utf8');
    } catch {
      return undefined;
    }
  },
  codeGraphState: toolCache => codeGraphBinaryState(toolCache),
  uid: process.geteuid?.(),
});

type Context = { options: HostCheckOptions; deps: HostDeps };
type Check = (context: Context) => Promise<HostCheck | undefined> | HostCheck | undefined;

const ok = (id: string, group: HostCheckGroup, title: string, detail: string): HostCheck => ({
  id,
  group,
  status: 'ok',
  title,
  detail,
});
const notOk = (
  status: 'warn' | 'fail',
  id: string,
  group: HostCheckGroup,
  title: string,
  detail: string,
  fix?: string
): HostCheck => ({ id, group, status, title, detail, ...(fix ? { fix } : {}) });

/** Whether path is root or lies under it. */
function under(path: string, root: string): boolean {
  const rel = relative(root, path);
  return rel === '' || (!rel.startsWith('..') && !rel.startsWith('/'));
}

// --------------------------------------------------------------------------- //
// Common checks
// --------------------------------------------------------------------------- //

/** upstream's engines range: ^22.13.0 || ^24.0.0 || ^26.0.0. */
export function nodeInRange(version: string): boolean {
  const [major, minor] = version.replace(/^v/, '').split('.').map(Number);
  return (major === 22 && (minor ?? 0) >= 13) || major === 24 || major === 26;
}

const nodeCheck: Check = ({ options, deps }) => {
  const title = 'Node.js';
  const version = deps.nodeVersion();
  const fix = 'Install Node.js 22.13 or later, 24 or 26, first on PATH.';
  // The docker runtime's scan runs the image's Node; the host's serves history commands only.
  if (!nodeInRange(version))
    return notOk(
      options.runtime === 'native' ? 'fail' : 'warn',
      'node',
      'common',
      title,
      `upstream needs ^22.13 || ^24 || ^26; found ${version || 'none'}`,
      fix
    );
  if (deps.isBun)
    return notOk(
      'warn',
      'node',
      'common',
      title,
      `this process runs on Bun; upstream runs on Node ${version} from PATH`,
      'Run cynos with Node, not Bun.'
    );
  return ok('node', 'common', title, `Node ${version}`);
};

const upstreamCheck: Check = ({ options, deps }) => {
  const title = `${UPSTREAM_PIN.package} ${UPSTREAM_PIN.version}`;
  try {
    const upstream = deps.resolveUpstream(options.upstream);
    verifyUpstream(upstream);
    return ok(
      'upstream',
      'common',
      title,
      `${upstream.version} at ${upstream.root}; Codex ${upstream.codex.version}`
    );
  } catch (error) {
    // The docker runtime scans with the image's copy; the host's serves history commands only.
    return notOk(
      options.runtime === 'native' ? 'fail' : 'warn',
      'upstream',
      'common',
      title,
      error instanceof Error ? error.message : String(error),
      'Reinstall cynos with optional dependencies enabled (npm i -g @averlon-ai/cynos).'
    );
  }
};

const stateDirCheck: Check = ({ options, deps }) => {
  // The docker runtime's scan keeps its state in the stage; doctor still checks upstream's own,
  // which the history commands read.
  if (options.scope === 'scan' && options.runtime === 'docker') return undefined;
  const title = "upstream's state dir";
  const path = resolve(options.stateDir ?? resolveStateDir(deps.env));
  const real = deps.realpath(path);
  if (
    options.project &&
    (under(path, resolve(options.project)) || under(real, deps.realpath(options.project)))
  )
    return notOk(
      'fail',
      'state-dir',
      'common',
      title,
      `${path} is inside the checkout; upstream refuses scan output there`,
      'Set CODEX_SECURITY_STATE_DIR to a directory outside the checkout.'
    );
  if (deps.platform === 'darwin' && (under(real, '/private/tmp') || under(path, '/tmp')))
    return notOk(
      'fail',
      'state-dir',
      'common',
      title,
      `${path} is under /tmp, where Codex's sandbox fails on macOS (openai/codex#32395)`,
      'Set CODEX_SECURITY_STATE_DIR to a directory under your home.'
    );
  const stat = deps.stat(path);
  if (!stat) return ok('state-dir', 'common', title, `${path} (created on first scan)`);
  if (!stat.isDirectory)
    return notOk(
      'fail',
      'state-dir',
      'common',
      title,
      `${path} is not a directory`,
      `Remove ${path}.`
    );
  if (deps.uid !== undefined && stat.uid !== deps.uid)
    return notOk(
      'fail',
      'state-dir',
      'common',
      title,
      `${path} belongs to uid ${stat.uid}, not this user`,
      'Use a state dir of your own (CODEX_SECURITY_STATE_DIR).'
    );
  if ((stat.mode & 0o077) !== 0)
    return notOk(
      'warn',
      'state-dir',
      'common',
      title,
      `${path} is readable by other users (mode ${(stat.mode & 0o777).toString(8)})`,
      `chmod 700 ${path}`
    );
  return ok('state-dir', 'common', title, path);
};

const checkoutCheck: Check = ({ options, deps }) => {
  if (!options.project) return undefined;
  const title = 'checkout';
  const git = (...args: string[]) => deps.run('git', ['-C', options.project as string, ...args]);
  const inside = git('rev-parse', '--is-inside-work-tree');
  if (inside.status !== 0 || inside.stdout.trim() !== 'true')
    return notOk(
      'fail',
      'checkout',
      'common',
      title,
      `${options.project} is not a git work tree`,
      'Scan a git checkout with at least one commit.'
    );
  const changes = git('status', '--porcelain').stdout.split('\n').filter(Boolean).length;
  const shallow = git('rev-parse', '--is-shallow-repository').stdout.trim() === 'true';
  const detail = `${options.project}: ${changes ? `${changes} uncommitted changes` : 'clean'}, ${shallow ? 'shallow' : 'full history'}`;
  if (changes)
    return notOk(
      'warn',
      'checkout',
      'common',
      title,
      detail,
      'Commit or stash: the scan reads the committed revision.'
    );
  if (shallow)
    return notOk(
      'warn',
      'checkout',
      'common',
      title,
      detail,
      'git fetch --unshallow, for diff scans.'
    );
  return ok('checkout', 'common', title, detail);
};

/** A note on proxies Node's fetch does not use unless told to. */
function proxyNote(env: NodeJS.ProcessEnv): string {
  const proxy = env['HTTPS_PROXY'] || env['https_proxy'];
  return proxy && !env['NODE_USE_ENV_PROXY']
    ? '; HTTPS_PROXY is set, but Node ignores it unless NODE_USE_ENV_PROXY=1'
    : '';
}

const cynosCheck: Check = async ({ options, deps }) => {
  if (!options.cynosKey || options.quick || options.scope === 'scan') return undefined;
  const title = 'cynos';
  const model = options.model ?? DEFAULT_MODEL;
  const answer = await checkKey(options.cynosKey, model, deps.fetch, options.baseUrl);
  if (answer.accepted)
    return ok('cynos', 'common', title, `the key is valid for ${model} (${answer.answer})`);
  // The fix follows the refusal's cause: a spent budget or an unservable model is not a bad key.
  const { failure, fix } = keyCheckFailure(answer, model, options.baseUrl);
  return notOk('fail', 'cynos', 'common', title, `${failure}${proxyNote(deps.env)}`, fix);
};

// --------------------------------------------------------------------------- //
// Native runtime checks
// --------------------------------------------------------------------------- //

/** upstream's own Python test (usablePython in dist/runtime.js). */
const PYTHON_TEST =
  "import importlib.util,sys\nif sys.version_info < (3, 10): raise SystemExit(1)\nif sys.version_info < (3, 11) and importlib.util.find_spec('tomli') is None: raise SystemExit(1)\nprint('codex-security-python-ok')";

const pythonCheck: Check = ({ deps }) => {
  const title = 'Python';
  const candidates = deps.env['PYTHON']?.trim()
    ? [deps.env['PYTHON'].trim()]
    : ['python3', 'python'];
  for (const python of candidates) {
    const version = deps.run(python, ['--version']);
    if (version.status !== 0) continue;
    const found = (version.stdout || version.stderr).trim();
    if (deps.run(python, ['-I', '-c', PYTHON_TEST]).stdout.trim() === 'codex-security-python-ok')
      return ok('python', 'native', title, `${found} (${python})`);
    return notOk(
      'fail',
      'python',
      'native',
      title,
      `${found} (${python}): upstream's plugin needs Python 3.10 or later, and tomli on 3.10`,
      /3\.10\./.test(found) ? `${python} -m pip install tomli` : 'Install Python 3.11 or later.'
    );
  }
  return notOk(
    'fail',
    'python',
    'native',
    title,
    `no ${candidates.join(' or ')} on PATH`,
    'Install Python 3.11 or later.'
  );
};

const gitCheck: Check = ({ deps }) => {
  const version = deps.run('git', ['--version']);
  return version.status === 0
    ? ok('git', 'native', 'git', version.stdout.trim())
    : notOk('fail', 'git', 'native', 'git', 'git is not on PATH', 'Install git.');
};

/** Upstream's Ubuntu sandbox setup (github-action/README.md), which lets Bubblewrap start on 24.04 and later. */
export const LINUX_SANDBOX_FIX =
  'sudo apt-get update && sudo apt-get install --yes bubblewrap apparmor-profiles && sudo apparmor_parser -r /usr/share/apparmor/extra-profiles/bwrap-userns-restrict';

const sandboxCheck: Check = ({ options, deps }) => {
  // The scan's preflight runs this probe itself, with its real error.
  if (options.scope === 'scan' || options.quick) return undefined;
  const backend = deps.platform === 'darwin' ? 'Seatbelt' : 'Bubblewrap';
  const title = `Codex's sandbox (${backend})`;
  let codex: string;
  try {
    codex = deps.resolveUpstream(options.upstream).codex.executable;
  } catch {
    return notOk('fail', 'sandbox', 'native', title, 'Codex is not installed (see upstream)');
  }
  const probe = deps.run(codex, ['sandbox', '--', '/usr/bin/true']);
  if (probe.status === 0)
    return ok('sandbox', 'native', title, `${codex} sandbox -- /usr/bin/true`);
  const reported = stderrTail(probe.stderr || probe.stdout) || `exit ${probe.status}`;
  if (deps.platform !== 'linux')
    return notOk(
      'fail',
      'sandbox',
      'native',
      title,
      `Seatbelt refused: ${reported}`,
      'Run outside another sandbox, or use --runtime docker.'
    );
  // Linux: which of Bubblewrap and the user-namespace restriction is in the way.
  const bwrap = deps.run('bwrap', ['--version']).status === 0;
  const restricted =
    deps.readFile('/proc/sys/kernel/apparmor_restrict_unprivileged_userns')?.trim() === '1';
  const cloneOff = deps.readFile('/proc/sys/kernel/unprivileged_userns_clone')?.trim() === '0';
  const why = [
    bwrap ? '' : 'bwrap is not installed',
    restricted
      ? 'AppArmor restricts unprivileged user namespaces (kernel.apparmor_restrict_unprivileged_userns=1)'
      : '',
    cloneOff ? 'unprivileged user namespaces are off (kernel.unprivileged_userns_clone=0)' : '',
  ].filter(Boolean);
  return notOk(
    'fail',
    'sandbox',
    'native',
    title,
    `${why.join('; ') || 'Bubblewrap refused'}: ${reported}`,
    cloneOff ? 'sudo sysctl -w kernel.unprivileged_userns_clone=1' : LINUX_SANDBOX_FIX
  );
};

const codeGraphCheck: Check = ({ options, deps }) => {
  // The scan downloads it on first use (runtime.prepare).
  if (options.scope === 'scan') return undefined;
  const title = 'code-graph binary (codebase-memory-mcp)';
  try {
    codeGraphPin(platformKey(deps.platform, process.arch));
  } catch (error) {
    return notOk('fail', 'code-graph', 'native', title, (error as Error).message);
  }
  const state = deps.codeGraphState(options.toolCache ?? defaultToolCache(deps.env));
  if (state.status === 'ok') return ok('code-graph', 'native', title, state.binary);
  return notOk(
    state.status === 'missing' ? 'warn' : 'fail',
    'code-graph',
    'native',
    title,
    state.status === 'missing'
      ? `not downloaded yet (${state.binary}); the first full scan downloads it`
      : `${state.binary} changed: ${state.detail}`,
    'cynos doctor --fix'
  );
};

// --------------------------------------------------------------------------- //
// Docker runtime checks
// --------------------------------------------------------------------------- //

const dockerDaemonCheck: Check = ({ deps }) => {
  const title = 'Docker daemon';
  const version = deps.run('docker', ['version', '--format', '{{.Server.Version}}']);
  if (version.status !== 0)
    return notOk(
      'fail',
      'docker-daemon',
      'docker',
      title,
      stderrTail(version.stderr) || 'docker is not on PATH',
      'Start Docker Desktop, or the docker service.'
    );
  const server = version.stdout.trim();
  const info = deps.run('docker', [
    'info',
    '--format',
    '{{.OperatingSystem}}|{{.NCPU}}|{{.MemTotal}}',
  ]);
  const [os, cpus, memory] = info.stdout.trim().split('|');
  const gib = Math.round(Number(memory) / 2 ** 30);
  const detail = `server ${server}${os ? `, ${os}` : ''}${cpus ? `, ${cpus} CPUs` : ''}${gib ? `, ${gib} GiB` : ''}`;
  if (Number(server.split('.')[0]) < 20)
    return notOk(
      'warn',
      'docker-daemon',
      'docker',
      title,
      detail,
      'Update Docker to 20.10 or later.'
    );
  return ok('docker-daemon', 'docker', title, detail);
};

/** The scanner image is present, and built for the Docker host's platform (dockerPlatform). */
const dockerImageCheck: Check = ({ options, deps }) => {
  const title = 'scanner image';
  const image = imageReference(options.assets ?? engineAssets());
  const fix = 'cynos doctor --runtime docker --fix';
  const inspect = deps.run('docker', [
    'image',
    'inspect',
    '--format',
    '{{.Id}} {{.Os}}/{{.Architecture}}',
    image,
  ]);
  if (inspect.status !== 0)
    return notOk('fail', 'docker-image', 'docker', title, `${image} is not present`, fix);
  const [id = '', platform = ''] = inspect.stdout.trim().split(' ');
  let host: string | undefined;
  try {
    host = dockerPlatform(deps.run);
  } catch {
    // The daemon check reports a daemon that does not answer.
  }
  if (host && platform !== host)
    return notOk('fail', 'docker-image', 'docker', title, foreignImage(image, platform, host), fix);
  return ok('docker-image', 'docker', title, `${image} (${id.slice(0, 19)}, ${platform})`);
};

/**
 * Whether Docker confines containers with AppArmor, and upstream's profile is loaded, as a scan
 * finds out (appArmorProfileLoaded). Telling that without root takes the scanner image, which
 * doctor checks, and fixes, first.
 */
function appArmorState(deps: HostDeps, image: string): { docker: boolean; loaded: boolean } {
  const info = deps.run('docker', ['info', '--format', '{{json .SecurityOptions}}']);
  const docker = info.stdout.includes('"name=apparmor"');
  return { docker, loaded: docker && appArmorProfileLoaded(image, deps.run, deps.readFile) };
}

const dockerAppArmorCheck: Check = ({ options, deps }) => {
  if (deps.platform !== 'linux') return undefined;
  const title = "upstream's AppArmor profile";
  const state = appArmorState(deps, imageReference(options.assets ?? engineAssets()));
  if (!state.docker)
    return ok('docker-apparmor', 'docker', title, 'Docker does not use AppArmor here');
  if (state.loaded)
    return ok('docker-apparmor', 'docker', title, `${APPARMOR_PROFILE_NAME} is loaded`);
  const restricted =
    deps.readFile('/proc/sys/kernel/apparmor_restrict_unprivileged_userns')?.trim() === '1';
  return notOk(
    restricted ? 'fail' : 'warn',
    'docker-apparmor',
    'docker',
    title,
    `${APPARMOR_PROFILE_NAME} is not loaded${restricted ? ', and unprivileged user namespaces are restricted' : ''}`,
    'cynos doctor --runtime docker --fix (asks for sudo)'
  );
};

const dockerSeccompCheck: Check = ({ options, deps }) => {
  // The scan's preflight runs upstream's container check itself.
  if (options.scope === 'scan' || options.quick) return undefined;
  const title = 'seccomp profile (upstream container check)';
  const assets = options.assets ?? engineAssets();
  const image = imageReference(assets);
  if (deps.run('docker', ['image', 'inspect', image]).status !== 0)
    return notOk('warn', 'docker-seccomp', 'docker', title, 'needs the scanner image first');
  const apparmor = deps.platform === 'linux' && appArmorState(deps, image).loaded;
  const [program, ...args] = upstreamSandboxCheck(
    assets,
    image,
    apparmor,
    deps.uid ?? 1000,
    process.getgid?.() ?? 1000
  );
  const check = deps.run(program ?? 'docker', args, dockerEnvironment());
  return check.status === 0
    ? ok('docker-seccomp', 'docker', title, "Codex's sandbox starts in the container")
    : notOk(
        'fail',
        'docker-seccomp',
        'docker',
        title,
        stderrTail(check.stderr) || `exit ${check.status}`,
        // doctor --fix loads upstream's AppArmor profile on Linux; the image's platform is
        // the image check's to fix.
        'cynos doctor --runtime docker --fix'
      );
};

const CHECKS: Record<HostCheckGroup, Check[]> = {
  common: [nodeCheck, upstreamCheck, stateDirCheck, checkoutCheck, cynosCheck],
  native: [pythonCheck, gitCheck, sandboxCheck, codeGraphCheck],
  docker: [dockerDaemonCheck, dockerImageCheck, dockerAppArmorCheck, dockerSeccompCheck],
};

/** Every check for the scope and runtime, common ones first, in the order the module lists them. */
export async function checkHost(
  options: HostCheckOptions,
  deps: Partial<HostDeps> = {}
): Promise<HostCheck[]> {
  const context: Context = { options, deps: { ...realDeps(), ...deps } };
  const results: HostCheck[] = [];
  for (const check of [...CHECKS.common, ...CHECKS[options.runtime]]) {
    const result = await check(context);
    if (result) results.push(result);
  }
  return results;
}

/**
 * Repairs one check (FIXABLE_CHECKS) and returns it checked again. Loading the AppArmor profile
 * runs sudo, so it needs allowSudo; anything else that cannot be fixed throws.
 */
export async function fixHost(
  id: string,
  options: HostCheckOptions & { allowSudo?: boolean },
  deps: Partial<HostDeps> = {}
): Promise<HostCheck> {
  const all = { ...realDeps(), ...deps };
  const assets = options.assets ?? engineAssets();
  if (id === 'state-dir') {
    const path = resolve(options.stateDir ?? resolveStateDir(all.env));
    mkdirSync(path, { recursive: true, mode: 0o700 });
    chmodSync(path, 0o700);
  } else if (id === 'code-graph') {
    await ensureCodeGraphBinary(options.toolCache ?? defaultToolCache(all.env));
  } else if (id === 'docker-image') {
    provideImage(assets, all.run);
  } else if (id === 'docker-apparmor') {
    if (!options.allowSudo)
      throw new Error(
        `Loading ${APPARMOR_PROFILE_NAME} runs sudo (install and apparmor_parser); allow it to continue.`
      );
    loadAppArmor(assets, all.run);
  } else {
    throw new Error(`${id} cannot be fixed automatically; see its fix.`);
  }
  // Checked again without the slow or networked checks: none of them is a fixable one.
  const offline: HostCheckOptions = { ...options };
  delete offline.cynosKey;
  const again = (await checkHost({ ...offline, scope: 'doctor', quick: true }, deps)).find(
    c => c.id === id
  );
  return again ?? { id, group: 'common', status: 'ok', title: id, detail: 'fixed' };
}
