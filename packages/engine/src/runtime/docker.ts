/**
 * The docker runtime: upstream in the scanner container, built, hardened, given its input, and
 * invoked as the codex-security action always has.
 *
 * Codex sandboxes every command with Bubblewrap, which needs nested user and mount
 * namespaces. Docker's default seccomp profile forbids them, and on Ubuntu 24.04 so does
 * AppArmor's unprivileged-userns restriction, so every container runs with upstream's own
 * hardening (tag npm-v0.9.1): --cap-drop ALL, no-new-privileges, upstream's seccomp profile
 * and, when loaded, upstream's AppArmor profile. Codex's sandbox stays on.
 *
 * The container runs as the runner's uid, not the image's `node`, so the 0700 mounts stay
 * writable and the action can read Codex's rollouts. Its working directory must then be one
 * that uid owns: once codex-security has written its configuration, Codex's sandbox protects
 * .codex under the working directory, and Bubblewrap cannot create /home/node/.codex as
 * another user.
 *
 * The cynos key reaches the container by name only (docker run -e NAME): Docker copies the
 * value from the environment it is given, so it never appears in argv or in logged commands.
 *
 * A benchmark runs this pipeline inside its own container and reaches the host's Docker daemon
 * through its socket. The daemon resolves a bind mount's source on the host, where this
 * process's paths do not exist, so every mount source goes through hostPath (HostPaths).
 *
 * The image: a release stamps assets/image.json ({ image, digest }) into the published package,
 * and the runtime pulls that reference by digest; without it (a checkout, the action), the image
 * is built from assets/Dockerfile and tagged IMAGE. Either way it is the Docker host's own
 * platform (dockerPlatform): under emulation Codex's sandbox cannot start.
 */
import { spawn, spawnSync, type ChildProcess, type StdioOptions } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  APPARMOR_PROFILE_NAME,
  BASE_INSTRUCTIONS_SHA256,
  C_GRAPH_HOME,
  C_FALSE_POSITIVES,
  C_HELPER_CONTEXT,
  C_PLUGIN,
  C_RUBRIC,
  C_HOME,
  C_KB_INDEX,
  C_KNOWLEDGE_BASE,
  C_MODEL_CATALOG,
  C_OUT,
  C_PROJECT,
  C_PROMPT,
  C_REVIEW,
  C_SCAN_OUT,
  C_STATE,
  C_UPSTREAM,
  CODEX_BIN,
  IMAGE,
  KEY_VARIABLE,
  KNOWLEDGE_BASE_INDEX,
  KNOWLEDGE_BASE_OUTPUT,
  PROFILE_SHA256,
} from '../constants';
import { AGENT_KEY_VARIABLE, agentExecArguments } from '../knowledge-base/architecture-agent';
import type { CodeGraphPlan } from '../knowledge-base/code-graph';
import {
  HELPER_CONTEXT_FILE,
  KNOWLEDGE_BASE_DIR,
  MODEL_CATALOG_FILE,
  PREFLIGHT_DIR,
  PLUGIN_DIR,
  RUN_PROMPT_FILE,
  UPSTREAM_PLUGIN_DIR,
  type ScanLayout,
} from '../layout';
import { PIPED, runCommand, type Runner } from '../processes';
import { makesModelCalls, scanArguments, type RunKind, type ScanOptions } from '../scan-command';
import { FALSE_POSITIVES_FILE, RUBRIC_FILE, SCAN_INPUTS_DIR } from '../scan-inputs';
import { UPSTREAM_PIN } from '../upstream';
import type {
  PrepareOptions,
  ReviewAgentPlan,
  RuntimeCommand,
  RuntimeOptions,
  ScanPaths,
  ScanRuntime,
} from './index';

// --------------------------------------------------------------------------- //
// The container's pieces: hardening, identity, environment, mounts
// --------------------------------------------------------------------------- //

/**
 * upstream compose.yaml's security options, which let Bubblewrap start. The Docker CLI reads the
 * seccomp profile itself and sends its content, so its path is this process's, never the host's.
 */
export function hardeningOptions(assets: string, apparmor: boolean): string[] {
  const options = [
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges',
    '--security-opt',
    `seccomp=${join(assets, 'codex-security-seccomp.json')}`,
  ];
  if (apparmor) options.push('--security-opt', `apparmor=${APPARMOR_PROFILE_NAME}`);
  return options;
}

/** The runner's uid:gid, and a HOME and working directory that uid owns. */
export function runnerIdentity(uid: number, gid: number): string[] {
  return ['--user', `${uid}:${gid}`, '--workdir', C_HOME, '-e', `HOME=${C_HOME}`];
}

/** The container's environment, minus HOME and the key. */
export function containerEnvironment(): string[] {
  return [
    '-e',
    `CODEX_SECURITY_STATE_DIR=${C_STATE}`,
    '-e',
    'CI=true',
    '-e',
    'CODEX_SECURITY_NO_UPDATE_NOTICE=1',
  ];
}

/**
 * Where this process's directories are on the Docker host, as [here, on the host] prefixes. Empty
 * when this process runs on the host itself, as the action does; a benchmark that reaches the
 * host's daemon from inside a container maps its output mount (bench --host-path).
 */
export type HostPaths = [string, string][];

/**
 * path as the Docker daemon sees it: the first HostPaths prefix it lies under, rewritten. Either
 * side may be the root, `/` (`/out=/` puts the output mount at the host's root), so the rest of
 * the path is joined onto the host's prefix rather than appended to it.
 */
export function hostPath(path: string, hostPaths: HostPaths = []): string {
  for (const [here, host] of hostPaths)
    if (here === '/' || path === here || path.startsWith(`${here}/`))
      return join(host, path.slice(here.length));
  return path;
}

/** A bind mount of source (a path in this process) at target, read-only unless writable. */
export function bind(
  source: string,
  target: string,
  hostPaths: HostPaths = [],
  writable = false
): string[] {
  return ['-v', `${hostPath(source, hostPaths)}:${target}${writable ? '' : ':ro'}`];
}

/** The caller's checkout (read-only: nothing the scanner writes reaches it), and the run's output and Codex state. */
export function mounts(project: string, workspace: string, hostPaths: HostPaths = []): string[] {
  return [
    ...bind(project, C_PROJECT, hostPaths),
    ...bind(join(workspace, 'out'), C_OUT, hostPaths, true),
    ...bind(join(workspace, 'state'), C_STATE, hostPaths, true),
  ];
}

/**
 * The environment Docker needs, and nothing else: the cynos key only when the scan uses it. Every
 * `docker run` gets it. Leaving out DOCKER_DEFAULT_PLATFORM matters: it would have Docker look for
 * another platform's image than the Docker host's, which provideImage made.
 */
export function dockerEnvironment(key?: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const name of [
    'PATH',
    'HOME',
    'DOCKER_HOST',
    'DOCKER_CONTEXT',
    'DOCKER_CONFIG',
    'XDG_RUNTIME_DIR',
  ])
    if (process.env[name]) env[name] = process.env[name];
  if (key) env[KEY_VARIABLE] = key;
  return env;
}

// --------------------------------------------------------------------------- //
// The scan and the preflight
// --------------------------------------------------------------------------- //

/** The paths the scanner sees in its container: fixed, whatever the stage. */
export const DOCKER_PATHS: ScanPaths = {
  project: C_PROJECT,
  prompt: C_PROMPT,
  plugin: C_PLUGIN,
  modelCatalog: C_MODEL_CATALOG,
  knowledgeBase: C_KNOWLEDGE_BASE,
  kbIndex: C_KB_INDEX,
  helperContext: C_HELPER_CONTEXT,
  rubric: C_RUBRIC,
  falsePositives: C_FALSE_POSITIVES,
  review: C_REVIEW,
  graphHome: C_GRAPH_HOME,
  scanDir: C_SCAN_OUT,
  promptScanDir: C_SCAN_OUT,
};

export interface ContainerPlan {
  name: string;
  image: string;
  /** The engine's assets: the seccomp profile is read from here. */
  actionRoot: string;
  /** The caller's checkout, mounted read-only. */
  project: string;
  /** Holds this run's out/ and state/. */
  workspace: string;
  apparmor: boolean;
  uid: number;
  gid: number;
  /** Mount sources on the Docker host, when this process is not on it. */
  hostPaths?: HostPaths;
}

/** The scan's docker command; the key goes in by name, never by value. */
export function dockerScanCommand(
  plan: ContainerPlan,
  options: ScanOptions,
  kind: RunKind
): string[] {
  const command = [
    'docker',
    'run',
    // upstream's dashboard needs a terminal: the container's, attached to this one.
    ...(options.interactive && kind === 'scan' ? ['-it'] : []),
    '--rm',
    '--init',
    '--name',
    plan.name,
    ...runnerIdentity(plan.uid, plan.gid),
    ...hardeningOptions(plan.actionRoot, plan.apparmor),
    ...containerEnvironment(),
    ...mounts(plan.project, plan.workspace, plan.hostPaths),
    ...bind(join(plan.workspace, RUN_PROMPT_FILE), C_PROMPT, plan.hostPaths),
    ...bind(join(plan.workspace, MODEL_CATALOG_FILE), C_MODEL_CATALOG, plan.hostPaths),
  ];
  if (options.knowledgeBaseBuilt)
    command.push(
      ...bind(
        join(plan.workspace, KNOWLEDGE_BASE_DIR, KNOWLEDGE_BASE_OUTPUT),
        C_KNOWLEDGE_BASE,
        plan.hostPaths
      ),
      ...bind(
        join(plan.workspace, KNOWLEDGE_BASE_DIR, KNOWLEDGE_BASE_INDEX),
        C_KB_INDEX,
        plan.hostPaths
      )
    );
  if (options.helperContext)
    command.push(
      ...bind(join(plan.workspace, HELPER_CONTEXT_FILE), C_HELPER_CONTEXT, plan.hostPaths)
    );
  if (options.plugin)
    command.push(...bind(join(plan.workspace, PLUGIN_DIR), C_PLUGIN, plan.hostPaths));
  // The caller's inputs, staged in the workspace (scan-inputs.ts), each only when given.
  if (options.rubric)
    command.push(
      ...bind(join(plan.workspace, SCAN_INPUTS_DIR, RUBRIC_FILE), C_RUBRIC, plan.hostPaths)
    );
  if (options.falsePositives)
    command.push(
      ...bind(
        join(plan.workspace, SCAN_INPUTS_DIR, FALSE_POSITIVES_FILE),
        C_FALSE_POSITIVES,
        plan.hostPaths
      )
    );
  if (makesModelCalls(options)) command.push('-e', KEY_VARIABLE);
  // None of these needs the network; proving that is part of the check.
  if (kind === 'preflight' || !makesModelCalls(options)) command.push('--network', 'none');
  return [...command, plan.image, ...scanArguments(options, DOCKER_PATHS)];
}

// --------------------------------------------------------------------------- //
// The sandbox check
// --------------------------------------------------------------------------- //

/** upstream's docker/verify-container-sandbox.sh, run as the runner's uid. */
export function upstreamSandboxCheck(
  assets: string,
  image: string,
  apparmor: boolean,
  uid: number,
  gid: number
): string[] {
  return [
    'docker',
    'run',
    '--rm',
    '--user',
    `${uid}:${gid}`,
    ...hardeningOptions(assets, apparmor),
    '--network',
    'none',
    // That uid has no home in the image, so give it the container's /tmp.
    '-e',
    'HOME=/tmp',
    '--entrypoint',
    'node',
    image,
    CODEX_BIN,
    'sandbox',
    '/usr/bin/true',
  ];
}

// --------------------------------------------------------------------------- //
// The SARIF export
// --------------------------------------------------------------------------- //

/** upstream's strict export in the scanner image, with no key and no network. */
export function sarifExportCommand(plan: Omit<ContainerPlan, 'name'>): string[] {
  return [
    'docker',
    'run',
    '--rm',
    '--init',
    ...runnerIdentity(plan.uid, plan.gid),
    ...hardeningOptions(plan.actionRoot, plan.apparmor),
    '--network',
    'none',
    ...containerEnvironment(),
    ...mounts(plan.project, plan.workspace, plan.hostPaths),
    plan.image,
    'export',
    C_SCAN_OUT,
    '--export-format',
    'sarif',
    '--source-root',
    C_PROJECT,
    '--output',
    `${C_OUT}/results.sarif`,
  ];
}

// --------------------------------------------------------------------------- //
// The architecture review agent
// --------------------------------------------------------------------------- //

export interface DockerAgentPlan extends Omit<ContainerPlan, 'workspace'> {
  /** A private directory for the agent's home, index, reader and answer, mounted at C_REVIEW. */
  work: string;
  cynosKey: string;
  /** The scan's model catalog (the model's real context window), when the run wrote one. */
  modelCatalog?: string;
  /** The cynos endpoint; BASE_URL unless a benchmark gives its own gateway. */
  baseUrl?: string;
}

/** The agent's docker command (a new session, or `resume` of the last); the key goes in by name. */
export function agentCommand(plan: DockerAgentPlan, resume = false): string[] {
  return [
    'run',
    '--rm',
    '-i',
    '--init',
    '--name',
    plan.name,
    '--user',
    `${plan.uid}:${plan.gid}`,
    ...hardeningOptions(plan.actionRoot, plan.apparmor),
    '-e',
    `HOME=${C_REVIEW}/home`,
    '-e',
    AGENT_KEY_VARIABLE,
    ...bind(plan.project, C_PROJECT, plan.hostPaths),
    ...bind(plan.work, C_REVIEW, plan.hostPaths, true),
    ...(plan.modelCatalog ? bind(plan.modelCatalog, C_MODEL_CATALOG, plan.hostPaths) : []),
    '--workdir',
    C_PROJECT,
    '--entrypoint',
    'node',
    plan.image,
    CODEX_BIN,
    ...agentExecArguments(
      {
        project: C_PROJECT,
        review: C_REVIEW,
        ...(plan.modelCatalog ? { modelCatalog: C_MODEL_CATALOG } : {}),
      },
      plan.baseUrl,
      resume
    ),
  ];
}

// --------------------------------------------------------------------------- //
// The code graph
// --------------------------------------------------------------------------- //

export interface DockerGraphPlan extends Omit<ContainerPlan, 'workspace'> {
  /** The graph's home on the runner, mounted at C_GRAPH_HOME. */
  home: string;
}

/** The graph's container: the scanner image idling with no network, the checkout read-only. */
export function graphContainerCommand(plan: DockerGraphPlan): string[] {
  return [
    'run',
    '--detach',
    '--rm',
    '--init',
    '--name',
    plan.name,
    '--network',
    'none',
    '--user',
    `${plan.uid}:${plan.gid}`,
    ...hardeningOptions(plan.actionRoot, plan.apparmor),
    '-e',
    `HOME=${C_GRAPH_HOME}`,
    '-e',
    `XDG_CACHE_HOME=${C_GRAPH_HOME}/.cache`,
    '--workdir',
    C_GRAPH_HOME,
    ...bind(plan.project, C_PROJECT, plan.hostPaths),
    ...bind(plan.home, C_GRAPH_HOME, plan.hostPaths, true),
    '--entrypoint',
    'sleep',
    plan.image,
    'infinity',
  ];
}

/** codebase-memory-mcp as an MCP server on stdio in the graph's container, for a whole build. */
export function graphServerCommand(name: string): string[] {
  return ['exec', '-i', name, 'codebase-memory-mcp'];
}

// --------------------------------------------------------------------------- //
// Stopping
// --------------------------------------------------------------------------- //

/** Stops the container by name; the Docker daemon, not this process, owns it. */
export function killContainer(name: string): void {
  spawnSync('docker', ['kill', name], { stdio: 'ignore' });
}

// --------------------------------------------------------------------------- //
// Preparing: profiles, image, AppArmor, versions
// --------------------------------------------------------------------------- //

/** Throws unless the vendored seccomp and AppArmor profiles are upstream's, byte for byte. */
export function verifyProfiles(assets: string): void {
  for (const [name, expected] of Object.entries(PROFILE_SHA256)) {
    const actual = createHash('sha256')
      .update(readFileSync(join(assets, name)))
      .digest('hex');
    if (actual !== expected)
      throw new Error(`${name} is not upstream npm-v${UPSTREAM_PIN.version} (sha256 ${actual})`);
  }
}

/** A release's scanner image, stamped into assets/image.json; absent in a checkout. */
export interface ReleasedImage {
  image: string;
  digest: string;
}

/** assets/image.json, when a release stamped it; throws when it is there but malformed. */
export function releasedImage(assets: string): ReleasedImage | undefined {
  const path = join(assets, 'image.json');
  if (!existsSync(path)) return undefined;
  const value = JSON.parse(readFileSync(path, 'utf8')) as Partial<ReleasedImage>;
  if (typeof value.image !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(value.digest ?? ''))
    throw new Error(`${path} must hold { "image": "<ref>", "digest": "sha256:<64 hex>" }`);
  return { image: value.image, digest: value.digest as string };
}

/** The image the runtime runs: the release's by digest, else the locally built IMAGE. */
export function imageReference(assets: string): string {
  const released = releasedImage(assets);
  return released ? `${released.image}@${released.digest}` : IMAGE;
}

/**
 * The platform the Docker host runs natively, as os/arch: linux/arm64 on Docker Desktop on Apple
 * silicon. The scanner image must be built for it. An image for another platform runs emulated
 * (an amd64 image on that Mac, which DOCKER_DEFAULT_PLATFORM=linux/amd64 builds and pulls), and
 * under emulation the kernel refuses the seccomp filter Codex installs for each command
 * (`SeccompInstall ... Invalid argument`), so no scan can start.
 */
export function dockerPlatform(run: Runner = runCommand): string {
  const version = run('docker', ['version', '--format', '{{.Server.Os}}/{{.Server.Arch}}']);
  const platform = version.stdout.trim();
  if (version.status !== 0 || !/^[a-z0-9]+\/[a-z0-9]+$/.test(platform))
    throw new Error(`docker version failed: ${(version.stderr || platform).trim()}`);
  return platform;
}

/** The image's platform (os/arch), or undefined when Docker does not have it. */
export function imagePlatform(image: string, run: Runner = runCommand): string | undefined {
  const inspect = run('docker', [
    'image',
    'inspect',
    '--format',
    '{{.Os}}/{{.Architecture}}',
    image,
  ]);
  return inspect.status === 0 ? inspect.stdout.trim() : undefined;
}

/** Why an image built for another platform than the Docker host's cannot run a scan. */
export function foreignImage(image: string, platform: string, host: string): string {
  return `The scanner image ${image} is ${platform}, but this Docker host runs ${host}: emulated, Codex's sandbox cannot start.`;
}

/** Builds the scanner image from the assets' Dockerfile, for the Docker host's platform. */
export function buildImage(
  assets: string,
  image: string,
  platform: string,
  run: Runner = runCommand
): void {
  const result = run('docker', ['build', '--platform', platform, '-t', image, assets]);
  if (result.status !== 0)
    throw new Error(`docker build failed: ${(result.stderr || result.stdout).trim().slice(-2000)}`);
}

/**
 * Makes the scanner image present for the Docker host's platform: pulls the release's by digest
 * (assets/image.json), or builds IMAGE from the Dockerfile when there is none. The platform is
 * explicit because both honour DOCKER_DEFAULT_PLATFORM, which can name another one. Returns the
 * reference the runtime runs.
 */
export function provideImage(assets: string, run: Runner = runCommand): string {
  const platform = dockerPlatform(run);
  const released = releasedImage(assets);
  if (!released) {
    buildImage(assets, IMAGE, platform, run);
    return IMAGE;
  }
  const reference = `${released.image}@${released.digest}`;
  const pulled = run('docker', ['pull', '--platform', platform, reference]);
  if (pulled.status !== 0)
    throw new Error(`docker pull ${reference} failed: ${(pulled.stderr || pulled.stdout).trim()}`);
  return reference;
}

/**
 * Whether upstream's AppArmor profile is loaded, so containers can run under it without sudo.
 *
 * The kernel's list of loaded profiles is root's to read, and a scan or doctor runs as the user,
 * so on a stock Ubuntu host the list reads as nothing even with the profile loaded (loadAppArmor
 * checks it through sudo). Where the list cannot be read, Docker answers instead: its daemon
 * refuses to start a container under a profile that is not loaded. That takes the image.
 */
export function appArmorProfileLoaded(
  image: string,
  run: Runner = runCommand,
  readFile: (path: string) => string | undefined = readable
): boolean {
  const profiles = readFile('/sys/kernel/security/apparmor/profiles');
  if (profiles) return profiles.includes(`${APPARMOR_PROFILE_NAME} (enforce)`);
  const probe = run(
    'docker',
    [
      'container',
      'run',
      '--rm',
      '--pull',
      'never',
      '--network',
      'none',
      '--security-opt',
      `apparmor=${APPARMOR_PROFILE_NAME}`,
      '--entrypoint',
      'true',
      image,
    ],
    dockerEnvironment()
  );
  return probe.status === 0;
}

/** Whether Docker confines containers with AppArmor (Ubuntu's Docker does; Docker Desktop not). */
export function dockerUsesAppArmor(run: Runner = runCommand): boolean {
  const info = run('docker', ['info', '--format', '{{json .SecurityOptions}}']);
  return info.stdout.includes('"name=apparmor"');
}

/** A file's text, or undefined when it cannot be read. */
function readable(path: string): string | undefined {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return undefined;
  }
}

/**
 * Loads upstream's AppArmor profile when Docker uses AppArmor, and returns whether it did.
 *
 * Ubuntu 24.04 restricts unprivileged user namespaces through AppArmor, and Docker's default
 * profile does not grant them. Upstream's profile grants userns to this container only: no
 * host-wide sysctl change, no apparmor=unconfined. Same steps as upstream's
 * docker/verify-container-sandbox.sh.
 */
export function loadAppArmor(assets: string, run: Runner = runCommand): boolean {
  if (!dockerUsesAppArmor(run)) return false;
  const target = `/etc/apparmor.d/${APPARMOR_PROFILE_NAME}`;
  const steps: [string, string[]][] = [
    ['sudo', ['install', '-m', '0644', join(assets, 'codex-security.apparmor'), target]],
    ['sudo', ['apparmor_parser', '-r', '-W', target]],
    [
      'sudo',
      [
        'grep',
        '-Fxq',
        `${APPARMOR_PROFILE_NAME} (enforce)`,
        '/sys/kernel/security/apparmor/profiles',
      ],
    ],
  ];
  for (const [command, args] of steps) {
    const result = run(command, args);
    if (result.status !== 0)
      throw new Error(`loading the AppArmor profile failed at ${args[0]}: ${result.stderr.trim()}`);
  }
  return true;
}

/** Records what the image runs, from its own versions.sh, plus the hardening it runs under. */
export function recordVersions(
  image: string,
  apparmor: boolean,
  output: string,
  run: Runner = runCommand
): Record<string, unknown> {
  const versions = run(
    'docker',
    ['run', '--rm', '--entrypoint', '/opt/codex-security/versions.sh', image],
    dockerEnvironment()
  );
  if (versions.status !== 0) throw new Error(`versions.sh failed: ${versions.stderr.trim()}`);
  const record = JSON.parse(versions.stdout) as Record<string, unknown>;
  const help = run(
    'docker',
    ['run', '--rm', '--entrypoint', 'codex-security', image, 'scan', '--help'],
    dockerEnvironment()
  );
  if (!help.stdout.includes('--show-cost'))
    throw new Error('codex-security scan --help does not list --show-cost');
  record['runtime'] = 'docker';
  record['image'] = image;
  record['image_id'] = run('docker', [
    'image',
    'inspect',
    '--format',
    '{{.Id}}',
    image,
  ]).stdout.trim();
  record['profile_sha256'] = PROFILE_SHA256;
  record['base_instructions_sha256'] = BASE_INSTRUCTIONS_SHA256;
  record['apparmor_profile'] = apparmor ? APPARMOR_PROFILE_NAME : null;
  const userns = '/proc/sys/kernel/apparmor_restrict_unprivileged_userns';
  record['apparmor_restrict_unprivileged_userns'] = existsSync(userns)
    ? readFileSync(userns, 'utf8').trim()
    : null;
  writeFileSync(output, `${JSON.stringify(record, null, 2)}\n`);
  return record;
}

/**
 * upstream's bundled plugin, copied out of the image into `dir` and checked against the pin;
 * returns the plugin's directory (dir/_bundled_plugin).
 *
 * A scan's plugin is upstream's bundled one with our workflow files in place (scan-plugin.ts),
 * staged on the host and mounted at C_PLUGIN. On this runtime upstream is installed only in the
 * image: the GitHub action bundles the engine without @openai/codex-security, so its runner has
 * none to copy from. So the plugin comes from the image that runs the scan, through a container
 * that is created, copied from and removed, never started. upstream's package.json comes with it
 * for the version check: an image the caller supplies (--no-build-image) may be another version's.
 */
export function copyBundledPlugin(
  image: string,
  dir: string,
  name: string,
  run: Runner = runCommand
): string {
  const env = dockerEnvironment();
  const created = run('docker', ['create', '--name', name, image], env);
  if (created.status !== 0)
    throw new Error(`docker create of ${image} failed: ${created.stderr.trim()}`);
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    for (const file of ['package.json', '_bundled_plugin']) {
      const copied = run('docker', ['cp', `${name}:${C_UPSTREAM}/${file}`, join(dir, file)], env);
      if (copied.status !== 0)
        throw new Error(`docker cp of upstream's ${file} failed: ${copied.stderr.trim()}`);
    }
  } finally {
    run('docker', ['rm', '--force', name], env);
  }
  const manifest = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as {
    version?: unknown;
  };
  if (manifest.version !== UPSTREAM_PIN.version)
    throw new Error(
      `${UPSTREAM_PIN.package} in ${image} is ${String(manifest.version)}, not the pinned ${UPSTREAM_PIN.version}.`
    );
  return join(dir, '_bundled_plugin');
}

// --------------------------------------------------------------------------- //
// The runtime
// --------------------------------------------------------------------------- //

/**
 * The docker runtime: each method builds today's container for one step. The image, the
 * AppArmor decision and the runner's uid:gid are fixed once prepare() has run.
 */
export class DockerRuntime implements ScanRuntime {
  readonly name = 'docker' as const;
  /** The container's paths are its own; nothing in its prompt belongs to the host. */
  readonly foreignPaths: string[] = [];
  private readonly assets: string;
  private readonly hostPaths: HostPaths | undefined;
  private readonly runName: string;
  private image: string;
  private apparmor = false;
  /** The bundled plugin copied out of the image, by stage: the preflight and the scan share one. */
  private readonly plugins = new Map<string, string>();
  private readonly uid = process.getuid?.() ?? 1000;
  private readonly gid = process.getgid?.() ?? 1000;

  constructor(options: Pick<RuntimeOptions, 'assets' | 'hostPaths' | 'runName'>) {
    this.assets = options.assets;
    this.hostPaths = options.hostPaths;
    this.runName = options.runName ?? 'codex-security';
    this.image = imageReference(options.assets);
  }

  /**
   * The profiles (sha256-checked), the image (pulled or built, and the Docker host's platform),
   * upstream's AppArmor profile.
   */
  async prepare(options: PrepareOptions): Promise<void> {
    verifyProfiles(this.assets);
    if (options.buildImage) {
      options.log(
        releasedImage(this.assets)
          ? `Pulling the codex-security image ${this.image}.`
          : 'Building the codex-security image.'
      );
      this.image = provideImage(this.assets);
    }
    // An image already there (--no-build-image, a benchmark's) may be another platform's; it
    // would fail later, in upstream's sandbox check, with Codex's panic.
    const platform = imagePlatform(this.image);
    const host = platform && dockerPlatform();
    if (platform && host && platform !== host)
      throw new Error(
        `${foreignImage(this.image, platform, host)} Run \`cynos doctor --runtime docker --fix\`.`
      );
    // A profile already loaded (doctor --fix, or the host's setup) is used without sudo;
    // loadAppArmor (the benchmarks' --apparmor) loads it first.
    this.apparmor = options.loadAppArmor
      ? loadAppArmor(this.assets)
      : dockerUsesAppArmor() && appArmorProfileLoaded(this.image);
  }

  /** The run's out/ and state/ in its workspace; upstream creates the scan dir at out/scan. */
  layout(stage: string, project: string, kind: RunKind): ScanLayout {
    const workspace = kind === 'scan' ? stage : join(stage, PREFLIGHT_DIR);
    return {
      project,
      stage,
      workspace,
      stateDir: join(workspace, 'state'),
      setsStateDir: true,
      privateState: true,
      scanDir: join(workspace, 'out', 'scan'),
    };
  }

  /** upstream creates the scan dir itself: it must not exist yet. */
  createScanDir(layout: ScanLayout): ScanLayout {
    return layout;
  }

  /** The container's fixed paths. */
  paths(): ScanPaths {
    return DOCKER_PATHS;
  }

  /** upstream's bundled plugin in the image, copied into the stage once (copyBundledPlugin). */
  bundledPlugin(stage: string): string {
    let plugin = this.plugins.get(stage);
    if (!plugin) {
      plugin = copyBundledPlugin(
        this.image,
        join(stage, UPSTREAM_PLUGIN_DIR),
        `${this.runName}-plugin`
      );
      this.plugins.set(stage, plugin);
    }
    return plugin;
  }

  /** `docker run` of the image's codex-security; the key by name, no network for the preflight. */
  scanCommand(
    layout: ScanLayout,
    options: ScanOptions,
    kind: RunKind,
    key?: string
  ): RuntimeCommand {
    const name = kind === 'scan' ? this.runName : `${this.runName}-preflight`;
    const interactive = Boolean(options.interactive) && kind === 'scan';
    return {
      argv: dockerScanCommand(
        this.container(name, layout.workspace, layout.project),
        options,
        kind
      ),
      env: dockerEnvironment(key),
      name,
      // `docker run -it` takes the whole terminal: the container's tty carries both streams.
      ...(interactive ? { stdio: 'inherit' as const } : {}),
    };
  }

  /** upstream's container check: Codex's sandbox in the image, under the scan's hardening. */
  sandboxCheck(): RuntimeCommand {
    return {
      argv: upstreamSandboxCheck(this.assets, this.image, this.apparmor, this.uid, this.gid),
      env: dockerEnvironment(),
      name: `${this.runName}-sandbox-check`,
    };
  }

  /** The export in the image, reading the workspace's out/scan, writing out/results.sarif. */
  exportSarif(layout: ScanLayout): RuntimeCommand {
    return {
      argv: sarifExportCommand(this.container('', layout.workspace, layout.project)),
      env: dockerEnvironment(),
      name: `${this.runName}-sarif`,
    };
  }

  /** `codex exec` in the image, the checkout and the agent's directory mounted. */
  reviewAgentCommand(plan: ReviewAgentPlan, resume: boolean): RuntimeCommand {
    const container = this.container(plan.name, '', plan.project);
    return {
      argv: [
        'docker',
        ...agentCommand(
          {
            ...container,
            work: plan.work,
            cynosKey: plan.cynosKey,
            ...(plan.modelCatalog ? { modelCatalog: plan.modelCatalog } : {}),
            ...(plan.baseUrl ? { baseUrl: plan.baseUrl } : {}),
          },
          resume
        ),
      ],
      env: { ...dockerEnvironment(), [AGENT_KEY_VARIABLE]: plan.cynosKey },
      name: plan.name,
    };
  }

  /** The graph's idle container, with no network. */
  codeGraphStart(plan: CodeGraphPlan): RuntimeCommand {
    return {
      argv: ['docker', ...graphContainerCommand(this.graphContainer(plan))],
      env: dockerEnvironment(),
      name: plan.name,
    };
  }

  /** `docker exec` of the MCP server in the graph's container. */
  codeGraphServer(plan: CodeGraphPlan): RuntimeCommand {
    return {
      argv: ['docker', ...graphServerCommand(plan.name)],
      env: dockerEnvironment(),
      name: plan.name,
    };
  }

  /** Removes the graph's container, whatever happened. */
  codeGraphStop(plan: CodeGraphPlan): RuntimeCommand {
    return {
      argv: ['docker', 'rm', '--force', plan.name],
      env: dockerEnvironment(),
      name: plan.name,
    };
  }

  /** The docker client as a plain child: the daemon owns the container. */
  spawn(command: RuntimeCommand, stdio?: StdioOptions): ChildProcess {
    const [program, ...args] = command.argv;
    return spawn(program ?? 'docker', args, {
      env: command.env,
      stdio: stdio ?? command.stdio ?? PIPED,
      ...(command.cwd ? { cwd: command.cwd } : {}),
    });
  }

  /** `docker kill` by name. */
  async stop(name: string): Promise<void> {
    killContainer(name);
  }

  /** The image's versions.sh, plus the hardening it runs under. */
  versions(output: string): Record<string, unknown> {
    return recordVersions(this.image, this.apparmor, output);
  }

  private container(name: string, workspace: string, project: string): ContainerPlan {
    return {
      name,
      image: this.image,
      actionRoot: this.assets,
      project,
      workspace,
      apparmor: this.apparmor,
      uid: this.uid,
      gid: this.gid,
      ...(this.hostPaths ? { hostPaths: this.hostPaths } : {}),
    };
  }

  private graphContainer(plan: CodeGraphPlan): DockerGraphPlan {
    const container = this.container(plan.name, '', plan.project);
    return { ...container, home: plan.home };
  }
}
