/**
 * The native runtime: upstream on the host, exactly as `codex-security` runs on a laptop.
 *
 * The pinned @openai/codex-security runs from node_modules (upstream.ts), under Codex's own OS
 * sandbox: Seatbelt on macOS, Bubblewrap on Linux. Nothing of ours is added around it: no outer
 * jail, no narrowed read scope; upstream's scan profile applies as upstream ships it. What the
 * runtime does decide is only what every host decides:
 *
 *   - which environment upstream gets: an allow-list (nativeEnvironment) of what a shell needs
 *     (PATH, HOME, locale, terminal, proxies, certificates) and what upstream itself reads
 *     (CODEX_HOME, CODEX_SECURITY_STATE_DIR, PYTHON), and the cynos key as CODEX_API_KEY only
 *     when the scan calls the model; never OPENAI_API_KEY, GITHUB_TOKEN, INPUT_* or ACTIONS_*;
 *   - where the scan dir is: where upstream would have put it (layout.ts createScanDir), passed
 *     as --output-dir, so the engine knows it before the scan starts;
 *   - how its processes stop: each in a process group of its own (processes.ts), so a stop
 *     reaches upstream's Codex and its shells.
 *
 * The paths the scanner sees are the stage's real ones, and the prompt and the helpers' reader
 * put them in shell commands the model runs, so the stage's path must need no quoting.
 *
 * The preflight cannot be cut off from the network as a container is, so it is pointed at a port
 * nothing listens on (PREFLIGHT_BASE_URL) with a placeholder key: preparation runs in full, and
 * the first model request fails before anything leaves the machine.
 */
import type { ChildProcess, StdioOptions } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { delimiter, join, resolve } from 'node:path';
import {
  BASE_INSTRUCTIONS_SHA256,
  KNOWLEDGE_BASE_INDEX,
  KNOWLEDGE_BASE_OUTPUT,
  PREFLIGHT_BASE_URL,
} from '../constants';
import { AGENT_KEY_VARIABLE, agentExecArguments } from '../knowledge-base/architecture-agent';
import type { CodeGraphPlan } from '../knowledge-base/code-graph';
import {
  CODE_GRAPH_BINARY,
  CODE_GRAPH_VERSION,
  codeGraphBinaryState,
  defaultToolCache,
  ensureCodeGraphBinary,
} from '../knowledge-base/code-graph-binary';
import {
  createScanDir,
  HELPER_CONTEXT_FILE,
  KNOWLEDGE_BASE_DIR,
  MODEL_CATALOG_FILE,
  PREFLIGHT_DIR,
  resolveStateDir,
  PLUGIN_DIR,
  RUN_PROMPT_FILE,
  type ScanLayout,
} from '../layout';
import { PIPED, ProcessRegistry, runCommand, spawnTracked, stopProcess } from '../processes';
import { scanArguments, type RunKind, type ScanOptions } from '../scan-command';
import { FALSE_POSITIVES_FILE, RUBRIC_FILE, SCAN_INPUTS_DIR } from '../scan-inputs';
import {
  bundledPluginRoot,
  nodeExecutable,
  resolveUpstream,
  upstreamCommand,
  verifyUpstream,
  type Upstream,
} from '../upstream';
import type {
  PrepareOptions,
  ReviewAgentPlan,
  RuntimeCommand,
  RuntimeOptions,
  ScanPaths,
  ScanRuntime,
} from './index';

// --------------------------------------------------------------------------- //
// The process's pieces: environment, the key, upstream's state dir
// --------------------------------------------------------------------------- //

/** What a shell needs, and what upstream and Codex read; everything else stays here. */
const PASSED = [
  'PATH',
  'HOME',
  'USER',
  'LOGNAME',
  'LANG',
  'TZ',
  'SHELL',
  'TMPDIR',
  // upstream's dashboard draws on the terminal it is given.
  'TERM',
  'COLORTERM',
  'NO_COLOR',
  // upstream's own settings: its home and state dir (resolveStateDir), its Python, its log level.
  'CODEX_HOME',
  'CODEX_SECURITY_STATE_DIR',
  'PYTHON',
  'CODEX_SECURITY_LOG_LEVEL',
];
const PROXIES = [
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'NO_PROXY',
  'ALL_PROXY',
  'http_proxy',
  'https_proxy',
  'no_proxy',
  'all_proxy',
  'NODE_USE_ENV_PROXY',
];
const CERTIFICATES = [
  'SSL_CERT_FILE',
  'SSL_CERT_DIR',
  'NODE_EXTRA_CA_CERTS',
  'REQUESTS_CA_BUNDLE',
  'CURL_CA_BUNDLE',
];

/** Never passed to a native process, whatever the allow-list says (a test holds it to this). */
export const FORBIDDEN_VARIABLES = [
  'OPENAI_API_KEY',
  'GITHUB_TOKEN',
  'GH_TOKEN',
  'CYNOS_API_KEY',
  'CODEX_CLI_PATH',
];
const FORBIDDEN_PREFIXES = ['INPUT_', 'ACTIONS_'];

/** The allow-listed part of env: no key of any kind, no CI or Actions settings. */
export function nativeEnvironment(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const [name, value] of Object.entries(env)) {
    if (value === undefined) continue;
    const passed =
      PASSED.includes(name) ||
      PROXIES.includes(name) ||
      CERTIFICATES.includes(name) ||
      name.startsWith('LC_');
    const forbidden =
      FORBIDDEN_VARIABLES.includes(name) || FORBIDDEN_PREFIXES.some(p => name.startsWith(p));
    if (passed && !forbidden) out[name] = value;
  }
  return out;
}

/**
 * upstream's environment for one run: the allow-list, its state dir when the engine chose one,
 * and the key as CODEX_API_KEY (the variable upstream reads and the cynos provider names).
 */
export function upstreamEnvironment(
  layout: Pick<ScanLayout, 'stateDir' | 'setsStateDir'>,
  key?: string,
  env: NodeJS.ProcessEnv = process.env
): NodeJS.ProcessEnv {
  const out = nativeEnvironment(env);
  if (layout.setsStateDir) out['CODEX_SECURITY_STATE_DIR'] = layout.stateDir;
  out['CODEX_SECURITY_NO_UPDATE_NOTICE'] = '1';
  if (key) out[AGENT_KEY_VARIABLE] = key;
  return out;
}

/** env with Codex's bundled tools (rg) first on PATH, as upstream's SDK starts Codex. */
function withCodexTools(env: NodeJS.ProcessEnv, toolsDir: string): NodeJS.ProcessEnv {
  const rest = (env['PATH'] ?? '').split(delimiter).filter(p => p && p !== toolsDir);
  return { ...env, PATH: [toolsDir, ...rest].join(delimiter) };
}

/** A path the model's shell commands can hold unquoted. */
const SHELL_SAFE = /^[A-Za-z0-9_./@%+=:,~-]+$/;

function requireShellSafe(path: string, what: string): string {
  if (!SHELL_SAFE.test(path))
    throw new Error(
      `The native runtime puts the ${what} in shell commands the model runs, and ${JSON.stringify(path)} would need quoting; use a path of letters, digits and . _ - / only.`
    );
  return path;
}

// --------------------------------------------------------------------------- //
// The runtime
// --------------------------------------------------------------------------- //

/**
 * The native runtime: each method builds the host command for one step. upstream is resolved
 * (and its pins checked) once, on first use.
 */
export class NativeRuntime implements ScanRuntime {
  readonly name = 'native' as const;
  /** The docker runtime's container paths: a native prompt that names one sends a helper nowhere. */
  readonly foreignPaths: string[] = ['/scan/'];
  private readonly assets: string;
  private readonly stateDir: 'upstream-default' | string;
  private readonly from: string | undefined;
  private readonly toolCache: string;
  private readonly registry: ProcessRegistry;
  private readonly runName: string;
  private resolved: Upstream | undefined;

  constructor(
    options: Pick<
      RuntimeOptions,
      'assets' | 'stateDir' | 'upstream' | 'toolCache' | 'processes' | 'runName'
    >
  ) {
    this.assets = options.assets;
    this.stateDir = options.stateDir ?? 'upstream-default';
    this.from = options.upstream;
    this.toolCache = options.toolCache ?? defaultToolCache();
    this.registry = options.processes ?? new ProcessRegistry();
    this.runName = options.runName ?? 'codex-security';
  }

  /** upstream and its Codex at the pins, and the code-graph binary when the scan builds a base. */
  async prepare(options: PrepareOptions): Promise<void> {
    verifyUpstream(this.upstream());
    if (options.codeGraph) {
      if (codeGraphBinaryState(this.toolCache).status !== 'ok')
        options.log(
          `Downloading codebase-memory-mcp ${CODE_GRAPH_VERSION} into ${this.toolCache}.`
        );
      await ensureCodeGraphBinary(this.toolCache);
    }
  }

  /** The scan's state dir is upstream's (or the caller's); the preflight's stays in the stage. */
  layout(stage: string, project: string, kind: RunKind): ScanLayout {
    if (kind === 'preflight') {
      const workspace = join(stage, PREFLIGHT_DIR);
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
    const configured = this.stateDir !== 'upstream-default';
    return {
      project,
      stage,
      workspace: stage,
      stateDir: configured ? resolve(this.stateDir) : resolveStateDir(),
      setsStateDir: configured,
      privateState: false,
      // Created just before the scan starts (createScanDir).
      scanDir: '',
    };
  }

  /** The scan's scan dir, created where upstream would have made it; the preflight's by upstream. */
  createScanDir(layout: ScanLayout): ScanLayout {
    if (layout.scanDir) return layout;
    return { ...layout, scanDir: createScanDir(layout.stateDir, layout.project) };
  }

  /** The stage's real paths; the scan dir as upstream's shell variable. */
  paths(layout: ScanLayout): ScanPaths {
    const stage = requireShellSafe(layout.stage, 'stage');
    const knowledgeBase = join(stage, KNOWLEDGE_BASE_DIR);
    return {
      project: layout.project,
      prompt: join(layout.workspace, RUN_PROMPT_FILE),
      plugin: join(layout.workspace, PLUGIN_DIR),
      modelCatalog: join(stage, MODEL_CATALOG_FILE),
      knowledgeBase: join(knowledgeBase, KNOWLEDGE_BASE_OUTPUT),
      kbIndex: join(knowledgeBase, KNOWLEDGE_BASE_INDEX),
      helperContext: join(stage, HELPER_CONTEXT_FILE),
      rubric: join(layout.workspace, SCAN_INPUTS_DIR, RUBRIC_FILE),
      falsePositives: join(layout.workspace, SCAN_INPUTS_DIR, FALSE_POSITIVES_FILE),
      review: join(knowledgeBase, 'review'),
      graphHome: join(knowledgeBase, 'graph'),
      scanDir: layout.scanDir,
      promptScanDir: '"$CODEX_SECURITY_SCAN_DIR"',
    };
  }

  /** upstream's bundled plugin in the host's install, the one prepare verified. */
  bundledPlugin(): string {
    return bundledPluginRoot(this.from);
  }

  /** upstream's bin on this Node; the key as CODEX_API_KEY, a dead endpoint for the preflight. */
  scanCommand(
    layout: ScanLayout,
    options: ScanOptions,
    kind: RunKind,
    key?: string
  ): RuntimeCommand {
    const name = kind === 'scan' ? this.runName : `${this.runName}-preflight`;
    const interactive = Boolean(options.interactive) && kind === 'scan';
    const settings =
      kind === 'preflight'
        ? { ...options, baseUrl: PREFLIGHT_BASE_URL, interactive: false }
        : options;
    return {
      argv: upstreamCommand(scanArguments(settings, this.paths(layout)), this.upstream()),
      env: upstreamEnvironment(layout, key),
      name,
      cwd: layout.workspace,
      // The dashboard reads keys from stdin and draws on stderr; stdout is still the result.
      ...(interactive ? { stdio: ['inherit', 'pipe', 'inherit'] as StdioOptions } : {}),
    };
  }

  /** upstream's probe: the pinned Codex's sandbox (Seatbelt, Bubblewrap) runs /usr/bin/true. */
  sandboxCheck(): RuntimeCommand {
    return {
      argv: [this.upstream().codex.executable, 'sandbox', '--', '/usr/bin/true'],
      env: nativeEnvironment(),
      name: `${this.runName}-sandbox-check`,
    };
  }

  /** upstream's export of the scan dir, writing <workspace>/out/results.sarif. */
  exportSarif(layout: ScanLayout): RuntimeCommand {
    return {
      argv: upstreamCommand(
        [
          'export',
          layout.scanDir,
          '--export-format',
          'sarif',
          '--source-root',
          layout.project,
          '--output',
          join(layout.workspace, 'out', 'results.sarif'),
        ],
        this.upstream()
      ),
      env: upstreamEnvironment(layout),
      name: `${this.runName}-sarif`,
    };
  }

  /** The pinned Codex's `codex exec`, its home in the agent's directory, rg on PATH. */
  reviewAgentCommand(plan: ReviewAgentPlan, resume: boolean): RuntimeCommand {
    const codex = this.upstream().codex;
    return {
      argv: [
        codex.executable,
        ...agentExecArguments(
          {
            project: plan.project,
            review: plan.work,
            ...(plan.modelCatalog ? { modelCatalog: plan.modelCatalog } : {}),
          },
          plan.baseUrl,
          resume
        ),
      ],
      env: {
        ...withCodexTools(nativeEnvironment(), codex.toolsDir),
        CODEX_HOME: join(plan.work, 'home'),
        [AGENT_KEY_VARIABLE]: plan.cynosKey,
      },
      name: plan.name,
      cwd: plan.project,
    };
  }

  /** Nothing to start: the server is the binary itself, with its home in the stage. */
  codeGraphStart(): undefined {
    return undefined;
  }

  /** The pinned binary as an MCP server on stdio, its home in the stage. */
  codeGraphServer(plan: CodeGraphPlan): RuntimeCommand {
    const state = codeGraphBinaryState(this.toolCache);
    return {
      argv: [state.binary],
      env: {
        ...nativeEnvironment(),
        HOME: plan.home,
        XDG_CACHE_HOME: join(plan.home, '.cache'),
      },
      name: plan.name,
      cwd: plan.home,
    };
  }

  /** Nothing to remove: the server ends when the graph closes it. */
  codeGraphStop(): undefined {
    return undefined;
  }

  /** A tracked process group (processes.ts); a command with a terminal stays in this group. */
  spawn(command: RuntimeCommand, stdio?: StdioOptions): ChildProcess {
    return spawnTracked(command.argv, {
      name: command.name,
      registry: this.registry,
      env: command.env,
      stdio: stdio ?? command.stdio ?? PIPED,
      detached: !command.stdio,
      ...(command.cwd ? { cwd: command.cwd } : {}),
    });
  }

  /** SIGTERM to the process group, SIGKILL after the grace period. */
  async stop(name: string): Promise<void> {
    const entry = this.registry.get(name);
    if (entry) await stopProcess(entry);
  }

  /** upstream, Codex, the plugin, Node, Python, git, Bubblewrap and the code-graph binary. */
  versions(output: string): Record<string, unknown> {
    const upstream = this.upstream();
    const node = nodeExecutable();
    const version = (command: string, args: string[]): string | null => {
      const result = runCommand(command, args, nativeEnvironment());
      return result.status === 0 ? (result.stdout || result.stderr).trim() : null;
    };
    let plugin: unknown = null;
    try {
      plugin = (
        JSON.parse(
          readFileSync(
            join(upstream.root, '_bundled_plugin', '.codex-plugin', 'plugin.json'),
            'utf8'
          )
        ) as Record<string, unknown>
      )['version'];
    } catch {
      // An install without the bundled plugin cannot scan; upstream reports that itself.
    }
    const codeGraph = codeGraphBinaryState(this.toolCache);
    const record: Record<string, unknown> = {
      runtime: 'native',
      codex_security: upstream.version,
      codex_security_root: upstream.root,
      codex_security_cli: version(node, [upstream.bin, '--version']),
      codex_npm: upstream.codex.version,
      codex_cli: version(upstream.codex.executable, ['--version']),
      codex_bin: upstream.codex.executable,
      plugin,
      node: version(node, ['--version']),
      python: version('python3', ['--version']),
      git: version('git', ['--version']),
      bwrap: process.platform === 'linux' ? version('bwrap', ['--version']) : null,
      code_graph: {
        version: CODE_GRAPH_VERSION,
        binary: codeGraph.status === 'ok' ? codeGraph.binary : null,
        name: CODE_GRAPH_BINARY,
      },
      assets: this.assets,
      base_instructions_sha256: BASE_INSTRUCTIONS_SHA256,
      patches: [],
    };
    writeFileSync(output, `${JSON.stringify(record, null, 2)}\n`);
    return record;
  }

  private upstream(): Upstream {
    this.resolved ??= resolveUpstream(this.from);
    return this.resolved;
  }
}
