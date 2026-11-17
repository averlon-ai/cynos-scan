/**
 * Where upstream runs: the seam between the scan and the machine.
 *
 * One scan (pipeline.ts) runs on two runtimes, and they differ in where every process starts and
 * what it sees, not in what the scan does:
 *
 *   docker   today's hardened container: upstream's seccomp and AppArmor profiles,
 *            --cap-drop ALL, the checkout mounted read-only at /scan/project, the key by name,
 *            no network for the preflight and the code graph (runtime/docker.ts)
 *   native   upstream exactly as upstream runs on a laptop: the pinned @openai/codex-security
 *            from node_modules on the host, under Codex's own OS sandbox (Seatbelt, Bubblewrap),
 *            with no jail or narrowed read scope of ours (runtime/native.ts)
 *
 * So everything that starts a process or names a path the scanner sees goes through ScanRuntime.
 * The two implementations are siblings: the same methods, in the same order, with the same
 * comment structure, so a difference between them is a difference in the runtime alone.
 */
import type { ChildProcess, StdioOptions } from 'node:child_process';
import type { ScanLayout } from '../layout';
import type { ProcessRegistry } from '../processes';
import type { CodeGraphPlan } from '../knowledge-base/code-graph';
import type { RunKind, ScanOptions } from '../scan-command';
import { DockerRuntime, type HostPaths } from './docker';
import { NativeRuntime } from './native';

export type RuntimeName = 'native' | 'docker';
export const RUNTIMES: readonly RuntimeName[] = ['native', 'docker'];

/** The paths the scanner sees, for one layout: the container's (docker) or the host's (native). */
export interface ScanPaths {
  /** The checkout, read-only. */
  project: string;
  /** This run's prompt (--scan-prompt-file). */
  prompt: string;
  /** upstream's plugin with this scan's workflow skill (--plugin-path). */
  plugin: string;
  /** The model catalog (model_catalog_json). */
  modelCatalog: string;
  /** The knowledge base the lead reads: its index and the threat model (--knowledge-base). */
  knowledgeBase: string;
  /** The helpers' briefs, the reader and its file and function index. */
  kbIndex: string;
  /** The prompt's helper sections, which every helper prints first. */
  helperContext: string;
  /** The caller's severity rubric, staged (scan-inputs.ts): --rubric, and what every helper prints. */
  rubric: string;
  /** The caller's dismissals, staged (scan-inputs.ts), which the scan prompt names. */
  falsePositives: string;
  /** The architecture review agent's directory: its index, reader and answer. */
  review: string;
  /** The code graph's home. */
  graphHome: string;
  /** upstream's scan dir (--output-dir). */
  scanDir: string;
  /** The scan dir as the prompt names it: a path, or "$CODEX_SECURITY_SCAN_DIR". */
  promptScanDir: string;
}

/** One command a runtime builds: what to spawn, in which environment, under which name. */
export interface RuntimeCommand {
  /** The program, then its arguments. */
  argv: string[];
  /** The whole environment: nothing is inherited that is not here. */
  env: NodeJS.ProcessEnv;
  /** What stop() stops: a container's name (docker), a tracked process's (native). */
  name: string;
  cwd?: string;
  /**
   * How the scan shares the terminal in interactive mode (upstream's dashboard); piped when unset.
   * A command with a terminal runs in this process's group, so it can read the terminal.
   */
  stdio?: StdioOptions;
}

/** What the review agent's runtime needs: its name, its directory, the key and the catalog. */
export interface ReviewAgentPlan {
  /** The name stop() knows the agent by. */
  name: string;
  /** The caller's checkout on this machine. */
  project: string;
  /** The agent's directory on this machine: its home, index, reader and answer. */
  work: string;
  cynosKey: string;
  /** The run's model catalog on this machine, when the run wrote one. */
  modelCatalog?: string;
  /** The cynos endpoint; BASE_URL unless a benchmark gives its own gateway. */
  baseUrl?: string;
}

/** What a runtime prepares before a scan. */
export interface PrepareOptions {
  /** docker: build (or pull) the scanner image; false when the caller has it already. */
  buildImage: boolean;
  /** docker: load upstream's AppArmor profile when Docker uses AppArmor (sudo on the host). */
  loadAppArmor: boolean;
  /** native: the scan builds a knowledge base, so the code-graph binary must be present. */
  codeGraph: boolean;
  log(message: string): void;
}

export interface ScanRuntime {
  readonly name: RuntimeName;
  /** Paths that belong to another runtime and must not appear in this one's prompt. */
  readonly foreignPaths: string[];

  /** Makes the machine ready to scan, or throws with what is missing. */
  prepare(options: PrepareOptions): Promise<void>;
  /** One run of upstream's files on this machine: the scan's (in the stage) or the preflight's. */
  layout(stage: string, project: string, kind: RunKind): ScanLayout;
  /** The layout with its scan dir created, when the runtime creates it before upstream starts. */
  createScanDir(layout: ScanLayout): ScanLayout;
  /** The paths the scanner sees for a layout. */
  paths(layout: ScanLayout): ScanPaths;
  /**
   * upstream's bundled plugin at the pin, as a directory on this machine: the scan's plugin is
   * copied from it (scan-plugin.ts) and a diff's packet rules are read from it. It is the plugin
   * of the upstream this runtime runs: the host's install (native), the image's (docker).
   */
  bundledPlugin(stage: string): string;

  /** upstream's scan or preflight; the cynos key (or the preflight's placeholder) goes in env. */
  scanCommand(
    layout: ScanLayout,
    options: ScanOptions,
    kind: RunKind,
    key?: string
  ): RuntimeCommand;
  /** upstream's own sandbox check: Codex's sandbox runs /usr/bin/true. */
  sandboxCheck(): RuntimeCommand;
  /** upstream's strict SARIF export of the layout's scan dir, to <workspace>/out/results.sarif. */
  exportSarif(layout: ScanLayout): RuntimeCommand;
  /** The architecture review agent: `codex exec`, a new session or `resume` of the last. */
  reviewAgentCommand(plan: ReviewAgentPlan, resume: boolean): RuntimeCommand;
  /** What the code graph's server runs in until codeGraphStop, when anything does. */
  codeGraphStart(plan: CodeGraphPlan): RuntimeCommand | undefined;
  /** codebase-memory-mcp as an MCP server on stdio, for every call of one build. */
  codeGraphServer(plan: CodeGraphPlan): RuntimeCommand;
  /** Removes what codeGraphStart started. */
  codeGraphStop(plan: CodeGraphPlan): RuntimeCommand | undefined;

  /** Starts a command this runtime built; stdio defaults to the command's own, else piped. */
  spawn(command: RuntimeCommand, stdio?: StdioOptions): ChildProcess;
  /** Stops a command by its name: its container, or its process group. */
  stop(name: string): Promise<void>;
  /** What this runtime runs (upstream, Codex, Node, Python, ...), written to output as JSON. */
  versions(output: string): Record<string, unknown>;
}

/** What creates a runtime: the assets, and each runtime's own settings. */
export interface RuntimeOptions {
  runtime: RuntimeName;
  /** The engine's assets: profiles, Dockerfile, base instructions, scan prompt. */
  assets: string;
  /** Every container's or tracked process's name starts with it (ScanConfig.runName). */
  runName?: string;
  /** native: upstream's state dir, or 'upstream-default' to leave upstream's own (resolveStateDir). */
  stateDir?: 'upstream-default' | string;
  /** native: where to resolve upstream from (resolveUpstream). */
  upstream?: string;
  /** native: where the code-graph binary is kept (code-graph-binary.ts). */
  toolCache?: string;
  /** native: the registry the runtime's processes are tracked in, so a caller can stop them. */
  processes?: ProcessRegistry;
  /** docker: mount sources on the Docker host, when this process is not on it. */
  hostPaths?: HostPaths;
}

export { DockerRuntime, NativeRuntime };

/** The runtime options name. */
export function createRuntime(options: RuntimeOptions): ScanRuntime {
  return options.runtime === 'native' ? new NativeRuntime(options) : new DockerRuntime(options);
}
