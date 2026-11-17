/**
 * upstream's scan command: the same arguments for both runtimes, at the paths the scanner sees.
 *
 * The scan is codex-security's own `scan`, configured only through its flags and stock Codex
 * configuration (--codex): the cynos endpoint, the model catalog that gives Codex the model's
 * window, compaction, the thread cap with a knowledge base. What differs between the runtimes is
 * where the scanner finds its inputs (/scan/... in a container, the stage's real paths on the
 * host), so every path comes from ScanPaths, and whether upstream draws its own dashboard
 * (interactive) or reports to a log (--headless --json).
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  BASE_INSTRUCTIONS_SHA256,
  BASE_URL,
  codexOverrides,
  JUDGE_HEADER,
  KNOWLEDGE_BASE_MAX_THREADS,
  KNOWLEDGE_BASE_MODEL,
  MODEL_CONTEXT_WINDOW,
  PROVIDER_ID,
  TASK_ROUTE_HEADER,
} from './constants';
import { MODEL_CATALOG_FILE } from './layout';
import type { ScanPaths } from './runtime';
import { UPSTREAM_PIN } from './upstream';

/** A scan's settings: upstream's scan inputs, plus mock and the knowledge base. */
export interface ScanOptions {
  paths: string[];
  /** Scan only the changes from this commit to HEAD. */
  diffBase: string;
  /** A repository-relative file passed as --knowledge-base: authoritative context. */
  knowledgeBase: string;
  model: string;
  effort: string;
  mode: string;
  cyberAccessProgram: string;
  maxTimeHours: number | undefined;
  failOnSeverity: string;
  verbose: boolean;
  /** Validate local configuration only: no model call, no key. */
  dryRun: boolean;
  /** codex-security's synthetic scan: no model call, no key. */
  mock: boolean;
  /**
   * The knowledge base was built (knowledge-base/index.ts): it is passed as --knowledge-base in
   * place of the threat model, and helpers may run in parallel up to KNOWLEDGE_BASE_MAX_THREADS.
   */
  knowledgeBaseBuilt: boolean;
  /**
   * The helpers' instructions (assets/scan-prompt/helper-<kind>.md) are written for this run
   * (pipeline.ts): at ScanPaths.helperContext for every helper or worker, in a full scan and in a
   * diff.
   */
  helperContext: boolean;
  /**
   * upstream's plugin with this scan's workflow skill was written for this run (scan-plugin.ts):
   * at ScanPaths.plugin, passed as --plugin-path.
   */
  plugin: boolean;
  /** The caller's severity rubric is staged at ScanPaths.rubric: passed as --rubric. */
  rubric: boolean;
  /**
   * The caller's dismissals are staged at ScanPaths.falsePositives, which the scan prompt names;
   * upstream has no flag for them (scan-inputs.ts).
   */
  falsePositives: boolean;
  /** cynos's quality judge for the scan's turns: on unless `cynos-judge: off`. */
  judge: boolean;
  /** cynos's task routing for the scan's turns: on unless `cynos-task-routing: off`. */
  taskRouting: boolean;
  /** The cynos endpoint; BASE_URL unless a benchmark gives its own gateway. */
  baseUrl?: string;
  /**
   * upstream draws its own dashboard on the terminal (no --headless, no --json); the outcome is
   * read from the scan dir afterwards.
   */
  interactive?: boolean;
}

/** The scan, or the preflight: the same scan stopped once it starts scanning. */
export type RunKind = 'scan' | 'preflight';

/**
 * The cynos endpoint as stock Codex configuration. Its HTTP headers switch the quality judge (see
 * JUDGE_HEADER), and task routing when it is off; Codex sends them on every model call, the
 * helpers' included.
 */
export function providerOverrides(
  gateway: Pick<ScanOptions, 'judge' | 'taskRouting' | 'baseUrl'> = {
    judge: true,
    taskRouting: true,
  }
): string[] {
  const pairs = [
    `"${JUDGE_HEADER}"="${gateway.judge ? 'on' : 'off'}"`,
    ...(gateway.taskRouting ? [] : [`"${TASK_ROUTE_HEADER}"="off"`]),
  ];
  const headers = `{${pairs.join(',')}}`;
  const table = `{name="cynos",base_url="${gateway.baseUrl ?? BASE_URL}",env_key="CODEX_API_KEY",wire_api="responses",http_headers=${headers}}`;
  return [`model_provider="${PROVIDER_ID}"`, `model_providers.${PROVIDER_ID}=${table}`];
}

/** Whether the scan makes model calls, and so needs the key and the network. */
export function makesModelCalls(options: Pick<ScanOptions, 'dryRun' | 'mock'>): boolean {
  return !(options.dryRun || options.mock);
}

/** codex-security's arguments for these options, built as upstream's Action builds them. */
export function scanArguments(
  options: ScanOptions,
  paths: Pick<
    ScanPaths,
    'project' | 'knowledgeBase' | 'scanDir' | 'prompt' | 'plugin' | 'modelCatalog' | 'rubric'
  >
): string[] {
  const args = ['scan', paths.project];
  // Bound and explicitly relative, so the CLI treats a leading '-' or '~' as a literal name.
  for (const path of options.paths) args.push(`--path=./${path}`);
  if (options.diffBase) args.push('--diff', options.diffBase);
  // upstream takes several knowledge bases: ours, and the repository's own threat-model file.
  if (options.knowledgeBaseBuilt) args.push('--knowledge-base', paths.knowledgeBase);
  if (options.knowledgeBase)
    args.push('--knowledge-base', `${paths.project}/${options.knowledgeBase}`);
  args.push(
    `--model=${options.model}`,
    '--effort',
    options.effort,
    '--mode',
    options.mode,
    '--output-dir',
    paths.scanDir,
    '--scan-prompt-file',
    paths.prompt,
    '--show-cost'
  );
  if (options.rubric) args.push('--rubric', paths.rubric);
  if (options.plugin) args.push('--plugin-path', paths.plugin);
  // upstream's dashboard runs unless the output is headless or a format (cli.js executeScan).
  if (!options.interactive) args.push('--headless', '--json');
  if (options.cyberAccessProgram) args.push('--cyber-access-program', options.cyberAccessProgram);
  if (options.maxTimeHours !== undefined)
    args.push('--max-time-hours', String(options.maxTimeHours));
  if (options.failOnSeverity !== 'none') args.push('--fail-on-severity', options.failOnSeverity);
  if (options.verbose) args.push('--verbose');
  if (options.mock) args.push('--mock');
  // The dry run never starts a model session; auto allows it without a key, as upstream does.
  else if (options.dryRun) args.push('--dry-run', '--auth', 'auto');
  else args.push('--auth', 'api-key');
  const overrides = [...providerOverrides(options), ...codexOverrides(paths.modelCatalog)];
  // Multi-agent v2 refuses the legacy agents.max_threads; this is its only thread cap.
  if (options.knowledgeBaseBuilt || options.helperContext)
    overrides.push(
      `features.multi_agent_v2.max_concurrent_threads_per_session=${KNOWLEDGE_BASE_MAX_THREADS}`
    );
  for (const override of overrides) args.push('--codex', override);
  return args;
}

/**
 * A Codex model catalog for the run's models: each one's entry is the fallback metadata Codex
 * gives a model it does not know (model_info_from_slug in codex-rs/models-manager/src/model_info.rs
 * at rust-v0.167.0), with MODEL_CONTEXT_WINDOW as its window. The catalog replaces Codex's bundled
 * one, which has no entry for a cynos model anyway. A model listed twice gets one entry.
 */
export function modelCatalog(
  models: readonly string[],
  baseInstructions: string
): Record<string, unknown> {
  return { models: [...new Set(models)].map(model => catalogEntry(model, baseInstructions)) };
}

/** One model's catalog entry: Codex's fallback metadata with the model's real window. */
function catalogEntry(model: string, baseInstructions: string): Record<string, unknown> {
  return {
    slug: model,
    display_name: model,
    description: null,
    supported_reasoning_levels: [],
    shell_type: 'unified_exec',
    visibility: 'none',
    supported_in_api: true,
    priority: 99,
    availability_nux: null,
    upgrade: null,
    model_messages: { instructions_template: baseInstructions },
    include_skills_usage_instructions: false,
    include_plugin_usage_instructions: false,
    include_apps_usage_instructions: false,
    supports_reasoning_summary_parameter: true,
    default_reasoning_summary: 'auto',
    support_verbosity: false,
    default_verbosity: null,
    apply_patch_tool_type: null,
    web_search_tool_type: 'text',
    truncation_policy: { mode: 'bytes', limit: 10000 },
    context_window: MODEL_CONTEXT_WINDOW,
    max_context_window: MODEL_CONTEXT_WINDOW,
    effective_context_window_percent: 95,
    experimental_supported_tools: [],
  };
}

/**
 * Writes the run's model catalog into workspace, after checking the vendored instructions.
 *
 * Two Codex sessions read this one catalog: the scan, on the scan model, and the knowledge base's
 * architecture agent, on KNOWLEDGE_BASE_MODEL. The two differ whenever the scan runs on another
 * model (the default does), and a model missing from the catalog gets Codex's 272k fallback
 * window, so the agent compacts a large review early. So the catalog lists both models.
 */
export function writeModelCatalog(assets: string, workspace: string, model: string): void {
  const instructions = readFileSync(join(assets, 'codex-base-instructions.md'));
  const actual = createHash('sha256').update(instructions).digest('hex');
  if (actual !== BASE_INSTRUCTIONS_SHA256)
    throw new Error(
      `codex-base-instructions.md is not Codex rust-v${UPSTREAM_PIN.codexVersion}'s prompt.md (sha256 ${actual})`
    );
  writeFileSync(
    join(workspace, MODEL_CATALOG_FILE),
    JSON.stringify(modelCatalog([model, KNOWLEDGE_BASE_MODEL], instructions.toString('utf8'))),
    { mode: 0o600 }
  );
}
