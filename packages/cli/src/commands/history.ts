/**
 * History: scans, findings, export and logs, which are upstream's.
 *
 * upstream keeps a scan's history, findings and session logs in its state dir, and its own
 * commands already list, show, compare, rerun and export them, with every format and filter. A
 * copy would drift from upstream with every release, so each history command runs upstream's
 * own, with the arguments exactly as given, in the same state dir as `cs`.
 *
 * Two things upstream has no record of are added, both from the run dir
 * (<state>/averlon/scans/<id>/):
 *
 *   scans show   after upstream's output, our knowledge-base summary for that scan
 *   logs         --source knowledge-base|architecture reads our log instead of upstream's;
 *                --follow keeps printing as the log grows
 */
import { existsSync, lstatSync, readdirSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { Command } from 'commander';
import { CLI_NAME, type Context } from '../context';
import { engine } from '../engine';
import { CliError } from '../exit-codes';
import { passesThrough, withExamples } from '../help';
import { RUN_FILES, runsDir } from '../settings';
import type { Terminal } from '../terminal';
import { captureUpstream, passThrough, upstreamJson, type UpstreamCapture } from '../upstream';

/** The history commands: our name, upstream's, and the examples for its help. */
const PASS_THROUGH: { path: string[]; description: string; examples: string[] }[] = [
  {
    path: ['scans', 'list'],
    description: 'List saved scans for this repository.',
    examples: ['scans list', 'scans list ~/code/api --json'],
  },
  {
    path: ['scans', 'show'],
    description: 'Show a scan: results, configuration, and our knowledge-base summary.',
    examples: ['scans show', 'scans show 1a2b3c4d', 'scans show 1a2b3c4d --json'],
  },
  {
    path: ['scans', 'logs'],
    description: "Show a scan's saved session events (upstream's; see also `logs`).",
    examples: ['scans logs', 'scans logs 1a2b3c4d --json'],
  },
  {
    path: ['scans', 'compare'],
    description: 'Compare findings and coverage between two scans.',
    examples: ['scans compare', 'scans compare 1a2b3c4d 5e6f7a8b'],
  },
  {
    path: ['scans', 'rerun'],
    description: 'Rerun a saved scan with its original configuration.',
    examples: ['scans rerun', 'scans rerun 1a2b3c4d'],
  },
  {
    path: ['findings', 'list'],
    description: 'List open findings for this repository across its scans.',
    examples: ['findings list', 'findings list --json'],
  },
  {
    path: ['findings', 'false-positive'],
    description: 'Mark a finding as a false positive for future scans.',
    examples: ['findings false-positive OCCURRENCE_ID --reason "input is validated upstream"'],
  },
];

export function registerHistory(program: Command, ctx: Context): void {
  // scans and findings: a parent each, upstream's subcommands under it.
  const parents = new Map<string, Command>();
  for (const [name, description, examples] of [
    [
      'scans',
      'Review saved scans (list, show, logs, compare, rerun).',
      ['scans list', 'scans show'],
    ],
    ['findings', 'Review saved findings (list, false-positive).', ['findings list']],
  ] as const) {
    const parent = program.command(name).description(description);
    withExamples(
      parent,
      examples.map(example => `${CLI_NAME} ${example}`)
    );
    parents.set(name, parent);
  }
  for (const { path, description, examples } of PASS_THROUGH) {
    const [group, sub] = path as [string, string];
    const command = parents
      .get(group)!
      .command(sub)
      .description(description)
      .argument('[args...]', "upstream's arguments and options")
      .allowUnknownOption()
      .action(async (_args: string[], _options: unknown, self: Command) => {
        process.exitCode = await runHistory(ctx, path, self.args);
      });
    withExamples(
      command,
      examples.map(example => `${CLI_NAME} ${example}`)
    );
    passesThrough(command, `codex-security ${path.join(' ')} --help`);
  }

  const exportCommand = program
    .command('export')
    .description('Export saved findings (json, csv, sarif) or a threat model, without a new scan.')
    .argument('[args...]', "upstream's arguments and options")
    .allowUnknownOption()
    .action(async (_args: string[], _options: unknown, self: Command) => {
      process.exitCode = await passThrough(['export', ...self.args]);
    });
  withExamples(exportCommand, [
    `${CLI_NAME} export --export-format sarif --output results.sarif`,
    `${CLI_NAME} export --scan 1a2b3c4d --export-format json --output -`,
    `${CLI_NAME} export --artifact threat-model --output -`,
  ]);
  passesThrough(exportCommand, 'codex-security export --help');

  const logs = program
    .command('logs')
    .description("Show a scan's logs: upstream's session events, or our knowledge-base log.")
    .argument('[id]', 'scan id or unique prefix (default: the latest scan)')
    .option('--follow', 'keep printing as the log grows (Ctrl-C to stop)')
    .option('--source <source>', 'upstream (default), knowledge-base or architecture', 'upstream')
    .action(async (id: string | undefined, options: { follow?: boolean; source: string }) => {
      process.exitCode = await logsCommand(ctx, id, options);
    });
  withExamples(logs, [
    `${CLI_NAME} logs`,
    `${CLI_NAME} logs 1a2b3c4d --follow`,
    `${CLI_NAME} logs --source knowledge-base`,
    `${CLI_NAME} logs 1a2b3c4d --source architecture`,
  ]);
}

/** Runs upstream's history command; `scans show` adds our summary in human output. */
async function runHistory(ctx: Context, path: string[], args: string[]): Promise<number> {
  const status = await passThrough([...path, ...args]);
  if (status !== 0 || path.join(' ') !== 'scans show' || machineReadable(args)) return status;
  const id = await shownScanId(args);
  const runDir = id ? findRunDir(engine().resolveStateDir(ctx.env), id) : undefined;
  if (runDir) ctx.terminal.result(knowledgeBaseSummary(ctx.terminal, runDir));
  return status;
}

/** Whether upstream was asked for JSON, YAML or the like: then stdout is upstream's alone. */
export function machineReadable(args: string[]): boolean {
  if (args.includes('--json') || args.includes('--llms') || args.includes('--schema')) return true;
  const index = args.findIndex(arg => arg === '--format' || arg.startsWith('--format='));
  if (index === -1) return false;
  const value = args[index]!.includes('=') ? args[index]!.split('=')[1] : args[index + 1];
  return value !== undefined && value !== 'md';
}

/** The scan `scans show` displayed: the id given, else upstream's latest completed. */
async function shownScanId(
  args: string[],
  capture: UpstreamCapture = captureUpstream
): Promise<string | undefined> {
  const given = args.find(arg => !arg.startsWith('-'));
  if (given) return given;
  const shown = await upstreamJson(['scans', 'show'], capture);
  const value = shown.value as Record<string, unknown> | undefined;
  const manifest = value?.['manifest'] as { scan?: { id?: unknown } } | undefined;
  const id = value?.['scanId'] ?? manifest?.scan?.id;
  return typeof id === 'string' ? id : undefined;
}

/**
 * A scan's run dir by its id or a unique prefix (upstream accepts prefixes of eight characters
 * or more), or a run that never got a scan id by its run name.
 */
export function findRunDir(stateDir: string, id: string): string | undefined {
  const root = runsDir(stateDir);
  if (!existsSync(root)) return undefined;
  if (existsSync(join(root, id))) return realpathSync(join(root, id));
  // A scan id's link and its run dir are one run: a prefix that names both is not ambiguous.
  const matches = new Set(
    readdirSync(root)
      .filter(name => name.startsWith(id) && existsSync(join(root, name)))
      .map(name => realpathSync(join(root, name)))
  );
  return matches.size === 1 ? [...matches][0] : undefined;
}

/** The newest run dir, for `logs` without an id when upstream has no scan yet. */
export function latestRunDir(stateDir: string): string | undefined {
  const root = runsDir(stateDir);
  if (!existsSync(root)) return undefined;
  // The run dirs themselves, not the scan-id links to them.
  const newest = readdirSync(root)
    .filter(name => lstatSync(join(root, name)).isDirectory())
    .map(name => ({ name, mtime: statSync(join(root, name)).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime)[0];
  return newest ? join(root, newest.name) : undefined;
}

function readJsonFile(path: string): Record<string, unknown> | undefined {
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

/** What our knowledge base gave the scan, from the engine's run.json and our timings. */
export function knowledgeBaseSummary(terminal: Terminal, runDir: string): string {
  const c = terminal.out;
  const run = readJsonFile(join(runDir, 'run.json')) ?? {};
  const result = readJsonFile(join(runDir, RUN_FILES.result)) ?? {};
  const built = (run['knowledge_base_build'] ?? result['knowledgeBase']) as
    Record<string, unknown> | null | undefined;
  const reused = (run['diff_threat_model'] ?? result['diffThreatModel']) as
    Record<string, unknown> | null | undefined;
  const lines = ['', c.bold('KNOWLEDGE BASE (cynos)')];
  if (built?.['kind'] === 'diff') {
    const n = (key: string): string => Number(built[key] ?? 0).toLocaleString('en-US');
    const briefs = Array.isArray(built['briefs']) ? built['briefs'].length : 0;
    const tm = (built['threat_model'] ?? {}) as { gate?: string[]; updated?: boolean };
    const model = tm.updated
      ? `updated for the change (${(tm.gate ?? []).length} reasons)`
      : "the last full scan's, unchanged";
    lines.push(
      `  ${n('changed_files')} changed files · ${n('changed_functions')} changed functions · ${n('path_functions')} on their paths`,
      `  ${briefs} helper briefs · ${n('jev_calls')} Jev calls ($${Number(built['cost_usd'] ?? 0).toFixed(2)})`,
      `  threat model: ${model}`
    );
  } else if (built) {
    const n = (key: string): string => Number(built[key] ?? 0).toLocaleString('en-US');
    const cache = (built['cache'] ?? {}) as { graph_reused?: boolean; answers_reused?: number };
    const briefs = Array.isArray(built['briefs']) ? built['briefs'].length : 0;
    lines.push(
      `  ${n('product_files')} product files · ${n('functions')} functions · ${n('entries')} entry points · ${n('sinks')} sinks`,
      `  ${briefs} helper briefs · ${n('jev_calls')} Jev calls ($${Number(built['cost_usd'] ?? 0).toFixed(2)})`,
      `  cache: code graph ${cache.graph_reused ? 'reused' : 'built'}, ${cache.answers_reused ?? 0} answers reused`,
      `  architecture review: ${built['architecture_review'] ? 'stored' : 'failed (the lead wrote the threat model)'}`
    );
  } else if (reused)
    lines.push(`  the last full scan's threat model, reused: ${JSON.stringify(reused)}`);
  else lines.push(`  ${c.dim('none for this scan (a mock, a dry run, or --no-knowledge-base)')}`);
  const timings = readJsonFile(join(runDir, RUN_FILES.timings));
  const total = timings?.['total_seconds'];
  if (typeof total === 'number')
    lines.push(c.dim(`  run took ${total}s; timings in ${join(runDir, RUN_FILES.timings)}`));
  lines.push(c.dim(`  extras: ${runDir}`));
  return lines.join('\n');
}

const SOURCES = ['upstream', 'knowledge-base', 'architecture'] as const;

/**
 * `logs`: upstream's session events by default; our run dir's log for the knowledge base or
 * the architecture review. upstream's `scans logs` has no --follow, so following it re-reads
 * the log every two seconds and prints only what is new.
 */
async function logsCommand(
  ctx: Context,
  id: string | undefined,
  options: { follow?: boolean; source: string }
): Promise<number> {
  if (!(SOURCES as readonly string[]).includes(options.source))
    throw new CliError(
      'usage',
      `--source must be one of ${SOURCES.join(', ')}, not ${options.source}`
    );
  if (options.source === 'upstream') {
    const args = ['scans', 'logs', ...(id ? [id] : [])];
    if (!options.follow) return passThrough(args);
    return follow(async () => (await captureUpstream(args)).stdout, ctx.terminal);
  }
  const stateDir = engine().resolveStateDir(ctx.env);
  const runDir = id ? findRunDir(stateDir, id) : latestRunDir(stateDir);
  if (!runDir)
    throw new CliError(
      'usage',
      id ? `No cynos run dir for ${id}` : 'No cynos run yet',
      `Find scan ids with \`${CLI_NAME} scans list\`.`
    );
  const read = async (): Promise<string> =>
    ourLog(runDir, options.source as 'knowledge-base' | 'architecture');
  if (!options.follow) {
    ctx.terminal.result(
      (await read()) || ctx.terminal.out.dim(`(no ${options.source} lines in ${runDir})`)
    );
    return 0;
  }
  return follow(read, ctx.terminal);
}

/** Our log's lines for one source: the knowledge base's build, or its architecture review. */
export function ourLog(runDir: string, source: 'knowledge-base' | 'architecture'): string {
  const path = join(runDir, RUN_FILES.log);
  if (!existsSync(path)) return '';
  const wanted =
    source === 'architecture'
      ? /architecture|review agent|review:/i
      : /knowledge base|knowledge-base/i;
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter(line => wanted.test(line))
    .join('\n');
}

/** Prints read()'s output, then whatever it adds, until Ctrl-C. */
async function follow(read: () => Promise<string>, terminal: Terminal): Promise<number> {
  let printed = 0;
  let stopped = false;
  const stop = (): void => {
    stopped = true;
  };
  process.once('SIGINT', stop);
  while (!stopped) {
    const lines = (await read()).replace(/\n$/, '').split('\n').filter(Boolean);
    // A log that shrank was replaced (a new scan): start over.
    if (lines.length < printed) printed = 0;
    if (lines.length > printed) terminal.result(lines.slice(printed).join('\n'));
    printed = lines.length;
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  process.off('SIGINT', stop);
  return 0;
}
