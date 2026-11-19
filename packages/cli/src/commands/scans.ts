/**
 * `scans`: the scans this machine ran, read from their run dirs: list, findings, export, logs.
 *
 * upstream keeps a history of its own (workbench.sqlite3 in its state dir), but only of the scans
 * it ran with that state dir. A docker scan's upstream ran in the container with the run dir's
 * state/ as its state dir, and recorded the container's paths (/scan/project, /scan/out/scan): the
 * history on the host has never heard of it, and its own names paths that are not on this machine.
 * So upstream's history commands cannot serve both runtimes. Every scan, on either runtime, has a
 * run dir with the same files, and these commands read only those:
 *
 *   <state>/averlon/scans/<run name>/   one scan's run dir
 *     cli-result.json                   the result `scan --format json` printed: scan id, status,
 *                                       runtime, project, commit, counts
 *     reports/                          the engine's validated copies of upstream's reports
 *       findings.json  results.sarif  report.md  …
 *     cli.log                           the CLI's log of the run
 *   <state>/averlon/scans/<scan id>     a link to it, once upstream's scan id is known
 *
 *   list      every run dir's cli-result.json, newest first
 *   findings  reports/findings.json, most severe first
 *   export    a copy of reports/results.sarif, findings.json or report.md
 *   logs      cli.log, and with --follow what it adds while the scan runs
 */
import {
  existsSync,
  lstatSync,
  readdirSync,
  readFileSync,
  realpathSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { Option, type Command } from 'commander';
import { CLI_NAME, type Context } from '../context';
import { engine } from '../engine';
import { CliError, EXIT } from '../exit-codes';
import { withExamples } from '../help';
import { RUN_FILES, runsDir } from '../settings';
import type { Colors, Terminal } from '../terminal';

/** The engine's validated reports, in each run dir (the engine's reports.ts). */
const REPORTS_DIR = 'reports';

/** What `scans export --format` copies from the reports. */
const EXPORTS = { sarif: 'results.sarif', json: 'findings.json', md: 'report.md' } as const;
type ExportFormat = keyof typeof EXPORTS;

export function registerScans(program: Command, ctx: Context): void {
  const scans = program
    .command('scans')
    .description('Review the scans this machine ran, on either runtime.');
  withExamples(scans, [`${CLI_NAME} scans list`, `${CLI_NAME} scans findings 1a2b3c4d`]);

  const list = scans
    .command('list')
    .description('List every scan: id, when, runtime, kind, status, findings and repository.')
    .option('--json', 'one JSON object on stdout')
    .action((options: { json?: boolean }) => {
      process.exitCode = listCommand(ctx, options);
    });
  withExamples(list, [`${CLI_NAME} scans list`, `${CLI_NAME} scans list --json`]);

  const findings = scans
    .command('findings')
    .description("Show a scan's findings, most severe first.")
    .argument('<id>', 'scan id, unique prefix or run name')
    .action((id: string) => {
      process.exitCode = findingsCommand(ctx, id);
    });
  withExamples(findings, [`${CLI_NAME} scans findings 1a2b3c4d`]);

  const exportCommand = scans
    .command('export')
    .description("Export a scan's findings as SARIF, JSON or Markdown.")
    .argument('<id>', 'scan id, unique prefix or run name')
    .addOption(
      new Option('--format <format>', 'sarif, json (findings.json) or md (the report)')
        .choices(Object.keys(EXPORTS))
        .default('sarif')
    )
    .option('--output <file>', 'where to write it (default: stdout)')
    .action((id: string, options: { format: ExportFormat; output?: string }) => {
      process.exitCode = exportScan(ctx, id, options);
    });
  withExamples(exportCommand, [
    `${CLI_NAME} scans export 1a2b3c4d --output results.sarif`,
    `${CLI_NAME} scans export 1a2b3c4d --format json`,
    `${CLI_NAME} scans export 1a2b3c4d --format md --output report.md`,
  ]);

  const logs = scans
    .command('logs')
    .description("Show a scan's log (default: the newest run's, a running scan included).")
    .argument('[id]', 'scan id, unique prefix or run name')
    .option('--follow', 'keep printing as the log grows (Ctrl-C to stop)')
    .action(async (id: string | undefined, options: { follow?: boolean }) => {
      process.exitCode = await logsCommand(ctx, id, options);
    });
  withExamples(logs, [`${CLI_NAME} scans logs`, `${CLI_NAME} scans logs 1a2b3c4d --follow`]);
}

/** One scan as its run dir records it. */
export interface ScanRun {
  /** upstream's scan id, or the run name of a run that never got one. */
  id: string;
  runDir: string;
  /** When the run wrote its result, or last wrote anything when it has none. */
  finishedAt: Date;
  /** cli-result.json; undefined while the scan runs, or after it failed before its result. */
  result: Record<string, unknown> | undefined;
  /** A mock scan (CYNOS_SCAN_MOCK=1): its findings are synthetic. */
  mock: boolean;
}

/** Every run dir under the state dir, newest first. */
export function listRuns(stateDir: string): ScanRun[] {
  const root = runsDir(stateDir);
  if (!existsSync(root)) return [];
  // The run dirs themselves, not the scan-id links to them.
  return readdirSync(root)
    .map(name => join(root, name))
    .filter(path => lstatSync(path).isDirectory())
    .map(readRun)
    .sort((a, b) => b.finishedAt.getTime() - a.finishedAt.getTime());
}

function readRun(runDir: string): ScanRun {
  const resultFile = join(runDir, RUN_FILES.result);
  const result = readJsonObject(resultFile);
  const scanId = result?.['scanId'];
  // The command the engine ran upstream with (run.json's), on either runtime: a mock scan's has
  // upstream's --mock. The docker runtime keeps even a mock scan's history in state/, so the
  // native runtime's mock-state/ does not tell them apart.
  const command = readJsonObject(join(runDir, 'run.json'))?.['command'];
  return {
    id: typeof scanId === 'string' && scanId ? scanId : runDir.split(/[\\/]/).pop()!,
    runDir,
    finishedAt: statSync(result ? resultFile : runDir).mtime,
    result,
    mock: Array.isArray(command) && command.includes('--mock'),
  };
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

/** The newest run dir: a running scan's has no scan id yet. */
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

/** The run dir id names, or a usage error pointing at `scans list`. */
function requireRunDir(ctx: Context, id: string): string {
  const runDir = findRunDir(engine().resolveStateDir(ctx.env), id);
  if (!runDir)
    throw new CliError(
      'usage',
      `No scan ${id} on this machine (or the prefix names more than one).`,
      `\`${CLI_NAME} scans list\` lists them.`
    );
  return runDir;
}

/** `scans list`: one row per run dir, or with --json one object with every run. */
function listCommand(ctx: Context, options: { json?: boolean }): number {
  const { terminal } = ctx;
  const runs = listRuns(engine().resolveStateDir(ctx.env));
  if (options.json) {
    terminal.json({ scans: runs.map(runRecord) });
    return EXIT.ok;
  }
  if (!runs.length) {
    terminal.result(`No scans yet. Run \`${CLI_NAME} scan\` first.`);
    return EXIT.ok;
  }
  const rows = runs.map(run => runRow(terminal.out, run));
  const header = ['SCAN ID', 'FINISHED', 'RUNTIME', 'KIND', 'STATUS', 'FINDINGS', 'REPOSITORY'];
  terminal.result(table([header.map(title => terminal.out.dim(title)), ...rows]));
  return EXIT.ok;
}

/** A run as `scans list --json` prints it: the fields of its result a script reads first. */
export function runRecord(run: ScanRun): Record<string, unknown> {
  const result = run.result ?? {};
  return {
    scanId: run.id,
    finishedAt: run.finishedAt.toISOString(),
    scanStatus: result['scanStatus'] ?? 'unfinished',
    runtime: result['runtime'] ?? null,
    kind: result['kind'] ?? null,
    diffBase: result['diffBase'] ?? null,
    project: result['project'] ?? null,
    scannedSha: result['scannedSha'] ?? null,
    counts: result['counts'] ?? null,
    mock: run.mock,
    runDir: run.runDir,
  };
}

function runRow(c: Colors, run: ScanRun): string[] {
  const record = runRecord(run);
  const text = (value: unknown): string => (typeof value === 'string' ? value : '');
  const status = text(record['scanStatus']);
  const diffBase = text(record['diffBase']);
  const sha = text(record['scannedSha']);
  const project = text(record['project']).replace(homedir(), '~');
  return [
    run.id,
    localTime(run.finishedAt),
    `${text(record['runtime']) || '-'}${run.mock ? ' (mock)' : ''}`,
    record['kind'] === 'diff' ? `diff from ${diffBase.slice(0, 8)}` : text(record['kind']) || '-',
    status === 'completed' ? c.green(status) : status === 'failed' ? c.red(status) : status,
    findingCount(record['counts']),
    project ? `${project}${sha ? ` @ ${sha.slice(0, 12)}` : ''}` : '-',
  ];
}

/** `6 (2 high)`: the total, and how many of the most severe level there are. */
function findingCount(counts: unknown): string {
  if (typeof counts !== 'object' || counts === null) return '-';
  const byLevel = counts as Record<string, number>;
  const total = Object.values(byLevel).reduce((sum, n) => sum + (Number(n) || 0), 0);
  const worst = engine().SEVERITIES.find(level => (byLevel[level] ?? 0) > 0);
  return worst ? `${total} (${byLevel[worst]} ${worst})` : String(total);
}

function localTime(date: Date): string {
  const pad = (n: number): string => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** Rows as columns, each as wide as its widest cell (colour codes not counted). */
function table(rows: string[][]): string {
  const visible = (cell: string): number => cell.replace(/\x1b\[[0-9;]*m/g, '').length;
  const widths = rows[0]!.map((_, column) =>
    Math.max(...rows.map(row => visible(row[column] ?? '')))
  );
  return rows
    .map(row =>
      row
        .map((cell, column) =>
          column === row.length - 1 ? cell : cell + ' '.repeat(widths[column]! - visible(cell) + 2)
        )
        .join('')
    )
    .join('\n');
}

/** `scans findings <id>`: every finding of the scan's validated findings.json. */
function findingsCommand(ctx: Context, id: string): number {
  const { terminal } = ctx;
  const runDir = requireRunDir(ctx, id);
  const reports = join(runDir, REPORTS_DIR);
  const status = statusOf(runDir);
  if (!existsSync(join(reports, EXPORTS.json)))
    throw new CliError('usage', `Scan ${id} has no findings report (${status}).`);
  // A scan that did not complete may have stopped before validation finished its findings.
  if (status !== 'completed')
    terminal.warn(`This scan's status is ${status}: its findings may be incomplete.`);
  const findings = readFindings(reports);
  if (!findings)
    throw new CliError(
      'usage',
      `Scan ${id}'s findings report is not readable: ${join(reports, EXPORTS.json)}.`
    );
  terminal.result(
    findings.length ? findingRows(terminal.out, findings).join('\n') : 'No findings.'
  );
  return EXIT.ok;
}

function statusOf(runDir: string): string {
  const status = readJsonObject(join(runDir, RUN_FILES.result))?.['scanStatus'];
  return typeof status === 'string' ? status : 'unfinished';
}

/** `scans export <id>`: one of the scan's validated reports, to stdout or --output. */
function exportScan(
  ctx: Context,
  id: string,
  options: { format: ExportFormat; output?: string }
): number {
  const { terminal } = ctx;
  const runDir = requireRunDir(ctx, id);
  const report = join(runDir, REPORTS_DIR, EXPORTS[options.format]);
  // The engine copies a report only once it validated it: a missing one failed, or never existed.
  if (!existsSync(report))
    throw new CliError(
      'usage',
      `Scan ${id} has no ${EXPORTS[options.format]} (${statusOf(runDir)}).`,
      `\`${CLI_NAME} scans logs ${id}\` shows what happened.`
    );
  const content = readFileSync(report);
  if (!options.output || options.output === '-') {
    terminal.stdout.write(content);
    return EXIT.ok;
  }
  const output = resolve(options.output);
  writeFileSync(output, content);
  terminal.result(output);
  return EXIT.ok;
}

/** `scans logs [id]`: the run's cli.log; --follow re-reads it every two seconds. */
async function logsCommand(
  ctx: Context,
  id: string | undefined,
  options: { follow?: boolean }
): Promise<number> {
  const stateDir = engine().resolveStateDir(ctx.env);
  const runDir = id ? requireRunDir(ctx, id) : latestRunDir(stateDir);
  if (!runDir) throw new CliError('usage', 'No scan yet.', `Run \`${CLI_NAME} scan\` first.`);
  const log = join(runDir, RUN_FILES.log);
  const read = (): string => (existsSync(log) ? readFileSync(log, 'utf8') : '');
  if (options.follow) return follow(read, ctx.terminal);
  ctx.terminal.result(read().replace(/\n$/, '') || ctx.terminal.out.dim(`(no log in ${runDir})`));
  return EXIT.ok;
}

/** Prints read()'s output, then whatever it adds, until Ctrl-C. */
async function follow(read: () => string, terminal: Terminal): Promise<number> {
  let printed = 0;
  let stopped = false;
  const stop = (): void => {
    stopped = true;
  };
  process.once('SIGINT', stop);
  while (!stopped) {
    const lines = read().replace(/\n$/, '').split('\n').filter(Boolean);
    if (lines.length > printed) terminal.result(lines.slice(printed).join('\n'));
    printed = lines.length;
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  process.off('SIGINT', stop);
  return EXIT.ok;
}

export interface FindingLine {
  /** Lowercase, as the engine's severityCounts() counts it; `unrated` when there is none. */
  severity: string;
  title: string;
  /** Where it happens: the sink's path:line, else the first location's. */
  location: string;
}

type Json = Record<string, unknown>;
const isObject = (value: unknown): value is Json =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
const list = (value: unknown): Json[] => (Array.isArray(value) ? value.filter(isObject) : []);

function readJsonObject(path: string): Json | undefined {
  try {
    const document: unknown = JSON.parse(readFileSync(path, 'utf8'));
    return isObject(document) ? document : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The findings of upstream's findings.json in dir (a scan dir, or a run dir's reports), most
 * severe first.
 *
 * The file is upstream's and its fields are the model's, and the engine checked only each
 * finding's annotated location before it called the scan completed. So each field is read
 * defensively: a null finding or location is skipped, a severity is ranked in any case (`High`
 * counts as high, as severityCounts() counts it), and a title or path keeps no terminal control
 * characters (`ESC[2J` would clear the output being printed). A file that cannot be read, or has
 * no findings list, is undefined: unreadable, not a scan that found nothing.
 */
export function readFindings(dir: string): FindingLine[] | undefined {
  const document = readJsonObject(join(dir, EXPORTS.json));
  if (!Array.isArray(document?.['findings'])) return undefined;
  const findings = list(document['findings']);
  const severities: readonly string[] = engine().SEVERITIES;
  const rank = (severity: string): number => {
    const at = severities.indexOf(severity);
    return at < 0 ? severities.length : at;
  };
  return findings.map(findingLine).sort((x, y) => rank(x.severity) - rank(y.severity));
}

/** One finding as it is printed, its model-written text stripped of control characters. */
function findingLine(finding: Json): FindingLine {
  const { plain } = engine();
  const level = isObject(finding['severity']) ? finding['severity']['level'] : undefined;
  const title = typeof finding['title'] === 'string' ? finding['title'] : '';
  // The sink is where the harm happens; a finding without one is shown at its first location.
  const locations = list(finding['locations']);
  const at = locations.find(l => l['role'] === 'sink') ?? locations[0];
  const path = typeof at?.['path'] === 'string' ? at['path'] : '';
  const start = at?.['startLine'];
  const line = typeof start === 'number' && start > 0 ? `:${start}` : '';
  return {
    severity: typeof level === 'string' && level ? plain(level).toLowerCase() : 'unrated',
    title: plain(title) || '(untitled)',
    location: path ? plain(`${path}${line}`) : '',
  };
}

/** Each finding on one line: its severity, coloured by how severe, its title and location. */
export function findingRows(c: Colors, findings: FindingLine[]): string[] {
  const colour = (severity: string): ((text: string) => string) =>
    severity === 'critical' || severity === 'high'
      ? c.red
      : severity === 'medium'
        ? c.yellow
        : c.dim;
  return findings.map(
    f =>
      `  ${colour(f.severity)(f.severity.toUpperCase().padEnd(13))} ${f.title}${f.location ? `  ${c.dim(f.location)}` : ''}`
  );
}
