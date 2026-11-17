/**
 * `cynos gc`: remove what scans left behind and nothing else.
 *
 * Our files grow without bound in two places, and a third is the docker runtime's:
 *
 *   stale run dirs   <state>/averlon/scans/<run name>/ that no scan id links to: a scan that
 *                    failed or was stopped before upstream registered it, older than a day; and
 *                    scan-id links whose run dir is gone
 *   cache snapshots  <state>/averlon/knowledge-base-cache/v1/<sha>/ beyond the newest N or the
 *                    size limit, oldest first, and half-written .pending-* dirs
 *   containers       exited docker containers named cynos-scan-*
 *
 * upstream's own history and scan dirs are never touched: they are upstream's to manage. gc lists
 * what it would remove and asks (or --yes); --dry-run only lists.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, lstatSync, readdirSync, realpathSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { Command } from 'commander';
import { CLI_NAME, type Context } from '../context';
import { engine } from '../engine';
import { CliError, EXIT } from '../exit-codes';
import { withExamples } from '../help';
import { confirm } from '../prompts';
import { knowledgeBaseCacheDir, runsDir } from '../settings';

interface GcOptions {
  dryRun?: boolean;
  yes?: boolean;
  keepSnapshots: string;
  maxCacheSize: string;
}

export interface Garbage {
  kind: 'run dir' | 'cache snapshot' | 'container';
  target: string;
  bytes: number;
  why: string;
}

const DAY_MS = 24 * 60 * 60 * 1000;

export function registerGc(program: Command, ctx: Context): void {
  const command = program
    .command('gc')
    .description('Remove stale run dirs, old knowledge-base snapshots and exited scan containers.')
    .option('--dry-run', 'only list what would be removed')
    .option('--yes', 'remove without asking')
    .option('--keep-snapshots <n>', 'knowledge-base snapshots to keep', '20')
    .option('--max-cache-size <size>', 'knowledge-base cache limit (e.g. 500M, 2G)', '2G')
    .action(async (options: GcOptions) => {
      process.exitCode = await gcCommand(ctx, options);
    });
  withExamples(command, [
    `${CLI_NAME} gc --dry-run`,
    `${CLI_NAME} gc --yes`,
    `${CLI_NAME} gc --keep-snapshots 5 --max-cache-size 500M`,
  ]);
}

async function gcCommand(ctx: Context, options: GcOptions): Promise<number> {
  const { terminal } = ctx;
  const stateDir = engine().resolveStateDir(ctx.env);
  const keep = Number(options.keepSnapshots);
  if (!Number.isInteger(keep) || keep < 0)
    throw new CliError('usage', '--keep-snapshots takes a whole number');

  // 1. Everything that qualifies.
  const garbage = [
    ...staleRunDirs(runsDir(stateDir)),
    ...surplusSnapshots(
      join(knowledgeBaseCacheDir(stateDir), 'v1'),
      keep,
      parseSize(options.maxCacheSize)
    ),
    ...exitedContainers(),
  ];
  if (!garbage.length) {
    terminal.result('Nothing to remove.');
    return EXIT.ok;
  }

  // 2. The list, then a yes.
  const total = garbage.reduce((sum, item) => sum + item.bytes, 0);
  for (const item of garbage)
    terminal.result(`  ${item.kind.padEnd(15)} ${item.target}  ${terminal.out.dim(item.why)}`);
  terminal.result(`${garbage.length} item(s), ${(total / 1024 / 1024).toFixed(1)} MB.`);
  if (options.dryRun) return EXIT.ok;
  if (
    !(await confirm(terminal, 'Remove them?', {
      ...(options.yes ? { yes: true } : {}),
      otherwise: 'Pass --yes to remove without asking.',
    }))
  )
    return EXIT.ok;

  // 3. Remove.
  for (const item of garbage) {
    if (item.kind === 'container') spawnSync('docker', ['rm', item.target], { stdio: 'ignore' });
    else rmSync(item.target, { recursive: true, force: true });
  }
  terminal.info(`${terminal.c.green('✓')} Removed ${garbage.length} item(s).`);
  return EXIT.ok;
}

/** 500M, 2G, 1024K or bytes. */
export function parseSize(value: string): number {
  const match = /^(\d+(?:\.\d+)?)\s*([KMG]?)B?$/i.exec(value.trim());
  if (!match) throw new CliError('usage', `a size is a number with K, M or G (not ${value})`);
  const unit = { '': 1, K: 1024, M: 1024 ** 2, G: 1024 ** 3 }[
    match[2]!.toUpperCase() as '' | 'K' | 'M' | 'G'
  ];
  return Number(match[1]) * unit;
}

function sizeOf(path: string): number {
  const stat = statSync(path);
  if (!stat.isDirectory()) return stat.size;
  return readdirSync(path).reduce((sum, name) => sum + sizeOf(join(path, name)), 0);
}

/**
 * Run dirs that no scan id links to, older than a day, and links whose run dir is gone.
 *
 * A scan upstream registered has a link named by its id beside its run dir (linkScanId); one it
 * never registered has none. Run dirs from before the links, renamed to their scan id, are not
 * run names and are kept.
 */
export function staleRunDirs(root: string, now = Date.now()): Garbage[] {
  if (!existsSync(root)) return [];
  const entries = readdirSync(root).map(name => ({ name, path: join(root, name) }));
  const links = entries.filter(entry => lstatSync(entry.path).isSymbolicLink());
  const linked = new Set(
    links.filter(link => existsSync(link.path)).map(link => realpathSync(link.path))
  );
  const unregistered = entries
    .filter(entry => /^(cynos-scan-|pending-)/.test(entry.name))
    .filter(entry => lstatSync(entry.path).isDirectory())
    .filter(entry => !linked.has(realpathSync(entry.path)))
    .filter(entry => now - statSync(entry.path).mtimeMs > DAY_MS)
    .map(entry => ({
      kind: 'run dir' as const,
      target: entry.path,
      bytes: sizeOf(entry.path),
      why: 'never registered with upstream, over a day old',
    }));
  const dangling = links
    .filter(link => !existsSync(link.path))
    .map(link => ({
      kind: 'run dir' as const,
      target: link.path,
      bytes: 0,
      why: 'scan-id link to a run dir that is gone',
    }));
  return [...unregistered, ...dangling];
}

/** Snapshots beyond the newest `keep`, then the oldest until the cache fits `maxBytes`. */
export function surplusSnapshots(
  root: string,
  keep: number,
  maxBytes: number,
  now = Date.now()
): Garbage[] {
  if (!existsSync(root)) return [];
  const entries = readdirSync(root).map(name => {
    const path = join(root, name);
    return { name, path, mtime: statSync(path).mtimeMs, bytes: sizeOf(path) };
  });
  const garbage: Garbage[] = entries
    .filter(entry => entry.name.startsWith('.pending-') && now - entry.mtime > 60 * 60 * 1000)
    .map(entry => ({
      kind: 'cache snapshot',
      target: entry.path,
      bytes: entry.bytes,
      why: 'half-written',
    }));
  const newestFirst = entries
    .filter(entry => !entry.name.startsWith('.'))
    .sort((a, b) => b.mtime - a.mtime);
  // Beyond the newest `keep`: all of them.
  for (const entry of newestFirst.slice(keep))
    garbage.push({
      kind: 'cache snapshot',
      target: entry.path,
      bytes: entry.bytes,
      why: `beyond the newest ${keep}`,
    });
  // Over the size limit: the oldest kept ones, but never the newest, which the next scan restores.
  const kept = newestFirst.slice(0, keep);
  let total = kept.reduce((sum, entry) => sum + entry.bytes, 0);
  for (let index = kept.length - 1; index > 0 && total > maxBytes; index--) {
    const entry = kept[index]!;
    garbage.push({
      kind: 'cache snapshot',
      target: entry.path,
      bytes: entry.bytes,
      why: 'over the size limit',
    });
    total -= entry.bytes;
  }
  return garbage;
}

/** Exited docker containers named cynos-scan-*, when docker is installed. */
function exitedContainers(): Garbage[] {
  const listed = spawnSync(
    'docker',
    [
      'ps',
      '-a',
      '--filter',
      'name=^cynos-scan-',
      '--filter',
      'status=exited',
      '--format',
      '{{.Names}}',
    ],
    {
      encoding: 'utf8',
      timeout: 15_000,
    }
  );
  if (listed.status !== 0) return [];
  return listed.stdout
    .split('\n')
    .filter(Boolean)
    .map(name => ({ kind: 'container' as const, target: name, bytes: 0, why: 'exited' }));
}
