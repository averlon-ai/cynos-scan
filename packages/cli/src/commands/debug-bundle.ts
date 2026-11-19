/**
 * `cynos debug bundle [ID]`: one tarball with what it takes to debug a scan, safe to share.
 *
 * A scan's evidence is its run dir, on either runtime (the result, the engine's run.json and
 * validated reports, the CLI's log, events and timings, the knowledge base), and this machine
 * (versions, doctor). The difficulty is that the same files can hold the keys the scan ran with:
 * Codex's state, session transcripts, an error message that echoed a header. So the bundle is
 * built in a private staging dir and checked before anything leaves it:
 *
 *   collect  the run dir, versions, `doctor --json`; never auth files, databases, compressed
 *            logs (they cannot be scrubbed) or session transcripts (they hold source code)
 *   scrub    every known key value (the environment's, every saved login's) replaced with ***
 *   verify   any key still present (in a name, or bytes the scrub could not reach) refuses
 *   confirm  every file listed, then a yes (or --yes) before the tarball is written
 *   write    tar -czf, mode 0600
 */
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { arch, platform, release, tmpdir } from 'node:os';
import { basename, dirname, join, relative, resolve } from 'node:path';
import type { Command } from 'commander';
import { CYNOS_ACCOUNT } from '../auth/keys';
import { CLI_NAME, CLI_VERSION, type Context } from '../context';
import { engine, hasEngine } from '../engine';
import { CliError, EXIT } from '../exit-codes';
import { withExamples } from '../help';
import { confirm } from '../prompts';
import { defaultRuntime } from '../settings';
import { collectChecks } from './doctor';
import { findRunDir, latestRunDir } from './scans';

interface BundleOptions {
  output?: string;
  yes?: boolean;
}

export function registerDebug(program: Command, ctx: Context): void {
  const debug = program.command('debug').description('Collect what it takes to debug a scan.');
  withExamples(debug, [`${CLI_NAME} debug bundle`]);
  const bundle = debug
    .command('bundle')
    .description('Write a tarball for a scan: its run dir, versions, doctor; keys scrubbed.')
    .argument('[id]', 'scan id, unique prefix or run name (default: the newest run)')
    .option('--output <file>', 'where to write it (default: ./cynos-debug-<id>-<date>.tar.gz)')
    .option('--yes', 'write it without asking')
    .action(async (id: string | undefined, options: BundleOptions) => {
      process.exitCode = await debugBundle(ctx, id, options);
    });
  withExamples(bundle, [
    `${CLI_NAME} debug bundle`,
    `${CLI_NAME} debug bundle 1a2b3c4d --output /tmp/scan-debug.tar.gz`,
    `${CLI_NAME} debug bundle --yes`,
  ]);
}

async function debugBundle(
  ctx: Context,
  id: string | undefined,
  options: BundleOptions
): Promise<number> {
  const { terminal } = ctx;
  const stateDir = engine().resolveStateDir(ctx.env);

  // 1. Which scan: the id given, else the newest run dir.
  const runDir = id ? findRunDir(stateDir, id) : latestRunDir(stateDir);
  if (!runDir)
    throw new CliError(
      'usage',
      id
        ? `No scan ${id} on this machine (or the prefix names more than one).`
        : 'No scan to bundle yet.',
      id ? `\`${CLI_NAME} scans list\` lists them.` : `Run \`${CLI_NAME} scan\` first.`
    );

  // 2. Collect into a private staging dir.
  const staging = mkdtempSync(join(tmpdir(), 'cynos-debug-'));
  try {
    const skipped = await collect(ctx, staging, runDir);

    // 3 and 4. Scrub every key, then refuse if one survived.
    const keys = knownKeys(ctx);
    scrubDir(staging, keys);
    const remaining = filesWithKeys(staging, keys);
    if (remaining.length)
      throw new CliError(
        'internal',
        `A key is still present after scrubbing (${remaining.map(path => relative(staging, path)).join(', ')}); no bundle was written.`
      );

    // 5. List, confirm, write.
    const files = listFiles(staging);
    const output = resolve(
      options.output ??
        `cynos-debug-${(id ?? basename(runDir)).slice(0, 12)}-${new Date().toISOString().slice(0, 10)}.tar.gz`
    );
    terminal.info(terminal.c.bold(`The bundle will hold ${files.length} files:`));
    for (const file of files)
      terminal.info(`  ${file.path.padEnd(60)} ${terminal.c.dim(size(file.bytes))}`);
    for (const [path, reason] of skipped)
      terminal.info(terminal.c.dim(`  left out: ${path} (${reason})`));
    const approved = await confirm(terminal, `Write ${output}?`, {
      ...(options.yes ? { yes: true } : {}),
      otherwise: 'Pass --yes to write it without asking.',
    });
    if (!approved) {
      terminal.info('Nothing written.');
      return EXIT.ok;
    }
    mkdirSync(dirname(output), { recursive: true });
    const tar = spawnSync('tar', ['-czf', output, '-C', staging, '.'], { encoding: 'utf8' });
    if (tar.status !== 0) throw new CliError('internal', `tar failed: ${tar.stderr.trim()}`);
    chmodSync(output, 0o600);
    terminal.result(output);
    return EXIT.ok;
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}

/** Fills staging; returns what was left out and why. */
async function collect(ctx: Context, staging: string, runDir: string): Promise<[string, string][]> {
  const write = (name: string, value: unknown): void =>
    writeFileSync(join(staging, name), `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });

  // The run dir, without what must never be shared. Its reports and result are the scan's record
  // on either runtime: upstream's history does not have a docker scan.
  const skipped = copyRunDir(runDir, join(staging, 'run'));

  // This machine.
  write('versions.json', versions());
  write('doctor.json', await collectChecks(ctx, [defaultRuntime(ctx.env)], { quick: true }));
  return skipped;
}

function versions(): Record<string, unknown> {
  const guarded = (read: () => unknown): unknown => {
    try {
      return read();
    } catch (error) {
      return { unavailable: (error as Error).message };
    }
  };
  return {
    cli: CLI_VERSION,
    engine: hasEngine('ENGINE_VERSION') ? engine().ENGINE_VERSION : null,
    upstream: guarded(() => engine().resolveUpstream()),
    node: process.version,
    platform: platform(),
    release: release(),
    arch: arch(),
  };
}

/**
 * Whether a run-dir file may go in the bundle: a reason to leave it out, or undefined.
 * Transcripts hold source code and model turns, so they never go: Codex's sessions, and the event
 * stream of a Codex session the engine ran itself (the architecture agent's
 * knowledge-base/review/events.jsonl, whose commands' output quotes the source). Only the run
 * dir's own events.jsonl, the CLI's progress events, is kept.
 */
export function leaveOut(relativePath: string): string | undefined {
  const name = basename(relativePath);
  const parts = relativePath.split(/[\\/]/);
  if (/^(auth|credentials)(\..*)?\.json$/i.test(name) || name === '.credentials.json')
    return 'credentials';
  if (/\.(sqlite3?|db)(-wal|-shm)?$/i.test(name)) return 'database';
  if (/\.(zst|gz|tgz|zip|xz|bz2)$/i.test(name)) return 'compressed: cannot be scrubbed';
  if (
    parts.includes('sessions') ||
    /^rollout-.*\.jsonl$/.test(name) ||
    (name === 'events.jsonl' && parts.length > 1)
  )
    return 'transcript: holds source code';
  return undefined;
}

function copyRunDir(from: string, to: string): [string, string][] {
  const skipped: [string, string][] = [];
  const walk = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      const rel = relative(from, path);
      if (entry.isDirectory()) walk(path);
      else if (entry.isFile()) {
        const reason = leaveOut(rel);
        if (reason) {
          skipped.push([`run/${rel}`, reason]);
          continue;
        }
        mkdirSync(dirname(join(to, rel)), { recursive: true, mode: 0o700 });
        copyFileSync(path, join(to, rel));
      }
    }
  };
  if (existsSync(from)) walk(from);
  return skipped;
}

/** Every key value this machine knows: the environment's and the saved login's. */
export function knownKeys(ctx: Context): string[] {
  const saved = ctx.credentials.get(CYNOS_ACCOUNT)?.value;
  return [ctx.envKeys.cynos, saved].filter(
    (key): key is string => typeof key === 'string' && key.length >= 8
  );
}

/** Replaces every key in every file under dir with ***; returns the files it changed. */
export function scrubDir(dir: string, keys: string[]): string[] {
  const changed: string[] = [];
  for (const path of filesUnder(dir)) {
    const content = readFileSync(path);
    if (!keys.some(key => content.includes(key))) continue;
    // latin1 maps bytes one to one, so binary content survives the replacement.
    let text = content.toString('latin1');
    for (const key of keys) text = text.split(Buffer.from(key).toString('latin1')).join('***');
    writeFileSync(path, Buffer.from(text, 'latin1'));
    changed.push(path);
  }
  return changed;
}

/** Files under dir whose name or content still holds a key. */
export function filesWithKeys(dir: string, keys: string[]): string[] {
  return filesUnder(dir).filter(path => {
    const content = readFileSync(path);
    return keys.some(key => content.includes(key) || relative(dir, path).includes(key));
  });
}

function filesUnder(dir: string): string[] {
  const found: string[] = [];
  const walk = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (entry.isFile()) found.push(path);
    }
  };
  walk(dir);
  return found;
}

function listFiles(dir: string): { path: string; bytes: number }[] {
  return filesUnder(dir)
    .map(path => ({ path: relative(dir, path), bytes: statSync(path).size }))
    .sort((a, b) => a.path.localeCompare(b.path));
}

function size(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}
