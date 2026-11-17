/**
 * The update notice: "Update available 0.1.0 → 0.2.0", at most once a day, never in the way.
 *
 * Asking the registry takes a second or more, and a command must never wait for it, so the check
 * is split across runs:
 *
 *   this run    when the cached answer is a day old, start a detached `npm view` that writes the
 *               cache file and outlives us; record that a check started, so the next runs today
 *               do not start another
 *   a later run read the cache; if it names a newer version, print the notice after the
 *               command's own output, on stderr, at most once a day
 *
 * It is off when nobody would see it or it could break a script: CI, output that is not a
 * terminal, NO_UPDATE_NOTIFIER or CYNOS_NO_UPDATE_NOTICE.
 */
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { CLI_VERSION, PACKAGE_NAME } from '../context';
import { inCI } from '../settings';

const DAY_MS = 24 * 60 * 60 * 1000;

export interface UpdateCache {
  /** When a check last started. */
  checkedAt?: number;
  /** The registry's latest version, from the last check that finished. */
  latest?: string;
  /** When the notice was last printed. */
  notifiedAt?: number;
}

export function updateCachePath(cacheDir: string): string {
  return join(cacheDir, 'update-check.json');
}

export function readUpdateCache(cacheDir: string): UpdateCache {
  try {
    return JSON.parse(readFileSync(updateCachePath(cacheDir), 'utf8')) as UpdateCache;
  } catch {
    return {};
  }
}

function writeUpdateCache(cacheDir: string, cache: UpdateCache): void {
  try {
    mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
    writeFileSync(updateCachePath(cacheDir), `${JSON.stringify(cache)}\n`, { mode: 0o600 });
  } catch {
    // An unwritable cache only means no notice.
  }
}

/** Whether a notice may be shown at all. */
export function noticeAllowed(conditions: {
  env: NodeJS.ProcessEnv;
  stdoutIsTTY: boolean;
  stderrIsTTY: boolean;
}): boolean {
  const { env } = conditions;
  if (inCI(env) || env['NO_UPDATE_NOTIFIER'] || env['CYNOS_NO_UPDATE_NOTICE']) return false;
  return conditions.stdoutIsTTY && conditions.stderrIsTTY;
}

/** a > b for dotted versions; a pre-release sorts before its release. */
export function newerVersion(a: string, b: string): boolean {
  const parse = (version: string): [number[], string] => {
    const [core = '', pre = ''] = version.replace(/^v/, '').split('-', 2);
    return [core.split('.').map(part => Number(part) || 0), pre];
  };
  const [coreA, preA] = parse(a);
  const [coreB, preB] = parse(b);
  for (let i = 0; i < 3; i++)
    if ((coreA[i] ?? 0) !== (coreB[i] ?? 0)) return (coreA[i] ?? 0) > (coreB[i] ?? 0);
  if (preA === preB) return false;
  if (!preA) return true;
  if (!preB) return false;
  return preA > preB;
}

/**
 * Before the command: starts the background check when the cache is a day old. Returns the
 * notice to print after the command, if one is due.
 */
export function prepareNotice(
  cacheDir: string,
  options: { now?: number; current?: string; startCheck?: (cacheDir: string) => void } = {}
): string | undefined {
  const now = options.now ?? Date.now();
  const current = options.current ?? CLI_VERSION;
  const cache = readUpdateCache(cacheDir);

  // 1. A day since the last check started: start one, and say so in the cache at once.
  if (!cache.checkedAt || now - cache.checkedAt >= DAY_MS) {
    writeUpdateCache(cacheDir, { ...cache, checkedAt: now });
    (options.startCheck ?? startBackgroundCheck)(cacheDir);
  }

  // 2. A newer version known from an earlier check, not announced today.
  if (!cache.latest || !newerVersion(cache.latest, current)) return undefined;
  if (cache.notifiedAt && now - cache.notifiedAt < DAY_MS) return undefined;
  writeUpdateCache(cacheDir, { ...readUpdateCache(cacheDir), notifiedAt: now });
  return `Update available ${current} → ${cache.latest} · run \`cynos update\``;
}

/** The detached check: `npm view <package> version`, written into the cache by a child node. */
export function startBackgroundCheck(cacheDir: string): void {
  const script = `
const { execFileSync } = require('node:child_process');
const { readFileSync, writeFileSync } = require('node:fs');
const [path, name] = process.argv.slice(1);
let latest;
try { latest = execFileSync('npm', ['view', name, 'version'], { encoding: 'utf8', timeout: 30000, stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch {}
let cache = {};
try { cache = JSON.parse(readFileSync(path, 'utf8')); } catch {}
if (latest && /^\\d+\\.\\d+\\.\\d+/.test(latest)) cache.latest = latest;
writeFileSync(path, JSON.stringify(cache) + '\\n', { mode: 0o600 });
`;
  try {
    if (!existsSync(cacheDir)) mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
    const child = spawn(process.execPath, ['-e', script, updateCachePath(cacheDir), PACKAGE_NAME], {
      detached: true,
      stdio: 'ignore',
      env: { ...process.env, NO_UPDATE_NOTIFIER: '1' },
    });
    child.unref();
  } catch {
    // No notice this time.
  }
}

/** The registry's latest version now (update and doctor), or undefined when it cannot be read. */
export function latestVersion(timeoutMs = 20_000): string | undefined {
  const run = spawnSync('npm', ['view', PACKAGE_NAME, 'version'], {
    encoding: 'utf8',
    timeout: timeoutMs,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const version = run.status === 0 ? run.stdout.trim() : '';
  return /^\d+\.\d+\.\d+/.test(version) ? version : undefined;
}
