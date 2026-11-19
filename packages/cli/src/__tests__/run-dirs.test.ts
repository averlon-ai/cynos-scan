import { describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mockEngine } from './engine-mock';

mockEngine();
const { findRunDir, latestRunDir } = await import('../commands/scans');
const { staleRunDirs } = await import('../commands/gc');
const { linkScanId } = await import('../commands/scan');

const DAY_AGO = (Date.now() - 2 * 24 * 3600_000) / 1000;

/** A state dir with run dirs under averlon/scans; returns the state dir and that root. */
function runs(): { stateDir: string; root: string } {
  const stateDir = realpathSync(mkdtempSync(join(tmpdir(), 'cynos-scan-state-')));
  const root = join(stateDir, 'averlon', 'scans');
  mkdirSync(root, { recursive: true });
  return { stateDir, root };
}

/** A run dir under its run name, last touched `mtime` (seconds) ago or now. */
function runDir(root: string, name: string, mtime?: number): string {
  const path = join(root, name);
  mkdirSync(path);
  if (mtime !== undefined) utimesSync(path, mtime, mtime);
  return path;
}

describe('run dirs found by their scan id', () => {
  test('an id, or a prefix of it, finds the run dir itself, not the link', () => {
    const { stateDir, root } = runs();
    const run = runDir(root, 'cynos-scan-20261027180613-4de8d5');
    linkScanId(run, 'fd8fb3a1-dc14-46aa-88a6-ba4f4b4c9e24');
    expect(findRunDir(stateDir, 'fd8fb3a1-dc14-46aa-88a6-ba4f4b4c9e24')).toBe(run);
    expect(findRunDir(stateDir, 'fd8f')).toBe(run);
    // The run name still finds it, and a prefix both names share is one run, not two.
    expect(findRunDir(stateDir, 'cynos-scan-2026')).toBe(run);
  });

  test('a run dir from before the links, named by its scan id, is still found', () => {
    const { stateDir, root } = runs();
    const run = runDir(root, 'b9f473ca-532f-49e8-9632-e97718d136eb');
    expect(findRunDir(stateDir, 'b9f4')).toBe(run);
  });

  test('the newest run is a run dir, never a link to one', () => {
    const { stateDir, root } = runs();
    const run = runDir(root, 'cynos-scan-20261027180613-4de8d5');
    linkScanId(run, 'fd8fb3a1');
    expect(latestRunDir(stateDir)).toBe(run);
  });
});

describe('gc of run dirs', () => {
  test('removes an old run dir no scan id links to, and links whose run dir is gone', () => {
    const { root } = runs();
    const registered = runDir(root, 'cynos-scan-20261020000000-aaaaaa', DAY_AGO);
    linkScanId(registered, 'scan-registered');
    const unregistered = runDir(root, 'cynos-scan-20261020000000-bbbbbb', DAY_AGO);
    runDir(root, 'cynos-scan-20261027000000-cccccc');
    const gone = runDir(root, 'cynos-scan-20261020000000-dddddd', DAY_AGO);
    linkScanId(gone, 'scan-gone');
    rmSync(gone, { recursive: true });

    const garbage = staleRunDirs(root).map(item => item.target);
    expect(garbage.sort()).toEqual([unregistered, join(root, 'scan-gone')].sort());
  });

  test('a dangling link made by hand is removed without following it', () => {
    const { root } = runs();
    symlinkSync('nowhere', join(root, 'scan-x'), 'dir');
    expect(staleRunDirs(root)).toMatchObject([{ target: join(root, 'scan-x'), bytes: 0 }]);
  });
});
