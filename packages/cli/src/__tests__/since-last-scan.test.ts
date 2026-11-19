import { describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mockEngine } from './engine-mock';

mockEngine();
const { lastCompletedScan, sinceLastScan } = await import('../commands/since-last-scan');
const { listRuns } = await import('../commands/scans');

const HEAD = 'c'.repeat(40);
const OLD = 'a'.repeat(40);
const NEWER = 'b'.repeat(40);

interface Run {
  name: string;
  result?: Record<string, unknown>;
  mock?: boolean;
  /** When its result was written, in seconds: the order `scans list` sorts by. */
  at: number;
}

/** A state dir whose run dirs hold these runs' results. */
function stateDir(runs: Run[]): string {
  const dir = mkdtempSync(join(tmpdir(), 'cynos-since-'));
  for (const { name, result, mock, at } of runs) {
    const runDir = join(dir, 'averlon', 'scans', name);
    mkdirSync(runDir, { recursive: true });
    // The engine's record of how it ran upstream: a mock scan's has upstream's --mock.
    if (mock)
      writeFileSync(join(runDir, 'run.json'), JSON.stringify({ command: ['scan', '--mock'] }));
    if (!result) continue;
    writeFileSync(join(runDir, 'cli-result.json'), JSON.stringify(result));
    utimesSync(join(runDir, 'cli-result.json'), at, at);
  }
  return dir;
}

const scan = (scanId: string, scannedSha: string, scanStatus = 'completed', project = '/repo') => ({
  scanId,
  scannedSha,
  scanStatus,
  project,
});

/** Two completed scans of this repository, then a failed one, another repository's, a mock and a running one. */
const history = stateDir([
  { name: 'run-old', result: scan('scan-old', OLD), at: 1_000 },
  { name: 'run-new', result: scan('scan-new', NEWER), at: 2_000 },
  { name: 'run-failed', result: scan('failed-1', HEAD, 'failed'), at: 3_000 },
  { name: 'run-other', result: scan('other-1', HEAD, 'completed', '/other'), at: 4_000 },
  { name: 'run-mock', result: scan('mock-1', HEAD), mock: true, at: 5_000 },
  { name: 'run-running', at: 6_000 },
]);

describe('lastCompletedScan', () => {
  test("this repository's newest completed scan; failed, mock and other repositories' do not count", () => {
    expect(lastCompletedScan(listRuns(history), '/repo')).toEqual({
      scanId: 'scan-new',
      revision: NEWER,
    });
  });

  test('nothing when there is no completed scan of the repository', () => {
    expect(lastCompletedScan(listRuns(history), '/nowhere')).toBeUndefined();
    expect(lastCompletedScan([], '/repo')).toBeUndefined();
  });
});

describe('sinceLastScan', () => {
  test('diffs from the last completed scan when it is an ancestor of HEAD', () => {
    const checked: string[][] = [];
    const since = sinceLastScan('/repo', HEAD, history, {
      isAncestor: (project, revision, head) => {
        checked.push([project, revision, head]);
        return true;
      },
    });
    expect(since).toEqual({ kind: 'diff', base: NEWER, scanId: 'scan-new' });
    expect(checked).toEqual([['/repo', NEWER, HEAD]]);
  });

  test('falls back to a full scan when it is not an ancestor (a rebase, another branch)', () => {
    const since = sinceLastScan('/repo', HEAD, history, { isAncestor: () => false });
    expect(since.kind).toBe('full');
    expect(since.kind === 'full' && since.reason).toContain('not an ancestor of HEAD');
  });

  test('a full scan when there is no completed scan yet', () => {
    expect(sinceLastScan('/repo', HEAD, stateDir([]), { isAncestor: () => true })).toEqual({
      kind: 'full',
      reason: 'this repository has no completed scan yet',
    });
  });

  test('nothing to do when the last completed scan was of HEAD', () => {
    const scanned = stateDir([{ name: 'run-1', result: scan('s1', HEAD), at: 1_000 }]);
    expect(sinceLastScan('/repo', HEAD, scanned, { isAncestor: () => true })).toEqual({
      kind: 'up-to-date',
      scanId: 's1',
    });
  });
});
