import { describe, expect, test } from 'bun:test';
import { mockEngine } from './engine-mock';

mockEngine();
const { lastCompletedScan, sinceLastScan } = await import('../commands/since-last-scan');

const HEAD = 'c'.repeat(40);
const OLD = 'a'.repeat(40);
const NEWER = 'b'.repeat(40);

/** upstream's `scans list --json` for this repository. */
const history = {
  scans: [
    {
      scanId: 'running-1',
      targetRevision: HEAD,
      progress: { status: 'running' },
      completedAt: null,
    },
    {
      scanId: 'scan-old',
      targetRevision: OLD,
      progress: { status: 'complete' },
      completedAt: '2026-10-01T10:00:00Z',
    },
    {
      scanId: 'scan-new',
      targetRevision: NEWER,
      progress: { status: 'complete' },
      completedAt: '2026-10-20T10:00:00Z',
    },
    {
      scanId: 'failed-1',
      targetRevision: HEAD,
      progress: { status: 'failed' },
      completedAt: '2026-10-25T10:00:00Z',
    },
  ],
};

const upstream = (stdout: unknown, status = 0) => {
  const calls: string[][] = [];
  const capture = async (args: string[]) => {
    calls.push(args);
    return {
      status,
      stdout: typeof stdout === 'string' ? stdout : JSON.stringify(stdout),
      stderr: status ? 'boom' : '',
    };
  };
  return { capture, calls };
};

describe('lastCompletedScan', () => {
  test('the newest completed scan with a revision; running and failed ones do not count', () => {
    expect(lastCompletedScan(history)).toMatchObject({ scanId: 'scan-new', revision: NEWER });
  });

  test('nothing when there is no completed scan, or the output is not a scan list', () => {
    expect(lastCompletedScan({ scans: [history.scans[0]] })).toBeUndefined();
    expect(lastCompletedScan({})).toBeUndefined();
    expect(lastCompletedScan(null)).toBeUndefined();
  });
});

describe('sinceLastScan', () => {
  test("asks upstream for this repository's history as JSON", async () => {
    const { capture, calls } = upstream(history);
    await sinceLastScan('/repo', HEAD, { capture, isAncestor: () => true });
    expect(calls).toEqual([['scans', 'list', '/repo', '--json']]);
  });

  test('diffs from the last completed scan when it is an ancestor of HEAD', async () => {
    const { capture } = upstream(history);
    const checked: string[][] = [];
    const since = await sinceLastScan('/repo', HEAD, {
      capture,
      isAncestor: (project, revision, head) => {
        checked.push([project, revision, head]);
        return true;
      },
    });
    expect(since).toEqual({ kind: 'diff', base: NEWER, scanId: 'scan-new' });
    expect(checked).toEqual([['/repo', NEWER, HEAD]]);
  });

  test('falls back to a full scan when it is not an ancestor (a rebase, another branch)', async () => {
    const { capture } = upstream(history);
    const since = await sinceLastScan('/repo', HEAD, { capture, isAncestor: () => false });
    expect(since.kind).toBe('full');
    expect(since.kind === 'full' && since.reason).toContain('not an ancestor of HEAD');
  });

  test('a full scan when there is no completed scan yet', async () => {
    const { capture } = upstream({ scans: [] });
    expect(await sinceLastScan('/repo', HEAD, { capture, isAncestor: () => true })).toEqual({
      kind: 'full',
      reason: 'this repository has no completed scan yet',
    });
  });

  test('nothing to do when the last completed scan was of HEAD', async () => {
    const { capture } = upstream({
      scans: [
        { scanId: 's1', targetRevision: HEAD, progress: { status: 'complete' }, completedAt: 'x' },
      ],
    });
    expect(await sinceLastScan('/repo', HEAD, { capture, isAncestor: () => true })).toEqual({
      kind: 'up-to-date',
      scanId: 's1',
    });
  });

  test("a full scan, saying why, when upstream's history cannot be read", async () => {
    const failing = upstream('', 2);
    const since = await sinceLastScan('/repo', HEAD, {
      capture: failing.capture,
      isAncestor: () => true,
    });
    expect(since.kind).toBe('full');
    expect(since.kind === 'full' && since.reason).toContain('boom');
    const garbled = upstream('not json');
    expect(
      (await sinceLastScan('/repo', HEAD, { capture: garbled.capture, isAncestor: () => true }))
        .kind
    ).toBe('full');
  });
});
