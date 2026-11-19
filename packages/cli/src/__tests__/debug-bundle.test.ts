import { describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mockEngine } from './engine-mock';

mockEngine();
const { filesWithKeys, knownKeys, leaveOut, scrubDir } = await import('../commands/debug-bundle');
const { createContext } = await import('../context');

const CYNOS = 'cynos-live-0123456789abcdef';
const OTHER = 'sk-other-v1-fedcba9876543210';

function bundleDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'cynos-scan-bundle-'));
  mkdirSync(join(dir, 'run'), { recursive: true });
  writeFileSync(join(dir, 'run', 'cli.log'), `info Authorization: Bearer ${CYNOS}\ninfo fine\n`);
  writeFileSync(join(dir, 'run', 'events.jsonl'), `{"message":"${OTHER} and ${CYNOS}"}\n`);
  writeFileSync(join(dir, 'versions.json'), '{"node":"v24"}\n');
  writeFileSync(
    join(dir, 'binary.bin'),
    Buffer.concat([Buffer.from([0, 255, 1]), Buffer.from(CYNOS), Buffer.from([254])])
  );
  return dir;
}

describe('the debug bundle scrub', () => {
  test('replaces every key value with ***, leaving the rest of each file intact', () => {
    const dir = bundleDir();
    const changed = scrubDir(dir, [CYNOS, OTHER]);
    expect(changed).toHaveLength(3);
    expect(readFileSync(join(dir, 'run', 'cli.log'), 'utf8')).toBe(
      'info Authorization: Bearer ***\ninfo fine\n'
    );
    expect(readFileSync(join(dir, 'run', 'events.jsonl'), 'utf8')).toBe(
      '{"message":"*** and ***"}\n'
    );
    expect([...readFileSync(join(dir, 'binary.bin'))]).toEqual([
      0,
      255,
      1,
      ...Buffer.from('***'),
      254,
    ]);
    expect(filesWithKeys(dir, [CYNOS, OTHER])).toEqual([]);
  });

  test('finds a key the scrub could not reach, so the bundle is refused', () => {
    const dir = bundleDir();
    scrubDir(dir, [CYNOS]);
    // The other key was not among the keys scrubbed.
    expect(filesWithKeys(dir, [CYNOS, OTHER])).toEqual([join(dir, 'run', 'events.jsonl')]);
    // A key in a file name survives any content scrub.
    writeFileSync(join(dir, `note-${CYNOS}.txt`), 'x');
    expect(filesWithKeys(dir, [CYNOS])).toContain(join(dir, `note-${CYNOS}.txt`));
  });

  test('leaves out credentials, databases, compressed logs and transcripts', () => {
    expect(leaveOut('state/home/auth.json')).toBe('credentials');
    expect(leaveOut('state/workbench.sqlite3')).toBe('database');
    expect(leaveOut('state/sessions/2026/rollout-1.jsonl.zst')).toContain('compressed');
    expect(leaveOut('state/sessions/2026/rollout-1.jsonl')).toContain('transcript');
    // The architecture agent's Codex events quote the source its commands printed.
    expect(leaveOut('knowledge-base/review/events.jsonl')).toContain('transcript');
    // The CLI's own progress events stay.
    expect(leaveOut('events.jsonl')).toBeUndefined();
    expect(leaveOut('cli.log')).toBeUndefined();
    expect(leaveOut('run.json')).toBeUndefined();
    expect(leaveOut('reports/findings.json')).toBeUndefined();
  });

  test("known keys: the environment's and the saved login's", () => {
    const configDir = mkdtempSync(join(tmpdir(), 'cynos-scan-config-'));
    const ctx = createContext({ XDG_CONFIG_HOME: configDir, CYNOS_CREDENTIAL_STORE: 'file' });
    ctx.envKeys = { cynos: 'env-cynos-0123456789' };
    ctx.credentials.set('cynos', 'saved-cynos-0123456789');
    expect(knownKeys(ctx).sort()).toEqual(['env-cynos-0123456789', 'saved-cynos-0123456789']);
  });
});
