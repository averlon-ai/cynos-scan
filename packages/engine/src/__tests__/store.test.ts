import { describe, expect, it } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LocalKnowledgeBaseStore, STORE_VERSION } from '../knowledge-base/store';

/** A local store holding a snapshot per commit, oldest first; each names its commit in `entry`. */
function storeWith(commits: string[]) {
  const root = mkdtempSync(join(tmpdir(), 'kb-store-'));
  commits.forEach((sha, i) => {
    const dir = join(root, STORE_VERSION, sha);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'entry'), sha);
    utimesSync(dir, 1_000 + i, 1_000 + i);
  });
  const dir = join(mkdtempSync(join(tmpdir(), 'kb-scan-')), 'cache');
  const store = new LocalKnowledgeBaseStore(root);
  const restored = () => readFileSync(join(dir, 'entry'), 'utf8');
  return { store, dir, restored };
}

const none = (): boolean => false;

describe('LocalKnowledgeBaseStore', () => {
  it("restores this commit's snapshot, else a preferred commit's, whatever is newer", async () => {
    const { store, dir } = storeWith(['base', 'head', 'newer']);
    expect(await store.restore(dir, 'head', ['base'], none)).toBe('head');
    expect(await store.restore(dir, 'other', ['base'], none)).toBe('base');
  });

  it('restores the newest snapshot of an ancestor before a newer one outside the history', async () => {
    // m1 is in the branch's history; m3, the default branch's latest full scan, is not.
    const { store, dir, restored } = storeWith(['m0', 'm1', 'm3']);
    const ancestors = new Set(['m0', 'm1']);
    expect(await store.restore(dir, 'head', ['base'], sha => ancestors.has(sha))).toBe('m1');
    expect(restored()).toBe('m1');
  });

  it('restores the newest snapshot when no snapshot is of an ancestor', async () => {
    const { store, dir } = storeWith(['m1', 'm3']);
    expect(await store.restore(dir, 'head', [], none)).toBe('m3');
  });

  it('restores nothing from an empty store', async () => {
    const { store, dir } = storeWith([]);
    expect(await store.restore(dir, 'head', [], none)).toBeUndefined();
  });
});
