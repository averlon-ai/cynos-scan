/**
 * Where the knowledge-base cache lives between scans.
 *
 * A scan reads and writes the cache (cache.ts: Jev's answers, the code graph, the stored
 * architecture review) as a plain directory of its own. What differs between hosts is how that
 * directory outlives the scan: the action carries it in the GitHub Actions cache, the CLI and a
 * benchmark keep it on disk. And a diff wants a particular snapshot, the one its base commit's
 * full scan saved (its review is the diff's threat model), not merely the newest:
 *
 *   restore  this commit's snapshot, else a preferred commit's (a diff's base), else the newest
 *   save     the directory as this commit's snapshot, unless it was restored from that one
 *
 * Snapshots are immutable, one per scanned commit, as Actions cache entries are, so two scans of
 * one repository never write the same directory: each restores into its own and saves a new
 * snapshot. Every store keeps that contract; the GitHub Actions one is the action's ci-cache.ts.
 */
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
} from 'node:fs';
import { join } from 'node:path';

/** Carries the knowledge-base cache between scans: immutable snapshots, one per scanned commit. */
export interface KnowledgeBaseStore {
  /** Fills dir with this commit's snapshot, else a preferred commit's, else the newest; returns its key. */
  restore(dir: string, sha: string, preferred: string[]): Promise<string | undefined>;
  /** Saves dir as this commit's snapshot, unless it was restored from that key. */
  save(dir: string, sha: string, restored: string | undefined): Promise<void>;
}

/** Bumped whenever the cached formats change meaning; the action's keys carry the same version. */
export const STORE_VERSION = 'v1';
/** Snapshots a local store keeps; older ones are pruned after each save. */
export const LOCAL_SNAPSHOTS = 20;

/**
 * Snapshots on this machine, under root/v1/<sha>/.
 *
 * A save copies into a temporary directory beside the snapshots and renames it into place, so a
 * snapshot appears whole or not at all, and never changes afterwards.
 */
export class LocalKnowledgeBaseStore implements KnowledgeBaseStore {
  private readonly snapshots: string;

  constructor(
    root: string,
    private readonly log: (message: string) => void = () => {},
    private readonly keep: number = LOCAL_SNAPSHOTS
  ) {
    this.snapshots = join(root, STORE_VERSION);
  }

  async restore(dir: string, sha: string, preferred: string[]): Promise<string | undefined> {
    const key = this.chooseSnapshot(sha, preferred);
    if (!key) {
      this.log('no knowledge-base cache yet');
      return undefined;
    }
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    cpSync(join(this.snapshots, key), dir, { recursive: true });
    this.log(`knowledge-base cache restored from ${key}`);
    return key;
  }

  async save(dir: string, sha: string, restored: string | undefined): Promise<void> {
    if (restored === sha || existsSync(join(this.snapshots, sha))) return;
    mkdirSync(this.snapshots, { recursive: true, mode: 0o700 });
    const pending = mkdtempSync(join(this.snapshots, '.pending-'));
    try {
      cpSync(dir, pending, { recursive: true });
      renameSync(pending, join(this.snapshots, sha));
    } catch (error) {
      rmSync(pending, { recursive: true, force: true });
      this.log(
        `knowledge-base cache not saved: ${error instanceof Error ? error.message : String(error)}`
      );
      return;
    }
    this.log(`knowledge-base cache saved as ${sha}`);
    this.prune();
  }

  /** This commit's snapshot, else the first preferred one present, else the newest. */
  private chooseSnapshot(sha: string, preferred: string[]): string | undefined {
    const present = this.snapshotsNewestFirst();
    for (const candidate of [sha, ...preferred]) if (present.includes(candidate)) return candidate;
    return present[0];
  }

  private snapshotsNewestFirst(): string[] {
    if (!existsSync(this.snapshots)) return [];
    return readdirSync(this.snapshots, { withFileTypes: true })
      .filter(entry => entry.isDirectory() && !entry.name.startsWith('.'))
      .map(entry => ({
        name: entry.name,
        mtime: statSync(join(this.snapshots, entry.name)).mtimeMs,
      }))
      .sort((a, b) => b.mtime - a.mtime)
      .map(entry => entry.name);
  }

  /** Keeps the newest snapshots; each holds the stored review it was saved with. */
  private prune(): void {
    for (const stale of this.snapshotsNewestFirst().slice(this.keep))
      rmSync(join(this.snapshots, stale), { recursive: true, force: true });
  }
}
