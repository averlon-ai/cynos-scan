/**
 * --since-last-scan: scan only what changed since this repository's last completed scan.
 *
 * The revision to diff from is in upstream's history, not ours: `scans list <repo> --json` lists
 * this repository's scans, each with its status and the revision it scanned
 * (`{ scans: [{ scanId, targetRevision, progress: { status }, completedAt }] }`). A diff is only
 * meaningful when that revision is an ancestor of HEAD; after a rebase or a branch switch it is
 * not, and a diff from it would rescan unrelated changes or fail upstream's target checks. So:
 *
 *   newest completed scan with a revision   none     → full scan, saying so
 *   its revision is HEAD                     yes      → nothing to scan
 *   its revision is an ancestor of HEAD      yes      → diff from it
 *   otherwise                                         → full scan, saying why
 */
import { spawnSync } from 'node:child_process';
import { captureUpstream, upstreamJson, type UpstreamCapture } from '../upstream';

export type SinceLastScan =
  | { kind: 'diff'; base: string; scanId: string }
  | { kind: 'full'; reason: string }
  | { kind: 'up-to-date'; scanId: string };

export interface LastScan {
  scanId: string;
  revision: string;
  completedAt: string;
}

export interface SinceLastScanDeps {
  capture?: UpstreamCapture;
  isAncestor?: (project: string, revision: string, head: string) => boolean;
}

/** git's answer: revision is an ancestor of head (or head itself). */
export function gitIsAncestor(project: string, revision: string, head: string): boolean {
  return (
    spawnSync('git', ['-C', project, 'merge-base', '--is-ancestor', revision, head], {
      stdio: 'ignore',
    }).status === 0
  );
}

/** The newest completed scan in upstream's `scans list --json` output that recorded a revision. */
export function lastCompletedScan(list: unknown): LastScan | undefined {
  const scans = (list as { scans?: unknown })?.scans;
  if (!Array.isArray(scans)) return undefined;
  const completed: LastScan[] = [];
  for (const scan of scans as Record<string, unknown>[]) {
    const status = (scan?.['progress'] as Record<string, unknown> | undefined)?.['status'];
    const revision = scan?.['targetRevision'];
    if (status !== 'complete' || typeof revision !== 'string' || !revision) continue;
    completed.push({
      scanId: String(scan['scanId']),
      revision,
      completedAt: String(scan['completedAt'] ?? scan['updatedAt'] ?? ''),
    });
  }
  return completed.sort((a, b) => b.completedAt.localeCompare(a.completedAt))[0];
}

export async function sinceLastScan(
  project: string,
  head: string,
  deps: SinceLastScanDeps = {}
): Promise<SinceLastScan> {
  const isAncestor = deps.isAncestor ?? gitIsAncestor;

  // 1. This repository's history, from upstream.
  const listed = await upstreamJson(['scans', 'list', project], deps.capture ?? captureUpstream);
  if (listed.error !== undefined)
    return { kind: 'full', reason: `upstream's scan history could not be read (${listed.error})` };

  // 2. The newest completed scan that recorded what it scanned.
  const last = lastCompletedScan(listed.value);
  if (!last) return { kind: 'full', reason: 'this repository has no completed scan yet' };
  if (last.revision === head) return { kind: 'up-to-date', scanId: last.scanId };

  // 3. Its revision must be in HEAD's history for a diff from it to mean "since then".
  if (!isAncestor(project, last.revision, head))
    return {
      kind: 'full',
      reason: `the last scan's revision ${last.revision.slice(0, 12)} is not an ancestor of HEAD (rebased or another branch)`,
    };
  return { kind: 'diff', base: last.revision, scanId: last.scanId };
}
