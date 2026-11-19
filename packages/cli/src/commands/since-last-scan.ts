/**
 * --since-last-scan: scan only what changed since this repository's last completed scan.
 *
 * The revision to diff from is in the run dirs (`scans list`), not upstream's history: a docker
 * scan is recorded only in its own run dir, so upstream's history never saw it. Each run dir's
 * result names the repository it scanned, its status and the revision (`project`, `scanStatus`,
 * `scannedSha`). A diff is only meaningful when that revision is an ancestor of HEAD; after a
 * rebase or a branch switch it is not, and a diff from it would rescan unrelated changes or fail
 * upstream's target checks. So:
 *
 *   newest completed scan of this repository with a revision   none  → full scan, saying so
 *   its revision is HEAD                                        yes   → nothing to scan
 *   its revision is an ancestor of HEAD                         yes   → diff from it
 *   otherwise                                                         → full scan, saying why
 *
 * A mock scan's findings are synthetic, so it never counts as the last scan.
 */
import { spawnSync } from 'node:child_process';
import { listRuns, type ScanRun } from './scans';

export type SinceLastScan =
  | { kind: 'diff'; base: string; scanId: string }
  | { kind: 'full'; reason: string }
  | { kind: 'up-to-date'; scanId: string };

export interface LastScan {
  scanId: string;
  revision: string;
}

export interface SinceLastScanDeps {
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

/** The newest completed, real scan of project that recorded a revision (runs come newest first). */
export function lastCompletedScan(runs: ScanRun[], project: string): LastScan | undefined {
  for (const run of runs) {
    const result = run.result;
    const revision = result?.['scannedSha'];
    if (run.mock || result?.['project'] !== project || result['scanStatus'] !== 'completed')
      continue;
    if (typeof revision === 'string' && revision) return { scanId: run.id, revision };
  }
  return undefined;
}

export function sinceLastScan(
  project: string,
  head: string,
  stateDir: string,
  deps: SinceLastScanDeps = {}
): SinceLastScan {
  const isAncestor = deps.isAncestor ?? gitIsAncestor;

  // 1. The newest completed scan of this repository that recorded what it scanned.
  const last = lastCompletedScan(listRuns(stateDir), project);
  if (!last) return { kind: 'full', reason: 'this repository has no completed scan yet' };
  if (last.revision === head) return { kind: 'up-to-date', scanId: last.scanId };

  // 2. Its revision must be in HEAD's history for a diff from it to mean "since then".
  if (!isAncestor(project, last.revision, head))
    return {
      kind: 'full',
      reason: `the last scan's revision ${last.revision.slice(0, 12)} is not an ancestor of HEAD (rebased or another branch)`,
    };
  return { kind: 'diff', base: last.revision, scanId: last.scanId };
}
