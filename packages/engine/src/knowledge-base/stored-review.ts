/**
 * The architecture review kept between scans, so a diff scan starts from the last full scan's
 * threat model instead of building one.
 *
 * A full scan's review costs minutes of a Codex agent; a diff changes a few files, and upstream's
 * diff workflow would otherwise model the whole repository again on every run. So a full build
 * stores its review in the knowledge-base cache (cache.ts, carried by the action's ci-cache.ts), as
 * does a diff that found none and built its own (diff.ts buildThreatModel), and a diff:
 *
 *   load     the stored review of the latest full scan the cache holds
 *   check    every citation against the current checkout: a file that no longer exists, or a line
 *            past its end, is cut to the file or to "(unverified)" (architecture.ts cutInvalid);
 *            lines that moved within a file are kept, so a citation can be a few lines off
 *   redact   credential-like literals present in the current checkout, as a fresh review does
 *
 * The review is a description of the architecture, not of the change: the diff scan adopts it as
 * its threat model unchanged.
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  cutInvalid,
  invalidCitations,
  normalise,
  redactSecretLiterals,
  wholeFiles,
  type ArchitectureReview,
} from './architecture';
import type { FileRow } from './inventory';

export const REVIEW_FILE = 'review.json';

export interface StoredReview {
  version: 1;
  /** The commit the review was made at. */
  sha: string;
  review: ArchitectureReview;
}

/** Where a diff's threat model came from, and what reuse did to it. */
export interface ReuseStats {
  /**
   * stored: a full scan's review, restored from the cache. built: none was stored, or it was of a
   * commit outside this checkout's history, so the diff reviewed the whole repository at HEAD
   * itself (diff.ts buildThreatModel); `sha` is then HEAD, and nothing was cut or redacted.
   */
  source: 'stored' | 'built';
  sha: string;
  citations: number;
  cut: number;
  redacted: number;
  /**
   * A diff's update of it (knowledge-base/diff.ts): why the change touched what it describes,
   * and whether the review agent then brought it up to date. Absent before the update ran.
   */
  update?: { gate: string[]; updated: boolean };
}

export function saveReview(cacheDir: string, sha: string, review: ArchitectureReview): void {
  const record: StoredReview = { version: 1, sha, review };
  writeFileSync(join(cacheDir, REVIEW_FILE), `${JSON.stringify(record)}\n`, { mode: 0o600 });
}

/** The stored review, or undefined when there is none or it cannot be read. */
export function loadReview(cacheDir: string): StoredReview | undefined {
  const path = join(cacheDir, REVIEW_FILE);
  if (!existsSync(path)) return undefined;
  try {
    const raw = JSON.parse(readFileSync(path, 'utf8')) as Partial<StoredReview>;
    if (raw.version !== 1 || typeof raw.sha !== 'string' || !raw.review) return undefined;
    return { version: 1, sha: raw.sha, review: normalise(raw.review) };
  } catch {
    return undefined;
  }
}

/** The stored review checked and redacted against the current checkout (a copy; stored is kept). */
export function reuseReview(
  stored: StoredReview,
  rows: FileRow[]
): { review: ArchitectureReview; stats: ReuseStats } {
  const review = normalise(JSON.parse(JSON.stringify(stored.review)));
  const files = wholeFiles(rows);
  const { invalid, total } = invalidCitations(review, files);
  const cut = cutInvalid(review, invalid, files);
  const redacted = redactSecretLiterals(review, rows);
  return { review, stats: { source: 'stored', sha: stored.sha, citations: total, cut, redacted } };
}
