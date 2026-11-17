/**
 * A knowledge-base build's cache: answers and graphs reused when nothing they depend on changed.
 *
 * Most of a build is work that only depends on content: Jev's answer about a function or a file,
 * the packet design for a digest, the code graph of a checkout. Rebuilding an unchanged repository
 * (a rerun, or a branch with only a few changed files) repeats that work. Instead:
 *
 *   answers  each Jev request is keyed by the hash of exactly what it sends (model, input and
 *            questions); an identical request gets the stored answer. A file that changed has a
 *            different input, so only it is asked again
 *   graph    the code graph's functions and calls are keyed by the hash of every file's path and
 *            content; any change rebuilds it, since one edit can move another file's calls
 *
 * Answers are appended one JSON line at a time, so a build stopped half way keeps what it got.
 * Between CI runs the directory travels in the Actions cache (the action's ci-cache.ts); before it is saved,
 * compact() keeps only the answers this build used and pruneGraphs() only this checkout's graph,
 * so the cache holds one repository state and never grows with its history.
 */
import { createHash } from 'node:crypto';
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import type { FunctionNode } from './code-graph';
import type { FileRow } from './inventory';

export const hashKey = (...parts: unknown[]): string =>
  createHash('sha256').update(JSON.stringify(parts)).digest('hex');

/** Stored answers by request hash, one JSON line each. */
export class AnswerCache {
  hits = 0;
  private readonly answers = new Map<string, unknown>();
  /** Keys this build read or wrote: what compact() keeps. */
  private readonly used = new Set<string>();

  constructor(private readonly path: string) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    if (!existsSync(path)) return;
    for (const line of readFileSync(path, 'utf8').split('\n')) {
      try {
        const { k, v } = JSON.parse(line) as { k: string; v: unknown };
        this.answers.set(k, v);
      } catch {
        // a line cut by a stopped build
      }
    }
  }

  get size(): number {
    return this.answers.size;
  }

  get<T>(key: string): T | undefined {
    const v = this.answers.get(key) as T | undefined;
    if (v !== undefined) {
      this.hits += 1;
      this.used.add(key);
    }
    return v;
  }

  set(key: string, value: unknown): void {
    this.answers.set(key, value);
    this.used.add(key);
    appendFileSync(this.path, `${JSON.stringify({ k: key, v: value })}\n`, { mode: 0o600 });
  }

  /** Rewrites the file with only the answers this build used: those of files that still exist. */
  compact(): void {
    const lines = [...this.used].map(k => `${JSON.stringify({ k, v: this.answers.get(k) })}\n`);
    writeFileSync(this.path, lines.join(''), { mode: 0o600 });
  }
}

export interface StoredGraph {
  index: Record<string, unknown>;
  functions: FunctionNode[];
  calls: [string, string][];
}

/** The checkout's content hash: every file's path and the hash of its text, in path order. */
export function checkoutHash(rows: FileRow[]): string {
  return hashKey(rows.map(r => [r.path, r.text === undefined ? null : hashKey(r.text)]));
}

export function loadGraph(dir: string, key: string): StoredGraph | undefined {
  const path = join(dir, `graph-${key}.json`);
  if (!existsSync(path)) return undefined;
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as StoredGraph;
  } catch {
    return undefined;
  }
}

/** Removes every stored graph but `key`'s. */
export function pruneGraphs(dir: string, key: string): void {
  if (!existsSync(dir)) return;
  for (const name of readdirSync(dir))
    if (/^graph-[0-9a-f]+\.json$/.test(name) && name !== `graph-${key}.json`)
      rmSync(join(dir, name), { force: true });
}

export function saveGraph(dir: string, key: string, graph: StoredGraph): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeFileSync(join(dir, `graph-${key}.json`), JSON.stringify(graph), { mode: 0o600 });
}
