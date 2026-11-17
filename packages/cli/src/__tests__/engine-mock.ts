/**
 * The engine seam (src/engine.ts), mocked for every CLI test.
 *
 * The CLI's tests must not load the engine: it is being refactored alongside, and the CLI's
 * behaviour is what is under test. So each test file calls mockEngine() and then imports the
 * modules under test dynamically, after the mock is in place; `setEngine` swaps the fake API.
 */
import { mock } from 'bun:test';
import type { Engine } from '../engine';

let api: Record<string, unknown> = {};

class EngineUnavailable extends Error {
  constructor(readonly exportName: string) {
    super(`This cynos build's engine has no ${exportName} export`);
  }
}

export function setEngine(fake: Partial<Engine>): void {
  api = fake as Record<string, unknown>;
}

export function mockEngine(fake: Partial<Engine> = {}): void {
  setEngine(fake);
  mock.module('../engine', () => ({
    RUNTIMES: ['native', 'docker'],
    SCAN_PHASES: ['stage', 'preflight', 'knowledge', 'brief', 'scan', 'report'],
    EngineUnavailable,
    hasEngine: (name: string) => api[name] !== undefined,
    engine: () =>
      new Proxy(
        {},
        {
          get(_target, name: string) {
            if (api[name] === undefined) throw new EngineUnavailable(name);
            return api[name];
          },
        }
      ),
    useEngineForTests: (next: Partial<Engine>) => {
      const previous = api;
      api = next as Record<string, unknown>;
      return () => {
        api = previous;
      };
    },
    assetsDir: () => '/assets',
  }));
}

/** Captures what a block writes to stdout and stderr. */
export async function captureOutput<T>(
  block: () => Promise<T>
): Promise<{ value: T; stdout: string; stderr: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const writeOut = process.stdout.write.bind(process.stdout);
  const writeErr = process.stderr.write.bind(process.stderr);
  process.stdout.write = ((chunk: string | Uint8Array) => {
    out.push(String(chunk));
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = ((chunk: string | Uint8Array) => {
    err.push(String(chunk));
    return true;
  }) as typeof process.stderr.write;
  try {
    const value = await block();
    return { value, stdout: out.join(''), stderr: err.join('') };
  } finally {
    process.stdout.write = writeOut;
    process.stderr.write = writeErr;
  }
}
