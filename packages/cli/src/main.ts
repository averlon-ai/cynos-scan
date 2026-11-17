#!/usr/bin/env node
/**
 * cynos's entry point (bin: dist/cynos.mjs).
 *
 * The Node version is checked before the rest of the CLI loads, since on an unsupported Node the
 * failure would otherwise be an obscure error from deep inside upstream. Then the run, and an
 * exit once stdout has drained: on macOS a pipe is written asynchronously, and exiting at once
 * could cut a JSON result short.
 */
import { unsupportedRuntime } from './node-version';

async function main(): Promise<void> {
  const problem = unsupportedRuntime();
  if (problem) {
    process.stderr.write(`${problem}\n`);
    process.exit(2);
  }
  const { run } = await import('./cli');
  const code = await run(process.argv.slice(2));
  process.stdout.write('', () => process.exit(code));
}

void main();
