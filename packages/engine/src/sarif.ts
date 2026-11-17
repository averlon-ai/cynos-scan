/**
 * The strict SARIF export.
 *
 * The scan's own SARIF export is best-effort; codex-security's export command surfaces its
 * errors. It runs on the scan's runtime with no key (in the scanner image with no network, or
 * upstream on the host), reads the scan dir, and writes <stage>/out/results.sarif, which
 * reports.ts validates like every other report. A missing SARIF makes the report partial, not
 * the scan failed (upstream's rule). As upstream does, each run's automationDetails is dropped:
 * upload-sarif applies its category only when it is absent, and the CLI's per-scan id must not
 * override the workflow's stable category.
 */
import { arr, obj, type JsonObject } from './json';
import type { ScanLayout } from './layout';
import { runCommand, type Runner } from './processes';
import type { ScanRuntime } from './runtime';

/** Drops each run's automationDetails. */
export function stripAutomationDetails(sarif: JsonObject): JsonObject {
  for (const run of arr(sarif['runs'])) delete obj(run)['automationDetails'];
  return sarif;
}

/** Exports SARIF to <workspace>/out/results.sarif; returns whether the export succeeded. */
export function exportSarif(
  runtime: Pick<ScanRuntime, 'exportSarif'>,
  layout: ScanLayout,
  run: Runner = runCommand
): boolean {
  const command = runtime.exportSarif(layout);
  const [program, ...args] = command.argv;
  return run(program ?? '', args, command.env).status === 0;
}
