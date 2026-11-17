/**
 * A scan's outcome, in upstream's GitHub Action vocabulary
 * (openai/codex-security github-action/src/results.ts at npm-v0.9.1, and main.ts).
 *
 * completed: the CLI's manifest says completed, it reported no warnings, the exit code is 0
 * (policy passed) or 1 (findings at or above fail-on-severity: policy failed), the scanned
 * revision is the checkout's, and findings.json passed validation (reports.ts). A dry run that
 * validated is skipped. Anything else is failed: a cancelled scan, and a scan the manifest
 * records as anything but completed, whose available results upstream keeps. Upstream records
 * no coverage completeness (the field went in 0.3.0, and coverage.json itself in 0.8.0: the
 * manifest's scan.review keeps only the excluded paths), so there is no incomplete outcome: the
 * manifest's status is the scan's. Only a completed scan may reach code scanning, where a
 * partial analysis would close real alerts as fixed.
 */
import { SEVERITIES, type Severity } from './constants';
import { arr, at, text, type JsonObject } from './json';
import { stderrTail } from './sandbox';
import type { ContainerRun } from './scan-run';

export type ScanStatus = 'completed' | 'failed' | 'skipped';
export type PolicyStatus = 'passed' | 'failed' | 'not-evaluated';
export type ReportStatus = 'ready' | 'partial' | 'failed';

export interface Outcome {
  scanStatus: ScanStatus;
  policyStatus: PolicyStatus;
  reason: string;
  skipReason: string;
}

const SAVE_REJECTED = /Could not save the Codex Security scan: ([^\n]+)/;

/** The commit codex-security recorded scanning, or '' when it recorded none. */
export function scannedRevision(result: JsonObject): string {
  const target = at(result, 'manifest', 'scan', 'target');
  const kind = at(target, 'kind');
  if (kind === 'git_diff') return text(at(target, 'headRevision'));
  if (kind === 'git_revision') return text(at(target, 'revision'));
  return '';
}

/** The scan's outcome by upstream's rules. */
export function classify(
  run: Pick<ContainerRun, 'exitCode' | 'stopStatus' | 'stopReason'>,
  result: JsonObject,
  findingsProblem: string,
  stderr: string,
  scannedSha: string,
  dryRun: boolean
): Outcome {
  const failed = (reason: string): Outcome => ({
    scanStatus: 'failed',
    policyStatus: 'not-evaluated',
    reason: reason.slice(0, 500),
    skipReason: '',
  });
  if (run.stopStatus) return failed(run.stopReason);
  if (dryRun) {
    if (run.exitCode === 0)
      return {
        scanStatus: 'skipped',
        policyStatus: 'not-evaluated',
        reason: 'Configuration validated; no security scan performed',
        skipReason: 'dry-run',
      };
    return failed(
      `CLI configuration validation failed (exit ${run.exitCode}): ${stderrTail(stderr)}`
    );
  }
  if (result['status'] === 'failed' && typeof result['message'] === 'string')
    return failed(result['message']);
  const manifestStatus = text(at(result, 'manifest', 'scan', 'status'));
  const warnings = arr(result['warnings']);
  const exitedCompleted = run.exitCode === 0 || run.exitCode === 1;
  if (
    !result['manifest'] ||
    manifestStatus !== 'completed' ||
    warnings.length ||
    !exitedCompleted
  ) {
    const rejected = SAVE_REJECTED.exec(stderr);
    if (rejected?.[1]) return failed(`save rejected: ${rejected[1].trim()}`);
    // A scan upstream stopped short records why in its manifest: "Scan partial; available
    // results were retained."
    if (manifestStatus && manifestStatus !== 'completed')
      return failed(`scan ${manifestStatus} (exit ${run.exitCode}): available results were kept`);
    const tail = stderrTail(stderr);
    return failed(
      `CLI did not complete successfully (exit ${run.exitCode})${tail ? `: ${tail}` : ''}`
    );
  }
  if (scannedRevision(result) !== scannedSha)
    return failed('CLI scan revision does not match the requested checkout commit');
  if (findingsProblem) return failed(findingsProblem);
  return run.exitCode === 1
    ? {
        scanStatus: 'completed',
        policyStatus: 'failed',
        reason: 'findings meet the configured failure threshold',
        skipReason: '',
      }
    : { scanStatus: 'completed', policyStatus: 'passed', reason: '', skipReason: '' };
}

/**
 * The CLI's own cost estimate, as upstream's action reports it: undefined when the CLI does not
 * price the model, as for cynos model ids.
 */
export function cliEstimatedCost(result: JsonObject): number | undefined {
  const usd = at(result, 'cost', 'estimatedUsd');
  return typeof usd === 'number' && Number.isFinite(usd) ? usd : undefined;
}

/** The number of findings per severity. */
export function severityCounts(findings: JsonObject | undefined): Record<Severity, number> {
  const counts = Object.fromEntries(SEVERITIES.map(level => [level, 0])) as Record<
    Severity,
    number
  >;
  for (const finding of arr(findings?.['findings'])) {
    const level = text(at(finding, 'severity', 'level')).toLowerCase() as Severity;
    if (level in counts) counts[level] += 1;
  }
  return counts;
}

export interface Report {
  reportStatus: ReportStatus;
  sarifUploadReady: boolean;
  success: boolean;
  title: string;
}

/**
 * The report status and whether the step passes, by upstream's rules.
 *
 * The step passes when reporting did not fail and the scan completed with its policy passed.
 * Reporting fails when the key was found in the outputs, or a required report (manifest,
 * findings) is missing or was rejected; a missing SARIF only makes it partial. Upstream since
 * 0.8.0 writes no coverage.json, so it is not a required report.
 */
export function decide(
  outcome: Pick<Outcome, 'scanStatus' | 'policyStatus' | 'reason'>,
  options: {
    sarifReady: boolean;
    leakClean: boolean;
    publishable: boolean;
    failOnSeverity: string;
    /** Whether the manifest and findings reports both passed validation. */
    requiredReports: boolean;
  }
): Report {
  const { scanStatus: status, policyStatus: policy } = outcome;
  if (status === 'skipped')
    return { reportStatus: 'ready', sarifUploadReady: false, success: true, title: outcome.reason };
  const reportStatus: ReportStatus =
    !options.leakClean || status !== 'completed' || !options.requiredReports
      ? 'failed'
      : options.sarifReady
        ? 'ready'
        : 'partial';
  const sarifUploadReady =
    status === 'completed' && reportStatus === 'ready' && options.publishable;
  let title: string;
  if (status !== 'completed')
    title = 'Scan could not complete. Available findings are provisional.';
  else if (reportStatus === 'failed') title = 'Scan completed, but required reporting failed.';
  else if (policy === 'failed')
    title = 'Scan completed. Findings meet the configured failure threshold.';
  else if (options.failOnSeverity === 'none')
    title = 'Scan completed. Findings are reported without failing the job.';
  else title = 'Scan completed. No findings meet the failure threshold.';
  const success = reportStatus !== 'failed' && status === 'completed' && policy === 'passed';
  return { reportStatus, sarifUploadReady, success, title };
}
