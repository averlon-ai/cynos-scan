/**
 * The scanner's reports, read the way upstream's action reads them
 * (openai/codex-security github-action/src/results.ts and sarif.ts).
 *
 * The reports are written by a model-driven process, in a directory beside Codex's state, whose
 * session logs hold full transcripts. A report that is a symlink or a hard link would make the
 * action publish a file that was never meant to leave the runner, past the leak check, which
 * reads regular files only. A finding location or a SARIF reference could also point outside
 * the repository. So, after the scanner has exited:
 *   1. each report is read once, only as a regular file with one link, reached through no
 *      symlink, and written to a fresh directory the action owns;
 *   2. every finding's annotated location must be a safe repository-relative path and line;
 *   3. the SARIF must reference only safe repository-relative sources, and loses its
 *      automationDetails so the upload category applies.
 * Everything the action publishes (outputs, summary, annotations, issues, artifacts, the threat
 * model, SARIF) comes from those copies.
 */
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import { join, resolve } from 'node:path';
import { arr, at, isRecord, obj, type JsonObject } from './json';
import { stripAutomationDetails } from './sarif';

/**
 * The scan directory's reports that the action keeps. Upstream since 0.8.0 writes no
 * coverage.json; it stays in the list because it names a key of ValidatedReports' paths, which
 * callers read.
 */
export const SCAN_REPORTS = [
  'scan-manifest.json',
  'findings.json',
  'coverage.json',
  'report.md',
  'threatmodel.md',
] as const;
export const SARIF_REPORT = 'results.sarif';

export interface ValidatedReports {
  /** The action's own copies of the reports that passed. */
  directory: string;
  /** Report name -> its copy, for each report that passed. */
  paths: Partial<Record<(typeof SCAN_REPORTS)[number] | typeof SARIF_REPORT, string>>;
  /** findings.json, parsed, when it passed. */
  findings: JsonObject | undefined;
  /** Why findings.json is unusable, or '' when it is usable. */
  findingsProblem: string;
  /** What else failed validation, for the log. */
  problems: string[];
}

/**
 * The bytes of root/name, read only if name is a regular file with one link and no part of the
 * path is a symlink. Throws when the file is absent, linked, or changes while it is read.
 */
export function readReport(root: string, name: string): Buffer {
  const absoluteRoot = resolve(root);
  if (realpathSync(absoluteRoot) !== absoluteRoot)
    throw new Error('Report root must be canonical and cannot contain symlinks.');
  const path = join(absoluteRoot, name);
  if (realpathSync(path) !== path) throw new Error('Report path contains a symlink.');
  const before = lstatSync(path);
  if (!before.isFile() || before.nlink !== 1)
    throw new Error('Report must be a regular file without links.');
  const descriptor = openSync(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK
  );
  try {
    const opened = fstatSync(descriptor);
    if (
      !opened.isFile() ||
      opened.nlink !== 1 ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino
    )
      throw new Error('Report changed while opening.');
    const bytes = readFileSync(descriptor);
    if (bytes.length !== opened.size) throw new Error('Report changed while reading.');
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}

/** A repository-relative POSIX path: no scheme, drive, absolute path, '..' or control character. */
export function safeSourcePath(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    !/[\\\x00-\x1f\x7f]/u.test(value) &&
    !value.startsWith('/') &&
    !/^(?:[a-z]:|[a-z][a-z0-9+.-]*:\/\/)/iu.test(value) &&
    value.split('/').every(part => part !== '..')
  );
}

/**
 * Throws unless every finding's annotated location (its root_control location, else its first)
 * is a safe source path with a valid line range. Upstream's rule: annotations and issue links
 * are built from these.
 */
export function checkFindingLocations(findings: JsonObject): void {
  if (!Array.isArray(findings['findings'])) throw new Error('findings.json has no findings list.');
  for (const finding of arr(findings['findings'])) {
    const locations = arr(at(finding, 'locations')).map(obj);
    const location = locations.find(item => item['role'] === 'root_control') ?? locations[0];
    if (!location) continue;
    const { path, startLine, endLine } = location;
    if (
      !safeSourcePath(path) ||
      !Number.isSafeInteger(startLine) ||
      (startLine as number) < 1 ||
      (endLine !== undefined &&
        (!Number.isSafeInteger(endLine) || (endLine as number) < (startLine as number)))
    )
      throw new Error('A finding has an unsafe source location for GitHub annotations.');
  }
}

/** Throws unless every SARIF source reference is a safe repository-relative path. */
export function assertSafeSarif(value: unknown): void {
  const pending: unknown[] = [value];
  while (pending.length) {
    const item = pending.pop();
    if (Array.isArray(item)) {
      pending.push(...(item as unknown[]));
      continue;
    }
    if (!isRecord(item)) continue;
    for (const [key, child] of Object.entries(item)) {
      if (key === 'externalPropertyFileReferences' || key === 'originalUriBaseIds')
        throw new Error('External SARIF references are unsupported.');
      if (
        key === 'artifactLocation' &&
        (!isRecord(child) ||
          typeof child['uri'] !== 'string' ||
          child['uriBaseId'] !== undefined ||
          child['index'] !== undefined ||
          /^[a-z][a-z0-9+.-]*:/iu.test(child['uri']) ||
          !safeSourcePath(decodeURIComponent(child['uri'])))
      )
        throw new Error('Unsafe SARIF source location.');
      if (typeof child === 'object' && child !== null) pending.push(child);
    }
  }
}

function writeCopy(directory: string, name: string, bytes: Buffer): string {
  const path = join(directory, name);
  writeFileSync(path, bytes, { mode: 0o600, flag: 'wx' });
  return path;
}

function isMissing(error: unknown): boolean {
  return (error as NodeJS.ErrnoException).code === 'ENOENT';
}

/**
 * Validates the scan's reports in its scan dir (the docker runtime's stage/out/scan by default)
 * and copies the ones that pass to stage/reports. Call only after the scanner has exited.
 */
export function validateReports(
  stage: string,
  scanDir: string = join(stage, 'out', 'scan')
): ValidatedReports {
  const directory = join(stage, 'reports');
  mkdirSync(directory, { mode: 0o700 });
  const reports: ValidatedReports = {
    directory,
    paths: {},
    findings: undefined,
    findingsProblem: 'no findings.json',
    problems: [],
  };

  // 1. Each report, read without following links.
  for (const name of SCAN_REPORTS) {
    try {
      reports.paths[name] = writeCopy(directory, name, readReport(scanDir, name));
    } catch (error) {
      if (!isMissing(error)) reports.problems.push(`${name}: ${(error as Error).message}`);
    }
  }

  // 2. The findings, with their annotated locations.
  if (reports.paths['findings.json']) {
    try {
      const findings = obj(JSON.parse(readFileSync(reports.paths['findings.json'], 'utf8')));
      checkFindingLocations(findings);
      reports.findings = findings;
      reports.findingsProblem = '';
    } catch (error) {
      reports.findingsProblem =
        error instanceof SyntaxError ? 'findings.json is not valid JSON' : (error as Error).message;
      // Rejected findings are not published, not even in the report artifact.
      delete reports.paths['findings.json'];
    }
  }
  return reports;
}

/**
 * Validates stage/out/results.sarif, written by the strict export, and adds its copy to
 * reports. Returns the copy's path, or '' when the SARIF is missing, unsafe or unreadable.
 * Call only after the export has exited.
 */
export function validateSarif(stage: string, reports: ValidatedReports): string {
  try {
    const sarif: unknown = JSON.parse(
      readReport(join(stage, 'out'), SARIF_REPORT).toString('utf8')
    );
    assertSafeSarif(sarif);
    reports.paths[SARIF_REPORT] = writeCopy(
      reports.directory,
      SARIF_REPORT,
      Buffer.from(JSON.stringify(stripAutomationDetails(obj(sarif))))
    );
    return reports.paths[SARIF_REPORT];
  } catch (error) {
    if (!isMissing(error)) reports.problems.push(`${SARIF_REPORT}: ${(error as Error).message}`);
    return '';
  }
}
