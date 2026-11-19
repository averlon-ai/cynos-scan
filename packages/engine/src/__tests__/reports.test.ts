import { describe, it, expect, beforeEach } from 'bun:test';
import {
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  assertSafeSarif,
  checkFindingLocations,
  readReport,
  safeSourcePath,
  validateReports,
  validateSarif,
} from '../reports';
import { stripAutomationDetails } from '../sarif';

/**
 * The scanner's reports are written by a model-driven process beside Codex's state, so the
 * action publishes only what it read as plain files with safe references (upstream's rules).
 */

let stage: string;
let scanDir: string;

beforeEach(() => {
  stage = realpathSync(mkdtempSync(join(tmpdir(), 'cs-reports-')));
  scanDir = join(stage, 'out', 'scan');
  mkdirSync(scanDir, { recursive: true });
  mkdirSync(join(stage, 'state'));
  writeFileSync(join(stage, 'state', 'rollout.jsonl'), 'transcript with secrets');
});

const finding = (location: Record<string, unknown>) => ({
  title: 't',
  locations: [{ role: 'root_control', ...location }],
});

describe('readReport', () => {
  it('reads a regular file', () => {
    writeFileSync(join(scanDir, 'report.md'), 'ok');
    expect(readReport(scanDir, 'report.md').toString()).toBe('ok');
  });

  it('refuses a symlink or a hard link to Codex state', () => {
    symlinkSync(join(stage, 'state', 'rollout.jsonl'), join(scanDir, 'report.md'));
    linkSync(join(stage, 'state', 'rollout.jsonl'), join(scanDir, 'findings.json'));
    expect(() => readReport(scanDir, 'report.md')).toThrow('symlink');
    expect(() => readReport(scanDir, 'findings.json')).toThrow('without links');
  });

  it('refuses a report reached through a symlinked directory', () => {
    symlinkSync(join(stage, 'state'), join(stage, 'out', 'linked'));
    expect(() => readReport(join(stage, 'out', 'linked'), 'rollout.jsonl')).toThrow('canonical');
  });
});

describe('source references', () => {
  it.each([
    ['functions/a.py', true],
    ['', false],
    ['/etc/passwd', false],
    ['../outside', false],
    ['a/../../b', false],
    ['C:/x', false],
    ['https://example.com/x', false],
    ['a\\b', false],
    ['a\nb', false],
  ])('%j is safe: %s', (path, safe) => expect(safeSourcePath(path)).toBe(safe));

  it('checks the annotated location of each finding', () => {
    const ok = { findings: [finding({ path: 'a.py', startLine: 3, endLine: 4 }), { title: 'x' }] };
    expect(() => checkFindingLocations(ok)).not.toThrow();
    for (const location of [
      { path: '../a.py', startLine: 3 },
      { path: 'a.py', startLine: 0 },
      { path: 'a.py', startLine: '3' },
      { path: 'a.py', startLine: 5, endLine: 4 },
    ])
      expect(() => checkFindingLocations({ findings: [finding(location)] })).toThrow(
        'unsafe source location'
      );
    expect(() => checkFindingLocations({})).toThrow('no findings list');
  });

  it('refuses SARIF that references anything outside the repository', () => {
    const sarif = (location: Record<string, unknown>) => ({
      runs: [{ results: [{ locations: [{ physicalLocation: { artifactLocation: location } }] }] }],
    });
    expect(() => assertSafeSarif(sarif({ uri: 'functions/a%20b.py' }))).not.toThrow();
    for (const location of [
      { uri: 'file:///etc/passwd' },
      { uri: '..%2Fsecret' },
      { uri: 'a.py', uriBaseId: 'SRCROOT' },
      { uri: 'a.py', index: 0 },
      {},
    ])
      expect(() => assertSafeSarif(sarif(location))).toThrow('Unsafe SARIF');
    expect(() => assertSafeSarif({ runs: [{ originalUriBaseIds: {} }] })).toThrow('External');
  });
});

describe('validateReports', () => {
  it('copies the reports that pass and withholds a linked one', () => {
    writeFileSync(
      join(scanDir, 'findings.json'),
      JSON.stringify({ findings: [finding({ path: 'a.py', startLine: 1 })] })
    );
    writeFileSync(join(scanDir, 'scan-manifest.json'), '{"scan":{"status":"completed"}}');
    symlinkSync(join(stage, 'state', 'rollout.jsonl'), join(scanDir, 'report.md'));
    const reports = validateReports(stage);
    expect(Object.keys(reports.paths).sort()).toEqual(['findings.json', 'scan-manifest.json']);
    expect(reports.paths['findings.json']).toBe(join(stage, 'reports', 'findings.json'));
    expect(reports.findingsProblem).toBe('');
    expect(reports.findings?.['findings']).toHaveLength(1);
    expect(reports.problems).toEqual([expect.stringContaining('report.md')]);
  });

  it('says when there are no findings', () => {
    expect(validateReports(stage).findingsProblem).toBe('no findings.json');
  });

  it('says when the findings are not JSON', () => {
    writeFileSync(join(scanDir, 'findings.json'), '{not json');
    expect(validateReports(stage).findingsProblem).toBe('findings.json is not valid JSON');
    // reports/ holds only validated reports: `cynos scans` exports what is there.
    expect(existsSync(join(stage, 'reports', 'findings.json'))).toBe(false);
  });

  it('refuses findings with unsafe locations', () => {
    writeFileSync(
      join(scanDir, 'findings.json'),
      JSON.stringify({ findings: [finding({ path: '/etc/passwd', startLine: 1 })] })
    );
    const reports = validateReports(stage);
    expect(reports.findings).toBeUndefined();
    expect(reports.findingsProblem).toContain('unsafe source location');
    expect(reports.paths['findings.json']).toBeUndefined();
    expect(existsSync(join(stage, 'reports', 'findings.json'))).toBe(false);
  });
});

describe('validateSarif', () => {
  it('keeps safe SARIF without automationDetails', () => {
    const reports = validateReports(stage);
    writeFileSync(
      join(stage, 'out', 'results.sarif'),
      JSON.stringify({ runs: [{ automationDetails: { id: 'scan-1' }, results: [] }] })
    );
    const path = validateSarif(stage, reports);
    expect(path).toBe(join(stage, 'reports', 'results.sarif'));
    expect(JSON.parse(readFileSync(path, 'utf8'))).toEqual({ runs: [{ results: [] }] });
  });

  it('withholds unsafe or missing SARIF', () => {
    const reports = validateReports(stage);
    expect(validateSarif(stage, reports)).toBe('');
    expect(reports.problems).toEqual([]);
    writeFileSync(
      join(stage, 'out', 'results.sarif'),
      JSON.stringify({ runs: [{ originalUriBaseIds: { ROOT: { uri: 'file:///' } } }] })
    );
    expect(validateSarif(stage, reports)).toBe('');
    expect(reports.problems).toEqual([expect.stringContaining('results.sarif')]);
  });
});

describe('sarif', () => {
  it('drops automationDetails so the upload category applies', () => {
    expect(
      stripAutomationDetails({ runs: [{ automationDetails: { id: 'x' }, results: [] }] })
    ).toEqual({ runs: [{ results: [] }] });
  });
});
