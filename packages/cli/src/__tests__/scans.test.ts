import { describe, expect, test } from 'bun:test';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { captureOutput, mockEngine, setEngine } from './engine-mock';

mockEngine();
const { run } = await import('../cli');
const { linkScanId } = await import('../commands/scan');

const NATIVE_ID = 'ec053717-1621-466e-b1d7-a3275fa26885';
const DOCKER_ID = '9f2c4d1e-0000-4000-8000-000000000001';
const SARIF = '{"version":"2.1.0","runs":[]}\n';

/** A state dir as two scans leave it: a native and a docker run dir, the docker one newer. */
function stateWithScans(): string {
  const stateDir = realpathSync(mkdtempSync(join(tmpdir(), 'cynos-scans-state-')));
  setEngine({
    resolveStateDir: () => stateDir,
    SEVERITIES: ['critical', 'high', 'medium', 'low', 'informational'],
    plain: (value: string) => value.replace(/[\x00-\x1f\x7f-\x9f]/g, ''),
  });
  const root = join(stateDir, 'averlon', 'scans');
  const scan = (name: string, id: string, runtime: string, seconds: number): string => {
    const runDir = join(root, name);
    mkdirSync(join(runDir, 'reports'), { recursive: true });
    writeFileSync(
      join(runDir, 'cli-result.json'),
      JSON.stringify({
        scanId: id,
        scanStatus: 'completed',
        runtime,
        kind: 'full',
        diffBase: null,
        project: '/repos/dsvw',
        scannedSha: 'a'.repeat(40),
        counts: { critical: 0, high: 2, medium: 1, low: 0, informational: 0 },
      })
    );
    writeFileSync(
      join(runDir, 'reports', 'findings.json'),
      JSON.stringify({
        findings: [
          { title: 'Reflected XSS', severity: { level: 'medium' }, locations: [{ path: 'a.py' }] },
          {
            title: 'SQL injection',
            severity: { level: 'high' },
            locations: [{ path: 'db.py', startLine: 7, role: 'sink' }],
          },
        ],
      })
    );
    writeFileSync(join(runDir, 'reports', 'results.sarif'), SARIF);
    writeFileSync(join(runDir, 'reports', 'report.md'), '# Security Review\n');
    writeFileSync(join(runDir, 'cli.log'), `info ${runtime} scan started\ninfo done\n`);
    utimesSync(join(runDir, 'cli-result.json'), seconds, seconds);
    linkScanId(runDir, id);
    return runDir;
  };
  scan('cynos-scan-20261119082826-580601', NATIVE_ID, 'native', 1_700_000_000);
  scan('cynos-scan-20261119090000-aa11bb', DOCKER_ID, 'docker', 1_700_001_000);
  return stateDir;
}

const env = (): NodeJS.ProcessEnv => ({
  CI: '1',
  NO_COLOR: '1',
  CYNOS_CREDENTIAL_STORE: 'file',
  XDG_CONFIG_HOME: mkdtempSync(join(tmpdir(), 'cynos-scans-config-')),
});

describe('scans list', () => {
  test('lists native and docker scans alike, newest first', async () => {
    stateWithScans();
    const { value, stdout } = await captureOutput(() => run(['scans', 'list', '--json'], env()));
    expect(value).toBe(0);
    const { scans } = JSON.parse(stdout) as { scans: Record<string, unknown>[] };
    expect(scans.map(scan => [scan['scanId'], scan['runtime']])).toEqual([
      [DOCKER_ID, 'docker'],
      [NATIVE_ID, 'native'],
    ]);
    expect(scans[0]).toMatchObject({
      scanStatus: 'completed',
      project: '/repos/dsvw',
      mock: false,
    });
  });

  test('prints one row per scan, with its findings and repository', async () => {
    stateWithScans();
    const { stdout } = await captureOutput(() => run(['scans', 'list'], env()));
    const docker = stdout.split('\n').find(line => line.startsWith(DOCKER_ID))!;
    expect(docker).toContain('docker');
    expect(docker).toContain('3 (2 high)');
    expect(docker).toContain(`/repos/dsvw @ ${'a'.repeat(12)}`);
  });

  test("a mock scan is marked by upstream's --mock in run.json, on the docker runtime too", async () => {
    const stateDir = stateWithScans();
    const runDir = join(stateDir, 'averlon', 'scans', 'cynos-scan-20261119090000-aa11bb');
    writeFileSync(
      join(runDir, 'run.json'),
      JSON.stringify({ command: ['docker', 'run', '--mock'] })
    );
    const { stdout } = await captureOutput(() => run(['scans', 'list'], env()));
    expect(stdout.split('\n').find(line => line.startsWith(DOCKER_ID))).toContain('docker (mock)');
    expect(stdout.split('\n').find(line => line.startsWith(NATIVE_ID))).not.toContain('mock');
  });

  test('a run without a result is listed as unfinished, by its run name', async () => {
    const stateDir = stateWithScans();
    mkdirSync(join(stateDir, 'averlon', 'scans', 'cynos-scan-20261119100000-cccccc'));
    const { stdout } = await captureOutput(() => run(['scans', 'list', '--json'], env()));
    const { scans } = JSON.parse(stdout) as { scans: Record<string, unknown>[] };
    expect(scans).toContainEqual(
      expect.objectContaining({
        scanId: 'cynos-scan-20261119100000-cccccc',
        scanStatus: 'unfinished',
      })
    );
  });
});

describe('scans findings', () => {
  test("prints a docker scan's findings from its run dir, most severe first", async () => {
    stateWithScans();
    const { value, stdout } = await captureOutput(() =>
      run(['scans', 'findings', DOCKER_ID.slice(0, 8)], env())
    );
    expect(value).toBe(0);
    const high = stdout.indexOf('HIGH          SQL injection  db.py:7');
    expect(high).toBeGreaterThanOrEqual(0);
    expect(stdout.indexOf('MEDIUM        Reflected XSS  a.py')).toBeGreaterThan(high);
  });

  test('an unreadable findings report is an error, not a scan that found nothing', async () => {
    const stateDir = stateWithScans();
    const runDir = join(stateDir, 'averlon', 'scans', 'cynos-scan-20261119082826-580601');
    writeFileSync(join(runDir, 'reports', 'findings.json'), '{not json');
    const { value, stdout, stderr } = await captureOutput(() =>
      run(['scans', 'findings', NATIVE_ID], env())
    );
    expect(value).toBe(2);
    expect(stdout).not.toContain('No findings.');
    expect(stderr).toContain('findings report is not readable');
  });

  test('an id no run dir has is a usage error', async () => {
    stateWithScans();
    const { value, stderr } = await captureOutput(() => run(['scans', 'findings', 'nope'], env()));
    expect(value).toBe(2);
    expect(stderr).toContain('No scan nope on this machine');
  });
});

describe('scans export', () => {
  test('copies the SARIF report by default, to stdout or --output', async () => {
    stateWithScans();
    const toStdout = await captureOutput(() => run(['scans', 'export', NATIVE_ID], env()));
    expect(toStdout.value).toBe(0);
    expect(toStdout.stdout).toBe(SARIF);

    const output = join(mkdtempSync(join(tmpdir(), 'cynos-scans-out-')), 'report.md');
    const toFile = await captureOutput(() =>
      run(['scans', 'export', DOCKER_ID, '--format', 'md', '--output', output], env())
    );
    expect(toFile.value).toBe(0);
    expect(readFileSync(output, 'utf8')).toBe('# Security Review\n');
  });

  test('a report the run does not have fails, saying which', async () => {
    const stateDir = stateWithScans();
    const runDir = join(stateDir, 'averlon', 'scans', 'cynos-scan-20261119100000-cccccc');
    mkdirSync(runDir);
    const { value, stderr } = await captureOutput(() =>
      run(['scans', 'export', 'cynos-scan-20261119100000'], env())
    );
    expect(value).toBe(2);
    expect(stderr).toContain('has no results.sarif (unfinished)');
  });

  test('refuses a format it does not export', async () => {
    stateWithScans();
    const { value } = await captureOutput(() =>
      run(['scans', 'export', NATIVE_ID, '--format', 'csv'], env())
    );
    expect(value).toBe(2);
  });
});

describe('scans logs', () => {
  test("prints a scan's log, and the newest run's without an id", async () => {
    stateWithScans();
    const native = await captureOutput(() => run(['scans', 'logs', NATIVE_ID], env()));
    expect(native.stdout).toContain('native scan started');
    // The docker run dir is the newest: it was written last.
    const newest = await captureOutput(() => run(['scans', 'logs'], env()));
    expect(newest.stdout).toContain('docker scan started');
  });
});
