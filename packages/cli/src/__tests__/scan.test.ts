import { describe, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { readScanInputs } from '@averlon-ai/cynos-scan-engine';
import type { ScanConfig, ScanIO, ScanResult } from '../engine';
import { captureOutput, mockEngine, setEngine } from './engine-mock';

mockEngine();
const { run } = await import('../cli');
const { interactiveScan, parseMaxTime, parseTimeout, parseHostPaths, linkScanId, newRunName } =
  await import('../commands/scan');
const { maxHypothesisPackets } = await import('../settings');

/** A committed git repository, as scripts/e2e.sh makes one. */
function fixture(): { project: string; head: string } {
  const project = mkdtempSync(join(tmpdir(), 'cynos-scan-fixture-'));
  writeFileSync(join(project, 'app.py'), 'print(1)\n');
  const git = (...args: string[]) =>
    spawnSync(
      'git',
      ['-C', project, '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', ...args],
      { encoding: 'utf8' }
    );
  git('init', '-q');
  git('add', '.');
  git('commit', '-q', '-m', 'fixture');
  return { project, head: git('rev-parse', 'HEAD').stdout.trim() };
}

/** The engine's constants every fake engine needs: the CLI keeps no copies of its own. */
const ENGINE_CONSTANTS = {
  REASONING_EFFORTS: ['none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max'],
  DEFAULT_MODEL: 'deepseek/deepseek-v4.1-flash',
  BASE_URL: 'https://cynos.example/v1',
  SEVERITIES: ['critical', 'high', 'medium', 'low', 'informational'],
  // The engine's plain(), as far as these tests need it: no control characters.
  plain: (value: string) => value.replace(/[\x00-\x1f\x7f-\x9f]/g, ''),
};

/** A fake scanCheckout: records its config, emits a phase and a step, returns a mock result. */
function fakeScan(stateDir: string) {
  const seen: { config?: ScanConfig; io?: ScanIO } = {};
  setEngine({
    ...ENGINE_CONSTANTS,
    // The engine's own checks of --rubric and --false-positives.
    readScanInputs,
    resolveStateDir: () => stateDir,
    LocalKnowledgeBaseStore: class {
      async restore() {
        return undefined;
      }
      async save() {}
    },
    scanCheckout: async (config: ScanConfig, io: ScanIO): Promise<ScanResult> => {
      seen.config = config;
      seen.io = io;
      io.progress?.({ type: 'phase', phase: 'stage', status: 'start' });
      io.progress?.({
        type: 'step',
        phase: 'preflight',
        step: 'key',
        message: 'cynos accepted the key',
      });
      io.log('a log line');
      io.progress?.({ type: 'phase', phase: 'stage', status: 'end', seconds: 0.3 });
      // The SARIF goes into the stage, the run dir, as the engine's report phase writes it.
      const sarif = join(config.stage, 'reports', 'results.sarif');
      mkdirSync(dirname(sarif), { recursive: true });
      writeFileSync(sarif, '{}');
      return {
        scanId: 'scan-0123456789',
        scanDir: join(stateDir, 'scans', 'fixture', 'codex-security-fixture-abc'),
        exitCode: 0,
        outcome: { scanStatus: 'completed', policyStatus: 'passed', reason: '', skipReason: '' },
        counts: { critical: 0, high: 1, medium: 0, low: 0, informational: 0 },
        sarif,
        knowledgeBase: undefined,
        diffThreatModel: undefined,
        usage: {
          input_tokens: 0,
          cached_input_tokens: 0,
          output_tokens: 0,
          reasoning_output_tokens: 0,
        },
        seconds: 1,
        cost: { scan_usd: null, knowledge_base_usd: null },
        versions: {},
      };
    },
  });
  return seen;
}

const baseEnv = (): NodeJS.ProcessEnv => ({
  CI: '1',
  NO_COLOR: '1',
  CYNOS_CREDENTIAL_STORE: 'file',
  XDG_CONFIG_HOME: mkdtempSync(join(tmpdir(), 'cynos-scan-config-')),
});
/** upstream's mock scan, which the CLI runs only when CYNOS_SCAN_MOCK=1 asks for it. */
const mockEnv = (): NodeJS.ProcessEnv => ({ ...baseEnv(), CYNOS_SCAN_MOCK: '1' });

describe('the pretty result', () => {
  test('lists what a completed scan found, most severe first, and where its report is', async () => {
    const { project } = fixture();
    const stateDir = mkdtempSync(join(tmpdir(), 'cynos-scan-state-'));
    fakeScan(stateDir);
    const scanDir = join(stateDir, 'scans', 'fixture', 'codex-security-fixture-abc');
    mkdirSync(scanDir, { recursive: true });
    writeFileSync(join(scanDir, 'report.md'), '# Security Review\n');
    const finding = (title: string, level: string, locations: unknown[]) => ({
      title,
      severity: { level },
      locations,
    });
    writeFileSync(
      join(scanDir, 'findings.json'),
      JSON.stringify({
        findings: [
          finding('Debug endpoint left on', 'low', [{ path: 'app/debug.py', startLine: 3 }]),
          finding('Command injection in the export job', 'high', [
            { path: 'app/routes.py', startLine: 10, role: 'source' },
            { path: 'app/jobs.py', startLine: 42, role: 'sink' },
          ]),
        ],
      })
    );
    const { value, stdout } = await captureOutput(() =>
      run(['scan', project, '--headless'], mockEnv())
    );
    expect(value).toBe(0);
    expect(stdout).toContain(`report    ${join(scanDir, 'report.md')}`);
    const high = stdout.indexOf(
      'HIGH          Command injection in the export job  app/jobs.py:42'
    );
    const low = stdout.indexOf('LOW           Debug endpoint left on  app/debug.py:3');
    expect(high).toBeGreaterThan(0);
    expect(low).toBeGreaterThan(high);
  });

  test('reads severities in any case, skips null findings and locations, and prints no control characters', async () => {
    const { project } = fixture();
    const stateDir = mkdtempSync(join(tmpdir(), 'cynos-scan-state-'));
    fakeScan(stateDir);
    const scanDir = join(stateDir, 'scans', 'fixture', 'codex-security-fixture-abc');
    mkdirSync(scanDir, { recursive: true });
    const findings = [
      { title: 'Verbose errors', severity: { level: 'low' }, locations: [{ path: 'a.py' }] },
      null,
      {
        title: 'SQL injection\u001b[2J in search',
        severity: { level: 'CRITICAL' },
        locations: [null, { path: 'app/\u001b[31msearch.py', startLine: 7, role: 'sink' }],
      },
      { title: 'Open redirect', severity: { level: 'High' }, locations: null },
    ];
    writeFileSync(join(scanDir, 'findings.json'), JSON.stringify({ findings }));
    const { value, stdout } = await captureOutput(() =>
      run(['scan', project, '--headless'], mockEnv())
    );
    expect(value).toBe(0);
    expect(stdout).not.toContain('\u001b');
    const critical = stdout.indexOf(
      'CRITICAL      SQL injection[2J in search  app/[31msearch.py:7'
    );
    const high = stdout.indexOf('HIGH          Open redirect');
    const low = stdout.indexOf('LOW           Verbose errors  a.py');
    expect(critical).toBeGreaterThan(0);
    expect(high).toBeGreaterThan(critical);
    expect(low).toBeGreaterThan(high);
  });

  test('a scan dir with no readable findings.json lists none, and still prints the result', async () => {
    const { project } = fixture();
    fakeScan(mkdtempSync(join(tmpdir(), 'cynos-scan-state-')));
    const { value, stdout } = await captureOutput(() =>
      run(['scan', project, '--headless'], mockEnv())
    );
    expect(value).toBe(0);
    expect(stdout).toContain('Scan completed: 1 finding (1 high)');
    expect(stdout).not.toContain('Findings:');
  });
});

describe('CYNOS_SCAN_MOCK=1 scan --headless --format json (the e2e contract)', () => {
  test('stdout is one JSON object with scanId, scanStatus, scanDir, exitCode and counts', async () => {
    const { project, head } = fixture();
    const stateDir = mkdtempSync(join(tmpdir(), 'cynos-scan-state-'));
    const seen = fakeScan(stateDir);
    const { value, stdout, stderr } = await captureOutput(() =>
      run(['scan', project, '--runtime', 'native', '--headless', '--format', 'json'], mockEnv())
    );
    expect(value).toBe(0);
    const result = JSON.parse(stdout) as Record<string, unknown>;
    expect(result).toMatchObject({
      scanId: 'scan-0123456789',
      scanStatus: 'completed',
      exitCode: 0,
      counts: { high: 1 },
      kind: 'full',
      runtime: 'native',
      scannedSha: head,
    });
    expect(typeof result['scanDir']).toBe('string');
    // What a knowledge base gave the scan, a full scan's or a diff's in one field: a mock builds
    // none, so both fields are null.
    expect(result).toMatchObject({ knowledgeBase: null, diffThreatModel: null });
    expect(result).not.toHaveProperty('diffKnowledgeBase');
    // Progress went to stderr, not stdout.
    expect(stderr).toContain('cynos accepted the key');

    // The config the engine got: no key for a mock, never publishing, and a scan history of its
    // own in the run dir, so its synthetic findings never reach the repository's.
    expect(seen.config).toMatchObject({
      runtime: 'native',
      stateDir: join(seen.config!.stage, 'mock-state'),
      interactive: false,
      publishes: false,
      kind: 'full',
      mock: true,
      scannedSha: head,
      assets: '/assets',
      judge: true,
      taskRouting: true,
    });
    expect(seen.config?.cynosKey).toBeUndefined();
    expect(seen.config?.promptAddendum).toBeUndefined();
    expect(seen.config?.hostPaths).toBeUndefined();
    expect(result).toMatchObject({
      judge: true,
      routing: true,
      timeout: null,
      scanPromptFile: null,
      stopped: null,
    });
    expect(seen.config?.stage.startsWith(join(stateDir, 'averlon', 'scans', 'cynos-scan-'))).toBe(
      true
    );

    // The run dir keeps its run name, so every path into it stays good: the result's SARIF and
    // run dir are where the scan wrote them.
    expect(result['runDir']).toBe(seen.config?.stage);
    expect(existsSync(String(result['sarif']))).toBe(true);
    // The scan id is a link to it, with the CLI's log, events, timings and result in it.
    const byId = join(stateDir, 'averlon', 'scans', 'scan-0123456789');
    expect(lstatSync(byId).isSymbolicLink()).toBe(true);
    expect(realpathSync(byId)).toBe(realpathSync(String(seen.config?.stage)));
    for (const file of ['cli.log', 'events.jsonl', 'timings.json', 'cli-result.json'])
      expect(existsSync(join(byId, file))).toBe(true);
    expect(readFileSync(join(byId, 'cli.log'), 'utf8')).toContain('a log line');
  });

  test('a scan that calls the model without a cynos key fails before the engine, as JSON', async () => {
    const { project } = fixture();
    const seen = fakeScan(mkdtempSync(join(tmpdir(), 'cynos-scan-state-')));
    const { value, stdout } = await captureOutput(() =>
      run(['scan', project, '--headless', '--format', 'json'], baseEnv())
    );
    expect(value).toBe(2);
    expect(JSON.parse(stdout)).toMatchObject({
      scanId: null,
      scanStatus: 'failed',
      exitCode: 2,
      error: { kind: 'auth' },
    });
    expect(seen.config).toBeUndefined();
  });

  test('a mock scan is not a scan option: --mock is refused, and only CYNOS_SCAN_MOCK=1 asks for one', async () => {
    const { project } = fixture();
    const seen = fakeScan(mkdtempSync(join(tmpdir(), 'cynos-scan-state-')));
    const flag = await captureOutput(() =>
      run(['scan', project, '--mock', '--headless'], baseEnv())
    );
    expect(flag.value).toBe(2);
    expect(flag.stderr).toContain("unknown option '--mock'");
    // Any other value is not a mock scan, so it calls the model and needs the key.
    const other = await captureOutput(() =>
      run(['scan', project, '--headless', '--format', 'json'], {
        ...baseEnv(),
        CYNOS_SCAN_MOCK: 'true',
      })
    );
    expect(JSON.parse(other.stdout)).toMatchObject({ error: { kind: 'auth' } });
    expect(seen.config).toBeUndefined();
  });

  test('a full scan builds its knowledge base with the cynos key alone', async () => {
    const { project } = fixture();
    const seen = fakeScan(mkdtempSync(join(tmpdir(), 'cynos-scan-state-')));
    const key = 'cynos-0123456789abcdef';
    const env = { ...baseEnv(), CYNOS_API_KEY: key };
    const { value, stdout, stderr } = await captureOutput(() =>
      run(['scan', project, '--headless', '--format', 'json'], env)
    );
    expect(value).toBe(0);
    expect(seen.config).toMatchObject({
      kind: 'full',
      cynosKey: key,
      buildKnowledgeBase: true,
      // A real scan goes into the repository's history, upstream's own state dir.
      stateDir: 'upstream-default',
    });
    expect(stdout + stderr).not.toContain(key);
  });

  test('--no-knowledge-base scans with the cynos key alone; the key is never printed', async () => {
    const { project } = fixture();
    const seen = fakeScan(mkdtempSync(join(tmpdir(), 'cynos-scan-state-')));
    const key = 'cynos-0123456789abcdef';
    const env = { ...baseEnv(), CYNOS_API_KEY: key };
    const { value, stdout, stderr } = await captureOutput(() =>
      run(['scan', project, '--no-knowledge-base', '--headless', '--format', 'json'], env)
    );
    expect(value).toBe(0);
    expect(seen.config).toMatchObject({ cynosKey: key, buildKnowledgeBase: false });
    expect(stdout + stderr).not.toContain(key);
  });

  test('--diff resolves the revision; --diff HEAD is refused', async () => {
    const { project, head } = fixture();
    fakeScan(mkdtempSync(join(tmpdir(), 'cynos-scan-state-')));
    const { value, stderr } = await captureOutput(() =>
      run(['scan', project, '--diff', 'HEAD', '--headless'], mockEnv())
    );
    expect(value).toBe(2);
    expect(stderr).toContain('HEAD itself');
    const missing = await captureOutput(() =>
      run(['scan', project, '--diff', 'no-such-rev', '--headless'], mockEnv())
    );
    expect(missing.value).toBe(2);
    expect(missing.stderr).toContain('not a commit');
    expect(head).toHaveLength(40);
  });
});

describe('scan options for a harness: prompt addendum, cynos switches, time limit, Docker host', () => {
  test('--scan-prompt-file, --no-judge, --no-routing, --timeout and --host-path reach the engine', async () => {
    const { project } = fixture();
    const seen = fakeScan(mkdtempSync(join(tmpdir(), 'cynos-scan-state-')));
    const addendum = join(mkdtempSync(join(tmpdir(), 'cynos-scan-prompt-')), 'addendum.md');
    writeFileSync(addendum, '## Benchmark rules\n');
    const { value, stdout } = await captureOutput(() =>
      run(
        [
          'scan',
          project,
          '--runtime',
          'docker',
          '--headless',
          '--format',
          'json',
          '--scan-prompt-file',
          addendum,
          '--no-judge',
          '--no-routing',
          '--timeout',
          '2h',
          '--host-path',
          '/srv/out=/out/',
          '--host-path',
          '/stage=/host/stage',
        ],
        mockEnv()
      )
    );
    expect(value).toBe(0);
    expect(seen.config).toMatchObject({
      runtime: 'docker',
      promptAddendum: '## Benchmark rules\n',
      judge: false,
      taskRouting: false,
      hostPaths: [
        ['/srv/out', '/out'],
        ['/stage', '/host/stage'],
      ],
    });
    expect(JSON.parse(stdout)).toMatchObject({
      judge: false,
      routing: false,
      timeout: 7200,
      scanPromptFile: addendum,
      stopped: null,
    });
  });

  test('--rubric and --false-positives reach the engine and the json result', async () => {
    const { project } = fixture();
    const seen = fakeScan(mkdtempSync(join(tmpdir(), 'cynos-scan-state-')));
    const inputs = mkdtempSync(join(tmpdir(), 'cynos-scan-inputs-'));
    const rubric = join(inputs, 'severity.md');
    writeFileSync(rubric, '# Our rubric\n');
    const dismissed = join(inputs, 'dismissed.json');
    writeFileSync(
      dismissed,
      JSON.stringify([{ title: 'T', locations: [{ path: 'a.py' }], reason: 'internal only' }])
    );
    const { value, stdout } = await captureOutput(() =>
      run(
        [
          'scan',
          project,
          '--headless',
          '--format',
          'json',
          '--rubric',
          rubric,
          '--false-positives',
          dismissed,
        ],
        mockEnv()
      )
    );
    expect(value).toBe(0);
    expect(seen.config).toMatchObject({
      rubricFile: rubric,
      falsePositivesFile: dismissed,
    });
    expect(JSON.parse(stdout)).toMatchObject({
      rubric: { file: rubric, sha256: expect.stringMatching(/^[0-9a-f]{64}$/) },
      falsePositives: { file: dismissed, count: 1 },
    });
  });

  test('a scan without them passes none to the engine', async () => {
    const { project } = fixture();
    const seen = fakeScan(mkdtempSync(join(tmpdir(), 'cynos-scan-state-')));
    const { stdout } = await captureOutput(() =>
      run(['scan', project, '--headless', '--format', 'json'], mockEnv())
    );
    expect(seen.config?.rubricFile).toBeUndefined();
    expect(seen.config?.falsePositivesFile).toBeUndefined();
    expect(JSON.parse(stdout)).toMatchObject({ rubric: null, falsePositives: null });
  });

  test('what cannot apply is refused before the engine starts', async () => {
    const { project } = fixture();
    const seen = fakeScan(mkdtempSync(join(tmpdir(), 'cynos-scan-state-')));
    const empty = join(mkdtempSync(join(tmpdir(), 'cynos-scan-prompt-')), 'empty.md');
    writeFileSync(empty, '\n');
    const reasonless = join(mkdtempSync(join(tmpdir(), 'cynos-scan-inputs-')), 'fp.json');
    writeFileSync(reasonless, JSON.stringify([{ title: 'T', locations: [{ path: 'a.py' }] }]));
    const refusals: [string[], string][] = [
      [['--runtime', 'native', '--host-path', '/a=/b'], 'needs --runtime docker'],
      [['--runtime', 'docker', '--host-path', 'a=/b'], '/path/here=/path/on/host'],
      [['--scan-prompt-file', join(project, 'missing.md')], 'not a readable file'],
      [['--scan-prompt-file', empty], 'is empty'],
      [['--timeout', '0'], '--timeout takes'],
      [['--effort', 'bogus'], 'Allowed choices are none, minimal, low, medium, high, xhigh, max'],
      [['--rubric', join(project, 'missing.md')], 'not a readable file'],
      [['--rubric', empty], 'is empty'],
      [['--false-positives', empty], 'is not JSON'],
      [['--false-positives', reasonless], 'needs a reason'],
    ];
    for (const [args, message] of refusals) {
      const { value, stderr } = await captureOutput(() =>
        run(['scan', project, '--headless', ...args], mockEnv())
      );
      expect(value).toBe(2);
      expect(stderr).toContain(message);
    }
    expect(seen.config).toBeUndefined();
  });

  test('--timeout stops the run, kills every container it may have started, and exits 2', async () => {
    const { project } = fixture();
    const stateDir = mkdtempSync(join(tmpdir(), 'cynos-scan-state-'));
    const killed: string[] = [];
    setEngine({
      ...ENGINE_CONSTANTS,
      resolveStateDir: () => stateDir,
      killContainer: (name: string) => killed.push(name),
      // The engine names the run's containers, then scans until the signal stops it.
      scanCheckout: async (config: ScanConfig, io: ScanIO): Promise<ScanResult> => {
        io.containers?.([`${config.runName}-knowledge-base`, config.runName]);
        await new Promise(done => io.signal?.addEventListener('abort', done));
        return {
          scanId: null,
          scanDir: null,
          exitCode: 130,
          outcome: {
            scanStatus: 'failed',
            policyStatus: 'failed',
            reason: String(io.signal?.reason),
            skipReason: '',
          },
          counts: undefined,
          sarif: '',
          knowledgeBase: undefined,
          diffThreatModel: undefined,
          usage: {
            input_tokens: 0,
            cached_input_tokens: 0,
            output_tokens: 0,
            reasoning_output_tokens: 0,
          },
          seconds: 1,
          cost: { scan_usd: null, knowledge_base_usd: null },
          versions: {},
        };
      },
    });
    const { value, stdout, stderr } = await captureOutput(() =>
      run(
        [
          'scan',
          project,
          '--runtime',
          'docker',
          '--headless',
          '--format',
          'json',
          '--timeout',
          '1s',
        ],
        mockEnv()
      )
    );
    expect(value).toBe(2);
    // run() reads a finished scan's code from process.exitCode; left at 2, it would be bun's own.
    process.exitCode = 0;
    const result = JSON.parse(stdout) as Record<string, unknown>;
    expect(result).toMatchObject({
      scanStatus: 'failed',
      exitCode: 2,
      timeout: 1,
      stopped: 'timed out after 1s',
    });
    const runName = basename(String(result['runDir']));
    expect(killed).toEqual([`${runName}-knowledge-base`, runName]);
    expect(stderr).toContain('--timeout 1s');
  });

  test('a run --timeout cuts short in a step that then fails is reported as timed out', async () => {
    const { project } = fixture();
    const stateDir = mkdtempSync(join(tmpdir(), 'cynos-scan-state-'));
    setEngine({
      ...ENGINE_CONSTANTS,
      resolveStateDir: () => stateDir,
      killContainer: () => {},
      // The stop kills the code graph's container, so the knowledge base fails with its own error.
      scanCheckout: async (config: ScanConfig, io: ScanIO): Promise<ScanResult> => {
        io.containers?.([`${config.runName}-knowledge-base`]);
        await new Promise(done => io.signal?.addEventListener('abort', done));
        throw new Error(
          'The knowledge base could not be built, so no scan was started: graph exited'
        );
      },
    });
    const { value, stdout } = await captureOutput(() =>
      run(
        ['scan', project, '--runtime', 'docker', '--headless', '--format', 'json'].concat([
          '--timeout',
          '1s',
        ]),
        mockEnv()
      )
    );
    expect(value).toBe(2);
    expect(JSON.parse(stdout)).toMatchObject({
      scanStatus: 'failed',
      exitCode: 2,
      stopped: 'timed out after 1s',
      error: {
        kind: 'timed-out',
        message:
          'The scan was stopped: timed out after 1s. The knowledge base could not be built, so no scan was started: graph exited',
      },
    });
  });
});

describe('scan helpers', () => {
  const tty = {
    stdinTTY: true,
    stderrTTY: true,
    headless: false,
    verbose: false,
    ci: false,
    format: 'pretty' as const,
  };

  test('interactive only at a terminal, without --headless, --verbose, CI or JSON', () => {
    expect(interactiveScan(tty)).toBe(true);
    expect(interactiveScan({ ...tty, stdinTTY: false })).toBe(false);
    expect(interactiveScan({ ...tty, stderrTTY: false })).toBe(false);
    expect(interactiveScan({ ...tty, headless: true })).toBe(false);
    expect(interactiveScan({ ...tty, verbose: true })).toBe(false);
    expect(interactiveScan({ ...tty, ci: true })).toBe(false);
    expect(interactiveScan({ ...tty, format: 'json' })).toBe(false);
    expect(interactiveScan({ ...tty, format: 'jsonl' })).toBe(false);
  });

  test('--max-time takes hours or a duration', () => {
    expect(parseMaxTime('2')).toBe(2);
    expect(parseMaxTime('90m')).toBe(1.5);
    expect(parseMaxTime('3h')).toBe(3);
    expect(parseMaxTime(undefined)).toBeUndefined();
    expect(() => parseMaxTime('100h')).toThrow(/96h/);
    expect(() => parseMaxTime('soon')).toThrow();
    // Seconds are --timeout's alone.
    expect(() => parseMaxTime('90s')).toThrow(/--max-time/);
  });

  test('--timeout takes hours or a duration, in whole seconds, up to 96h', () => {
    expect(parseTimeout('2')).toBe(7200);
    expect(parseTimeout('90m')).toBe(5400);
    expect(parseTimeout('45s')).toBe(45);
    expect(parseTimeout(undefined)).toBeUndefined();
    expect(() => parseTimeout('0')).toThrow(/--timeout/);
    expect(() => parseTimeout('97h')).toThrow(/96h/);
    expect(() => parseTimeout('soon')).toThrow();
  });

  test('--host-path takes absolute HERE=HOST pairs, without trailing slashes', () => {
    expect(parseHostPaths(['/srv/out/=/out'])).toEqual([['/srv/out', '/out']]);
    // The root stays the root: `/out=/` must not become an empty host path.
    expect(parseHostPaths(['/out=/', '/=/host/'])).toEqual([
      ['/out', '/'],
      ['/', '/host'],
    ]);
    expect(() => parseHostPaths(['/a'])).toThrow(/here=/);
    expect(() => parseHostPaths(['/a=/b=/c'])).toThrow(/here=/);
    expect(() => parseHostPaths(['relative=/b'])).toThrow(/here=/);
  });

  test('CYNOS_SCAN_HYPOTHESES takes a whole number of hypothesis packets, else the engine default', () => {
    expect(maxHypothesisPackets({ CYNOS_SCAN_HYPOTHESES: '0' })).toBe(0);
    expect(maxHypothesisPackets({ CYNOS_SCAN_HYPOTHESES: '6' })).toBe(6);
    expect(maxHypothesisPackets({})).toBeUndefined();
    expect(() => maxHypothesisPackets({ CYNOS_SCAN_HYPOTHESES: '1.5' })).toThrow(
      /CYNOS_SCAN_HYPOTHESES/
    );
  });

  test('run names sort by time and are valid container names', () => {
    expect(newRunName(new Date('2026-10-27T11:22:33Z'))).toMatch(
      /^cynos-scan-20261027112233-[0-9a-f]{6}$/
    );
  });

  test('the scan-id link refuses a path-like id and a missing run dir', () => {
    const root = mkdtempSync(join(tmpdir(), 'cynos-scan-runs-'));
    mkdirSync(join(root, 'cynos-scan-run'));
    linkScanId(join(root, 'cynos-scan-run'), '../escape');
    linkScanId(join(root, 'cynos-scan-run'), null);
    linkScanId(join(root, 'missing'), 'scan-1');
    expect(readdirSync(root)).toEqual(['cynos-scan-run']);
  });
});
