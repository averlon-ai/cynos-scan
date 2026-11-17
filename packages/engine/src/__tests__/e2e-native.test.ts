import { describe, it, expect } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { scanCheckout } from '../pipeline';
import type { ScanEvent } from '../progress';
import { upstreamCommand } from '../upstream';

/**
 * One real scan on the native runtime: upstream's --mock, through scanCheckout, on a fixture git
 * repository. It runs upstream and Codex's sandbox on this machine, so it is opt-in
 * (CYNOS_SCAN_E2E=1) and needs a Node in upstream's engines range first on PATH. Everything goes
 * under packages/engine/.e2e/ (git-ignored), outside /tmp, where Codex's sandbox fails on macOS.
 */
const E2E = process.env['CYNOS_SCAN_E2E'] === '1';
const ROOT = resolve(import.meta.dir, '../../.e2e');

describe.skipIf(!E2E)('a native mock scan', () => {
  it('runs upstream as upstream does, into its state dir and history', async () => {
    mkdirSync(ROOT, { recursive: true, mode: 0o700 });
    const run = mkdtempSync(join(ROOT, 'run-'));
    const project = join(run, 'repo');
    mkdirSync(project);
    writeFileSync(join(project, 'app.py'), 'def login(user):\n    return user\n');
    const git = (...args: string[]) =>
      spawnSync('git', ['-C', project, '-c', 'user.name=t', '-c', 'user.email=t@t', ...args], {
        encoding: 'utf8',
      });
    git('init', '-q');
    git('add', '.');
    git('commit', '-qm', 'init');
    const sha = git('rev-parse', 'HEAD').stdout.trim();
    const stateDir = join(run, 'state');
    const events: ScanEvent[] = [];
    const lines: string[] = [];

    const result = await scanCheckout(
      {
        kind: 'full',
        diffBase: '',
        project,
        stage: join(run, 'stage'),
        runtime: 'native',
        stateDir,
        interactive: false,
        publishes: false,
        runName: 'cs-e2e',
        scannedSha: sha,
        knowledgeBase: '',
        buildImage: false,
        loadAppArmor: false,
        paths: [],
        model: 'deepseek/deepseek-v4.1-flash',
        effort: 'xhigh',
        mode: 'standard',
        cyberAccessProgram: '',
        maxTimeHours: undefined,
        failOnSeverity: 'none',
        verbose: false,
        dryRun: false,
        mock: true,
        judge: true,
        taskRouting: true,
      },
      {
        log: line => lines.push(line),
        warn: line => lines.push(`warning: ${line}`),
        error: line => lines.push(`error: ${line}`),
        progress: event => events.push(event),
      }
    );
    writeFileSync(join(run, 'events.json'), JSON.stringify({ events, lines, result }, null, 1));

    expect(result.outcome).toMatchObject({ scanStatus: 'completed', policyStatus: 'passed' });
    expect(result.exitCode).toBe(0);
    expect(result.scanId).toMatch(/^[0-9a-f-]{36}$/);
    expect(result.scanDir.startsWith(join(stateDir, 'scans', 'repo', 'codex-security-repo-'))).toBe(
      true
    );
    expect(result.sarif).not.toBe('');
    expect(result.leaked).toEqual([]);
    expect(events.filter(e => e.type === 'phase').map(e => `${e.phase}:${e.status}`)).toEqual([
      'stage:start',
      'stage:end',
      'preflight:start',
      'preflight:end',
      'knowledge:skipped',
      'brief:start',
      'brief:end',
      'scan:start',
      'scan:end',
      'report:start',
      'report:end',
    ]);
    expect(events.find(e => e.type === 'outcome')).toMatchObject({
      scanStatus: 'completed',
      scanId: result.scanId,
      scanDir: result.scanDir,
    });
    // The preflight ran in full: Codex's sandbox, then the scan against a dead endpoint.
    expect(events.filter(e => e.type === 'step').map(e => e.type === 'step' && e.step)).toEqual([
      'sandbox',
      'preparation',
    ]);
    // upstream's own history lists the scan, as `codex-security scans list` shows it.
    const [node, ...args] = upstreamCommand(['scans', 'list', project, '--json']);
    const listed = spawnSync(node as string, args, {
      encoding: 'utf8',
      env: {
        PATH: process.env['PATH'],
        HOME: process.env['HOME'],
        CODEX_SECURITY_STATE_DIR: stateDir,
      },
    });
    expect(
      JSON.parse(listed.stdout).scans.map(
        (s: { scanDir?: string; id?: string }) => s.scanDir ?? s.id
      )
    ).toContain(result.scanDir);
    expect(existsSync(join(run, 'stage', 'reports', 'findings.json'))).toBe(true);
  }, 300_000);
});
