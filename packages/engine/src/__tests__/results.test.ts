import { describe, it, expect } from 'bun:test';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { dockerEnvironment } from '../runtime/docker';
import { filesContaining } from '../pipeline';
import { classify, cliEstimatedCost, decide, severityCounts } from '../results';
import { exitCodeOf, sessionUsage } from '../scan-run';

const HEAD = 'c'.repeat(40);

describe('token usage', () => {
  it("sums each thread's last running total", () => {
    const state = mkdtempSync(join(tmpdir(), 'cs-state-'));
    const sessions = join(state, 'codex-home', 'sessions', '2026', '10', '14');
    mkdirSync(sessions, { recursive: true });
    const line = (input: number, cached: number, output: number) =>
      JSON.stringify({
        payload: {
          type: 'token_count',
          info: {
            total_token_usage: {
              input_tokens: input,
              cached_input_tokens: cached,
              output_tokens: output,
            },
          },
        },
      });
    writeFileSync(
      join(sessions, 'rollout-root.jsonl'),
      [line(100, 50, 10), '{"type":"other"}', line(1000, 600, 80)].join('\n')
    );
    writeFileSync(join(sessions, 'rollout-worker.jsonl'), `${line(500, 100, 20)}\nnot json\n`);
    expect(sessionUsage(state)).toMatchObject({
      input_tokens: 1500,
      cached_input_tokens: 700,
      output_tokens: 100,
    });
    expect(sessionUsage(join(state, 'empty')).input_tokens).toBe(0);
  });

  it("reports the CLI's own cost estimate, and none when the CLI does not price the model", () => {
    expect(cliEstimatedCost({ cost: { estimatedUsd: 1.53 } })).toBe(1.53);
    expect(cliEstimatedCost({ cost: { estimatedUsd: null } })).toBeUndefined();
    expect(cliEstimatedCost({})).toBeUndefined();
  });
});

describe("upstream's exit code", () => {
  it('is its own code, or 128 plus the signal that killed it', () => {
    expect(exitCodeOf(0, null)).toBe(0);
    expect(exitCodeOf(2, null)).toBe(2);
    // upstream's second Ctrl-C kills it: Node reports no code, only the signal.
    expect(exitCodeOf(null, 'SIGINT')).toBe(130);
    expect(exitCodeOf(null, 'SIGTERM')).toBe(143);
    expect(exitCodeOf(null, null)).toBeNull();
  });
});

describe('classify', () => {
  // upstream's --json result as the pin prints it: the manifest's status is the scan's, and the
  // review summary lists the excluded paths, not whether everything was covered.
  const result = (status: string, extra: Record<string, unknown> = {}) => ({
    manifest: { scan: { status, target: { kind: 'git_revision', revision: HEAD } } },
    review: { excludedPaths: [] },
    ...extra,
  });
  const NO_FINDINGS = 'no findings.json';
  const UNSAFE = 'A finding has an unsafe source location for GitHub annotations.';
  const exit = (exitCode: number | null, stopStatus: '' | 'cancelled' = '', stopReason = '') => ({
    exitCode,
    stopStatus,
    stopReason,
  });

  it.each([
    ['exit 0, completed', exit(0), result('completed'), '', 'completed', 'passed'],
    ['exit 1 from fail-on-severity', exit(1), result('completed'), '', 'completed', 'failed'],
    ['no findings.json', exit(0), result('completed'), NO_FINDINGS, 'failed', 'not-evaluated'],
    ['unsafe locations', exit(0), result('completed'), UNSAFE, 'failed', 'not-evaluated'],
    ['a scan upstream stopped short', exit(2), result('partial'), '', 'failed', 'not-evaluated'],
    ['a completed manifest, exit 2', exit(2), result('completed'), '', 'failed', 'not-evaluated'],
    [
      'a target warning',
      exit(0),
      result('completed', { warnings: ['target changed'] }),
      '',
      'failed',
      'not-evaluated',
    ],
    [
      'a cancelled job',
      exit(137, 'cancelled', 'job cancelled (SIGTERM)'),
      {},
      NO_FINDINGS,
      'failed',
      'not-evaluated',
    ],
  ] as const)('%s -> scan %s', (_, container, cli, findings, scan, policy) => {
    const outcome = classify(container, cli as Record<string, unknown>, findings, '', HEAD, false);
    expect([outcome.scanStatus, outcome.policyStatus]).toEqual([scan, policy]);
  });

  it('says that a scan upstream stopped short kept its available results', () => {
    expect(classify(exit(2), result('partial'), '', '', HEAD, false).reason).toBe(
      'scan partial (exit 2): available results were kept'
    );
  });

  it('refuses a scan of another revision', () => {
    const other = {
      ...result('completed'),
      manifest: {
        scan: { status: 'completed', target: { kind: 'git_revision', revision: 'f'.repeat(40) } },
      },
    };
    expect(classify(exit(0), other, '', '', HEAD, false).reason).toContain(
      'does not match the requested checkout commit'
    );
  });

  it('reads the diff head of a diff scan', () => {
    const diff = {
      ...result('completed'),
      manifest: { scan: { status: 'completed', target: { kind: 'git_diff', headRevision: HEAD } } },
    };
    expect(classify(exit(0), diff, '', '', HEAD, false).scanStatus).toBe('completed');
  });

  it("names a rejected save and the CLI's own failure message", () => {
    const stderr = 'debug: x\nCould not save the Codex Security scan: draft is incomplete\n';
    expect(classify(exit(2), {}, NO_FINDINGS, stderr, HEAD, false).reason).toBe(
      'save rejected: draft is incomplete'
    );
    expect(
      classify(
        exit(2),
        {
          status: 'failed',
          message: 'The API key from CODEX_API_KEY cannot access the configured model.',
        },
        NO_FINDINGS,
        '',
        HEAD,
        false
      ).reason
    ).toContain('cannot access the configured model');
  });

  it('skips a validated dry run', () => {
    expect(classify(exit(0), {}, NO_FINDINGS, '', HEAD, true)).toMatchObject({
      scanStatus: 'skipped',
      skipReason: 'dry-run',
    });
  });

  it('counts findings by severity', () => {
    expect(
      severityCounts({
        findings: [{ severity: { level: 'High' } }, { severity: { level: 'low' } }, {}],
      })
    ).toEqual({
      critical: 0,
      high: 1,
      medium: 0,
      low: 1,
      informational: 0,
    });
  });
});

describe('decide', () => {
  const options = {
    sarifReady: true,
    leakClean: true,
    publishable: true,
    failOnSeverity: 'none',
    requiredReports: true,
  };
  const outcome = (
    scanStatus: 'completed' | 'failed' | 'skipped',
    policyStatus: 'passed' | 'failed' | 'not-evaluated' = 'not-evaluated'
  ) => ({ scanStatus, policyStatus, reason: 'r' });

  it.each([
    ['a passing scan', outcome('completed', 'passed'), options, 'ready', true, true],
    [
      'a scan whose findings fail the policy',
      outcome('completed', 'failed'),
      options,
      'ready',
      true,
      false,
    ],
    [
      'a scan with no SARIF',
      outcome('completed', 'passed'),
      { ...options, sarifReady: false },
      'partial',
      false,
      true,
    ],
    [
      'a scan of an unpublishable ref',
      outcome('completed', 'passed'),
      { ...options, publishable: false },
      'ready',
      false,
      true,
    ],
    [
      'a scan missing a required report',
      outcome('completed', 'passed'),
      { ...options, requiredReports: false },
      'failed',
      false,
      false,
    ],
    [
      'a scan whose outputs hold the key',
      outcome('completed', 'passed'),
      { ...options, leakClean: false },
      'failed',
      false,
      false,
    ],
    ['a failed scan', outcome('failed'), options, 'failed', false, false],
    ['a skipped scan', outcome('skipped'), options, 'ready', false, true],
  ] as const)(
    '%s -> report %s, SARIF upload-ready %s, success %s',
    (_, scan, opts, report, uploadReady, success) => {
      expect(decide(scan, opts)).toMatchObject({
        reportStatus: report,
        sarifUploadReady: uploadReady,
        success,
      });
    }
  );
});

describe('the scanner environment and the leak check', () => {
  it('passes Docker only what it needs, and the key only when asked', () => {
    process.env['UNRELATED_SECRET'] = 'x';
    expect(dockerEnvironment()).not.toHaveProperty('UNRELATED_SECRET');
    expect(dockerEnvironment()).not.toHaveProperty('CYNOS_API_KEY');
    expect(dockerEnvironment('sk-test')['CYNOS_API_KEY']).toBe('sk-test');
    delete process.env['UNRELATED_SECRET'];
  });

  it('finds the key anywhere in the stage, but not in Codex state', () => {
    const stage = mkdtempSync(join(tmpdir(), 'cs-stage-'));
    const put = (path: string, text: string): void => {
      mkdirSync(join(stage, path, '..'), { recursive: true });
      writeFileSync(join(stage, path), text);
    };
    put('out/scan/report.md', 'clean');
    put('stderr.log', 'leaked sk-test');
    put('reports/findings.json', '{"summary": "sk-test"}');
    // What the action uploads as evidence: the knowledge base and the review agent's log.
    put('knowledge-base/kb/packets/auth.md', 'brief sk-test');
    put('knowledge-base/review/events.jsonl', '{"output": "sk-test"}');
    // Codex's state: the scan's, the preflight's and the review agent's home.
    put('state/rollout.jsonl', 'sk-test');
    put('preflight/state/rollout.jsonl', 'sk-test');
    put('knowledge-base/review/home/sessions/s.jsonl', 'sk-test');
    expect(filesContaining(stage, 'sk-test').sort()).toEqual(
      [
        'knowledge-base/kb/packets/auth.md',
        'knowledge-base/review/events.jsonl',
        'reports/findings.json',
        'stderr.log',
      ].map(path => join(stage, path))
    );
  });

  it('finds the key in a knowledge-base cache directory, whose files sit at its top', () => {
    const cache = mkdtempSync(join(tmpdir(), 'cs-cache-'));
    writeFileSync(join(cache, 'jev-answers.jsonl'), '{"answer": "sk-test"}');
    writeFileSync(join(cache, 'review.json'), '{}');
    expect(filesContaining(cache, 'sk-test')).toEqual([join(cache, 'jev-answers.jsonl')]);
  });
});
