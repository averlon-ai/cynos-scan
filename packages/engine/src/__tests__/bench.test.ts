import { describe, it, expect } from 'bun:test';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  benchMain,
  benchScan,
  parseHostPaths,
  parsePrice,
  parseScanArgs,
  priced,
  resultStatus,
  runCost,
  scrubKeys,
  takeKey,
} from '../bench/cli';

const ASSETS = resolve(import.meta.dir, '../../assets');

/** Every file under directory. */
function files(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry =>
    entry.isDirectory()
      ? files(join(directory, entry.name))
      : entry.isFile()
        ? [join(directory, entry.name)]
        : []
  );
}

describe('bench scan arguments', () => {
  it("defaults like the action: xhigh, the action's model, judge and routing on, no limit", () => {
    const args = parseScanArgs(
      ['--project', 'p', '--out', 'o', '--name', 'rv-1'],
      '/a/dist/bench.js'
    );
    expect(args).toMatchObject({
      name: 'rv-1',
      model: 'deepseek/deepseek-v4-pro-0813',
      effort: 'xhigh',
      judge: true,
      routing: true,
      timeoutSeconds: 0,
      hostPaths: [],
      apparmor: false,
      assets: '/a/dist/assets',
    });
    expect(args.project).toBe(resolve('p'));
  });

  it('takes the gateway, its switches, a time limit, host paths and a price', () => {
    const args = parseScanArgs([
      ...['--project', 'p', '--out', 'o', '--name', 'rv-1'],
      ...['--base-url', 'https://gw.example/openai/v1/', '--judge', 'off', '--routing', 'off'],
      ...['--timeout', '3600', '--host-path', '/srv/out=/data/out/', '--price', '0.28,0.028,0.42'],
    ]);
    expect(args).toMatchObject({
      baseUrl: 'https://gw.example/openai/v1',
      judge: false,
      routing: false,
      timeoutSeconds: 3600,
      hostPaths: [['/srv/out', '/data/out']],
      price: [0.28, 0.028, 0.42],
    });
  });

  it('refuses what it cannot use', () => {
    const base = ['--project', 'p', '--out', 'o', '--name', 'rv-1'];
    expect(() => parseScanArgs(['--project', 'p', '--out', 'o'])).toThrow('--name is required');
    expect(() => parseScanArgs([...base.slice(0, 5), 'bad name'])).toThrow('container name');
    expect(() => parseScanArgs([...base, '--judge', 'maybe'])).toThrow('on or off');
    expect(() => parseScanArgs([...base, '--timeout', '1.5'])).toThrow('whole seconds');
    expect(() => parseScanArgs([...base, '--base-url', 'file:///x'])).toThrow('http(s) URL');
    expect(() => parseHostPaths(['relative=/x'])).toThrow('--host-path');
    expect(parseHostPaths(['/out/=/', '/=/host/'])).toEqual([
      ['/out', '/'],
      ['/', '/host'],
    ]);
    expect(() => parsePrice('1,2')).toThrow('--price');
  });
});

describe('bench keys', () => {
  it('reads a key from the environment and removes it there', () => {
    const env: NodeJS.ProcessEnv = { CYNOS_API_KEY: 'sk-x' };
    expect(takeKey('CYNOS_API_KEY', env)).toBe('sk-x');
    expect(env).not.toHaveProperty('CYNOS_API_KEY');
    expect(takeKey('CYNOS_API_KEY', env)).toBeUndefined();
    expect(() => takeKey('K', { K: 'a\nb' })).toThrow('line break');
  });

  it('replaces every key value under the output, Codex state included, and lists the files', () => {
    const out = mkdtempSync(join(tmpdir(), 'bench-scrub-'));
    mkdirSync(join(out, 'state', 'sessions'), { recursive: true });
    writeFileSync(join(out, 'state', 'sessions', 'rollout-1.jsonl'), 'env: sk-secret or-secret\n');
    writeFileSync(join(out, 'clean.txt'), 'nothing here');
    expect(scrubKeys(out, ['sk-secret', 'or-secret', undefined])).toEqual([
      join(out, 'state', 'sessions', 'rollout-1.jsonl'),
    ]);
    expect(readFileSync(join(out, 'state', 'sessions', 'rollout-1.jsonl'), 'utf8')).toBe(
      'env: *** ***\n'
    );
    expect(readFileSync(join(out, 'clean.txt'), 'utf8')).toBe('nothing here');
  });
});

describe('bench cost', () => {
  const usage = {
    input_tokens: 1_000_000,
    cached_input_tokens: 800_000,
    output_tokens: 100_000,
    reasoning_output_tokens: 0,
  };
  const knowledgeBase = {
    cost_usd: 0.05,
    architecture_review: {
      agent: { inputTokens: 200_000, cachedInputTokens: 100_000, outputTokens: 10_000 },
    },
  } as never;

  it('prices uncached input, cached input and output separately', () => {
    expect(
      priced({ input: 1_000_000, cached: 800_000, output: 100_000 }, [0.28, 0.028, 0.42])
    ).toBe(0.1204);
  });

  it("adds the scan, the review agent and Jev's labels, and says how the scan is known", () => {
    const scan = { cost: { scan_usd: null, knowledge_base_usd: 0.05 }, usage, knowledgeBase };
    expect(runCost(scan, [0.28, 0.028, 0.42])).toEqual({
      scan_usd: 0.1204,
      scan_source: 'tokens-x-price',
      review_agent_usd: 0.035,
      jev_usd: 0.05,
      total_usd: 0.2054,
    });
    expect(
      runCost({ ...scan, cost: { scan_usd: 1, knowledge_base_usd: 0.05 } }, undefined)
    ).toMatchObject({
      scan_usd: 1,
      scan_source: 'cli-estimate',
      review_agent_usd: null,
      total_usd: null,
    });
  });
});

describe('bench CLI', () => {
  it('exits 2 with the usage on a bad command', async () => {
    expect(await benchMain(['nope'])).toBe(2);
    expect(await benchMain(['scan', '--project', 'p'])).toBe(2);
  });

  it('writes result.json without the keys when the scan cannot start', async () => {
    const root = mkdtempSync(join(tmpdir(), 'bench-run-'));
    const project = join(root, 'project');
    mkdirSync(project);
    writeFileSync(join(project, 'app.py'), 'print(1)\n');
    for (const args of [
      ['init', '-q'],
      ['add', '-A'],
      ['commit', '-q', '-m', 's'],
    ])
      spawnSync('git', ['-C', project, '-c', 'user.name=t', '-c', 'user.email=t@t', ...args]);
    // A Docker that fails every command, and prints the key it would have been given.
    const bin = join(root, 'bin');
    mkdirSync(bin);
    writeFileSync(
      join(bin, 'docker'),
      '#!/bin/sh\necho "no daemon ${CYNOS_API_KEY}" >&2\nexit 1\n'
    );
    chmodSync(join(bin, 'docker'), 0o755);
    const path = process.env['PATH'];
    process.env['PATH'] = `${bin}:${path}`;
    // The cynos key alone: the knowledge base's calls go through cynos too.
    process.env['CYNOS_API_KEY'] = 'sk-bench-test';
    const lines: string[] = [];
    try {
      const out = join(root, 'out');
      const code = await benchScan(
        parseScanArgs([
          '--project',
          project,
          '--out',
          out,
          '--name',
          'rv-test',
          '--assets',
          ASSETS,
        ]),
        line => lines.push(line)
      );
      expect(code).toBe(0);
      const raw = readFileSync(join(out, 'result.json'), 'utf8');
      const result = JSON.parse(raw);
      expect(result.status).toBe('error');
      expect(result.error).toContain('versions.sh failed');
      expect(result.findings).toBeNull();
      for (const file of files(out))
        expect(readFileSync(file, 'utf8')).not.toContain('sk-bench-test');
      expect(lines.join('\n')).not.toContain('sk-bench-test');
      expect(process.env['CYNOS_API_KEY']).toBeUndefined();
    } finally {
      process.env['PATH'] = path;
    }
  });

  it('refuses an output directory that already holds a run', async () => {
    const out = mkdtempSync(join(tmpdir(), 'bench-out-'));
    writeFileSync(join(out, 'result.json'), '{}');
    process.env['CYNOS_API_KEY'] = 'k';
    expect(await benchMain(['scan', '--project', out, '--out', out, '--name', 'rv'])).toBe(2);
  });
});

describe('bench result status', () => {
  const outcome = (scanStatus: 'completed' | 'failed') =>
    ({ scanStatus, policyStatus: 'passed', reason: '', skipReason: '' }) as const;

  it('says stopped for a run its time limit cut short, though the scan calls that failed', () => {
    expect(resultStatus({ leaked: [], outcome: outcome('failed') }, true)).toBe('stopped');
    expect(resultStatus(undefined, true)).toBe('stopped');
    expect(resultStatus({ leaked: [], outcome: outcome('completed') }, true)).toBe('completed');
  });

  it('puts a key in the outputs before anything else, and error when there is no scan', () => {
    expect(resultStatus({ leaked: ['x'], outcome: outcome('completed') }, false)).toBe('key-leak');
    expect(resultStatus(undefined, false)).toBe('error');
    expect(resultStatus({ leaked: [], outcome: outcome('failed') }, false)).toBe('failed');
  });
});
