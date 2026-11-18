import { describe, it, expect } from 'bun:test';
import { spawnSync, type ChildProcess } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  cutInvalid,
  coreEvidence,
  evidenceCandidates,
  invalidCitations,
  normalise,
  packParts,
  printedLines,
  redactSecretLiterals,
  secretValues,
  wholeFiles,
  renderPack,
  reviewArchitecture,
  type Evidence,
  type ReviewInput,
} from '../knowledge-base/architecture';
import {
  agentEvents,
  answerJson,
  checklist,
  components,
  indexFiles,
  kbScript,
  linesRead,
  agentReview,
  type AgentInput,
  type AgentPlan,
} from '../knowledge-base/architecture-agent';
import { BASE_URL } from '../constants';
import type { ScanRuntime } from '../runtime';
import { CynosChat, type ReviewModel } from '../knowledge-base/cynos';
import { agentCommand, type DockerAgentPlan } from '../runtime/docker';
import type { FileRow } from '../knowledge-base/inventory';
import type { Answers } from '../knowledge-base/jev';

/** A review model for inputs the test never reviews. */
const unasked: ReviewModel = {
  chatJson: () => Promise.reject(new Error('the review model was not to be asked')),
};
const numbered = (n: number, prefix = 'line') =>
  Array.from({ length: n }, (_, i) => `${prefix} ${i + 1}`).join('\n');
const row = (path: string, text: string, kind = 'code'): FileRow => ({
  path,
  lines: text.split('\n').length,
  kind,
  reason: '',
  text,
});
const piece = (path: string, tokens: number): Evidence => ({ path, why: 'test', tokens });

describe('packParts', () => {
  it('keeps everything in one part when it fits', () => {
    const { parts, leftOut } = packParts([piece('README.md', 10)], [piece('src/a.ts', 20)], 100, 4);
    expect(parts).toHaveLength(1);
    expect(leftOut).toBe(0);
  });

  it('splits a large pack by component, shares the head, and leaves out what does not fit', () => {
    const shared = [piece('README.md', 10)];
    const component = [
      piece('core/a/x.ts', 40),
      piece('core/a/y.ts', 40),
      piece('ui/b/z.ts', 40),
      piece('ui/b/w.ts', 40),
      piece('more/c.ts', 40),
    ];
    const { parts, leftOut } = packParts(shared, component, 90, 2);
    expect(parts).toHaveLength(2);
    for (const part of parts) expect(part[0]?.path).toBe('README.md');
    const paths = parts.map(p =>
      p
        .slice(1)
        .map(e => e.path)
        .sort()
    );
    expect(paths).toContainEqual(['core/a/x.ts', 'core/a/y.ts']);
    expect(paths).toContainEqual(['ui/b/w.ts', 'ui/b/z.ts']);
    expect(leftOut).toBe(40);
  });
});

describe('citations', () => {
  const byPath = new Map([
    ['src/auth.ts', row('src/auth.ts', numbered(50))],
    ['src/big.ts', row('src/big.ts', numbered(500))],
  ]);
  const printed = printedLines(
    [
      { path: 'src/auth.ts', why: '', tokens: 1 },
      { path: 'src/big.ts', start: 100, end: 160, why: '', tokens: 1 },
    ],
    byPath
  );
  const review = () =>
    normalise({
      threatModel: {
        summary: 'Gateway (src/auth.ts:3)',
        trustBoundaries: [
          'Browser -> API: JWT (src/auth.ts:10-12), roles (src/big.ts:120)',
          'Admin (src/big.ts:20)',
        ],
        assumptions: ['Unknown file (src/nowhere.ts:4)'],
      },
      effectiveResources: [{ consumer: 'JWT key', evidence: 'src/auth.ts:99' }],
    });

  it('accepts only lines the pack printed', () => {
    const { invalid, total } = invalidCitations(review(), printed);
    expect(total).toBe(6);
    expect(invalid.sort()).toEqual(['src/auth.ts:99', 'src/big.ts:20', 'src/nowhere.ts:4']);
  });

  it('cuts an invalid citation to its file, or marks it unverified when the pack never showed the file', () => {
    const r = review();
    const { invalid } = invalidCitations(r, printed);
    expect(cutInvalid(r, invalid, printed)).toBe(3);
    expect(r.threatModel.trustBoundaries[1]).toBe('Admin (src/big.ts)');
    expect(r.threatModel.assumptions[0]).toBe('Unknown file ((unverified))');
    expect(r.effectiveResources[0]?.['evidence']).toBe('src/auth.ts');
    expect(invalidCitations(r, printed).invalid).toEqual([]);
  });

  it('renders the pack with each file numbered from its own lines', () => {
    const text = renderPack(
      [{ path: 'src/big.ts', start: 100, end: 101, why: '', tokens: 1 }],
      byPath
    );
    expect(text).toContain('==> src/big.ts (lines 100-101) <==');
    expect(text).toMatch(/\s+100\tline 100\n\s+101\tline 101/);
  });
});

const role = (r: string, p: number): Answers => ({
  architecture_role: { type: 'choice', choice: r, probabilities: { [r]: p } },
});

describe('evidence by architecture role', () => {
  const rows = [
    row('README.md', '# App', 'docs'),
    row('package.json', '{}', 'config'),
    row('Dockerfile', 'FROM node', 'other'),
    row('src/main.ts', numbered(20)),
    row('src/auth/guard.ts', numbered(20)),
    row('src/db/query.ts', numbered(20)),
    row('src/util/format.ts', numbered(20)),
    row('tests/README.md', 'x', 'test'),
  ];
  const input: ReviewInput = {
    rows,
    product: rows.filter(r => r.kind === 'code' || r.kind === 'config'),
    functions: [{ qn: 'db.query', name: 'query', path: 'src/db/query.ts', start: 2, end: 9 }],
    fileLabels: new Map(),
    functionLabels: new Map<string, Answers>([
      ['db.query', { sink: { type: 'choice', choice: 'database' } }],
    ]),
    roles: new Map([
      ['README.md', role('architecture_docs', 0.9)],
      ['package.json', role('none', 0.9)],
      ['Dockerfile', role('deployment', 0.8)],
      ['src/main.ts', role('startup', 0.95)],
      ['src/auth/guard.ts', role('access_control', 0.9)],
      ['src/db/query.ts', role('data_integrations', 0.7)],
      ['src/util/format.ts', role('none', 0.8)],
      ['tests/README.md', role('architecture_docs', 0.3)],
    ]),
    entryFiles: new Map(),
    cynos: unasked,
  };

  it('takes files by their role, not their name, and leaves out role none and weak answers', () => {
    const { shared, component } = evidenceCandidates(input);
    expect(shared.map(e => [e.path, e.why])).toEqual([
      ['Dockerfile', 'deployment'],
      ['README.md', 'architecture_docs'],
    ]);
    expect(component.map(e => [e.path, e.why])).toEqual([
      ['src/main.ts', 'startup'],
      ['src/auth/guard.ts', 'access_control'],
      ['src/db/query.ts', 'data_integrations'],
    ]);
  });

  it('fills the core role by role, code before documentation', () => {
    expect(coreEvidence(input).map(e => e.path)).toEqual([
      'src/main.ts',
      'src/auth/guard.ts',
      'src/db/query.ts',
      'Dockerfile',
      'README.md',
    ]);
  });
});

describe('reviewArchitecture', () => {
  it('reviews in one call, repairs invalid citations once, and reports its numbers', async () => {
    const rows = [row('README.md', 'An app', 'docs'), row('src/auth/guard.ts', numbered(30))];
    const replies = [
      {
        threatModel: { summary: 'App', trustBoundaries: ['Browser -> API (src/auth/guard.ts:40)'] },
      },
      {
        threatModel: { summary: 'App', trustBoundaries: ['Browser -> API (src/auth/guard.ts:12)'] },
      },
    ];
    const systems: string[] = [];
    const cynos = new CynosChat(
      'k',
      async (_url, init) => {
        const body = JSON.parse(String(init.body)) as { messages: { content: string }[] };
        systems.push(body.messages[0]?.content ?? '');
        return new Response(
          JSON.stringify({ choices: [{ message: { content: JSON.stringify(replies.shift()) } }] })
        );
      },
      async () => {}
    );
    const input: ReviewInput = {
      rows,
      product: rows.slice(1),
      functions: [],
      fileLabels: new Map(),
      functionLabels: new Map(),
      roles: new Map([['src/auth/guard.ts', role('access_control', 0.9)]]),
      entryFiles: new Map(),
      cynos,
    };
    const { review, stats } = await reviewArchitecture(input, () => {});
    expect(review.threatModel.trustBoundaries).toEqual(['Browser -> API (src/auth/guard.ts:12)']);
    expect(stats).toMatchObject({
      calls: 2,
      parts: 1,
      citations: 1,
      invalidBeforeRepair: 1,
      repaired: true,
      cutToFile: 0,
    });
    expect(systems[1]).toContain('not lines printed in the evidence pack');
  });
});

describe('secretValues', () => {
  it('finds values assigned to credential names, and not plain words or names', () => {
    const values = secretValues([
      row(
        'src/a.ts',
        [
          "secret: process.env.JWT_SECRET || 'crm-jwt-secret-key-change-in-production',",
          "const ADMIN_PASSWORD = 'Password123!';",
          '"password": "password",',
          "apiKeyHeader: 'provider',",
          "tokenUrl = 'https://auth.example.com/token'",
          "type: 'credentials',",
          '"admin_password": "env.BIFROST_ADMIN_PASSWORD",',
          "passwordField: 'admin_password',",
          "tokenHeader: 'x-api-key',",
        ].join('\n')
      ),
    ]);
    expect([...values].sort()).toEqual(['Password123!', 'crm-jwt-secret-key-change-in-production']);
  });
});

describe('redactSecretLiterals', () => {
  it('replaces a quoted value that sits on a secret-bearing line, and keeps names and other quotes', () => {
    const rows = [
      row(
        'src/auth.module.ts',
        "secret: process.env.JWT_SECRET || 'crm-jwt-secret-key-change-in-production',"
      ),
      row('src/app.ts', "app.setGlobalPrefix('api/v1/public');"),
    ];
    const review = normalise({
      effectiveResources: [
        {
          consumer: 'JWT',
          effectiveValue:
            "env JWT_SECRET, else the literal 'crm-jwt-secret-key-change-in-production'",
        },
      ],
      threatModel: {
        summary: "Routes under 'api/v1/public' (src/app.ts:1); key from 'JWT_SECRET'",
      },
    });
    expect(redactSecretLiterals(review, rows)).toBe(1);
    expect(review.effectiveResources[0]?.['effectiveValue']).toBe(
      "env JWT_SECRET, else the literal '<redacted literal>'"
    );
    expect(review.threatModel.summary).toBe(
      "Routes under 'api/v1/public' (src/app.ts:1); key from 'JWT_SECRET'"
    );
  });
});

describe('architecture review agent', () => {
  const plan: DockerAgentPlan = {
    name: 'cs-test-knowledge-base-review',
    image: 'cynos-scan-scanner:0.9.1',
    actionRoot: '/action',
    project: '/workspace/repository',
    work: '/stage/knowledge-base/review',
    apparmor: true,
    uid: 1001,
    gid: 1001,
    cynosKey: 'sk-test-value',
  };

  it('runs read-only through cynos with the router and judge off, and takes the key by name only', () => {
    const args = agentCommand(plan);
    const joined = args.join(' ');
    expect(args[args.indexOf('--sandbox') + 1]).toBe('read-only');
    expect(args).toContain('/workspace/repository:/scan/project:ro');
    expect(args[args.indexOf('-e', args.indexOf('-e') + 1) + 1]).toBe('CODEX_API_KEY');
    expect(joined).not.toContain('sk-test-value');
    expect(joined).toContain('"x-cy-eh-task-route"="off"');
    expect(joined).toContain('"x-cy-eh-domain-expert-judge"="off"');
    expect(joined).toContain('model_reasoning_effort="xhigh"');
    expect(args).not.toContain('--network');
  });

  it("downloads no plugin marketplace into the run dir: Codex's plugins and apps are off", () => {
    const args = agentCommand(plan);
    expect(args).toContain('features.plugins=false');
    expect(args).toContain('features.apps=false');
  });

  it('writes no shell snapshot, which would hold the key and outlive a stopped review', () => {
    expect(agentCommand(plan)).toContain('features.shell_snapshot=false');
  });

  it("keeps the key out of every command's environment, where the agent could print it", () => {
    expect(agentCommand(plan)).toContain('shell_environment_policy.ignore_default_excludes=false');
  });

  it('counts turns, commands and tokens from the event stream', () => {
    const events = [
      { type: 'item.completed', item: { type: 'command_execution' } },
      { type: 'item.completed', item: { type: 'agent_message' } },
      {
        type: 'turn.completed',
        usage: { input_tokens: 1000, cached_input_tokens: 800, output_tokens: 50 },
      },
      'not json',
    ].map(e => (typeof e === 'string' ? e : JSON.stringify(e)));
    expect(agentEvents(events.join('\n'))).toEqual({
      turns: 1,
      commands: 1,
      inputTokens: 1000,
      cachedInputTokens: 800,
      outputTokens: 50,
    });
  });

  it('reads the JSON object from the final message, and nothing from a message without one', () => {
    expect(
      answerJson('Done.\n```json\n{"threatModel": {"summary": "App"}}\n```')?.threatModel.summary
    ).toBe('App');
    expect(answerJson('I could not finish.')).toBeUndefined();
    expect(answerJson('{"threatModel": {}}')).toBeUndefined();
    expect(
      answerJson('{"threatModel": {"summary": ["A {braced}", "app"]}}}')?.threatModel.summary
    ).toBe('A {braced} app');
  });

  it('accepts an agent citation anywhere in a real file, and not past its end', () => {
    const files = wholeFiles([row('src/a.ts', numbered(10))]);
    const review = normalise({
      threatModel: { summary: 'x', assets: ['a (src/a.ts:9)', 'b (src/a.ts:11)'] },
    });
    expect(invalidCitations(review, files).invalid).toEqual(['src/a.ts:11']);
  });
});

describe('the agent index and reader', () => {
  const rows = [
    row('src/app.ts', numbered(30)),
    row('src/auth/guard.ts', numbered(12)),
    row('src/db/query.ts', numbered(8)),
    row('README.md', 'An app', 'docs'),
  ];
  const input: AgentInput = {
    core: '',
    corePrinted: new Map([['README.md', [[1, 1]]]]),
    rows,
    functions: [
      { qn: 'app.listen', name: 'listen', path: 'src/app.ts', start: 10, end: 14 },
      { qn: 'db.query', name: 'query', path: 'src/db/query.ts', start: 2, end: 6 },
    ],
    fileLabels: new Map<string, Answers>([
      ['src/auth/guard.ts', { access_control: { type: 'noul', noul: 0.9 } }],
    ]),
    functionLabels: new Map<string, Answers>([
      ['app.listen', { entry_point: { type: 'noul', noul: 0.8 } }],
      ['db.query', { sink: { type: 'choice', choice: 'database' } }],
    ]),
    roles: new Map([['src/app.ts', role('startup', 0.9)]]),
    entryFiles: new Map([['src/app.ts', 1]]),
    maintained: '',
  };

  it('stops the session when the run is stopped, and starts none after', async () => {
    const controller = new AbortController();
    const spawned: string[] = [];
    const stopped: string[] = [];
    // A session that is still running when the stop comes: it ends only when stopped.
    const child = Object.assign(new EventEmitter(), {
      stdout: new EventEmitter(),
      stderr: new EventEmitter(),
      stdin: { end: () => controller.abort('timed out after 1s') },
    });
    const runtime = {
      reviewAgentCommand: (agent: AgentPlan) => ({ name: agent.name, argv: ['true'] }),
      spawn: (command: { name: string }) => {
        spawned.push(command.name);
        return child as unknown as ChildProcess;
      },
      stop: async (name: string) => {
        stopped.push(name);
        child.emit('close', 137);
      },
    } as unknown as ScanRuntime;
    const plan: AgentPlan = {
      name: 'cs-run-knowledge-base-review',
      project: '/project',
      work: mkdtempSync(join(tmpdir(), 'agent-stopped-')),
      cynosKey: 'k',
      runtime,
      paths: { project: '/scan/project', review: '/scan/review' },
      signal: controller.signal,
    };
    expect((await agentReview(plan, input, () => [])).review).toBeUndefined();
    expect(stopped).toEqual([plan.name]);
    // The run is stopped now: another review starts no session at all.
    expect((await agentReview(plan, input, () => [])).review).toBeUndefined();
    expect(spawned).toEqual([plan.name]);
  });

  it('asks a session that answered with invalid JSON for the review once more', async () => {
    // A final message with a quote left unescaped inside a string, as a model wrote one.
    const answers = [
      '```json\n{"threatModel":{"summary":["the "admin" role decides access"]}}\n```',
      '{"threatModel":{"summary":["the \\"admin\\" role decides access"]}}',
    ];
    const work = mkdtempSync(join(tmpdir(), 'agent-invalid-json-'));
    const sessions: { resume: boolean; prompt: string }[] = [];
    let resume = false;
    const runtime = {
      reviewAgentCommand: (agent: AgentPlan, again: boolean) => {
        resume = again;
        return { name: agent.name, argv: ['true'] };
      },
      spawn: () => {
        const child = Object.assign(new EventEmitter(), {
          stdout: new EventEmitter(),
          stderr: new EventEmitter(),
          stdin: {
            end: (prompt: string) => {
              writeFileSync(join(work, 'answer.txt'), answers[Math.min(sessions.length, 1)]!);
              sessions.push({ resume, prompt });
              queueMicrotask(() => child.emit('close', 0));
            },
          },
        });
        return child as unknown as ChildProcess;
      },
      stop: async () => {},
    } as unknown as ScanRuntime;
    const plan: AgentPlan = {
      name: 'cs-run-knowledge-base-review',
      project: '/project',
      work,
      cynosKey: 'k',
      runtime,
      paths: { project: '/scan/project', review: '/scan/review' },
    };
    const { review } = await agentReview(plan, input, () => []);
    expect(review?.threatModel.summary).toBe('the "admin" role decides access');
    expect(sessions[1]?.resume).toBe(true);
    expect(sessions[1]?.prompt).toContain('its JSON object does not parse');
  });

  it('labels every file and function in the index', () => {
    const { files, functions } = indexFiles(input);
    expect(files).toContain('src/app.ts\tcode\t30\trole:startup,entry:1');
    expect(files).toContain('src/auth/guard.ts\tcode\t12\taccess-control');
    expect(files).toContain('src/db/query.ts\tcode\t8\tsink:database');
    expect(functions).toContain('app.listen\tsrc/app.ts\t10\t14\tentry');
    expect(functions).toContain('db.query\tsrc/db/query.ts\t2\t6\tsink:database');
  });

  it('builds components from code and deployment roles, outside tests and docs', () => {
    const withTest: AgentInput = {
      ...input,
      rows: [...rows, row('tests/app.test.ts', numbered(5))],
      roles: new Map([
        ['src/app.ts', role('startup', 0.9)],
        ['src/auth/guard.ts', role('access_control', 0.8)],
        ['tests/app.test.ts', role('startup', 0.9)],
        ['README.md', role('architecture_docs', 0.9)],
      ]),
    };
    expect(checklist(withTest)).toEqual([
      {
        component: 'src',
        files: 2,
        labels: '1 startup, 1 with entry points, 1 access control',
        // the guard ranks first: its role and its access-control label
        examples: ['src/auth/guard.ts', 'src/app.ts'],
        members: ['src/app.ts', 'src/auth/guard.ts'],
      },
    ]);
  });

  it('splits a large directory into its parts and keeps small and repetitive ones together', () => {
    const paths = [
      ...Array.from({ length: 20 }, (_, i) => `transports/bifrost-http/handlers/h${i}.go`),
      ...Array.from({ length: 10 }, (_, i) => `transports/bifrost-http/lib/l${i}.go`),
      'transports/bifrost-http/server/s0.go',
      'transports/bifrost-http/server/s1.go',
      'transports/bifrost-http/main.go',
      ...Array.from({ length: 23 }, (_, i) => `core/providers/p${i}/x.go`),
      'core/bifrost.go',
      'ui/app/a.tsx',
      'ui/lib/b.ts',
      'README.md',
    ];
    const grouped = components(paths);
    expect([...grouped].map(([c, f]) => [c, f.length]).sort()).toEqual([
      ['.', 1],
      ['core', 24],
      ['transports/bifrost-http', 3],
      ['transports/bifrost-http/handlers', 20],
      ['transports/bifrost-http/lib', 10],
      ['ui', 2],
    ]);
  });

  it('prints files, ranges and functions with their own line numbers', () => {
    const root = mkdtempSync(join(tmpdir(), 'kb-'));
    mkdirSync(join(root, 'project', 'src'), { recursive: true });
    mkdirSync(join(root, 'review'));
    writeFileSync(join(root, 'project', 'src', 'app.ts'), numbered(30) + '\n');
    const { files, functions } = indexFiles(input);
    writeFileSync(join(root, 'review', 'files.tsv'), files);
    writeFileSync(join(root, 'review', 'functions.tsv'), functions);
    const script = kbScript(join(root, 'project'), join(root, 'review'));
    const kb = (...args: string[]) =>
      spawnSync('sh', ['-c', script, 'kb', ...args], { encoding: 'utf8' }).stdout;
    expect(kb('read', 'src/app.ts:3-4')).toMatch(
      /==> src\/app.ts \(lines 3-4\) <==\n\s+3\tline 3\n\s+4\tline 4\n$/
    );
    expect(kb('read', 'src/app.ts')).toContain('==> src/app.ts (lines 1-30) <==');
    expect(kb('fn', 'app.listen')).toMatch(/==> src\/app.ts \(lines 10-14\) <==\n\s+10\tline 10/);
    expect(kb('fn', 'nothing')).toContain('kb: no function matches nothing');
    expect(kb('find', 'guard')).toContain('src/auth/guard.ts');
    expect(kb('read', 'src/none.ts')).toContain('kb: no such file: src/none.ts');
  });

  it('counts only the numbered lines the reader printed, and rg hits, plus the core', () => {
    const log = [
      // a read cut short by a pipe: the header names 3-9, only 3-4 were printed
      {
        type: 'item.completed',
        item: {
          type: 'command_execution',
          aggregated_output: '==> src/app.ts (lines 3-9) <==\n     3\tx\n     4\ty',
        },
      },
      {
        type: 'item.completed',
        item: {
          type: 'command_execution',
          aggregated_output: 'src/db/query.ts:4:  return db.run(q)',
        },
      },
    ]
      .map(e => JSON.stringify(e))
      .join('\n');
    const read = linesRead(log, new Map([['README.md', [[1, 1]]]]), '/scan/project');
    expect([...read]).toEqual([
      ['README.md', [[1, 1]]],
      ['src/app.ts', [[3, 4]]],
      ['src/db/query.ts', [[4, 4]]],
    ]);
  });
});

describe('CynosChat', () => {
  it('sends the review to cynos with the router and judge off, retrying a gateway error', async () => {
    const seen: { url: string; headers: Record<string, string>; body: string }[] = [];
    let calls = 0;
    const chat = new CynosChat(
      'sk-test-value',
      async (url, init) => {
        seen.push({
          url,
          headers: init.headers as Record<string, string>,
          body: String(init.body),
        });
        if (calls++ === 0) return new Response('busy', { status: 502 });
        return new Response(
          JSON.stringify({
            choices: [{ message: { content: '{"ok":true}' } }],
            usage: { prompt_tokens: 10, completion_tokens: 2 },
          })
        );
      },
      async () => {}
    );
    expect(await chat.chatJson('deepseek/deepseek-v4.1-flash', 'system', 'user')).toBe(
      '{"ok":true}'
    );
    expect(seen).toHaveLength(2);
    expect(seen[1]?.url).toBe(`${BASE_URL}/chat/completions`);
    expect(seen[1]?.headers).toMatchObject({
      Authorization: 'Bearer sk-test-value',
      'x-cy-eh-task-route': 'off',
      'x-cy-eh-domain-expert-judge': 'off',
    });
    expect(seen[1]?.body).not.toContain('sk-test-value');
    expect([chat.calls, chat.inputTokens, chat.outputTokens]).toEqual([1, 10, 2]);
  });
});
