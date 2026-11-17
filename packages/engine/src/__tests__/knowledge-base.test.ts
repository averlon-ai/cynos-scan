import { describe, it, expect } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { statSync } from 'node:fs';
import { C_PROJECT, KNOWLEDGE_BASE_INDEX, KNOWLEDGE_BASE_OUTPUT } from '../constants';
import { buildKnowledgeBase, type BuildPlan } from '../knowledge-base';
import {
  decisionFor,
  fakeFetch,
  fakeServer,
  gitCheckout,
  pick,
  recordingRunner,
  row,
  yes,
} from './knowledge-base-fakes';
import { loadReview, REVIEW_FILE, reuseReview, saveReview } from '../knowledge-base/stored-review';
import {
  chains,
  EXEC_HEADER,
  notReviewed,
  printPiece,
  secretPieces,
  threatModelSection,
} from '../knowledge-base/briefing';
import type { ArchitectureReview } from '../knowledge-base/architecture';
import {
  DockerRuntime,
  DOCKER_PATHS,
  graphContainerCommand,
  graphServerCommand,
  type DockerGraphPlan,
} from '../runtime/docker';
import { pause } from '../processes';
import {
  CodeGraph,
  runProcess,
  type GraphPlan,
  type McpConnector,
} from '../knowledge-base/code-graph';
import { AnswerCache, checkoutHash, pruneGraphs, saveGraph } from '../knowledge-base/cache';
import { classify, inventory } from '../knowledge-base/inventory';
import {
  askMany,
  chunks,
  CostCapReached,
  JEV,
  MAX_STATE_CHARS,
  mergeAnswers,
  noul,
  choice,
  type Answers,
  type Questions,
} from '../knowledge-base/jev';
import {
  CynosChat,
  CynosDecisions,
  decisionAnswers,
  decisionCost,
  decisionRequest,
  type Decision,
  type DecisionRequest,
} from '../knowledge-base/cynos';
import { BASE_URL } from '../constants';
import {
  assignFiles,
  callGraphHubs,
  checkedDesign,
  designPackets,
  entryPoints,
  membershipQuestions,
  packetSpec,
  sinkFunctions,
  type Entry,
  type Packet,
  type Repository,
} from '../knowledge-base/plan';

const numbered = (n: number, prefix = 'line') =>
  Array.from({ length: n }, (_, i) => `${prefix} ${i + 1}`).join('\n');

/** A yes/no question, as the build writes one. */
const asked = (instructions = 'q?'): Questions[string] => ({
  type: 'noul',
  instructions,
  criteria: { true: 'yes', false: 'no' },
});

describe('jev', () => {
  it('splits a long text on line boundaries into pieces that fit one call', () => {
    const line = `${'x'.repeat(99)}\n`;
    const text = line.repeat(Math.ceil((MAX_STATE_CHARS * 2.5) / line.length));
    const parts = chunks(text);
    expect(parts.length).toBe(3);
    expect(parts.join('')).toBe(text);
    for (const part of parts) expect(part.length).toBeLessThanOrEqual(MAX_STATE_CHARS);
  });

  it('merges chunked answers: a fact holds if any chunk shows it', () => {
    const merged = mergeAnswers([
      { secret: yes(0.1), sink: pick('none', { none: 0.9, database: 0.1 }) },
      { secret: yes(0.8), sink: pick('database', { none: 0.3, database: 0.7 }) },
    ]);
    expect(merged['secret']).toEqual(yes(0.8));
    expect(merged['sink']).toMatchObject({
      choice: 'none',
      probabilities: { none: 0.9, database: 0.7 },
    });
  });

  it('keeps an answer a later chunk gives to a question an earlier chunk refused', async () => {
    // A file of two chunks: cynos refuses embedded_secret for the first and finds the secret in
    // the second; the role question is answered by the first chunk only.
    const line = `${'x'.repeat(99)}\n`;
    const content = line.repeat(Math.ceil((MAX_STATE_CHARS * 1.5) / line.length));
    let calls = 0;
    const client = new CynosDecisions(
      'k',
      5,
      fakeFetch((_, body) => {
        const first = calls++ === 0;
        return decisionFor(body, name => {
          if (name === 'embedded_secret') return first ? undefined : yes(0.99);
          return first ? pick('configuration') : undefined;
        });
      }),
      async () => {}
    );
    const questions: Questions = {
      embedded_secret: asked('Does this file hold a secret?'),
      architecture_role: {
        type: 'choice',
        instructions: 'Which role?',
        criteria: { configuration: 'Configuration.', none: 'None.' },
      },
    };
    const { answers } = await askMany(
      client,
      [['config.py', { path: 'config.py', content }]],
      questions
    );
    expect(calls).toBe(2);
    expect(noul(answers.get('config.py'), 'embedded_secret')).toBe(0.99);
    expect(choice(answers.get('config.py'), 'architecture_role')).toBe('configuration');
  });
});

describe('cynos decisions', () => {
  /** OpenAI's Decisions request as cynos defines it, and a Decision cynos answered with. */
  const fixture = JSON.parse(
    readFileSync(join(import.meta.dir, 'fixtures', 'cynos-decisions.json'), 'utf8')
  ) as {
    request: {
      required: string[];
      properties: string[];
      question: { required: string[]; properties: string[]; types: string[] };
      choice: { required: string[]; properties: string[] };
      inputItemTypes: string[];
      contentPartTypes: string[];
    };
    decision: Decision;
  };
  const undefinedFields = (value: object, defined: string[]) =>
    Object.keys(value).filter(k => !defined.includes(k));

  it("asks Jev's questions in OpenAI's Decisions request, with only the fields cynos takes", () => {
    const questions: Questions = {
      entry_point: {
        type: 'noul',
        instructions: 'Can an outside caller invoke it?',
        criteria: { true: 'A caller can.', false: 'Only other code calls it.' },
      },
      sink: {
        type: 'choice',
        instructions: 'Which sensitive operation?',
        criteria: { none: 'No sensitive operation.', database: 'Runs database queries.' },
      },
    };
    const state = { path: 'app/db.py', function: 'app.db.find', code: 'def find(q): ...' };
    const request = decisionRequest(state, questions);
    expect(request).toEqual({
      model: 'openrouter/typesafe/jev-1.14',
      input: [{ type: 'message', role: 'user', content: [{ type: 'input_json', data: state }] }],
      questions: [
        {
          type: 'predicate',
          name: 'entry_point',
          instructions:
            'Can an outside caller invoke it?\ntrue: A caller can.\nfalse: Only other code calls it.',
        },
        {
          type: 'choice',
          name: 'sink',
          instructions: 'Which sensitive operation?',
          choices: [
            { value: 'none', description: 'No sensitive operation.' },
            { value: 'database', description: 'Runs database queries.' },
          ],
        },
      ],
    });
    expect(decisionRequest('plain text', questions).input).toBe('plain text');

    // cynos refuses a field OpenAI's request does not define with a 400, so none is sent.
    const schema = fixture.request;
    expect(undefinedFields(request, schema.properties)).toEqual([]);
    for (const field of schema.required) expect(request).toHaveProperty(field);
    for (const question of request.questions) {
      expect(undefinedFields(question, schema.question.properties)).toEqual([]);
      expect(schema.question.types).toContain(question.type);
      for (const field of schema.question.required) expect(question).toHaveProperty(field);
      for (const option of question.type === 'choice' ? question.choices : [])
        expect(undefinedFields(option, schema.choice.properties)).toEqual([]);
    }
    for (const item of request.input as Exclude<DecisionRequest['input'], string>) {
      expect(schema.inputItemTypes).toContain(item.type);
      for (const part of item.content) expect(schema.contentPartTypes).toContain(part.type);
    }
  });

  it("reads cynos's Decision back as Jev's answers, by question order, and prices its tokens", () => {
    // The fixture's questions in Jev's terms. Its last is a score, which the build never asks:
    // asked here as a noul, its answer is of another type and the question goes unanswered.
    const questions: Questions = {
      is_billing: asked("Is the customer's message about billing?"),
      intent: {
        type: 'choice',
        instructions: 'What does the customer want?',
        criteria: { refund: 'A refund.', cancel: 'To cancel.', false: 'nothing in particular' },
      },
      frustration: asked('How frustrated is the customer?'),
    };
    expect(decisionAnswers(questions, fixture.decision)).toEqual({
      is_billing: { type: 'noul', noul: 1 },
      intent: {
        type: 'choice',
        choice: 'refund',
        probabilities: { refund: 1, cancel: 0, false: 0 },
        confidence: 1,
      },
    });
    // The Decision carries tokens, not cost: 395 input tokens at Jev's catalog rate.
    expect(decisionCost(fixture.decision.usage)).toBeCloseTo(395 * 4.2e-8, 12);
  });

  it('leaves a refused question unanswered, and fails a Decision not laid out as asked', () => {
    const questions = { a: asked(), b: asked() };
    const a = { type: 'predicate' as const, name: 'a', probability: 0.9 };
    const b = { type: 'predicate' as const, name: 'b', probability: 0.2 };
    expect(decisionAnswers(questions, { answers: [{ type: 'refusal', name: 'a' }, b] })).toEqual({
      b: { type: 'noul', noul: 0.2 },
    });
    expect(() => decisionAnswers(questions, { answers: [a] })).toThrow(
      'cynos returned 1 decision answers for 2 questions'
    );
    expect(() => decisionAnswers(questions, { answers: [b, a] })).toThrow('named b; expected a');
  });

  it("posts to cynos's /v1/decisions with the cynos key, retries a rate limit, and counts the cost", async () => {
    const urls: string[] = [];
    const authorizations: string[] = [];
    const bodies: Record<string, unknown>[] = [];
    const fetchImpl = async (url: string, init: RequestInit): Promise<Response> => {
      urls.push(url);
      authorizations.push((init.headers as Record<string, string>)['Authorization'] ?? '');
      const body = JSON.parse(String(init.body)) as Record<string, unknown>;
      bodies.push(body);
      if (urls.length === 1) return new Response('slow down', { status: 429 });
      return new Response(JSON.stringify(decisionFor(body, () => yes(1))));
    };
    const client = new CynosDecisions('sk-cynos-test', 5, fetchImpl, async () => {});
    expect(await client.decide({ content: 'x' }, { q: asked() })).toEqual({ q: yes(1) });
    expect(urls).toEqual([`${BASE_URL}/decisions`, `${BASE_URL}/decisions`]);
    expect(authorizations).toEqual(['Bearer sk-cynos-test', 'Bearer sk-cynos-test']);
    expect(bodies[0]?.['model']).toBe(JEV);
    expect(client.calls).toBe(1);
    expect(client.cost).toBeCloseTo(1000 * 4.2e-8, 12);
  });

  it('makes no call once the run is stopped, and retries none the stop cut short', async () => {
    const controller = new AbortController();
    const signals: (AbortSignal | null | undefined)[] = [];
    // The stop comes while the first call is in flight, which then fails as retryable.
    const fetchImpl = async (_: string, init: RequestInit): Promise<Response> => {
      signals.push(init.signal);
      controller.abort('timed out after 1s');
      return new Response('slow down', { status: 429 });
    };
    const client = new CynosDecisions(
      'k',
      5,
      fetchImpl,
      async () => {},
      BASE_URL,
      controller.signal
    );
    await expect(client.decide({ content: 'x' }, { q: asked() })).rejects.toThrow(
      'cynos decisions stopped: timed out after 1s'
    );
    // The call in flight had the run's signal, and none came after it.
    expect(signals).toHaveLength(1);
    expect(signals[0]?.aborted).toBe(true);
    await expect(client.decide({ content: 'y' }, { q: asked() })).rejects.toThrow('stopped');
    expect(signals).toHaveLength(1);
  });

  it('ends a backoff when the run is stopped, and retries nothing after it', async () => {
    const controller = new AbortController();
    let calls = 0;
    const fetchImpl = async (): Promise<Response> => {
      calls += 1;
      return new Response('slow down', { status: 429 });
    };
    // The stop comes during the backoff after the first call, which would otherwise never end.
    const client = new CynosDecisions(
      'k',
      5,
      fetchImpl,
      (_, signal) => {
        setTimeout(() => controller.abort('timed out after 1s'), 10);
        return pause(60_000, signal);
      },
      BASE_URL,
      controller.signal
    );
    await expect(client.decide({ content: 'x' }, { q: asked() })).rejects.toThrow(
      'cynos decisions stopped: timed out after 1s'
    );
    expect(calls).toBe(1);
  });

  it('starts no step of a stopped build: no graph container, no call', async () => {
    const project = gitCheckout({ 'app.py': 'print(1)\n' });
    const commands: string[][] = [];
    const transport = { run: recordingRunner(commands), connect: fakeServer(() => ({}), commands) };
    let calls = 0;
    const fetchImpl = async (): Promise<Response> => {
      calls += 1;
      return new Response('{}');
    };
    const controller = new AbortController();
    controller.abort('timed out after 1s');
    const plan: BuildPlan = {
      name: 'cs-stopped-knowledge-base',
      project,
      runtime: new DockerRuntime({ assets: '/action' }),
      paths: DOCKER_PATHS,
      work: mkdtempSync(join(tmpdir(), 'kb-work-')),
      cynosKey: 'k',
      reviewAgent: false,
      maxHypothesisPackets: 3,
      signal: controller.signal,
    };
    await expect(
      buildKnowledgeBase(plan, () => {}, transport, {
        decisions: new CynosDecisions('k', 5, fetchImpl, async () => {}),
        chat: new CynosChat('k', fetchImpl, async () => {}),
      })
    ).rejects.toThrow('the build was stopped: timed out after 1s');
    expect(commands).toEqual([]);
    expect(calls).toBe(0);
  });

  it('counts a failed item, and stops the whole build at the cost cap', async () => {
    const failing = new CynosDecisions(
      'k',
      5,
      async () => new Response('bad request', { status: 400 }),
      async () => {}
    );
    expect(await askMany(failing, [['a', 'x']], { q: asked() })).toEqual({
      answers: new Map(),
      failed: 1,
    });

    // 250,000 input tokens a call is about a cent; the cap is a cent and a half.
    const capped = new CynosDecisions(
      'k',
      0.015,
      fakeFetch((_, body) => ({
        ...decisionFor(body, () => yes(0)),
        usage: { input_tokens: 250_000, output_tokens: 0 },
      })),
      async () => {}
    );
    const items = Array.from({ length: 40 }, (_, i): [string, unknown] => [`f${i}`, 'x']);
    await expect(askMany(capped, items, { q: asked() })).rejects.toBeInstanceOf(CostCapReached);
  });
});

describe('inventory', () => {
  it.each([
    ['app/views.py', 'def f(): pass', 'code'],
    ['node_modules/x/index.js', 'x', 'skip'],
    ['static/js/app.min.js', 'x', 'skip'],
    ['tests/test_views.py', 'x', 'test'],
    ['src/app.test.ts', 'x', 'test'],
    ['locales/en.json', '{}', 'data'],
    ['templates/index.html', '<p>', 'template'],
    ['config/settings.yml', 'a: 1', 'config'],
    ['.env', 'KEY=1', 'config'],
    ['README.md', '# x', 'docs'],
    // Infrastructure as code, scripts and interface definitions are product code too.
    ['infra/main.tf', 'resource "aws_s3_bucket" "b" {}', 'code'],
    ['infra/prod.tfvars', 'region = "us-west-2"', 'code'],
    ['infra/.terraform.lock.hcl', 'provider {}', 'skip'],
    ['scripts/deploy.sh', 'curl "$URL" | sh', 'code'],
    ['Dockerfile', 'FROM node:24', 'code'],
    ['docker/Dockerfile.prod', 'FROM node:24', 'code'],
    ['Makefile', 'all:', 'code'],
    ['api/service.proto', 'syntax = "proto3";', 'code'],
    ['db/migrate.sql', 'GRANT ALL ON db TO app;', 'code'],
    ['db/seed.sql', 'INSERT INTO t VALUES (1);\n'.repeat(1500), 'data'],
    ['plugin.lua', 'return {}', 'code'],
    // Code is what no rule sets aside: a language, script or build file no list names.
    ['src/main.zig', 'pub fn main() void {}', 'code'],
    ['bin/run', '#!/bin/sh\nexec "$@"', 'code'],
    ['CMakeLists.txt', 'add_executable(app main.c)', 'code'],
    ['public/robots.txt', 'Disallow: /admin', 'code'],
    ['app/changes.py', 'x = 1', 'code'],
    ['web/App.vue', '<template></template>', 'code'],
    // Set aside: documentation, records, stylesheets and repository metadata.
    ['LICENSE', 'Apache License', 'docs'],
    ['LICENSE-MIT', 'MIT License', 'docs'],
    ['NOTICE.txt', 'Copyright', 'docs'],
    ['docs/guide.adoc', '= Guide', 'docs'],
    ['exports/users.csv', 'id,name', 'data'],
    ['web/site.css', 'body {}', 'other'],
    ['.gitignore', 'node_modules/', 'other'],
    ['bun.lock', '{}', 'skip'],
  ])('classifies %s as %s', (path, text, kind) => {
    expect(classify(path, text)[0]).toBe(kind);
  });

  it('lists the files git would commit: no ignored file, symbolic link or .git', () => {
    const root = gitCheckout({
      '.gitignore': '.env\n*.tfstate\n',
      'app/a.py': 'x = 1\n',
      'app/gone.py': 'y = 2\n',
    });
    // Untracked but not ignored: a file git would commit, so the scan reads it.
    writeFileSync(join(root, 'app', 'new.py'), 'z = 3\n');
    writeFileSync(join(root, 'app', 'logo.bin'), Buffer.from([0, 1, 2]));
    // Ignored: a developer's local secrets, which must never reach the model.
    writeFileSync(join(root, '.env'), 'DATABASE_PASSWORD=synthetic-pw\n');
    writeFileSync(join(root, 'prod.tfstate'), '{"password":"synthetic-pw"}\n');
    spawnSync('ln', ['-s', '/etc/passwd', join(root, 'app', 'link.py')]);
    rmSync(join(root, 'app', 'gone.py'));
    const rows = inventory(root);
    expect(rows.map(r => r.path)).toEqual(['.gitignore', 'app/a.py', 'app/logo.bin', 'app/new.py']);
    expect(rows.find(r => r.path === 'app/logo.bin')).toMatchObject({
      kind: 'skip',
      text: undefined,
    });
    expect(rows.some(r => r.text?.includes('synthetic-pw'))).toBe(false);
  });

  it('does not follow a tracked directory a dirty checkout replaced with a symbolic link', () => {
    const root = gitCheckout({ 'app/a.py': 'x = 1\n', 'src/config.py': 'DEBUG = False\n' });
    // git still lists src/config.py; through the link it is a file outside the checkout.
    const outside = mkdtempSync(join(tmpdir(), 'inventory-outside-'));
    writeFileSync(join(outside, 'config.py'), 'PASSWORD = "synthetic-pw"\n');
    rmSync(join(root, 'src'), { recursive: true });
    spawnSync('ln', ['-s', outside, join(root, 'src')]);
    const rows = inventory(root);
    expect(rows.map(r => r.path)).toEqual(['app/a.py']);
    expect(rows.some(r => r.text?.includes('synthetic-pw'))).toBe(false);
  });

  it('refuses a directory git cannot list rather than reading every file in it', () => {
    const root = mkdtempSync(join(tmpdir(), 'inventory-not-git-'));
    writeFileSync(join(root, '.env'), 'KEY=1\n');
    expect(() => inventory(root)).toThrow(/git cannot list the files/);
  });
});

describe('code graph', () => {
  const plan: DockerGraphPlan = {
    name: 'cs-test-knowledge-base',
    image: 'cynos-scan-scanner:0.9.1',
    actionRoot: '/action',
    project: '/workspace/repository',
    home: '/stage/knowledge-base/graph',
    apparmor: true,
    uid: 1001,
    gid: 1001,
  };

  it("runs with no network, the scan's hardening, the checkout read-only and no key", () => {
    const args = graphContainerCommand(plan);
    expect(args[args.indexOf('--network') + 1]).toBe('none');
    expect(args).toContain('no-new-privileges');
    expect(args).toContain(`/workspace/repository:${C_PROJECT}:ro`);
    expect(args.join(' ')).not.toMatch(/API_KEY/);
    expect(graphServerCommand(plan.name)).toEqual(['exec', '-i', plan.name, 'codebase-memory-mcp']);
  });

  const graphPlan = (signal?: AbortSignal): GraphPlan => ({
    name: plan.name,
    project: plan.project,
    home: plan.home,
    runtime: new DockerRuntime({ assets: '/action' }),
    paths: DOCKER_PATHS,
    ...(signal ? { signal } : {}),
  });

  it('serves every call from one server: the project name the index reports, a retried tool error, every page', async () => {
    const inputs: Record<string, unknown>[] = [];
    const commands: string[][] = [];
    const servers: string[][] = [];
    let failures = 1;
    const connect = fakeServer((tool, args) => {
      inputs.push(args);
      if (tool === 'index_repository') return { project: 'scan-x' };
      if (failures-- > 0) return new Error('daemon starting');
      return args['cursor']
        ? { rows: [['scan-x.app.b', 'b', 'app.py', 9, 12]], has_more: false }
        : {
            rows: [
              ['scan-x.app.a', 'a', 'app.py', 1, 5],
              ['len', 'len', '<builtin>', 0, 0],
            ],
            has_more: true,
            next_cursor: 'c1',
          };
    }, servers);
    const codeGraph = new CodeGraph(
      graphPlan(),
      { run: recordingRunner(commands), connect },
      async () => {}
    );
    await codeGraph.start();
    await codeGraph.index();
    const functions = await codeGraph.functions();
    await codeGraph.stop();
    expect(functions.map(f => f.qn)).toEqual(['app.a', 'app.b']);
    expect(inputs.slice(1).every(i => i['project'] === 'scan-x')).toBe(true);
    expect(inputs.at(-1)?.['cursor']).toBe('c1');
    // One container, one server for all four calls, and the container removed at the end.
    expect(servers).toEqual([['docker', 'exec', '-i', plan.name, 'codebase-memory-mcp']]);
    expect(commands.map(c => c[0])).toEqual(['run', 'rm']);
  });

  it('reads call references: a function passed as a value, as the wiring that hands it over', async () => {
    const queries: string[] = [];
    const connect = fakeServer((tool, args) => {
      if (tool === 'index_repository') return { project: 'scan' };
      queries.push(String(args['query']));
      return {
        rows: [
          [
            'scan.server.loadBuiltinPlugin',
            'scan.server.newInternalShadowContext',
            'server/slm.go',
          ],
          ['scan.server.loadBuiltinPlugin', 'fmt.Sprintf', '<external>'],
        ],
      };
    });
    const codeGraph = new CodeGraph(graphPlan(), { run: recordingRunner([]), connect });
    await codeGraph.start();
    await codeGraph.index();
    expect(await codeGraph.callReferences()).toEqual([
      ['server.loadBuiltinPlugin', 'server.newInternalShadowContext'],
    ]);
    await codeGraph.stop();
    expect(queries).toEqual([
      'MATCH (a)-[:CALL_REFERENCE]->(b) RETURN a.qualified_name, b.qualified_name, b.file_path',
    ]);
  });

  it('takes a write the server no longer reads as its exit, on Node, not as an error that ends it', async () => {
    // Node raises EPIPE on a child's stdin when the child has closed it, and an unhandled one ends
    // the process; Bun does not raise it, so the engine's own server code runs under Node here,
    // against a server that closes its input and keeps running.
    const out = mkdtempSync(join(tmpdir(), 'cg-node-'));
    const built = await Bun.build({
      entrypoints: [join(import.meta.dir, '../knowledge-base/code-graph.ts')],
      outdir: out,
      target: 'node',
      format: 'esm',
    });
    expect(built.success).toBe(true);
    const script = `
      import { spawnMcpServer } from ${JSON.stringify(join(out, 'code-graph.js'))};
      import { spawn } from 'node:child_process';
      const runtime = { spawn: (_, stdio) => spawn('/bin/sh', ['-c', 'exec 0<&-; sleep 2'], { stdio }) };
      const channel = spawnMcpServer({ argv: ['x'], env: {}, name: 'g' }, runtime);
      channel.onExit(detail => { console.log('EXIT ' + detail); channel.kill(); process.exit(0); });
      setTimeout(() => { for (let i = 0; i < 50; i++) channel.send({ pad: 'p'.repeat(65536) }); }, 300);`;
    const run = spawnSync('node', ['--input-type=module', '-e', script], {
      encoding: 'utf8',
      timeout: 20_000,
    });
    expect(run.stdout).toContain('EXIT stopped reading its input');
  });

  it('fails the call in flight when the server exits, with what it said', async () => {
    let exit: (detail: string) => void = () => {};
    const connect: McpConnector = () => {
      let deliver: (message: Record<string, unknown>) => void = () => {};
      return {
        send: message => {
          if (message['method'] === 'initialize')
            queueMicrotask(() => deliver({ jsonrpc: '2.0', id: message['id'], result: {} }));
          else if (message['method'] === 'tools/call')
            queueMicrotask(() => exit('exited with 1: out of memory'));
        },
        onMessage: listener => (deliver = listener),
        onExit: listener => (exit = listener),
        close: async () => {},
        kill: () => {},
      };
    };
    const codeGraph = new CodeGraph(graphPlan(), { run: recordingRunner([]), connect });
    await codeGraph.start();
    await expect(codeGraph.index()).rejects.toThrow(
      "the code graph's server exited with 1: out of memory"
    );
    await expect(codeGraph.functions()).rejects.toThrow('out of memory');
  });

  it('kills the server when the run is stopped mid-call, and retries nothing', async () => {
    const controller = new AbortController();
    let killed = 0;
    let calls = 0;
    // The stop comes while the index call runs; the server never answers it.
    const connect: McpConnector = () => {
      let deliver: (message: Record<string, unknown>) => void = () => {};
      return {
        send: message => {
          if (message['method'] === 'initialize')
            queueMicrotask(() => deliver({ jsonrpc: '2.0', id: message['id'], result: {} }));
          else if (message['method'] === 'tools/call') {
            calls += 1;
            queueMicrotask(() => controller.abort('timed out after 1s'));
          }
        },
        onMessage: listener => (deliver = listener),
        onExit: () => {},
        close: async () => {},
        kill: () => void (killed += 1),
      };
    };
    const codeGraph = new CodeGraph(
      graphPlan(controller.signal),
      { run: recordingRunner([]), connect },
      async () => {}
    );
    await codeGraph.start();
    await expect(codeGraph.index()).rejects.toThrow(
      'the code graph was stopped: timed out after 1s'
    );
    expect(killed).toBe(1);
    expect(calls).toBe(1);
  });

  it('ends a backoff between graph calls when the run is stopped', async () => {
    const controller = new AbortController();
    let calls = 0;
    const connect = fakeServer(() => {
      calls += 1;
      return new Error('daemon starting');
    });
    // The backoff after the failed call is a minute long.
    const sleep = (_: number, signal?: AbortSignal): Promise<void> => {
      setTimeout(() => controller.abort('timed out after 1s'), 10);
      return pause(60_000, signal);
    };
    const codeGraph = new CodeGraph(
      graphPlan(controller.signal),
      { run: recordingRunner([]), connect },
      sleep
    );
    await codeGraph.start();
    await expect(codeGraph.index()).rejects.toThrow(
      'the code graph was stopped: timed out after 1s'
    );
    expect(calls).toBe(1);
  });

  it("runProcess kills its command when the run's signal fires", async () => {
    const controller = new AbortController();
    const started = Date.now();
    const running = runProcess('sleep', ['30'], '', { signal: controller.signal });
    setTimeout(() => controller.abort('stopped'), 50);
    expect((await running).status).toBeNull();
    expect(Date.now() - started).toBeLessThan(10_000);
  });
});

describe('plan', () => {
  const repo: Repository = {
    rows: [],
    product: [row('app/routes.py', numbered(10, 'route')), row('app/db.py', numbered(10, 'db'))],
    functions: [
      { qn: 'app.routes.login', name: 'login', path: 'app/routes.py', start: 2, end: 4 },
      { qn: 'app.routes.helper', name: 'helper', path: 'app/routes.py', start: 6, end: 8 },
      { qn: 'app.db.query', name: 'query', path: 'app/db.py', start: 1, end: 3 },
    ],
    calls: [],
    tokens: new Map(),
  };

  it('takes function and file-level entry points at the threshold, not below', () => {
    const functionLabels = new Map<string, Answers>([
      ['app.routes.login', { entry_point: yes(0.9) }],
      ['app.routes.helper', { entry_point: yes(0.1) }],
    ]);
    const fileLabels = new Map<string, Answers>([
      ['app/routes.py', { entry_point: yes(0.9) }],
      ['app/db.py', { entry_point: yes(0.5) }],
    ]);
    const entries = entryPoints(repo, functionLabels, fileLabels);
    expect(entries.map(e => [e.qn, e.how, e.line])).toEqual([
      ['app/db.py', 'file', 1],
      ['app.routes.login', 'function', 2],
    ]);
    expect(entries[1]?.text).toBe('[p=0.90] route 2');
  });

  it('ends chains at sinks other than rendering', () => {
    const sinks = sinkFunctions(
      new Map<string, Answers>([
        ['a', { sink: pick('database') }],
        ['b', { sink: pick('rendering') }],
        ['c', { sink: pick('none') }],
      ])
    );
    expect([...sinks]).toEqual([['a', 'database']]);
  });

  it('finds the functions two entry points reach, functions only, ties by name', () => {
    const entries = ['e1', 'e2'].map(qn => ({ qn }) as Entry);
    const functions = ['e1', 'e2', 'h', 'g', 'z'].map(qn => ({
      qn,
      name: qn,
      path: `${qn}.py`,
      start: 1,
      end: 2,
    }));
    const calls: [string, string][] = [
      ['e1', 'h'],
      ['e2', 'h'],
      ['e1', 'g'],
      ['g', 'z'],
      ['e2', 'z'],
      ['e1', 'SomeClass'],
      ['e2', 'SomeClass'],
    ];
    expect(callGraphHubs(entries, functions, calls)).toEqual([
      ['h', 2, 'h.py'],
      ['z', 2, 'z.py'],
    ]);
  });

  it('checks a design: product seeds only, unique ids, exactly one owner of app-wide controls', () => {
    const product = new Set(['app/auth.py', 'app/files.py']);
    const packets = checkedDesign(
      {
        packets: [
          {
            id: 'Files!',
            seed_review_files: ['./app/files.py', 3],
            membership_criteria: 'file handling',
          },
          {
            id: 'files',
            perspective: 'Sessions and login',
            seed_review_files: ['app/auth.py'],
            membership_criteria: 'auth',
          },
        ],
      },
      8,
      product
    );
    expect(packets.map(p => [p.id, p.seeds, p.ownsAppWide])).toEqual([
      ['files', ['app/files.py'], false],
      ['files-x', ['app/auth.py'], true],
    ]);
    const design = (packet: Record<string, unknown>) => ({ packets: [{ id: 'a', ...packet }] });
    expect(() =>
      checkedDesign(design({ seed_review_files: [1], membership_criteria: 'x' }), 8, product)
    ).toThrow('no seed file');
    expect(() => checkedDesign(design({ seed_review_files: ['app/auth.py'] }), 8, product)).toThrow(
      'membership criteria'
    );
  });

  it('puts a file in every packet it meets, its likeliest when it meets none, and leaves none out', () => {
    const packets = ['a', 'b', 'c'].map(
      id => ({ id, seeds: id === 'a' ? ['seed.py'] : [] }) as unknown as Packet
    );
    const tokens = new Map(['seed.py', 'two.py', 'weak.py', 'lost.py'].map(f => [f, 10]));
    const member = new Map<string, Answers>([
      ['two.py', { in_a: yes(0.9), in_b: yes(0.1), in_c: yes(0.7) }],
      ['weak.py', { in_a: yes(0.1), in_b: yes(0.3), in_c: yes(0.2) }],
    ]);
    const review = assignFiles(packets, member, tokens);
    expect([...(review.get('a') ?? [])].sort()).toEqual(['seed.py', 'two.py']);
    // weak.py meets no packet, so it goes to its likeliest; lost.py has no answer, so to the smallest.
    expect([...(review.get('b') ?? [])].sort()).toEqual(['lost.py', 'weak.py']);
    expect([...(review.get('c') ?? [])].sort()).toEqual(['two.py']);
    expect(Object.keys(membershipQuestions(packets))).toEqual(['in_a', 'in_b', 'in_c']);
  });

  it('asks the given model (cynos in a build) for the design, and retries a rejected one', async () => {
    const replies = [
      '{"packets": []}',
      JSON.stringify({
        packets: [{ id: 'a', seed_review_files: ['app/a.py'], membership_criteria: 'x' }],
      }),
    ];
    const asked: string[] = [];
    const cynos = {
      chatJson: async (model: string) => {
        asked.push(model);
        return replies.shift() as string;
      },
    };
    const packets = await designPackets(cynos, 'digest', 8, new Set(['app/a.py']), () => {});
    expect(packets.map(p => p.id)).toEqual(['a']);
    expect(asked).toEqual(['deepseek/deepseek-v4.1-flash', 'deepseek/deepseek-v4.1-flash']);
  });

  it('gives every packet one helper, however many files it has', () => {
    const packet: Packet = {
      id: 'p',
      perspective: '',
      attacker: '',
      seeds: ['a/1'],
      criteria: '',
      context: ['a/1', 'z/9'],
      ownsAppWide: true,
    };
    const files = Array.from({ length: 500 }, (_, i) => `a/${i}`);
    const spec = packetSpec([packet], new Map([['p', new Set(files)]]));
    expect(spec.map(s => [s.id, s.review.length, s.seeds, s.context])).toEqual([
      ['p', 500, ['a/1'], ['z/9']],
    ]);
  });
});

describe('briefing', () => {
  it('prints a piece as the reader does: its own line numbers under a header', () => {
    const text = 'a\nb\nc\n';
    expect(printPiece({ path: 'x.py', lines: 4, text })).toBe(
      '==> x.py (lines 1-3) <==\n     1\ta\n     2\tb\n     3\tc'
    );
    expect(printPiece({ path: 'x.py', lines: 2, text, start: 2, end: 3 })).toBe(
      '==> x.py (lines 2-3) <==\n     2\tb\n     3\tc'
    );
  });

  it('cuts a long secret window into pieces of at most 120 lines', () => {
    const r = row('locales/en.json', numbered(400), 'data');
    const pieces = secretPieces([{ path: r.path, start: 10, end: 300 }], new Map([[r.path, r]]));
    expect(pieces.map(p => [p.start, p.end])).toEqual([
      [10, 129],
      [130, 249],
      [250, 300],
    ]);
  });

  it('gives a helper the whole threat model, its own boundaries first', () => {
    const review = {
      threatModel: {
        origin: 'generated',
        summary: 'A gateway.',
        scope: { includePaths: ['.'], summary: '' },
        assets: [],
        trustBoundaries: [
          'Client -> /api admin surface: admin only (handlers/middlewares.go:10)',
          'Log reads -> object storage (logstore/payload.go:5)',
        ],
        attackerCapabilities: ['Tenant holding a virtual key: inference only'],
        securityObjectives: ['Admin routes require a session (handlers/middlewares.go:10)'],
        assumptions: [],
      },
      effectiveResources: [],
      resolvedQuestions: [],
    } as unknown as ArchitectureReview;
    const text = threatModelSection(review, new Set(['logstore/payload.go'])).join('\n');
    // The /api boundary cites no packet file and is still there, after the packet's own.
    expect(text.indexOf('Log reads')).toBeLessThan(text.indexOf('/api admin surface'));
    expect(text).toContain('### Attacker capabilities');
    expect(text).toContain('### Security objectives');
  });

  it('names exactly the files the scan does not review, never a whole directory for one file', () => {
    const rows = [
      row('terraform/main.tf', 'resource "x" "y" {}', 'code'),
      row('terraform/.terraform.lock.hcl', 'provider {}', 'skip', 'lock file'),
      row('README.md', '# x', 'docs'),
      ...Array.from({ length: 5 }, (_, i) => row(`src/a${i}.test.ts`, 'x', 'test')),
      ...Array.from({ length: 4 }, (_, i) =>
        row(`node_modules/m/i${i}.js`, 'x', 'skip', 'in node_modules/')
      ),
    ];
    expect(notReviewed(rows)).toEqual([
      '- test files under `src/`: 5 files',
      '- vendored or build output under `node_modules/`: 4 files',
      '- `README.md` (documentation)',
      '- `terraform/.terraform.lock.hcl` (lock file)',
    ]);
  });

  it('chains each entry point to the sinks it reaches within three calls', () => {
    const entry = { qn: 'e', path: 'e.py', line: 1, how: 'function', p: 1, text: '' } as Entry;
    const calls: [string, string][] = [
      ['e', 'a'],
      ['a', 'b'],
      ['b', 'c'],
      ['c', 'd'],
    ];
    const sinks = new Map([
      ['b', 'database'],
      ['d', 'execution'],
    ]);
    expect(chains([entry], calls, sinks)[0]?.paths).toEqual([['a', 'b']]);
  });
});

describe('buildKnowledgeBase', () => {
  it("builds the lead's index and every helper's brief, and keeps the key in this process", async () => {
    const project = gitCheckout({
      'app/routes.py': 'import db\n\ndef login(req):\n    return db.find(req.args["u"])\n',
      'app/db.py': 'def find(u):\n    return execute(f"select {u}")\n',
      'tests/test_login.py': 'PASSWORD = "hunter2"\n',
    });
    const work = mkdtempSync(join(tmpdir(), 'kb-work-'));

    // The graph: login calls find.
    const commands: string[][] = [];
    const transport = {
      run: recordingRunner(commands),
      connect: fakeServer(
        (tool, args) =>
          tool === 'index_repository'
            ? { project: 'scan', nodes: 9, edges: 4 }
            : String(args['query']).includes('CALLS')
              ? { rows: [['scan.app.routes.login', 'scan.app.db.find', 'app/db.py']] }
              : {
                  rows: [
                    ['scan.app.routes.login', 'login', 'app/routes.py', 3, 4],
                    ['scan.app.db.find', 'find', 'app/db.py', 1, 2],
                  ],
                },
        commands
      ),
    };
    // The answers: login is the entry point, find runs a query, the test file holds a password.
    const design = {
      packets: [
        {
          id: 'injection',
          perspective: 'Injection',
          seed_review_files: ['app/db.py'],
          membership_criteria: 'runs queries',
        },
        {
          id: 'auth',
          perspective: 'Login',
          seed_review_files: ['app/routes.py'],
          membership_criteria: 'logs users in',
        },
      ],
    };
    const urls: string[] = [];
    const asked: string[][] = [];
    const fetchImpl = fakeFetch((url, body) => {
      urls.push(url);
      if (url.endsWith('/chat/completions'))
        return { choices: [{ message: { content: JSON.stringify(design) } }] };
      asked.push((body['questions'] as { name: string }[]).map(q => q.name));
      return decisionFor(body, (name, state) => {
        if (name === 'sink') return pick(state['function'] === 'app.db.find' ? 'database' : 'none');
        if (name === 'in_injection') return yes(0.6);
        if (name === 'in_auth') return yes(0.4);
        if (name === 'entry_point') return yes(state['path'] === 'app/db.py' ? 0 : 0.9);
        if (name === 'embedded_secret')
          return yes(String(state['path']).startsWith('tests/') ? 0.9 : 0);
        return yes(0.9);
      });
    });
    // The cynos key is the build's only key; the review runs in calls rather than as an agent.
    const plan: BuildPlan = {
      name: 'cs-test-knowledge-base',
      project,
      runtime: new DockerRuntime({ assets: '/action' }),
      paths: DOCKER_PATHS,
      work,
      cynosKey: 'sk-cynos-secret',
      reviewAgent: false,
      maxHypothesisPackets: 3,
    };
    const summary = await buildKnowledgeBase(plan, () => {}, transport, {
      decisions: new CynosDecisions(plan.cynosKey, 5, fetchImpl, async () => {}),
      chat: new CynosChat(plan.cynosKey, fetchImpl, async () => {}),
    });

    expect(summary).toMatchObject({
      kind: 'full',
      product_files: 2,
      functions: 2,
      entries: 1,
      sinks: 1,
      secret_windows: 1,
      hypotheses: { computed: 0, packets: 0 },
    });
    expect(summary.briefs.map(b => b.id)).toEqual(['injection', 'auth', 'baseline']);
    // The hypothesis templates' questions ride on each function's call; the phase follows, only of the
    // functions that touch state a later request uses (here, both).
    expect(asked.filter(q => q.includes('sink'))[0]).toEqual(
      expect.arrayContaining([
        'entry_point',
        'sink',
        'non_local_exit',
        'persistent_state',
        'memory',
      ])
    );
    expect(asked.filter(q => q.join() === 'phase')).toHaveLength(2);
    // The lead reads one row per helper; no source.
    const index = readFileSync(join(work, KNOWLEDGE_BASE_OUTPUT, 'code-graph.md'), 'utf8');
    expect(index).toContain('| packet_auth | auth |');
    expect(index).toContain('| baseline_auditor | baseline |');
    expect(index).not.toContain('==> ');
    // No hypothesis (no function here runs in a request phase), so no hypothesis packet.
    expect(index).not.toContain('packet_hypotheses_');
    // Each brief: the reader's instructions, chains, and its core printed with line numbers.
    const kb = join(work, KNOWLEDGE_BASE_INDEX);
    const brief = (id: string) => readFileSync(join(kb, 'packets', `${id}.md`), 'utf8');
    expect(brief('injection')).toContain(EXEC_HEADER);
    expect(brief('injection')).toContain('reported by packet `auth`');
    expect(brief('injection')).toMatch(/==> app\/db.py \(lines 1-2\) <==\n\s+1\tdef find/);
    expect(brief('auth')).toContain('-> `app.db.find` (app/db.py:1, database)');
    expect(brief('baseline')).toContain('==> tests/test_login.py (lines 1-1) <==');
    for (const name of ['files.tsv', 'functions.tsv', 'packets/auth.md'])
      expect(existsSync(join(kb, name))).toBe(true);
    expect(statSync(join(kb, 'kb')).mode & 0o111).toBeTruthy();
    // The graph's container is removed, and the key reaches neither docker nor the output.
    expect(commands.at(-1)).toEqual(['rm', '--force', plan.name]);
    expect(JSON.stringify(commands)).not.toContain('sk-cynos-secret');
    expect(spawnSync('grep', ['-r', 'sk-cynos-secret', work]).status).toBe(1);
    // Every model call went to cynos: Jev's decisions, the review's and the design's chat.
    expect(new Set(urls)).toEqual(
      new Set([`${BASE_URL}/decisions`, `${BASE_URL}/chat/completions`])
    );
    expect(summary.jev_calls).toBeGreaterThan(0);
    expect(summary.cost_usd).toBeCloseTo(summary.jev_calls * 1000 * 4.2e-8, 4);
  });
});

describe('cache', () => {
  it('answers a repeated Jev request from the cache, and keeps it across builds', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'kb-cache-'));
    let calls = 0;
    const fetchImpl = async (_: string, init: RequestInit): Promise<Response> => {
      calls += 1;
      const body = JSON.parse(String(init.body)) as Record<string, unknown>;
      return new Response(JSON.stringify(decisionFor(body, () => yes(0.7))));
    };
    const questions = { q: asked() };
    const first = new CynosDecisions('k', 5, fetchImpl, async () => {});
    first.cache = new AnswerCache(join(dir, 'answers.jsonl'));
    expect(await first.decide({ content: 'x' }, questions)).toEqual({ q: yes(0.7) });
    expect(await first.decide({ content: 'x' }, questions)).toEqual({ q: yes(0.7) });
    expect(calls).toBe(1);
    const next = new CynosDecisions('k', 5, fetchImpl, async () => {});
    next.cache = new AnswerCache(join(dir, 'answers.jsonl'));
    expect(await next.decide({ content: 'x' }, questions)).toEqual({ q: yes(0.7) });
    expect(await next.decide({ content: 'changed' }, questions)).toEqual({ q: yes(0.7) });
    expect([calls, next.cache.hits]).toEqual([2, 1]);
    // A stored answer is given even past the cost cap: only a new call is refused.
    const capped = new CynosDecisions('k', 0, fetchImpl, async () => {});
    capped.cache = new AnswerCache(join(dir, 'answers.jsonl'));
    expect(await capped.decide({ content: 'x' }, questions)).toEqual({ q: yes(0.7) });
    await expect(capped.decide({ content: 'new' }, questions)).rejects.toBeInstanceOf(
      CostCapReached
    );
  });

  it('keys the code graph on every file path and its content', () => {
    const a = [row('a.py', 'x = 1'), row('b.py', 'y = 2')];
    expect(checkoutHash(a)).toBe(checkoutHash([row('a.py', 'x = 1'), row('b.py', 'y = 2')]));
    expect(checkoutHash(a)).not.toBe(checkoutHash([row('a.py', 'x = 1'), row('b.py', 'y = 3')]));
  });
});

describe('stored review for diff scans', () => {
  const review = (boundaries: string[], assumptions: string[] = []): ArchitectureReview =>
    ({
      threatModel: {
        origin: 'generated',
        summary: 'A gateway.',
        scope: { includePaths: ['.'], summary: 'Whole repository.' },
        assets: [],
        trustBoundaries: boundaries,
        attackerCapabilities: [],
        securityObjectives: [],
        assumptions,
      },
      effectiveResources: [],
      resolvedQuestions: [],
    }) as ArchitectureReview;

  it('keeps the review of a full scan, and reads it back', () => {
    const dir = mkdtempSync(join(tmpdir(), 'kb-review-'));
    expect(loadReview(dir)).toBeUndefined();
    saveReview(dir, 'abc123', review(['Client -> API (app/api.py:3)']));
    expect(loadReview(dir)?.sha).toBe('abc123');
    writeFileSync(join(dir, REVIEW_FILE), 'not json');
    expect(loadReview(dir)).toBeUndefined();
  });

  it('checks citations against the current checkout and redacts credentials, leaving the stored copy', () => {
    const rows = [row('app/api.py', 'a\nb\nc\nAPI_TOKEN = "s3cr3t-value-1234"\n')];
    const stored = {
      version: 1 as const,
      sha: 'abc123',
      review: review(
        ['Client -> API (app/api.py:3)', 'Old route (app/gone.py:7)', 'Too far (app/api.py:90)'],
        ['The token s3cr3t-value-1234 is set in app/api.py:4']
      ),
    };
    const { review: reused, stats } = reuseReview(stored, rows);
    const text = JSON.stringify(reused);
    expect(text).toContain('app/api.py:3');
    expect(text).not.toContain('app/gone.py:7');
    expect(text).not.toContain('app/api.py:90');
    expect(text).not.toContain('s3cr3t-value-1234');
    expect(stats).toMatchObject({ sha: 'abc123', cut: 2, redacted: 1 });
    expect(JSON.stringify(stored.review)).toContain('app/gone.py:7');
  });
});

describe('cache pruning', () => {
  it('keeps only the answers a build used, and only the current graph', () => {
    const dir = mkdtempSync(join(tmpdir(), 'kb-compact-'));
    const path = join(dir, 'answers.jsonl');
    const old = new AnswerCache(path);
    old.set('gone', 1);
    old.set('kept', 2);
    const next = new AnswerCache(path);
    expect(next.get<number>('kept')).toBe(2);
    next.set('new', 3);
    next.compact();
    expect(new AnswerCache(path).size).toBe(2);
    expect(readFileSync(path, 'utf8')).not.toContain('gone');
    const graph = { index: {}, functions: [], calls: [] as [string, string][] };
    saveGraph(dir, 'aa', graph);
    saveGraph(dir, 'bb', graph);
    pruneGraphs(dir, 'bb');
    expect([
      existsSync(join(dir, 'graph-aa.json')),
      existsSync(join(dir, 'graph-bb.json')),
    ]).toEqual([false, true]);
  });
});
