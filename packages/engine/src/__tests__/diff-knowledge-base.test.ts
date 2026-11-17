import { describe, expect, it } from 'bun:test';
import { cpSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { KNOWLEDGE_BASE_INDEX, KNOWLEDGE_BASE_OUTPUT } from '../constants';
import {
  citedRanges,
  reviewArchitecture,
  updateEvidence,
  type ArchitectureReview,
} from '../knowledge-base/architecture';
import { checklist, shellWord, type AgentInput } from '../knowledge-base/architecture-agent';
import { CynosChat, CynosDecisions } from '../knowledge-base/cynos';
import {
  buildDiffKnowledgeBase,
  changedFunctions,
  checkedDiffDesign,
  baseRows,
  DIFF_BASELINE,
  functionPaths,
  headerPath,
  MAX_PATHS,
  mentionsPath,
  packetRules,
  pathFunctions,
  parseDiff,
  reviewGate,
  valueEdge,
  type DiffBuildPlan,
} from '../knowledge-base/diff';
import { diffBriefing, diffTaskName } from '../knowledge-base/diff-briefing';
import { saveReview } from '../knowledge-base/stored-review';
import type { FunctionNode } from '../knowledge-base/code-graph';
import { DockerRuntime, DOCKER_PATHS } from '../runtime/docker';
import { bundledPluginRoot } from '../upstream';
import {
  decisionFor,
  fakeFetch,
  fakeServer,
  gitCheckout,
  gitCommit,
  gitHead,
  pick,
  recordingRunner,
  reviewOf,
  row,
  yes,
} from './knowledge-base-fakes';

const ASSETS = resolve(import.meta.dir, '../../assets');

const fn = (qn: string, path: string, start: number, end: number): FunctionNode => ({
  qn,
  name: qn.split('.').pop() as string,
  path,
  start,
  end,
});

describe('the change', () => {
  it('reads every kind of file change, with the HEAD lines each hunk changed', () => {
    const diff = [
      'diff --git a/app/api.py b/app/api.py',
      'index 1..2 100644',
      '--- a/app/api.py',
      '+++ b/app/api.py',
      '@@ -1,4 +1,5 @@',
      ' def login(req):',
      '-    return req',
      '+    user = req.user',
      '+    return user',
      ' ',
      ' def other():',
      'diff --git a/app/new.py b/app/new.py',
      'new file mode 100644',
      '--- /dev/null',
      '+++ b/app/new.py',
      '@@ -0,0 +1,2 @@',
      '+def added():',
      '+    pass',
      'diff --git a/docs/old.md b/docs/old.md',
      'deleted file mode 100644',
      '--- a/docs/old.md',
      '+++ /dev/null',
      '@@ -1 +0,0 @@',
      '-old',
      'diff --git a/lib/a.py b/lib/b.py',
      'similarity index 90%',
      'rename from lib/a.py',
      'rename to lib/b.py',
      'diff --git a/logo.png b/logo.png',
      'Binary files a/logo.png and b/logo.png differ',
    ].join('\n');
    const changes = parseDiff(diff);
    expect(changes.map(c => [c.status, c.path])).toEqual([
      ['modified', 'app/api.py'],
      ['added', 'app/new.py'],
      ['deleted', 'docs/old.md'],
      ['renamed', 'lib/b.py'],
      ['modified', 'logo.png'],
    ]);
    // The removed line marks both lines it sits between (1 and 2); the added ones are 2 and 3.
    expect(changes[0]?.hunks[0]?.changedLines).toEqual([1, 2, 3]);
    expect(changes[1]?.hunks[0]?.changedLines).toEqual([1, 2]);
    expect(changes[3]?.from).toBe('lib/a.py');
    expect(changes[4]?.binary).toBe(true);
  });

  it('decodes a path git quoted: a quote, a tab, octal bytes', () => {
    const changes = parseDiff(
      [
        'diff --git "a/a\\"b.py" "b/a\\"b.py"',
        '--- "a/a\\"b.py"',
        '+++ "b/a\\"b.py"',
        '@@ -1 +1,2 @@',
        ' x',
        '+z',
        'diff --git "a/tab\\t\\303\\251.py" "b/tab\\t\\303\\251.py"',
        '--- "a/tab\\t\\303\\251.py"',
        '+++ "b/tab\\t\\303\\251.py"',
        '@@ -1 +1,2 @@',
        ' y',
        '+w',
      ].join('\n')
    );
    expect(changes.map(c => c.path)).toEqual(['a"b.py', 'tab\té.py']);
    expect(headerPath('plain/path.py')).toBe('plain/path.py');
  });

  it('decodes a quoted path in the headers a mode change or a binary file has alone', () => {
    // As git writes them for `a"b.sh` made executable and a binary `q"b.bin` added.
    const changes = parseDiff(
      [
        'diff --git "a/a\\"b.sh" "b/a\\"b.sh"',
        'old mode 100644',
        'new mode 100755',
        'diff --git "a/q\\"b.bin" "b/q\\"b.bin"',
        'new file mode 100644',
        'index 0000000..8835708',
        'Binary files /dev/null and "b/q\\"b.bin" differ',
        'diff --git a/plain dir/x.bin b/plain dir/x.bin',
        'index bdc955b..8835708 100644',
        'Binary files a/plain dir/x.bin and b/plain dir/x.bin differ',
        // A bare path that holds " b/" itself, made executable, and one that holds " and b/".
        'diff --git a/foo b/run.sh b/foo b/run.sh',
        'old mode 100644',
        'new mode 100755',
        'diff --git a/x and b/y.bin b/x and b/y.bin',
        'deleted file mode 100644',
        'Binary files a/x and b/y.bin and /dev/null differ',
      ].join('\n')
    );
    expect(changes.map(c => [c.status, c.path, c.binary])).toEqual([
      ['modified', 'a"b.sh', false],
      ['added', 'q"b.bin', true],
      ['modified', 'plain dir/x.bin', true],
      ['modified', 'foo b/run.sh', false],
      ['deleted', 'x and b/y.bin', true],
    ]);
  });

  it('counts a function as changed when a changed line falls in its HEAD range', () => {
    const [change] = parseDiff(
      [
        'diff --git a/a.py b/a.py',
        '--- a/a.py',
        '+++ b/a.py',
        '@@ -5,3 +5,3 @@',
        ' x',
        '-y',
        '+z',
        ' w',
      ].join('\n')
    );
    const functions = [
      fn('a.one', 'a.py', 1, 4),
      fn('a.two', 'a.py', 5, 9),
      fn('b.x', 'b.py', 5, 9),
    ];
    expect(changedFunctions(change ? [change] : [], functions).map(f => f.qn)).toEqual(['a.two']);
  });

  it('counts a function as changed when a line just above it was removed: a decorator, a check', () => {
    const [change] = parseDiff(
      [
        'diff --git a/a.py b/a.py',
        '--- a/a.py',
        '+++ b/a.py',
        '@@ -1,4 +1,3 @@',
        ' import auth',
        '-@auth.require_login',
        ' def handler(req):',
        '     return req',
      ].join('\n')
    );
    // Line 1 is the import, line 2 the handler at HEAD; the decorator sat between them.
    expect(change?.hunks[0]?.changedLines).toEqual([1, 2]);
    const functions = [fn('a.handler', 'a.py', 2, 3)];
    expect(changedFunctions(change ? [change] : [], functions).map(f => f.qn)).toEqual([
      'a.handler',
    ]);
  });
});

/** The ZDR shape of the 64-minute diff: a changed context builder, reached through wiring. */
const ZDR = {
  functions: [
    fn('server.internalslm.new_internal_call_context', 'server/internalslm.py', 1, 3),
    fn('server.internalslm.new_internal_shadow_context', 'server/internalslm.py', 5, 6),
    fn('server.plugins.load_builtin_plugin', 'server/plugins.py', 3, 4),
    fn('plugins.shadowjudge.start_shadow_judge', 'plugins/shadowjudge.py', 4, 6),
    fn('api.routes.handle', 'api/routes.py', 3, 4),
    fn('tests.test_slm.test_shadow', 'tests/test_slm.py', 3, 4),
  ],
  calls: [
    [
      'server.internalslm.new_internal_shadow_context',
      'server.internalslm.new_internal_call_context',
    ],
    ['tests.test_slm.test_shadow', 'server.internalslm.new_internal_shadow_context'],
    ['api.routes.handle', 'plugins.shadowjudge.start_shadow_judge'],
  ] as [string, string][],
  references: [
    ['server.plugins.load_builtin_plugin', 'server.internalslm.new_internal_shadow_context'],
  ] as [string, string][],
};

describe('the paths through the change', () => {
  it('reaches the changed function through the code that wires its caller in, and leaves tests out', () => {
    const changed = ZDR.functions.slice(0, 1);
    const [paths] = functionPaths(changed, ZDR.calls, ZDR.references, ZDR.functions, path =>
      path.startsWith('tests/')
    );
    expect(paths?.callers).toEqual([
      ['server.plugins.load_builtin_plugin', 'server.internalslm.new_internal_shadow_context'],
    ]);
    expect(JSON.stringify(paths)).not.toContain('test_shadow');
  });

  it('stops a caller path at an entry point', () => {
    const functions = [
      fn('a.changed', 'a.py', 1, 2),
      fn('a.route', 'a.py', 3, 4),
      fn('a.main', 'a.py', 5, 6),
    ];
    const calls: [string, string][] = [
      ['a.route', 'a.changed'],
      ['a.main', 'a.route'],
    ];
    const [open] = functionPaths(functions.slice(0, 1), calls, [], functions, () => false);
    const [cut] = functionPaths(
      functions.slice(0, 1),
      calls,
      [],
      functions,
      () => false,
      qn => qn === 'a.route'
    );
    expect(open?.callers).toEqual([['a.main', 'a.route']]);
    expect(cut?.callers).toEqual([['a.route']]);
  });
});

describe('ranking the paths', () => {
  it('keeps the path that reaches an entry point ahead of a dozen shallow dead ends', () => {
    // a.c00..a.c11 call the changed function and nothing calls them; z.route reaches it in two.
    const dead = Array.from({ length: 12 }, (_, i) =>
      fn(`a.c${String(i).padStart(2, '0')}`, 'a.py', 10 + i, 10 + i)
    );
    const functions = [
      fn('x.changed', 'x.py', 1, 2),
      fn('z.mid', 'z.py', 1, 2),
      fn('z.route', 'z.py', 3, 4),
      ...dead,
    ];
    const calls: [string, string][] = [
      ...dead.map(d => [d.qn, 'x.changed'] as [string, string]),
      ['z.mid', 'x.changed'],
      ['z.route', 'z.mid'],
    ];
    const [paths] = functionPaths(
      functions.slice(0, 1),
      calls,
      [],
      functions,
      () => false,
      qn => qn === 'z.route'
    );
    expect(paths?.callers[0]).toEqual(['z.route', 'z.mid']);
    expect(paths?.callers).toHaveLength(MAX_PATHS);
    expect(paths?.more.callers).toBe(1);
  });

  it('finds a direct caller that is an entry point however many paths earlier callers fan out to', () => {
    // a.c00..a.c21 call the changed function, each called by 22 functions, each called by 22 more:
    // over ten thousand paths, all of them before z.entry in name order.
    const callers = Array.from({ length: 22 }, (_, i) => `a.c${String(i).padStart(2, '0')}`);
    const calls: [string, string][] = [['z.entry', 'x.changed']];
    const names = new Set(['x.changed', 'z.entry']);
    for (const c of callers) {
      calls.push([c, 'x.changed']);
      names.add(c);
      for (let j = 0; j < 22; j++) {
        const up = `${c}.u${j}`;
        calls.push([up, c]);
        names.add(up);
        for (let k = 0; k < 22; k++) {
          calls.push([`${up}.v${k}`, up]);
          names.add(`${up}.v${k}`);
        }
      }
    }
    const functions = [...names].map(qn => fn(qn, `${qn.split('.')[0]}.py`, 1, 2));
    const [paths] = functionPaths(
      functions.filter(f => f.qn === 'x.changed'),
      calls,
      [],
      functions,
      () => false,
      qn => qn === 'z.entry'
    );
    expect(paths?.callers[0]).toEqual(['z.entry']);
  });

  it("finds an entry point two steps up behind thousands of other callers' callers", () => {
    // 334 callers a.c000..a.c333, each called by 30 functions, then z.late, called by 30 too,
    // z.entry among them: past ten thousand paths before z.late's parents are reached.
    const calls: [string, string][] = [
      ['z.late', 'x.changed'],
      ['z.entry', 'z.late'],
    ];
    const names = new Set(['x.changed', 'z.late', 'z.entry']);
    for (let j = 0; j < 29; j++) {
      calls.push([`z.late.p${j}`, 'z.late']);
      names.add(`z.late.p${j}`);
    }
    for (let i = 0; i < 334; i++) {
      const c = `a.c${String(i).padStart(3, '0')}`;
      calls.push([c, 'x.changed']);
      names.add(c);
      for (let j = 0; j < 30; j++) {
        calls.push([`${c}.p${j}`, c]);
        names.add(`${c}.p${j}`);
      }
    }
    const functions = [...names].map(qn => fn(qn, `${qn.split('.')[0]}.py`, 1, 2));
    const [paths] = functionPaths(
      functions.filter(f => f.qn === 'x.changed'),
      calls,
      [],
      functions,
      () => false,
      qn => qn === 'z.entry'
    );
    expect(paths?.callers[0]).toEqual(['z.entry', 'z.late']);
  });

  it('labels every function the paths reach, so an entry point behind hundreds of others is found', () => {
    const callers = Array.from({ length: 650 }, (_, i) => `a.c${String(i).padStart(3, '0')}`);
    const calls: [string, string][] = [
      ...callers.map(c => [c, 'x.changed'] as [string, string]),
      ['z.entry', 'x.changed'],
    ];
    const functions = ['x.changed', 'z.entry', ...callers].map(qn => fn(qn, 'a.py', 1, 2));
    const walked = functionPaths(
      functions.slice(0, 1),
      calls,
      [],
      functions,
      () => false,
      () => false,
      () => false,
      Infinity
    );
    expect(pathFunctions(walked)).toContain('z.entry');
  });

  it('keeps the callee path that reaches a sensitive operation first, wherever on the path it is', () => {
    const functions = [
      fn('x.changed', 'x.py', 1, 2),
      fn('a.helper', 'a.py', 1, 2),
      fn('b.query', 'b.py', 1, 2),
      fn('b.format', 'b.py', 3, 4),
    ];
    const calls: [string, string][] = [
      ['x.changed', 'a.helper'],
      ['x.changed', 'b.query'],
      ['b.query', 'b.format'],
    ];
    const [paths] = functionPaths(
      functions.slice(0, 1),
      calls,
      [],
      functions,
      () => false,
      () => false,
      qn => qn === 'b.query'
    );
    expect(paths?.callees[0]).toEqual(['b.query', 'b.format']);
  });
});

describe('the changed files at the base', () => {
  it('are read as they were, deleted, modified or renamed, and an added one has no base', () => {
    const project = gitCheckout({
      'auth/middleware.py': 'def check(req):\n    return req\n',
      'auth/views.py': 'def view(req):\n    check(req)\n',
      'old/name.py': 'x = 1\n',
    });
    const base = gitHead(project);
    gitCommit(project, {
      'auth/middleware.py': null,
      'auth/views.py': 'def view(req):\n    pass\n',
    });
    const change = (path: string, status: string, from?: string) => ({
      path,
      status: status as 'modified',
      ...(from ? { from } : {}),
      patch: '',
      hunks: [],
      binary: false,
    });
    const rows = baseRows(project, base, [
      change('auth/middleware.py', 'deleted'),
      change('auth/views.py', 'modified'),
      change('new/name.py', 'renamed', 'old/name.py'),
      change('added.py', 'added'),
    ]);
    expect(rows.map(r => [r.path, r.text])).toEqual([
      ['auth/middleware.py', 'def check(req):\n    return req\n'],
      ['auth/views.py', 'def view(req):\n    check(req)\n'],
      ['new/name.py', 'x = 1\n'],
    ]);
  });

  it('reads a text base of a file that became binary, and none of a binary base', () => {
    const project = gitCheckout({
      'auth/keys.py': 'def check(req):\n    return req\n',
      'logo.bin': '\u0000\u0001',
    });
    const base = gitHead(project);
    gitCommit(project, { 'auth/keys.py': '\u0000\u0002', 'logo.bin': '\u0000\u0003' });
    const change = (path: string) => ({
      path,
      status: 'modified' as const,
      patch: '',
      hunks: [],
      binary: true,
    });
    const rows = baseRows(project, base, [change('auth/keys.py'), change('logo.bin')]);
    expect(rows.map(r => [r.path, r.text])).toEqual([
      ['auth/keys.py', 'def check(req):\n    return req\n'],
    ]);
  });

  it('classifies a renamed file as what it was: a route moved into tests/ was a route', () => {
    const project = gitCheckout({ 'api/handler.py': 'def handle(req):\n    return req\n' });
    const base = gitHead(project);
    gitCommit(project, {
      'api/handler.py': null,
      'tests/handler.py': 'def handle(req):\n    return req\n',
    });
    const [row] = baseRows(project, base, [
      {
        path: 'tests/handler.py',
        status: 'renamed',
        from: 'api/handler.py',
        patch: '',
        hunks: [],
        binary: false,
      },
    ]);
    expect(row).toMatchObject({ path: 'tests/handler.py', kind: 'code' });
  });
});

describe('the threat model gate', () => {
  const labels = {
    roles: new Map(),
    fileLabels: new Map(),
    functionLabels: new Map(),
  };
  const change = (path: string, status = 'modified') => ({
    path,
    status: status as 'modified',
    patch: '',
    hunks: [],
    binary: false,
  });

  it('opens when the change touches a cited file, an architecture file, or an entry point', () => {
    const review = reviewOf(['Client -> login (app/api.py:3)']);
    expect(reviewGate(review, [change('app/api.py')], [], labels)).toEqual([
      'app/api.py (modified) is cited by the threat model',
    ]);
    const roles = new Map([['deploy/compose.yml', { architecture_role: pick('deployment') }]]);
    expect(reviewGate(review, [change('deploy/compose.yml')], [], { ...labels, roles })).toEqual([
      'deploy/compose.yml (modified) has the architecture role deployment',
    ]);
    const functionLabels = new Map([
      ['app.views.new_route', { entry_point: yes(0.9), sink: pick('none') }],
    ]);
    expect(
      reviewGate(
        review,
        [change('app/views.py')],
        [fn('app.views.new_route', 'app/views.py', 1, 3)],
        {
          ...labels,
          functionLabels,
        }
      )
    ).toEqual(['app.views.new_route is an entry point']);
  });

  it('opens when a changed file defines an entry point no function holds, now or at the base', () => {
    const review = reviewOf(['Client -> login (app/api.py:3)']);
    const routes = new Map([['app/urls.py', { entry_point: yes(0.9) }]]);
    expect(
      reviewGate(review, [change('app/urls.py')], [], { ...labels, fileLabels: routes })
    ).toEqual(['app/urls.py (modified) defines an entry point']);
    // The change removed the route table's last route: only the base shows it.
    const base = { roles: new Map(), fileLabels: routes };
    expect(reviewGate(review, [change('app/urls.py')], [], { ...labels, base })).toEqual([
      'app/urls.py (modified) defined an entry point',
    ]);
  });

  it('opens when the stored review names a changed file bare: a citation the full review cut', () => {
    const review = reviewOf(['Auth boundary (server/auth.py)', 'Unrelated (server/auth.pyc.md:1)']);
    expect(reviewGate(review, [change('server/auth.py')], [], labels)).toEqual([
      'server/auth.py (modified) is cited by the threat model',
    ]);
    expect(reviewGate(review, [change('auth.py')], [], labels)).toEqual([]);
  });

  it('stays shut for a helper the model never mentions', () => {
    const review = reviewOf(['Client -> login (app/api.py:3)']);
    expect(
      reviewGate(review, [change('app/util.py')], [fn('app.util.pad', 'app/util.py', 1, 2)], labels)
    ).toEqual([]);
  });
});

describe("upstream's packet rules", () => {
  it("are the pinned plugin's three rules", () => {
    const rules = packetRules(bundledPluginRoot());
    expect(rules).toHaveLength(3);
    expect(rules[0]).toStartWith('4. Group promising source-backed questions');
    expect(rules[1]).toContain('Choose assignments by complexity and shared code');
    expect(rules[2]).toContain(
      'expand to sibling callers when a changed shared control affects them'
    );
  });

  it('refuse a plugin whose rules moved', () => {
    const plugin = join(mkdtempSync(join(tmpdir(), 'kb-rules-')), 'plugin');
    cpSync(bundledPluginRoot(), plugin, { recursive: true });
    writeFileSync(join(plugin, 'references/core-scan.md'), 'rewritten\n');
    expect(() => packetRules(plugin)).toThrow('not where the pinned plugin had them');
  });
});

describe('the packet design check', () => {
  it('keeps changed files from the change, gives every changed product file a packet, and needs one', () => {
    const changed = ['server/internalslm.py', 'plugins/logging/main.go'];
    const files = new Set([...changed, 'server/plugins.py']);
    const related = new Map([['plugins/logging/main.go', new Set(['server/plugins.py'])]]);
    const packets = checkedDiffDesign(
      {
        packets: [
          {
            id: 'ZDR propagation',
            changed_files: ['server/internalslm.py', 'nope.py'],
            context_files: ['server/plugins.py', 'gone.py'],
            perspective: 'ZDR now reaches internal calls.',
            attacker: 'A tenant holding a virtual key',
            questions: ['Does `newInternalCallContext` copy the flag?'],
          },
          { id: 'ZDR propagation', changed_files: [] },
          {
            id: DIFF_BASELINE,
            changed_files: ['server/internalslm.py'],
            perspective: 'The same change, again.',
            attacker: 'A tenant holding a virtual key',
            questions: ['Which callers reach it?'],
          },
        ],
      },
      changed,
      files,
      related
    );
    expect(packets.map(p => p.id)).toEqual(['zdr-propagation', `${DIFF_BASELINE}-x`]);
    // main.go no packet took joins the one whose context shares its paths' files.
    expect(packets[0]?.changed).toEqual(['server/internalslm.py', 'plugins/logging/main.go']);
    expect(packets[0]?.context).toEqual(['server/plugins.py']);
    // ...with a question of its own, since the questions bound the helper's review.
    expect(packets[0]?.questions.at(-1)).toContain('`plugins/logging/main.go`');
    expect(() =>
      checkedDiffDesign(
        { packets: [{ id: 'x', changed_files: ['nope.py'] }] },
        changed,
        files,
        related
      )
    ).toThrow('no packet of the design reviews a changed product file');
    // A packet without questions has nothing bounding its review: the design is asked again.
    expect(() =>
      checkedDiffDesign(
        {
          packets: [
            {
              id: 'open',
              changed_files: ['server/internalslm.py'],
              perspective: 'p',
              attacker: 'a',
              questions: [' '],
            },
          ],
        },
        changed,
        files,
        related
      )
    ).toThrow('packets with no questions: open');
    // Nor without its perspective or attacker, which frame the helper's assignment.
    expect(() =>
      checkedDiffDesign(
        {
          packets: [
            { id: 'bare', changed_files: ['server/internalslm.py'], questions: ['Who calls it?'] },
          ],
        },
        changed,
        files,
        related
      )
    ).toThrow('packets with no perspective or attacker: bare');
  });

  it('gives every packet its own task name, which names its helper and its result file', () => {
    const packet = (id: string) => ({
      id,
      changed_files: ['a.py'],
      perspective: 'p',
      attacker: 'a',
      questions: ['q?'],
    });
    const packets = checkedDiffDesign(
      { packets: [packet('auth'), packet('packet-auth'), packet('diff-baseline')] },
      ['a.py'],
      new Set(['a.py']),
      new Map()
    );
    const names = packets.map(p => diffTaskName(p.id));
    expect(new Set([...names, diffTaskName(DIFF_BASELINE)]).size).toBe(names.length + 1);
  });
});

describe('the threat model update', () => {
  it('is cored on the change and what the starting review cites around it, and may keep its citations', () => {
    const rows = [
      row('server/internalslm.py', 'def a():\n    return 1\n\ndef b():\n    return a()'),
      row('server/plugins.py', 'x = 1\ny = 2\nz = 3'),
      row('api/routes.py', 'def handle():\n    pass'),
    ];
    const previous = reviewOf([
      'Plugins wire contexts (server/plugins.py:2)',
      'Client -> handler (api/routes.py:1)',
    ]);
    const evidence = updateEvidence({
      rows,
      product: rows,
      functions: [],
      fileLabels: new Map(),
      functionLabels: new Map(),
      roles: new Map(),
      entryFiles: new Map(),
      cynos: { chatJson: async () => '{}' },
      update: {
        previous,
        change: '',
        changedFiles: ['server/internalslm.py'],
        changedFunctions: new Set(),
      },
    });
    expect(evidence.map(e => [e.path, e.why])).toEqual([
      ['server/internalslm.py', 'changed'],
      ['server/plugins.py', 'cited by the starting review'],
    ]);
    expect(citedRanges(previous).get('api/routes.py')).toEqual([[1, 1]]);
  });

  it("cuts a kept citation into a changed file's lines the update never read, and keeps one into an unchanged file", async () => {
    // big.py is large, and the starting review cites so much of it that the update's core runs
    // out before the last citations: the update never reads lines 19000-19150.
    const line = (i: number) => `x${i} = "${'v'.repeat(48)}"`;
    const big = Array.from({ length: 20000 }, (_, i) => line(i + 1)).join('\n');
    const rows = [row('big.py', big), row('other.py', 'def ok():\n    pass')];
    const filler = Array.from(
      { length: 40 },
      (_, i) => `Filler (big.py:${1000 + i * 300}-${1150 + i * 300})`
    );
    const previous = reviewOf([
      ...filler,
      'Stale fact (big.py:19000-19150)',
      'Changed fact (big.py:105)',
      'Unchanged fact (other.py:1)',
    ]);
    const answer = JSON.stringify(previous);
    const { review } = await reviewArchitecture(
      {
        rows,
        product: rows,
        functions: [fn('big.changed', 'big.py', 100, 110)],
        fileLabels: new Map(),
        functionLabels: new Map(),
        roles: new Map(),
        entryFiles: new Map(),
        cynos: { chatJson: async () => answer },
        update: {
          previous,
          change: '',
          changedFiles: ['big.py'],
          changedFunctions: new Set(['big.changed']),
        },
      },
      () => {}
    );
    const kept = review.threatModel.trustBoundaries;
    expect(kept).toContain('Stale fact (big.py)');
    expect(kept).toContain('Changed fact (big.py:105)');
    expect(kept).toContain('Unchanged fact (other.py:1)');
  });

  it('checks only the components that hold a changed file', () => {
    const rows = [row('server/a.py', 'x'), row('billing/b.py', 'y')];
    const roles = new Map(rows.map(r => [r.path, { architecture_role: pick('routes') }]));
    const input: AgentInput = {
      core: '',
      corePrinted: new Map(),
      rows,
      functions: [],
      fileLabels: new Map(),
      functionLabels: new Map(),
      roles,
      entryFiles: new Map(),
      maintained: '',
    };
    expect(
      checklist(input)
        .map(i => i.component)
        .sort()
    ).toEqual(['billing', 'server']);
    expect(checklist({ ...input, scope: new Set(['server/a.py']) }).map(i => i.component)).toEqual([
      'server',
    ]);
  });
});

/** The fixture checkout at its base, and the change that follows it. */
const BASE_FILES = {
  'docs/threat-model.md': '# Threat model\n\nTenants reach the gateway with a virtual key.\n',
  'server/admin.py':
    'import os\n\ndef run(cmd):\n    return os.system(cmd)\n\ndef other():\n    pass\n',
  'server/auth.py': 'def require_key(req):\n    return req.headers.get("x-api-key")\n',
  'server/internalslm.py':
    'def new_internal_call_context(parent):\n    return {"zdr": False}\n\ndef new_internal_shadow_context(parent):\n    return new_internal_call_context(parent)\n',
  'server/plugins.py':
    'from server.internalslm import new_internal_shadow_context\n\ndef load_builtin_plugin(judge):\n    judge.shadow_context = new_internal_shadow_context\n',
  'plugins/shadowjudge.py':
    'def detached_request_context(ctx):\n    return {}\n\ndef start_shadow_judge(ctx, cb):\n    parent = detached_request_context(ctx)\n    return cb(parent)\n',
  'api/routes.py':
    'from plugins.shadowjudge import start_shadow_judge\n\ndef handle(req):\n    return start_shadow_judge(req, None)\n',
  'tests/test_slm.py':
    'from server.internalslm import new_internal_shadow_context\n\ndef test_shadow():\n    assert new_internal_shadow_context({})\n',
  'README.md': '# Gateway\n',
};
const CHANGE = {
  'server/internalslm.py':
    'def new_internal_call_context(parent):\n    zdr = parent.get("zdr", False)\n    return {"zdr": zdr}\n\ndef new_internal_shadow_context(parent):\n    return new_internal_call_context(parent)\n',
  'README.md': '# Gateway\n\nPer-call ZDR.\n',
};

/** The graph at HEAD, as the fake server answers its queries. */
const graphAnswer = (tool: string, args: Record<string, unknown>): unknown => {
  if (tool === 'index_repository') return { project: 'scan', status: 'indexed' };
  const query = String(args['query']);
  const scan = (qn: string) => `scan.${qn}`;
  if (query.includes('CALL_REFERENCE'))
    return { rows: ZDR.references.map(([a, b]) => [scan(a), scan(b), 'server/internalslm.py']) };
  if (query.includes('CALLS'))
    return { rows: ZDR.calls.map(([a, b]) => [scan(a), scan(b), 'x.py']) };
  return { rows: ZDR.functions.map(f => [scan(f.qn), f.name, f.path, f.start, f.end]) };
};

/** Jev: handle is the entry point, nothing performs a sensitive operation, no secrets. */
const jev = (name: string, state: Record<string, unknown>) => {
  if (name === 'entry_point')
    return yes(
      state['function'] === 'api.routes.handle' || state['path'] === 'api/routes.py' ? 0.9 : 0
    );
  if (name === 'sink')
    return pick(String(state['code'] ?? '').includes('os.system') ? 'execution' : 'none');
  if (name === 'architecture_role') return pick('none');
  if (name === 'access_control')
    return yes(String(state['content']).includes('x-api-key') ? 0.9 : 0);
  return yes(0);
};

/** A diff build of the fixture, its graph and model calls faked; returns what it called. */
async function buildFixture(
  stored: ArchitectureReview | undefined,
  change: Record<string, string | null> = CHANGE,
  /** The commit the stored review names, when not the fixture's own (another repository's). */
  storedSha?: string,
  /** A commit between the stored review's and the diff's base: an earlier diff's change. */
  between?: Record<string, string | null>
) {
  const project = gitCheckout(BASE_FILES);
  const reviewed = gitHead(project);
  const base = between ? gitCommit(project, between) : reviewed;
  gitCommit(project, change);
  const cacheDir = mkdtempSync(join(tmpdir(), 'kb-diff-cache-'));
  if (stored) saveReview(cacheDir, storedSha ?? reviewed, stored);
  const work = mkdtempSync(join(tmpdir(), 'kb-diff-work-'));
  const chats: { system: string; user: string }[] = [];
  const servers: string[][] = [];
  const commands: string[][] = [];
  const logs: string[] = [];
  const steps: string[] = [];
  const fetchImpl = fakeFetch((url, body) => {
    if (!url.endsWith('/chat/completions')) return decisionFor(body, jev);
    const [system, user] = (body['messages'] as { content: string }[]).map(m => m.content);
    chats.push({ system: system ?? '', user: user ?? '' });
    const answer = system?.includes('You split the security review')
      ? {
          packets: [
            {
              id: 'zdr',
              perspective: 'Per-call ZDR now reaches internal calls.',
              attacker: 'A tenant holding a virtual key, through the inference surface',
              changed_files: ['server/internalslm.py'],
              context_files: ['server/plugins.py'],
              questions: [
                "Does every caller of `server.internalslm.new_internal_call_context` pass the caller's ZDR flag?",
              ],
            },
          ],
        }
      : {
          threatModel: {
            summary: 'A gateway.',
            assets: [],
            trustBoundaries: [
              'Client -> handler (api/routes.py:3)',
              'Internal calls copy the caller ZDR flag (server/internalslm.py:2)',
              'Made up (server/internalslm.py:90)',
            ],
            attackerCapabilities: ['A tenant holding a virtual key, through the inference surface'],
            securityObjectives: [],
            assumptions: [],
          },
          effectiveResources: [],
          resolvedQuestions: [],
        };
    return { choices: [{ message: { content: JSON.stringify(answer) } }] };
  });
  const plan: DiffBuildPlan = {
    name: 'cs-test-knowledge-base',
    project,
    runtime: new DockerRuntime({ assets: ASSETS }),
    paths: DOCKER_PATHS,
    work,
    cynosKey: 'sk-cynos-secret',
    reviewAgent: false,
    cacheDir,
    base,
    plugin: () => bundledPluginRoot(),
    step: (step, message) => steps.push(`${step}: ${message}`),
  };
  const summary = await buildDiffKnowledgeBase(
    plan,
    message => logs.push(message),
    {
      decisions: new CynosDecisions(plan.cynosKey, 5, fetchImpl, async () => {}),
      chat: new CynosChat(plan.cynosKey, fetchImpl, async () => {}),
    },
    { run: recordingRunner(commands), connect: fakeServer(graphAnswer, servers) }
  );
  const kb = join(work, KNOWLEDGE_BASE_INDEX);
  const read = (path: string) => readFileSync(path, 'utf8');
  return { summary, work, kb, chats, servers, commands, read, base, logs, steps };
}

describe('buildDiffKnowledgeBase', () => {
  it('briefs each packet with its change and the paths through it, and updates a threat model the change touches', async () => {
    const stored = reviewOf([
      'Client -> handler (api/routes.py:3)',
      'Internal calls store nothing (server/internalslm.py:2)',
    ]);
    const { summary, work, kb, chats, servers, read, base } = await buildFixture(stored);

    expect(summary).toMatchObject({
      kind: 'diff',
      base,
      changed_files: 2,
      changed_functions: 1,
      graph: { functions: 6, calls: 3, call_references: 1 },
    });
    expect(servers).toHaveLength(1);

    // The threat model: the change touches a line it cites, so the reviewer updated it; a citation
    // of a line nobody saw is cut, one the starting review cited is kept.
    expect(summary.threat_model.gate).toEqual([
      'server/internalslm.py (modified) is cited by the threat model',
    ]);
    expect(summary.threat_model.updated).toBe(true);
    const tm = JSON.parse(read(join(work, KNOWLEDGE_BASE_OUTPUT, 'threat-model.json')));
    expect(tm.threatModel.trustBoundaries).toEqual([
      'Client -> handler (api/routes.py:3)',
      'Internal calls copy the caller ZDR flag (server/internalslm.py:2)',
      'Made up (server/internalslm.py)',
    ]);
    const update = chats.find(c => !c.system.includes('You split the security review'));
    expect(update?.user).toContain('Starting review:');
    expect(update?.user).toContain('Internal calls store nothing (server/internalslm.py:2)');

    // The design follows upstream's rules, with the threat model in front of it.
    const design = chats.find(c => c.system.includes('You split the security review'));
    expect(design?.system).toContain('Choose assignments by complexity and shared code');
    expect(design?.user).toContain('Internal calls copy the caller ZDR flag');

    // The packet's brief: the change, the path through the wiring, the core; no test.
    const brief = read(join(kb, 'packets', 'zdr.md'));
    expect(brief).toContain('## Questions');
    expect(brief).toContain('+    zdr = parent.get("zdr", False)');
    expect(brief).toContain(
      '`server.plugins.load_builtin_plugin` (server/plugins.py:3-4) =passes as a value=> `server.internalslm.new_internal_shadow_context` (server/internalslm.py:5-6) -> (changed)'
    );
    expect(brief).toMatch(/==> server\/plugins.py \(lines 3-4\) <==/);
    expect(brief).not.toContain('test_shadow');
    const order = [
      '## Scope',
      '## Threat model',
      '## Reading',
      '## The change',
      '## Paths through the change',
      '## Core',
    ];
    expect(order.map(h => brief.indexOf(h))).toEqual(
      [...order.map(h => brief.indexOf(h))].sort((a, b) => a - b)
    );

    // The README goes to the diff baseline; the lead's index names both helpers and no source.
    expect(read(join(kb, 'packets', `${DIFF_BASELINE}.md`))).toContain('+Per-call ZDR.');
    const index = read(join(work, KNOWLEDGE_BASE_OUTPUT, 'code-graph.md'));
    expect(index).toContain('| packet_zdr | zdr |');
    expect(index).toContain('| diff_baseline | diff-baseline |');
    expect(index).toContain(
      'updated for this change because server/internalslm.py (modified) is cited'
    );
    expect(index).not.toContain('==> ');
    expect(readdirSync(kb).sort()).toEqual(['files.tsv', 'functions.tsv', 'kb', 'packets']);
  });

  it('reuses a threat model the change leaves alone, with no model call for it', async () => {
    const { summary, chats, work } = await buildFixture(
      reviewOf(['Client -> handler (api/routes.py:3)'])
    );
    expect(summary.threat_model).toMatchObject({ gate: [], updated: false, review: null });
    expect(chats.every(c => c.system.includes('You split the security review'))).toBe(true);
    const tm = JSON.parse(
      readFileSync(join(work, KNOWLEDGE_BASE_OUTPUT, 'threat-model.json'), 'utf8')
    );
    expect(tm.threatModel.trustBoundaries).toEqual(['Client -> handler (api/routes.py:3)']);
  });

  it('updates the threat model when the change touches a file cited only at a line that is gone', async () => {
    // The stored review cites line 90 of a 6-line file: the check cuts that citation to the file.
    const { summary } = await buildFixture(
      reviewOf(['Client -> handler (api/routes.py:3)', 'Old fact (server/internalslm.py:90)'])
    );
    expect(summary.threat_model.gate).toContain(
      'server/internalslm.py (modified) is cited by the threat model'
    );
  });

  it('updates the threat model when the change deletes an access control it never cited', async () => {
    const { summary } = await buildFixture(reviewOf(['Client -> handler (api/routes.py:3)']), {
      ...CHANGE,
      'server/auth.py': null,
    });
    expect(summary.threat_model.gate).toContain(
      'server/auth.py (deleted) decided authentication or authorization'
    );
    expect(summary.threat_model.updated).toBe(true);
  });

  it('updates the threat model when the change removes the only access check from a file it keeps', async () => {
    const { summary } = await buildFixture(reviewOf(['Client -> handler (api/routes.py:3)']), {
      ...CHANGE,
      'server/auth.py': 'def require_key(req):\n    return True\n',
    });
    expect(summary.threat_model.gate).toContain(
      'server/auth.py (modified) decided authentication or authorization'
    );
  });

  it('updates the threat model when the change removes a sensitive operation from a file it keeps', async () => {
    const { summary } = await buildFixture(reviewOf(['Client -> handler (api/routes.py:3)']), {
      ...CHANGE,
      'server/admin.py': 'import os\n\ndef other():\n    pass\n',
    });
    expect(summary.threat_model.gate).toContain(
      'server/admin.py (modified) lost code that performed a sensitive operation (execution)'
    );
  });

  it("updates a review older than the diff base for every change since it, an earlier diff's too", async () => {
    // The earlier diff removed the only access check; this diff touches neither it nor the review.
    const { summary, chats } = await buildFixture(
      reviewOf(['Client -> handler (api/routes.py:3)']),
      CHANGE,
      undefined,
      { 'server/auth.py': 'def require_key(req):\n    return True\n' }
    );
    expect(summary.threat_model.gate).toContain(
      'server/auth.py (modified) decided authentication or authorization'
    );
    const update = chats.find(c => c.user.includes('Starting review:'));
    expect(update?.user).toContain('server/auth.py');
  });

  it("labels the paths of an earlier diff's change as the diff's own, entry points included", async () => {
    // The earlier diff changed start_shadow_judge, which the entry point api.routes.handle calls.
    const { chats } = await buildFixture(
      reviewOf(['Shadow judge (plugins/shadowjudge.py:4)']),
      CHANGE,
      undefined,
      {
        'plugins/shadowjudge.py':
          'def detached_request_context(ctx):\n    return {}\n\ndef start_shadow_judge(ctx, cb):\n    parent = detached_request_context(ctx)\n    return cb(parent, ctx)\n',
      }
    );
    const update = chats.find(c => c.user.includes('Starting review:'));
    expect(update?.user).toContain('reached from: `api.routes.handle` entry');
  });

  it('logs its packets, since the action prints only log lines and no progress events', async () => {
    const { logs, steps } = await buildFixture(reviewOf([]));
    expect(logs).toContain('1 packets: zdr');
    expect(steps).toContain('packets: 1 packets: zdr');
  });

  it("fails without a full scan's threat model, or with another repository's", async () => {
    await expect(buildFixture(undefined)).rejects.toThrow(
      "no full scan's threat model is stored for this repository: run a full scan first"
    );
    await expect(buildFixture(reviewOf([]), CHANGE, 'f'.repeat(40))).rejects.toThrow(
      `the stored threat model is of ${'f'.repeat(12)}, which is not in this checkout's history`
    );
  });

  it('keeps the key in this process', async () => {
    const { work, commands } = await buildFixture(reviewOf([]));
    expect(JSON.stringify(commands)).not.toContain('sk-cynos-secret');
    const files = (dir: string): string[] =>
      readdirSync(dir, { withFileTypes: true }).flatMap(e =>
        e.isDirectory() ? files(join(dir, e.name)) : [join(dir, e.name)]
      );
    for (const file of files(work))
      expect(readFileSync(file, 'utf8')).not.toContain('sk-cynos-secret');
  });
});

describe('the diff baseline brief', () => {
  it('quotes a path the shell would read otherwise, a leading ~ included, and leaves a plain one', () => {
    expect(shellWord('~/keys.txt:1-120')).toBe("'~/keys.txt:1-120'");
    expect(shellWord('conf/a~b.env:1-9')).toBe('conf/a~b.env:1-9');
    expect(shellWord("it's.txt")).toBe(`'it'\\''s.txt'`);
  });

  it('quotes the checkout in the command for the changes it does not print', () => {
    const path = 'docs/huge.md';
    const kb = diffBriefing({
      paths: { project: "/Users/dev/my repo; it's", kbIndex: '/scan/kb' },
      base: 'a'.repeat(40),
      rows: [row(path, 'x', 'docs')],
      functions: [],
      fileLabels: new Map(),
      functionLabels: new Map(),
      roles: new Map(),
      entryFiles: new Map(),
      calls: [],
      values: new Set(),
      changes: [{ path, status: 'modified', patch: 'x'.repeat(200_000), hunks: [], binary: false }],
      changed: [],
      through: [],
      packets: [],
      entries: [],
      sinks: new Map(),
      secretWindows: [],
      review: reviewOf([]),
      threatModel: { from: 'a'.repeat(40), gate: [], updated: false },
    });
    const brief = kb.files.get(`packets/${DIFF_BASELINE}.md`) ?? '';
    expect(brief).toContain(`git -C '/Users/dev/my repo; it'\\''s' diff ${'a'.repeat(40)} HEAD`);
  });

  it('quotes each path in the reader command for the secret windows it does not print', () => {
    const text = Array.from({ length: 120 }, (_, i) => `token_${i} = "${'k'.repeat(400)}"`).join(
      '\n'
    );
    const path = 'notes/my secrets; rm -rf ~.txt';
    const kb = diffBriefing({
      paths: { project: '/scan/project', kbIndex: '/scan/kb' },
      base: 'a'.repeat(40),
      rows: [row(path, text, 'docs')],
      functions: [],
      fileLabels: new Map(),
      functionLabels: new Map(),
      roles: new Map(),
      entryFiles: new Map(),
      calls: [],
      values: new Set(),
      changes: [{ path, status: 'modified', patch: '', hunks: [], binary: false }],
      changed: [],
      through: [],
      packets: [],
      entries: [],
      sinks: new Map(),
      secretWindows: [{ path, start: 1, end: 120 }],
      review: reviewOf([]),
      threatModel: { from: 'a'.repeat(40), gate: [], updated: false },
    });
    const brief = kb.files.get(`packets/${DIFF_BASELINE}.md`) ?? '';
    expect(brief).toContain(`sh /scan/kb/kb read 'notes/my secrets; rm -rf ~.txt:1-120'`);
  });
});

describe('naming a path', () => {
  it('counts a path only as a whole word', () => {
    expect(mentionsPath('Auth boundary (server/auth.py)', 'server/auth.py')).toBe(true);
    expect(mentionsPath('see server/auth.py.', 'server/auth.py')).toBe(true);
    expect(mentionsPath('server/auth.py:90 checks keys', 'server/auth.py')).toBe(true);
    expect(mentionsPath('see server/auth.pyc', 'server/auth.py')).toBe(false);
    expect(mentionsPath('see lib/server/auth.py', 'server/auth.py')).toBe(false);
    expect(mentionsPath('see server/auth.py.bak', 'server/auth.py')).toBe(false);
    // cutInvalid keeps a citation's spelling, ./ included.
    expect(mentionsPath('Auth boundary (./server/auth.py)', 'server/auth.py')).toBe(true);
  });
});

describe('the edge marker', () => {
  it('names a value passed from one function to another', () => {
    expect(valueEdge('a.wire', 'a.callback')).toBe('a.wire>a.callback');
  });
});

describe('task names', () => {
  it('prefix a packet once, however the design named it', () => {
    expect(diffTaskName('zdr-propagation')).toBe('packet_zdr_propagation');
    expect(diffTaskName('packet-3-internal-slm')).toBe('packet_3_internal_slm');
    expect(diffTaskName(DIFF_BASELINE)).toBe('diff_baseline');
  });
});
