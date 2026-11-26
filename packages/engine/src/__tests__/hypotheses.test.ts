import { describe, it, expect } from 'bun:test';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import {
  briefSections,
  computeHypotheses,
  labelQuestions,
  hypothesisPackets,
  TEMPLATES,
  type Hypothesis,
  type Labels,
  type HypothesisInput,
  type HypothesisTemplate,
  type SourceFunction,
} from '../hypotheses';
import { globalWrites } from '../hypotheses/languages/c';
import { functionBody, linesByPath, matchingBrace } from '../hypotheses/source';
import { facts, reachedState } from '../hypotheses/templates/interrupted-request/facts';
import { briefing } from '../knowledge-base/briefing';

const HYPOTHESES = resolve(import.meta.dir, '../hypotheses');
const yes = (p: number) => ({ type: 'noul' as const, noul: p });
const pick = (choice: string) => ({ type: 'choice' as const, choice });
const fn = (name: string, path: string, start: number, end: number): SourceFunction => ({
  qn: name,
  name,
  path,
  start,
  end,
});
const file = (path: string, lines: string[]) => ({ path, text: lines.join('\n') });
const input = (
  files: { path: string; text: string }[],
  functions: SourceFunction[],
  labels: [string, Labels][] = [],
  calls: [string, string][] = []
): HypothesisInput => ({ files, functions, calls, labels: new Map(labels) });
/** A function that touches state outliving a request, in `phase`. */
const state = (phase: string, extra: Labels = {}): Labels => ({
  persistent_state: yes(0.9),
  phase: pick(phase),
  ...extra,
});

describe('the hypotheses module', () => {
  it('imports nothing from the rest of the engine, so it can become a package unchanged', () => {
    const sources = (dir: string): string[] =>
      readdirSync(dir).flatMap(name => {
        const path = join(dir, name);
        return statSync(path).isDirectory() ? sources(path) : path.endsWith('.ts') ? [path] : [];
      });
    for (const path of sources(HYPOTHESES))
      for (const [, spec] of readFileSync(path, 'utf8').matchAll(/from '([^']+)'/g)) {
        const target = spec as string;
        if (target.startsWith('node:')) continue;
        expect(target.startsWith('.')).toBe(true);
        expect(relative(HYPOTHESES, resolve(dirname(path), target)).startsWith('..')).toBe(false);
      }
  });

  it('asks each question once, and only follow-ups where earlier answers make them matter', () => {
    const questions = labelQuestions(TEMPLATES);
    expect(questions.map(q => q.name)).toEqual([
      'non_local_exit',
      'persistent_state',
      'memory',
      'phase',
    ]);
    const phase = questions.find(q => q.name === 'phase');
    expect(phase?.askIf?.({ persistent_state: yes(0.9) })).toBe(true);
    expect(phase?.askIf?.({ persistent_state: yes(0.1) })).toBe(false);
  });

  it('refuses two templates that define one question differently', () => {
    const template = (instructions: string): HypothesisTemplate => ({
      id: instructions,
      description: '',
      questions: [{ name: 'q', type: 'noul', instructions, criteria: {} }],
      hypotheses: () => [],
    });
    expect(() => labelQuestions([template('a'), template('b')])).toThrow(/question q twice/);
  });
});

describe('non-local exits', () => {
  it('follows longjmp through macros and functions to the calls code uses, most used first', () => {
    const files = [
      file('portability.h', [
        '#define LONGJMP(a, b) longjmp(a, b)',
        '#define emalloc(n) _emalloc(n)',
      ]),
      file('alloc.c', [
        'void bailout(void) {',
        '  LONGJMP(env, 1);',
        '}',
        'void *_emalloc(size_t n) {',
        '  if (n > limit) bailout(); /* never returns */',
        '  return malloc(n);',
        '}',
      ]),
      file('parser.c', [
        'void parse(void) {',
        '  char *a = emalloc(1);',
        '}',
        'void parse_more(void) {',
        '  char *b = emalloc(2);',
        '  int n = strlen(b);',
        '}',
      ]),
    ];
    const { exits } = facts(
      input(files, [
        fn('bailout', 'alloc.c', 1, 3),
        fn('_emalloc', 'alloc.c', 4, 7),
        fn('parse', 'parser.c', 1, 3),
        fn('parse_more', 'parser.c', 4, 7),
      ])
    );
    expect(exits[0]).toEqual({
      name: 'emalloc',
      callers: 2,
      path: ['emalloc', '_emalloc', 'bailout', 'LONGJMP'],
      root: 'portability.h:1',
    });
    expect(exits.map(e => e.name)).not.toContain('strlen');
  });

  it('does not let a function named by a signature macro capture calls to the C library name', () => {
    const files = [
      file('ext.c', [
        'PHP_FUNCTION(assert)',
        '{',
        '  longjmp(env, 1);',
        '}',
        'void check(int x) {',
        '  assert(x);',
        '}',
      ]),
    ];
    const { exits } = facts(
      input(files, [fn('assert', 'ext.c', 1, 4), fn('check', 'ext.c', 5, 7)])
    );
    expect(exits.map(e => e.name)).not.toContain('assert');
  });

  it('starts from the functions the decision model says exit when no code calls longjmp', () => {
    const files = [
      file('app.js', [
        'function fail() {',
        '  process.exit(1);',
        '}',
        'function load() {',
        '  fail();',
        '}',
      ]),
    ];
    const functions = [fn('fail', 'app.js', 1, 3), fn('load', 'app.js', 4, 6)];
    const { exits } = facts(
      input(files, functions, [['fail', { non_local_exit: yes(0.8) }]], [['load', 'fail']])
    );
    expect(exits).toEqual([{ name: 'fail', callers: 1, path: ['fail'], root: 'app.js:1' }]);
  });

  it("reads a body to its closing brace, past the graph's early end line and braces in text", () => {
    const files = [
      // php-src's fold markers: a brace in the comment after the signature opens nothing.
      file('alloc.c', [
        'void bailout(void) /* {{{ */',
        '{',
        '  log("}"); /* { */',
        '  longjmp(env, 1);',
        '}',
        '/* }}} */',
        'void unrelated(void) {',
        '}',
      ]),
      file('parser.c', ['void parse(void) {', '  bailout();', '}']),
    ];
    // The graph's end line for bailout stops before its jump.
    const { exits } = facts(
      input(files, [
        fn('bailout', 'alloc.c', 1, 3),
        fn('unrelated', 'alloc.c', 7, 8),
        fn('parse', 'parser.c', 1, 3),
      ])
    );
    expect(exits.map(e => e.name)).toEqual(['bailout']);
    // The body ends at its own closing brace, not at a later function's.
    const body = functionBody(fn('bailout', 'alloc.c', 1, 3), linesByPath(files));
    expect(body?.text.split('\n')).toHaveLength(5);
  });

  it('finds nothing where no code calls longjmp and nothing is said to exit', () => {
    const files = [file('app.py', ['def f():', '    raise ValueError()'])];
    expect(facts(input(files, [fn('f', 'app.py', 1, 2)])).exits).toEqual([]);
  });
});

/**
 * An interpreter in miniature: main.c's request start sets G(started) after parsing the input and
 * its end shuts the modules down only when it is set; session.c has input code with its own reset
 * and teardown, installed in a hook parser.c calls; parser.c builds an array with an allocator
 * that can longjmp. The null check in request_end is not a lifecycle flag: nothing sets buf to 1.
 */
const mainC = file('main.c', [
  'int request_start(void) {',
  '  G(started) = 0;',
  '  /* parse_later() runs elsewhere */',
  '  parse_input();',
  '  activate_modules();',
  '  G(started) = 1;',
  '  return 0;',
  '}',
  'void request_end(void) {',
  '  if (buf) {',
  '    free_buffer();',
  '  }',
  '  if (G(started)) {',
  '    shutdown_modules();',
  '  }',
  '  flush_output();',
  '  if (G(started)) {',
  '    free_shutdown_functions();',
  '  }',
  '}',
]);
const interpreter = {
  files: [
    mainC,
    file('alloc.c', [
      'void bailout(void) {',
      '  longjmp(env, 1);',
      '}',
      'void *emalloc(size_t n) {',
      '  if (n > limit) bailout();',
      '  return malloc(n);',
      '}',
    ]),
    file('session.c', [
      'void upload_callback(void) {',
      '  UNSER_INIT(d);',
      '}',
      'void reset(void) {',
      '}',
      'void teardown(void) {',
      '}',
      'void init(void) {',
      '  upload_hook = upload_callback;',
      '}',
    ]),
    file('var.h', ['#define UNSER_INIT(d) \\', '  (d) = unser_init()']),
    file('unser.re', [
      'static int depth;',
      'void *unser_init(void) {',
      '  BG(unser).level = 1;',
      '  depth++;',
      '  return 0;',
      '}',
    ]),
    file('parser.c', ['void parse(void) {', '  upload_hook(1);', '  build_array();', '}']),
    file('array.c', [
      'void build_array(void) {',
      '  char *a = emalloc(1);',
      '  char *b = emalloc(2);',
      '}',
    ]),
  ],
  functions: [
    // The graph's end line for request_end stops early, as it does in macro-heavy C.
    fn('request_start', 'main.c', 1, 8),
    fn('request_end', 'main.c', 9, 12),
    ...[
      'parse_input',
      'parse_later',
      'activate_modules',
      'free_buffer',
      'shutdown_modules',
      'flush_output',
      'free_shutdown_functions',
    ].map((n, i) => fn(n, 'lib.c', i * 3 + 1, i * 3 + 2)),
    fn('bailout', 'alloc.c', 1, 3),
    fn('emalloc', 'alloc.c', 4, 7),
    fn('upload_callback', 'session.c', 1, 3),
    fn('reset', 'session.c', 4, 5),
    fn('teardown', 'session.c', 6, 7),
    fn('parse', 'parser.c', 1, 4),
    fn('build_array', 'array.c', 1, 4),
  ],
  labels: [
    ['request_start', state('request_init')],
    ['request_end', state('request_end')],
    ['upload_callback', state('input')],
    ['reset', state('request_init')],
    ['teardown', state('request_end')],
    ['parse', { entry_point: yes(0.9) }],
    ['build_array', { memory: yes(0.9) }],
  ] as [string, Labels][],
  calls: [
    ['parse', 'build_array'],
    ['build_array', 'emalloc'],
    ['emalloc', 'bailout'],
  ] as [string, string][],
};
const interpreterInput = (): HypothesisInput =>
  input(interpreter.files, interpreter.functions, interpreter.labels, interpreter.calls);

describe('matchingBrace', () => {
  it('skips braces in comments and in string and character literals, escapes included', () => {
    const s = `{ log("}\\"{"); /* } */ c = '}'; // }\n started = 1; }`;
    expect(matchingBrace(s, 1)).toBe(s.length - 1);
  });
});

describe('guarded teardowns', () => {
  it('finds a teardown guarded by a flag the request start sets, with the calls before it', () => {
    const [g, ...rest] = facts(interpreterInput()).guarded;
    expect(rest).toEqual([]);
    expect(g?.teardown.qn).toBe('request_end');
    expect(g?.line).toBe(13);
    expect(g?.flag).toBe('G(started)');
    expect(g?.calls).toEqual(['shutdown_modules', 'free_shutdown_functions']);
    expect(g?.setter.qn).toBe('request_start');
    expect(g?.setAt).toBe(6);
    // Calls in comments are left out.
    expect(g?.before).toEqual(['parse_input', 'activate_modules']);
  });

  it('finds nothing without request phases', () => {
    const plain = input(interpreter.files, interpreter.functions, [], interpreter.calls);
    expect(facts(plain).guarded).toEqual([]);
  });
});

describe('reached state', () => {
  // A long run of name characters, as in a generated file's data, made the hook-install pattern
  // rescan the run from each of its characters: seconds at this size, past the test's timeout.
  it('reads a file with a long run of name characters in linear time', () => {
    const run = 'a'.repeat(100_000);
    const padded = interpreterInput();
    padded.files = padded.files.map(f => ({ ...f, text: `${f.text}\n${run}` }));

    expect(facts(padded)).toEqual(facts(interpreterInput()));
  });

  it("finds other components' global writes behind macros and outside the code graph", () => {
    // session.c reaches the serializer through a macro; its definition is in an re2c source the
    // graph does not parse.
    expect(reachedState('session.c', interpreterInput())).toEqual([
      { name: 'unser_init', at: 'unser.re:2', writes: ['BG(unser).level', 'depth'] },
    ]);
    expect(reachedState('none.c', interpreterInput())).toEqual([]);
  });
});

describe('interrupted-request hypotheses', () => {
  it('computes a stale-state and a half-built hypothesis for the input component, sharing one brief', () => {
    const hypotheses = computeHypotheses(TEMPLATES, interpreterInput());
    expect(hypotheses.map(l => [l.template, l.where])).toEqual([
      ['stale-state', 'session.c:1'],
      ['half-built', 'parser.c:1'],
    ]);
    const [stale, halfBuilt] = hypotheses;
    expect(stale?.claim).toContain(
      'survives a request that fails before `G(started)` is set (main.c:6)'
    );
    expect(stale?.claim).toContain('`unser_init` writes `BG(unser).level`, `depth`');
    // The builder the parser reaches, with two calls that can jump; the allocator itself is the
    // jump's machinery, not a builder.
    expect(halfBuilt?.claim).toContain('`build_array` (array.c:1)');
    expect(halfBuilt?.claim).not.toContain('`emalloc` (');
    // The component, the parser that calls its hook, then the request lifecycle; the jump's
    // file beside them.
    expect(stale?.brief).toBe(halfBuilt?.brief as never);
    expect(stale?.brief.seeds).toEqual(['session.c', 'parser.c', 'main.c']);
    expect(stale?.brief.related).toEqual(['alloc.c']);
  });

  it('ranks a component another file parses through a hook above one with more input code', () => {
    // A library whose many constructors are labelled input, called directly by its own parser:
    // more input code than session.c, but no hook a parser runs it through.
    const library = file('lib/css.c', [
      ...['css_a', 'css_b', 'css_c'].flatMap(n => [`void ${n}(void) {`, '}']),
      'void css_init(void) {',
      '}',
      'void css_free(void) {',
      '}',
    ]);
    const libraryParser = file('lib/css_parser.c', ['void css_parse(void) {', '  css_a();', '}']);
    const functions = [
      ...interpreter.functions,
      ...['css_a', 'css_b', 'css_c', 'css_init', 'css_free'].map((n, i) =>
        fn(n, 'lib/css.c', i * 2 + 1, i * 2 + 2)
      ),
      fn('css_parse', 'lib/css_parser.c', 1, 3),
    ];
    const labels: [string, Labels][] = [
      ...interpreter.labels,
      ['css_a', state('input')],
      ['css_b', state('input')],
      ['css_c', state('input')],
      ['css_init', state('request_init')],
      ['css_free', state('request_end')],
      ['css_parse', state('input')],
      ['parse', { entry_point: yes(0.9), ...state('input') }],
    ];
    const { components } = facts(
      input([...interpreter.files, library, libraryParser], functions, labels, [
        ...interpreter.calls,
        ['css_parse', 'css_a'],
      ])
    );
    expect(components.map(c => [c.path, c.parsers])).toEqual([
      ['session.c', ['parser.c']],
      ['lib/css.c', ['lib/css_parser.c']],
    ]);
  });

  it('names no builder a signature macro defines: it is not the C function the parser calls', () => {
    // Another caller keeps emalloc among the listed exits once build_array is no definition.
    const files = [
      ...interpreter.files.map(f =>
        f.path === 'array.c'
          ? file('array.c', [
              'PHP_FUNCTION(build_array)',
              '{',
              '  char *a = emalloc(1);',
              '  char *b = emalloc(2);',
              '}',
            ])
          : f
      ),
      file('other.c', ['void other(void) {', '  emalloc(1);', '}']),
    ];
    const functions = [
      ...interpreter.functions.map(f =>
        f.name === 'build_array' ? fn('build_array', 'array.c', 1, 5) : f
      ),
      fn('other', 'other.c', 1, 3),
    ];
    const hypotheses = computeHypotheses(
      TEMPLATES,
      input(files, functions, interpreter.labels, interpreter.calls)
    );
    expect(hypotheses.find(l => l.template === 'half-built')?.claim).not.toContain('build_array');
  });

  it('counts the calls a builder makes that can jump, not its own name in its signature', () => {
    // build_array can unwind (through emalloc), so it is a listed exit itself: with one jumping
    // call it builds nothing half-way.
    const files = interpreter.files.map(f =>
      f.path === 'array.c'
        ? file('array.c', ['void build_array(void) {', '  char *a = emalloc(1);', '}'])
        : f
    );
    const functions = interpreter.functions.map(f =>
      f.name === 'build_array' ? fn('build_array', 'array.c', 1, 3) : f
    );
    const hypotheses = computeHypotheses(
      TEMPLATES,
      input(files, functions, interpreter.labels, interpreter.calls)
    );
    expect(hypotheses.find(l => l.template === 'half-built')?.claim).not.toContain('build_array');
  });

  it('takes the first parser that takes outside input, past an internal wrapper ranked first', () => {
    // wrapper.c parses input too, so it ranks first, but nothing outside calls it.
    const wrapper = file('wrapper.c', ['void wrap(void) {', '  upload_callback();', '}']);
    const hypotheses = computeHypotheses(
      TEMPLATES,
      input(
        [...interpreter.files, wrapper],
        [...interpreter.functions, fn('wrap', 'wrapper.c', 1, 3)],
        [...interpreter.labels, ['wrap', state('input')]],
        [...interpreter.calls, ['wrap', 'upload_callback']]
      )
    );
    expect(facts(interpreterInput()).components[0]?.parsers).toEqual(['parser.c']);
    expect(hypotheses.find(l => l.template === 'half-built')?.where).toBe('parser.c:1');
  });

  it('computes nothing without an exit, without phases, or without a component', () => {
    const withoutJump = interpreter.files.map(f =>
      f.path === 'alloc.c' ? file('alloc.c', ['void bailout(void) {', '}']) : f
    );
    expect(
      computeHypotheses(
        TEMPLATES,
        input(withoutJump, interpreter.functions, interpreter.labels, interpreter.calls)
      )
    ).toEqual([]);
    expect(
      computeHypotheses(
        TEMPLATES,
        input(interpreter.files, interpreter.functions, [], interpreter.calls)
      )
    ).toEqual([]);
    // A guarded teardown alone is not a component: no hypothesis falls back to a lifecycle file.
    const noComponent = interpreter.labels.filter(([qn]) => !['reset', 'teardown'].includes(qn));
    const hypotheses = computeHypotheses(
      TEMPLATES,
      input(interpreter.files, interpreter.functions, noComponent, interpreter.calls)
    );
    expect(hypotheses).toEqual([]);
  });

  it("gives a brief the exits, its components' state and the guarded teardown, once", () => {
    const section = briefSections(TEMPLATES, interpreterInput(), new Set(['session.c'])).join('\n');
    expect(section).toContain('## Non-local exits (computed from the code)');
    expect(section).toContain('- `bailout` (called in 1 functions): bailout (exits at alloc.c:1)');
    expect(section).toContain('### Component `session.c`: state written while the input is parsed');
    expect(section).toContain('- `unser_init` (`unser.re:2`) writes `BG(unser).level`, `depth`');
    expect(section).toContain(
      '- `request_end` (`main.c:13`) runs `shutdown_modules`, `free_shutdown_functions` only if `G(started)`; `request_start` sets it at `main.c:6`, after `parse_input`, `activate_modules`'
    );
    // Both templates share the section; it appears once.
    expect(section.split('## State that outlives a request').length).toBe(2);
    // A repository without a component or a guarded teardown gets no section.
    expect(
      briefSections(
        TEMPLATES,
        input(interpreter.files, interpreter.functions, [], interpreter.calls),
        new Set(['session.c'])
      )
    ).toEqual([]);
  });
});

describe('the knowledge base with hypotheses', () => {
  const brief = (packets: number, entryFiles = new Map<string, number>()) => {
    const hypothesisInput = interpreterInput();
    return briefing({
      paths: { project: '/scan/project', kbIndex: '/scan/kb' },
      rows: interpreter.files.map(f => ({
        path: f.path,
        lines: f.text.split('\n').length,
        kind: 'code',
        reason: '',
        text: f.text,
      })),
      functions: interpreter.functions,
      calls: interpreter.calls,
      index: {},
      entries: [],
      sinks: new Map(),
      spec: [
        {
          id: 'input',
          perspective: 'Request input',
          attacker: 'A remote client',
          review: ['parser.c', 'session.c'],
          seeds: ['parser.c'],
          context: [],
          ownsAppWide: true,
        },
      ],
      baseline: [],
      secretWindows: [],
      fileLabels: new Map(),
      functionLabels: hypothesisInput.labels,
      roles: new Map(),
      entryFiles,
      hypotheses: {
        input: hypothesisInput,
        computed: computeHypotheses(TEMPLATES, hypothesisInput),
        packets,
      },
    });
  };

  it('gives the hypotheses to a hypothesis packet, a packet of the first round', () => {
    const kb = brief(3);
    // Two hypotheses, three packets allowed: one each, a row each in the helpers' table.
    expect(kb.briefs.map(b => b.id)).toEqual(['input', 'hypotheses-1', 'hypotheses-2', 'baseline']);
    expect(kb.markdown).toContain('| packet_hypotheses_1 | hypotheses-1 |');
    expect(kb.markdown).not.toContain('## Hypotheses');
    // The brief asks its hypothesis as a question, and its core starts from the hypothesis's seeds.
    const hypothesis = kb.files.get('packets/hypotheses-1.md') ?? '';
    expect(hypothesis).toContain('Perspective: Interruption audit.');
    expect(hypothesis).toContain('## Hypotheses to settle');
    expect(hypothesis).toContain('   - where: session.c:1');
    expect(hypothesis).toContain('==> session.c (lines 1-10) <==');
    expect(hypothesis).not.toContain('\n2. ');
    // A packet's brief gets the facts about its own files, and no hypotheses.
    const packet = kb.files.get('packets/input.md') ?? '';
    expect(packet).toContain('### Component `session.c`: state written while the input is parsed');
    expect(packet).not.toContain('## Hypotheses to settle');
  });

  it("prints a hypothesis packet's seeds in their order, before a seed that ranks higher", () => {
    // main.c, the request lifecycle, has the most entry points, but the component comes first.
    const hypothesis =
      brief(3, new Map([['main.c', 5]])).files.get('packets/hypotheses-1.md') ?? '';
    const at = (path: string) => hypothesis.indexOf(`==> ${path} (`);
    expect(at('session.c')).toBeGreaterThan(-1);
    expect(at('session.c')).toBeLessThan(at('parser.c'));
    expect(at('parser.c')).toBeLessThan(at('main.c'));
  });

  it('puts both hypotheses in one packet when one is allowed, and makes none for 0', () => {
    expect(brief(1).briefs.map(b => b.id)).toEqual(['input', 'hypotheses-1', 'baseline']);
    expect(brief(1).files.get('packets/hypotheses-1.md')).toContain('\n2. ');
    expect(brief(0).briefs.map(b => b.id)).toEqual(['input', 'baseline']);
  });
});

describe('hypothesisPackets', () => {
  const hypothesis = (template: string, n: number): Hypothesis => ({
    template,
    claim: `${template}${n}`,
    where: `${template}.c:${n}`,
    check: 'c',
    brief: { perspective: '', attacker: '', seeds: [], related: [] },
  });
  const claims = (packets: Hypothesis[][]) => packets.map(p => p.map(h => h.claim));
  const hypotheses = [
    hypothesis('S', 1),
    hypothesis('H', 1),
    hypothesis('S', 2),
    hypothesis('H', 2),
  ];

  it("shares the hypotheses out evenly, a template's hypotheses together where the sizes allow", () => {
    expect(claims(hypothesisPackets(hypotheses, 2))).toEqual([
      ['S1', 'S2'],
      ['H1', 'H2'],
    ]);
    expect(claims(hypothesisPackets(hypotheses, 3))).toEqual([['S1', 'S2'], ['H1'], ['H2']]);
    expect(claims(hypothesisPackets(hypotheses, 1))).toEqual([['S1', 'S2', 'H1', 'H2']]);
  });

  it('makes no more packets than there are hypotheses, and none for 0', () => {
    expect(claims(hypothesisPackets(hypotheses.slice(0, 2), 3))).toEqual([['S1'], ['H1']]);
    expect(hypothesisPackets(hypotheses, 0)).toEqual([]);
    expect(hypothesisPackets([], 3)).toEqual([]);
  });
});

describe('globalWrites', () => {
  it("reads a file's statics, not its prototypes or inline functions", () => {
    const file = [
      'static int depth;',
      'static char buf[64] = {0};',
      'static const char *name = "x";',
      'static struct state *current;',
      'static int f(void);',
      'static inline int g(void) { return 0; }',
    ].join('\n');
    const body = 'depth = 1; name = "y"; current++; f = 2; g--; buf[0] = 1;';

    expect(globalWrites(body, file)).toEqual(['depth', 'name', 'current']);
  });

  // A regex read the spaces after each candidate name two ways, so this prototype took quadratic
  // time: seconds at this size, past the test's timeout.
  it('reads a prototype with a long run of spaces in linear time', () => {
    const file = `static int f${' '.repeat(100_000)}(void);\nstatic int depth;`;

    expect(globalWrites('depth = 1;', file)).toEqual(['depth']);
  });
});
