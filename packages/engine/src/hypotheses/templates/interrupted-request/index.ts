/**
 * Interrupted requests: two hypotheses about what a request leaves when it stops part-way.
 *
 * Found on an interpreter whose memory limit and fatal errors leave through `longjmp`, where a
 * scan with helpers alone never got either bug and these two hypotheses got both:
 *
 *   stale state   a component's input code writes state (its own, and that of the components it
 *                 calls into) before the request's start sets the flag that guards teardown, so a
 *                 request that fails while its input is parsed skips the reset: does the next
 *                 request's input code meet that state before its own initialisation?
 *   half-built    the parser that runs that input code builds the request's structures with calls
 *                 that can jump: what state is each in at a jump, and what does shutdown do with
 *                 it?
 *
 * Both come from the same facts (facts.ts) and share one brief per component: its input code,
 * the parsers that run it, and the request's start and teardown. The briefs of every helper also
 * get those facts for their own files (briefSection), so a packet's helper sees where its code
 * can be interrupted and what resets its state.
 */
import { yes, type Labels } from '../../labels';
import type { SourceFunction } from '../../source';
import type {
  Hypothesis,
  LabelQuestion,
  HypothesisBrief,
  HypothesisInput,
  HypothesisTemplate,
} from '../../types';
import {
  facts,
  LABEL_P,
  phaseOf,
  reachedState,
  seedsOf,
  stateBuilders,
  type Component,
  type Facts,
  type GuardedTeardown,
  type NonLocalExit,
} from './facts';

/** Reached state and writes a hypothesis names: enough to point at, short enough to read in a claim. */
const MAX_REACHED_IN_HYPOTHESIS = 3;
const MAX_WRITES_IN_HYPOTHESIS = 2;

// --------------------------------------------------------------------------- //
// The questions
// --------------------------------------------------------------------------- //

const NON_LOCAL_EXIT: LabelQuestion = {
  name: 'non_local_exit',
  type: 'noul',
  instructions:
    'Does this function itself end the current operation without returning to its caller: longjmp or an engine bailout, exit or abort, a fatal error that does not return, or a panic, so that the code it interrupts never runs its own cleanup?',
  criteria: {
    true: 'It can leave by a non-local exit, not by returning.',
    false: 'It returns to its caller, or only calls code that might not.',
  },
};

const PERSISTENT_STATE: LabelQuestion = {
  name: 'persistent_state',
  type: 'noul',
  instructions:
    'Does this function itself read, write or reset state that outlives the current request, call or connection (process- or thread-wide globals, static caches, persistent or pooled objects) that a later request or connection will use? Count globals reached through an accessor macro or function (a macro that names a field of a global structure) as well as by name. Reading configuration only is not this.',
  criteria: {
    true: 'It touches state a later request or connection will use.',
    false: 'It works only on its own data and the current request.',
  },
};

const MEMORY: LabelQuestion = {
  name: 'memory',
  type: 'noul',
  instructions:
    'In a language without memory safety (C, C++, unsafe Rust), does this function itself copy data into a raw buffer, compute a buffer size, length or offset that is then used to read or write, or free or reallocate memory that other code may still reference?',
  criteria: {
    true: 'It does one of these itself.',
    false:
      'It does none of these, or only allocates, or only calls a string helper on the way to other work.',
  },
};

/**
 * When a function that touches state outliving a request runs. Asked only of those functions:
 * the phase puts code outside a request's own setup and teardown (a parser's callback, cleanup)
 * beside the reset that covers its state.
 */
const PHASE: LabelQuestion = {
  name: 'phase',
  type: 'choice',
  instructions:
    'When, in the life of a long-running process that serves requests or connections, does this function run?',
  criteria: {
    startup: 'Once, when the process, a worker or a module starts.',
    request_init:
      "At the start of each request or connection, to initialise or reset per-request state, before the request's own work.",
    input:
      "While the request's input is read or parsed, including callbacks or hooks that the reader or parser invokes.",
    request: "During the request's own work: the handler, the script or the business logic.",
    request_end:
      'At the end of each request or connection: cleanup, teardown or per-request shutdown.',
    shutdown: 'Once, when the process, a worker or a module shuts down.',
    any: 'A helper called from several of these phases, or from none of them.',
  },
  askIf: (labels: Labels | undefined) => yes(labels, 'persistent_state') >= LABEL_P,
};

const QUESTIONS = [NON_LOCAL_EXIT, PERSISTENT_STATE, MEMORY, PHASE];

// --------------------------------------------------------------------------- //
// The hypotheses
// --------------------------------------------------------------------------- //

const code = (names: string[]): string => names.map(n => `\`${n}\``).join(', ');

/** One brief per component, shared by its hypotheses. */
const briefs = new WeakMap<HypothesisInput, Map<string, HypothesisBrief>>();
function briefOf(input: HypothesisInput, component: Component, f: Facts): HypothesisBrief {
  const byPath = briefs.get(input) ?? new Map<string, HypothesisBrief>();
  briefs.set(input, byPath);
  const known = byPath.get(component.path);
  if (known) return known;
  const brief: HypothesisBrief = {
    perspective:
      'Interruption audit. In this code an allocation, a limit or a fatal error can leave a ' +
      'function through a non-local exit instead of returning (the brief lists the calls that ' +
      'can). Start from the request start and teardown and from the code that parses the ' +
      'request input. For each function that builds or publishes state (parser state, a ' +
      "component's per-request globals), take each call that can jump and write down what is " +
      'half-built or published at that point; then follow what runs after the jump: the ' +
      'teardown that frees or reads it, the teardown steps a failed start skips, and what the ' +
      'next request on the same worker finds, including the per-request state of the ' +
      'components that code called into, each reset only at its own initialisation.',
    attacker:
      'A remote client that can make a request hit a limit or a fatal error part-way, with a ' +
      'large, deeply nested or many-part input.',
    seeds: seedsOf(component, f.guarded),
    related: [...new Set(f.exits.map(e => e.root.split(':')[0] as string).filter(Boolean))],
  };
  byPath.set(component.path, brief);
  return brief;
}

/** The guard with the most guarded calls: the teardown a failed start skips the most of. */
function mainGuard(f: Facts): GuardedTeardown | undefined {
  return [...f.guarded].sort((a, b) => b.calls.length - a.calls.length)[0];
}

/** Stale state: one hypothesis per component with input code, when a teardown step is guarded. */
function staleStateHypotheses(input: HypothesisInput): Hypothesis[] {
  const f = facts(input);
  const guard = mainGuard(f);
  if (!guard) return [];
  const onExitPath = new Set(f.exits.flatMap(e => e.path));
  return f.components
    .filter(c => c.inputs.length)
    .map(c => {
      // The state reached through calls, not the jump's own bookkeeping.
      const reached = reachedState(c.path, input)
        .filter(r => !onExitPath.has(r.name))
        .slice(0, MAX_REACHED_IN_HYPOTHESIS);
      const writes = reached.map(
        r => `\`${r.name}\` writes ${code(r.writes.slice(0, MAX_WRITES_IN_HYPOTHESIS))}`
      );
      const first = c.inputs[0] as SourceFunction;
      return {
        template: STALE_STATE.id,
        claim:
          `State that ${c.path}'s input code (${code(c.inputs.map(i => i.name))}) writes` +
          (writes.length
            ? `, and the state of the components it calls into (${writes.join('; ')}),`
            : '') +
          ` survives a request that fails before \`${guard.flag}\` is set (${guard.setter.path}:${guard.setAt}),` +
          ` because \`${guard.teardown.name}\` then skips ${code(guard.calls)}.`,
        where: `${first.path}:${first.start}`,
        check:
          `Follow the next request on the same worker from its start: does ${c.path}'s input code run before ` +
          `${c.path}'s own initialisation and before that of the components it calls into, and does it read or ` +
          "use the state the failed request left? A pointer into the failed request's freed memory is a use after free.",
        brief: briefOf(input, c, f),
      };
    });
}

/** Half-built: one hypothesis per component whose parser takes input from outside the process. */
function halfBuiltHypotheses(input: HypothesisInput): Hypothesis[] {
  const f = facts(input);
  const lifecycle = new Set(f.guarded.flatMap(g => [g.setter.path, g.teardown.path]));
  const out: Hypothesis[] = [];
  for (const c of f.components) {
    // The first parser outside the request's start and teardown that takes outside input: an
    // internal wrapper ranked before it does not stop the hypothesis.
    const entryIn = (path: string) =>
      input.functions.find(
        fn => fn.path === path && yes(input.labels.get(fn.qn), 'entry_point') >= LABEL_P
      );
    const parser = c.parsers.find(p => !lifecycle.has(p) && entryIn(p));
    const entry = parser && entryIn(parser);
    if (!parser || !entry) continue;
    const builders = stateBuilders(parser, input, f.exits);
    out.push({
      template: HALF_BUILT.id,
      claim:
        `A non-local exit in ${parser} part-way through building the request's input leaves the structures it ` +
        'and the functions it calls publish half-built, and request shutdown still frees or walks them' +
        (builders.length
          ? `; the functions it reaches that build them with calls that can jump: ${builders.map(b => `\`${b.name}\` (${b.path}:${b.start})`).join(', ')}.`
          : '.'),
      where: `${entry.path}:${entry.start}`,
      check:
        `For each structure ${parser} and the functions it calls build, its state at each call that can ` +
        'jump, and what request shutdown then does with it: an element left half-initialised or already freed, ' +
        "that shutdown destroys, is memory corruption. Read those functions' bodies: none is atomic, and a call " +
        'that jumps inside one leaves its own work half-done (an element freed and not yet replaced, an array ' +
        'linked before it is filled).',
      brief: briefOf(input, c, f),
    });
  }
  return out;
}

export const STALE_STATE: HypothesisTemplate = {
  id: 'stale-state',
  description:
    'State a request writes while its input is parsed survives a failure that skips the guarded teardown.',
  questions: QUESTIONS,
  hypotheses: staleStateHypotheses,
  briefSection,
};

export const HALF_BUILT: HypothesisTemplate = {
  id: 'half-built',
  description:
    'A non-local exit while a parser builds the request leaves structures half-built for shutdown.',
  questions: QUESTIONS,
  hypotheses: halfBuiltHypotheses,
  briefSection,
};

// --------------------------------------------------------------------------- //
// The facts in a helper's brief
// --------------------------------------------------------------------------- //

/**
 * The phases around a request's own work, in the order a request meets them. Start-up and
 * shutdown run once, so no later request meets what they leave.
 */
const PHASE_TITLES: [string, string][] = [
  ['request_init', 'At the start of each request: initialisation and resets'],
  ['input', "While the request's input is read or parsed (the reader's and parser's callbacks)"],
  ['request_end', 'At the end of each request: cleanup and teardown'],
];
const MAX_STATE_PER_PHASE = 12;
const MAX_INPUT_COMPONENTS = 6;
const MAX_UNWINDING_CALLS = 5;

/** A brief's functions that touch state outliving a request, by file and then by phase. */
type StatePhases = Map<string, Map<string, SourceFunction[]>>;

/**
 * Where a brief's code can be interrupted, and the state that outlives a request, by component.
 *
 * A later request meets stale state when code outside the request's own setup and teardown
 * writes state the per-request reset covers. The reset that matters is the one of the component
 * that owns the state, not the first reset of the request, and no single file shows the order:
 *
 *   1  the calls that can leave their caller without returning, with each one's path to the exit
 *   2  the brief's state functions grouped by file and phase
 *   3  each file with code that runs while input is parsed, as one component: its input code
 *      beside its own initialisation and teardown, each input function with its own calls that
 *      can unwind, and the state of other components its code reaches
 *   4  the teardown steps a flag guards, which a request that fails while its input is parsed
 *      skips
 *   5  the other files' resets and teardowns by phase
 *
 * Only in a repository where the facts found a component or a guarded teardown: elsewhere the
 * section would ask every helper about request lifecycles the code does not have.
 */
function briefSection(input: HypothesisInput, files: ReadonlySet<string>): string[] {
  const f = facts(input);
  if (!f.components.length && !f.guarded.length) return [];
  const md = exitLines(f.exits);
  const byFile = statePhasesByFile(input, files);
  const components = inputComponents(byFile);
  const rest = PHASE_TITLES.map(([phase, title]) => ({
    title,
    fs: [...byFile]
      .filter(([path]) => !components.includes(path))
      .flatMap(([, phases]) => phases.get(phase) ?? []),
  })).filter(p => p.fs.length);
  if (!components.length && !rest.length) return md;
  md.push(
    '## State that outlives a request',
    '',
    "This brief's functions that touch state a later request or connection uses (globals,",
    'statics, caches, pooled objects), by component and by when they run. For each component whose',
    "state is written while the request's input is parsed, establish the order against that",
    "component's own initialisation, not another component's: does its input code run before or",
    "after it? Input code that runs before its component's initialisation sees what the previous",
    'request left behind. Ask what that is when the previous request ended early (an error, a',
    'non-local exit, a limit): a teardown often runs only for components whose initialisation ran,',
    'so a request that failed before that point leaves what its input code wrote with no cleanup,',
    'such as a pointer into memory that request freed. Record the order you found for each',
    'component, with the lines that show it, in your resolved questions.',
    ''
  );
  for (const path of components)
    md.push(
      ...componentLines(path, byFile.get(path) as Map<string, SourceFunction[]>, input, f.unwinding)
    );
  if (components.length) md.push(...guardedTeardownLines(f.guarded));
  for (const { title, fs } of rest) md.push(`### ${title}`, '', ...functionLines(fs, input), '');
  return md;
}

/** Step 1: the calls that can unwind, each with its path to the exit. */
function exitLines(exits: NonLocalExit[]): string[] {
  if (!exits.length) return [];
  return [
    '## Non-local exits (computed from the code)',
    '',
    'These calls can leave their caller without returning (longjmp, an engine bailout, an exit),',
    'so whatever the caller has published or half-built at that point is left as it is, and its',
    'own cleanup does not run. A call that reaches one of these can leave its caller the same way.',
    '',
    ...exits.map(e => {
      const reached = e.root ? ` (exits at ${e.root})` : ' -> …';
      return `- \`${e.name}\` (called in ${e.callers} functions): ${e.path.join(' -> ')}${reached}`;
    }),
    '',
  ];
}

/** Step 2: the brief's state functions by file and phase, each list in line order. */
function statePhasesByFile(input: HypothesisInput, files: ReadonlySet<string>): StatePhases {
  const byFile: StatePhases = new Map();
  for (const fn of input.functions) {
    const phase = files.has(fn.path) ? phaseOf(input, fn) : undefined;
    if (phase === undefined) continue;
    const phases = byFile.get(fn.path) ?? new Map<string, SourceFunction[]>();
    phases.set(phase, [...(phases.get(phase) ?? []), fn]);
    byFile.set(fn.path, phases);
  }
  for (const phases of byFile.values())
    for (const fs of phases.values()) fs.sort((a, b) => a.start - b.start);
  return new Map([...byFile].sort(([a], [b]) => (a < b ? -1 : 1)));
}

/** Step 3: the files with code that runs while input is parsed, most such functions first. */
function inputComponents(byFile: StatePhases): string[] {
  return [...byFile]
    .filter(([, phases]) => phases.get('input')?.length)
    .sort(
      ([a, x], [b, y]) =>
        (y.get('input')?.length ?? 0) - (x.get('input')?.length ?? 0) || (a < b ? -1 : 1)
    )
    .slice(0, MAX_INPUT_COMPONENTS)
    .map(([path]) => path);
}

/** Step 3: one component's input code, its own initialisation and teardown, the state it reaches. */
function componentLines(
  path: string,
  phases: Map<string, SourceFunction[]>,
  input: HypothesisInput,
  unwinding: Set<string>
): string[] {
  const md = [`### Component \`${path}\`: state written while the input is parsed`, ''];
  for (const [phase, label] of [
    ['input', 'Runs while the input is parsed'],
    ['request_init', 'Its own initialisation and resets'],
    ['request_end', 'Its own cleanup and teardown'],
  ] as const) {
    const fs = phases.get(phase) ?? [];
    md.push(`${label}:`);
    md.push(
      ...(fs.length
        ? functionLines(fs, input, phase === 'input' ? unwinding : undefined)
        : ['- none in this file: find where this state is reset, if anywhere'])
    );
  }
  const reached = reachedState(path, input);
  if (reached.length) {
    md.push("Other components' state its code writes (reset only by their own initialisation):");
    for (const r of reached) md.push(`- \`${r.name}\` (\`${r.at}\`) writes ${code(r.writes)}`);
  }
  md.push('');
  return md;
}

/** Step 4: the guarded teardown steps, with where the request's start sets each flag. */
function guardedTeardownLines(guarded: GuardedTeardown[]): string[] {
  if (!guarded.length) return [];
  return [
    "### Teardown that runs only after the request's start finished",
    '',
    "These teardown steps run only when a flag says the request's start finished (computed from the",
    'code). A request that fails before the flag is set, for example while its input is parsed,',
    'skips them, so they do not clean up what the input code above wrote: check what the next',
    "request's input code then finds.",
    '',
    ...guarded.map(
      g =>
        `- \`${g.teardown.qn}\` (\`${g.teardown.path}:${g.line}\`) runs ${code(g.calls)} only if \`${g.flag}\`; ` +
        `\`${g.setter.qn}\` sets it at \`${g.setter.path}:${g.setAt}\`` +
        (g.before.length ? `, after ${code(g.before)}` : '')
    ),
    '',
  ];
}

/**
 * Functions with what they do to state (and, for input code, their own calls that can unwind:
 * where a jump stops them before their component's cleanup), cut at MAX_STATE_PER_PHASE.
 */
function functionLines(
  fs: SourceFunction[],
  input: HypothesisInput,
  unwinding?: Set<string>
): string[] {
  const nameOf = new Map(input.functions.map(fn => [fn.qn, fn]));
  const lines = fs.slice(0, MAX_STATE_PER_PHASE).map(fn => {
    const labels = input.labels.get(fn.qn);
    const kinds = [
      'state',
      yes(labels, 'memory') >= LABEL_P ? 'memory' : '',
      yes(labels, 'non_local_exit') >= LABEL_P ? 'exits' : '',
    ].filter(Boolean);
    const line = `- \`${fn.qn}\` (\`${fn.path}:${fn.start}\`): ${kinds.join(', ')}`;
    if (!unwinding) return line;
    const stops = unwindingCalls(fn, input, nameOf, unwinding);
    return stops.length ? `${line}; can leave without returning in ${code(stops)}` : line;
  });
  if (fs.length > MAX_STATE_PER_PHASE)
    lines.push(`- … and ${fs.length - MAX_STATE_PER_PHASE} more`);
  return lines;
}

/** A function's own calls that can unwind, by name, calls in its own file first. */
function unwindingCalls(
  fn: SourceFunction,
  input: HypothesisInput,
  byQn: Map<string, SourceFunction>,
  unwinding: Set<string>
): string[] {
  const own = [
    ...new Set(
      input.calls
        .filter(([a, b]) => a === fn.qn && b !== fn.qn && unwinding.has(byQn.get(b)?.name ?? ''))
        .map(([, b]) => byQn.get(b) as SourceFunction)
    ),
  ].sort(
    (a, b) => Number(a.path !== fn.path) - Number(b.path !== fn.path) || (a.qn < b.qn ? -1 : 1)
  );
  return [...new Set(own.map(g => g.name))].slice(0, MAX_UNWINDING_CALLS);
}
