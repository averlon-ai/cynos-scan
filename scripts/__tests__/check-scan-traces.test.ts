import { describe, it, expect, beforeAll, afterAll } from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  OUR_PROMPTS,
  failedCalls,
  pluginChanges,
  readAnswer,
  runDirs,
  traceFolders,
} from '../check-scan-traces.mjs';
import { HELPER_CONTEXT_FILE, PLUGIN_DIR, RUN_PROMPT_FILE } from '../../packages/engine/src/layout';
import { DOCKER_PATHS } from '../../packages/engine/src/runtime/docker';

interface FailedCall {
  id: string;
  agent: string;
  kind: string;
  name: string;
  error: string;
}

/** One trace record, as Codex writes it: a type and its payload. */
const record = (type: string, payload: object): string => JSON.stringify({ type, payload });
const completed = (item: object): string =>
  record('response_item', { type: 'item_completed', item });
const execCell = (callId: string, output: string): string[] => [
  record('response_item', { type: 'custom_tool_call', name: 'exec', call_id: callId, input: '…' }),
  record('response_item', {
    type: 'custom_tool_call_output',
    call_id: callId,
    output: [{ type: 'input_text', text: output }],
  }),
];

// The lead and a helper of one scan, as v0.3.0's real scans left them: the draft tool rejecting
// the lead's first draft, which a later draft fixed, among calls that succeeded.
const LEAD = [
  record('session_meta', { id: 'lead', thread_source: 'security_scan' }),
  ...execCell('c1', 'Script completed\nWall time 0.1 seconds\nOutput:\n'),
  completed({
    type: 'McpToolCall',
    server: 'codex-security',
    tool: 'record_codex_security_scan_draft',
    status: 'failed',
    result: {
      content: [
        {
          type: 'text',
          text: 'MCP error -32602: Input validation error: Invalid arguments for tool record_codex_security_scan_draft: Invalid input: expected never, received array at scope.includePaths',
        },
      ],
      isError: true,
    },
  }),
  completed({
    type: 'McpToolCall',
    server: 'codex-security',
    tool: 'record_codex_security_scan_draft',
    status: 'completed',
    result: { content: [{ type: 'text', text: 'accepted' }] },
  }),
  ...execCell(
    'c2',
    'exec pragma must be valid JSON with supported fields `yield_time_ms` and `max_output_tokens`: EOF while parsing a string at line 1 column 51'
  ),
];
const HELPER = [
  record('session_meta', {
    id: 'h1',
    thread_source: 'subagent',
    agent_path: '/root/baseline_auditor',
  }),
  completed({
    type: 'CommandExecution',
    command: ['/bin/zsh', '-c', 'rg -n "xpath" tests'],
    status: 'failed',
    exit_code: 2,
    aggregated_output:
      'rg: tests: IO error for operation on tests: No such file or directory (os error 2)\n',
  }),
  completed({
    type: 'CommandExecution',
    command: ['/bin/zsh', '-c', 'cat dsvw.py'],
    status: 'completed',
    exit_code: 0,
  }),
  ...execCell(
    'c3',
    'Script failed\nWall time 0.0 seconds\nOutput:\nScript error:\nReferenceError: process is not defined'
  ),
  // A record that ends no call.
  completed({ type: 'AgentMessage', content: [{ type: 'Text', text: 'Reading the brief.' }] }),
];

let dir = '';
let folders: string[] = [];
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'scan-traces-'));
  const sessions = join(dir, 'state', 'codex-home', 'sessions', '2026', '11', '20');
  mkdirSync(sessions, { recursive: true });
  writeFileSync(join(sessions, 'rollout-2026-11-20T11-47-56-lead.jsonl'), LEAD.join('\n') + '\n');
  writeFileSync(
    join(sessions, 'rollout-2026-11-20T11-48-35-helper.jsonl'),
    HELPER.join('\n') + '\n'
  );
  folders = traceFolders(dir);
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('failedCalls', () => {
  it('lists every failed tool call, shell command and exec cell, numbered, by agent', () => {
    const { calls, failed } = failedCalls(folders) as { calls: number; failed: FailedCall[] };
    expect(calls).toBe(7);
    expect(failed.map(f => [f.id, f.agent, f.kind, f.name])).toEqual([
      ['F1', 'lead', 'tool call', 'codex-security/record_codex_security_scan_draft'],
      ['F2', 'lead', 'exec cell', 'exec'],
      ['F3', '/root/baseline_auditor', 'shell command', 'rg -n "xpath" tests'],
      ['F4', '/root/baseline_auditor', 'exec cell', 'exec'],
    ]);
    expect(failed[0]!.error).toContain('expected never, received array at scope.includePaths');
    expect(failed[2]!.error).toMatch(/^exit 2: …rg: tests: IO error/);
    expect(failed[3]!.error).toContain('ReferenceError: process is not defined');
  });

  it('lists a failed call whose error says nothing', () => {
    // A tool call can fail with no content, and an exec cell with no output.
    const other = mkdtempSync(join(tmpdir(), 'scan-traces-'));
    const sessions = join(other, 'sessions', '2026', '11', '20');
    mkdirSync(sessions, { recursive: true });
    const trace = [
      record('session_meta', { id: 'lead', thread_source: 'security_scan' }),
      completed({ type: 'McpToolCall', server: 's', tool: 't', status: 'failed', result: {} }),
      ...execCell('c1', ''),
    ];
    writeFileSync(join(sessions, 'rollout-x.jsonl'), trace.join('\n') + '\n');
    const { failed } = failedCalls(traceFolders(other)) as { failed: FailedCall[] };
    expect(failed.map(f => [f.id, f.kind, f.error])).toEqual([
      ['F1', 'tool call', '(no error text)'],
      ['F2', 'exec cell', '(no error text)'],
    ]);
    rmSync(other, { recursive: true, force: true });
  });

  it('ends a yielded exec cell at the wait that gives its result', () => {
    // exec answers "Script running" past its yield time; a wait on that cell gives the result.
    const other = mkdtempSync(join(tmpdir(), 'scan-traces-'));
    const sessions = join(other, 'sessions', '2026', '11', '20');
    mkdirSync(sessions, { recursive: true });
    const running = (cell: string) =>
      `Script running with cell ID ${cell}\nWall time 1.0 seconds\n`;
    const wait = (callId: string, cell: string, output: string): string[] => [
      record('response_item', {
        type: 'function_call',
        name: 'wait',
        call_id: callId,
        arguments: JSON.stringify({ cell_id: cell, yield_time_ms: 1000 }),
      }),
      record('response_item', { type: 'function_call_output', call_id: callId, output }),
    ];
    const trace = [
      record('session_meta', { id: 'lead', thread_source: 'security_scan' }),
      // Cell 1 completes after two waits, cell 2 fails after one, cell 3 never ends.
      ...execCell('e1', running('1')),
      ...wait('w1', '1', running('1')),
      ...wait('w2', '1', 'Script completed\nWall time 2.0 seconds\nOutput:\n'),
      ...execCell('e2', running('2')),
      ...wait('w3', '2', 'Script failed\nScript error:\nTypeError: x is undefined'),
      ...execCell('e3', running('3')),
    ];
    writeFileSync(join(sessions, 'rollout-x.jsonl'), trace.join('\n') + '\n');
    const { calls, failed } = failedCalls(traceFolders(other)) as {
      calls: number;
      failed: FailedCall[];
    };
    expect(calls).toBe(3);
    expect(failed.map(f => [f.id, f.name, f.error])).toEqual([
      ['F1', 'exec (cell 2)', 'Script failed Script error: TypeError: x is undefined'],
      ['F2', 'exec (cell 3)', '(still running when the trace ends)'],
    ]);
    rmSync(other, { recursive: true, force: true });
  });

  it("leaves out this check's own sessions in its report dir", () => {
    // A second run into the same report dir finds the first run's Codex session there.
    const report = join(dir, 'traces');
    const own = join(report, 'codex-home', 'sessions', '2026', '11', '20');
    mkdirSync(own, { recursive: true });
    writeFileSync(join(own, 'rollout-2026-11-20T12-30-00-check.jsonl'), LEAD.join('\n') + '\n');
    expect(traceFolders(dir, report)).toEqual(folders);
    expect(traceFolders(dir)).toHaveLength(folders.length + 1);
    rmSync(report, { recursive: true, force: true });
  });

  it('counts no calls in traces it cannot read', () => {
    const other = mkdtempSync(join(tmpdir(), 'scan-traces-'));
    const sessions = join(other, 'sessions', '2026', '11', '20');
    mkdirSync(sessions, { recursive: true });
    writeFileSync(
      join(sessions, 'rollout-x.jsonl'),
      record('event_msg', { type: 'task_started' }) + '\n'
    );
    expect(failedCalls(traceFolders(other))).toEqual({ calls: 0, failed: [] });
    rmSync(other, { recursive: true, force: true });
  });
});

describe('readAnswer', () => {
  const failed = [{ id: 'F1' }, { id: 'F2' }];
  const answer = (value: object): string => `Here is my answer:\n${JSON.stringify(value)}`;
  const pattern = {
    error: 'expected never',
    count: 1,
    agents: 'lead',
    file: 'packages/engine/assets/scan-prompt/references/core-scan.md',
    cause: 'the workflow shows that scope',
    failures: ['F1'],
  };

  it('takes an answer that accounts for every failed call once', () => {
    const pass = {
      result: 'pass',
      patterns: [],
      dismissed: [
        { failure: 'F1', reason: 'a guessed path' },
        { failure: 'F2', reason: 'its own typo' },
      ],
    };
    expect(readAnswer(answer(pass), failed)).toEqual(pass);
    const fail = {
      result: 'fail',
      patterns: [pattern],
      dismissed: [{ failure: 'F2', reason: 'its own typo' }],
    };
    expect(readAnswer(answer(fail), failed)).toEqual(fail);
  });

  it('refuses a pass that does not say why it excused each failed call', () => {
    // v0.3.0's release passed this way: "no failing tool calls the workflow caused", while the
    // draft tool had rejected the lead's first draft.
    expect(readAnswer(answer({ result: 'pass', patterns: [] }), failed)).toBe(
      'it does not account for F1, F2'
    );
    const noReason = {
      result: 'pass',
      patterns: [],
      dismissed: [
        { failure: 'F1', reason: '' },
        { failure: 'F2', reason: 'x' },
      ],
    };
    expect(readAnswer(answer(noReason), failed)).toBe(
      'it dismisses a failed call without a reason'
    );
  });

  it('refuses a dismissed that is not a list', () => {
    // Read as an empty list, it passed, and printing the dismissed calls then threw.
    expect(readAnswer(answer({ result: 'pass', patterns: [], dismissed: {} }), [])).toBe(
      'its dismissed is not a list'
    );
    expect(readAnswer(answer({ result: 'pass', patterns: [] }), [])).toEqual({
      result: 'pass',
      patterns: [],
    });
  });

  it('refuses a pattern that does not name the file of ours it comes from', () => {
    const fail = (p: object) => answer({ result: 'fail', patterns: [p], dismissed: [] });
    const reason = 'it lists a pattern without the file of ours it comes from';
    expect(readAnswer(fail({ ...pattern, file: undefined }), failed)).toBe(reason);
    expect(readAnswer(fail({ ...pattern, file: ' ' }), failed)).toBe(reason);
  });

  it('refuses a failed call accounted for twice, or one the list does not have', () => {
    const twice = {
      result: 'fail',
      patterns: [pattern],
      dismissed: [
        { failure: 'F1', reason: 'x' },
        { failure: 'F2', reason: 'y' },
      ],
    };
    expect(readAnswer(answer(twice), failed)).toBe('it accounts for F1 more than once');
    const unknown = {
      result: 'pass',
      patterns: [],
      dismissed: ['F1', 'F2', 'F9'].map(f => ({ failure: f, reason: 'x' })),
    };
    expect(readAnswer(answer(unknown), failed)).toBe(
      'it names failed calls the list does not have: F9'
    );
  });
});

describe('our prompts', () => {
  it('names each where the docker runtime mounts it', () => {
    expect(OUR_PROMPTS.map(f => [f.path, f.container])).toEqual([
      [PLUGIN_DIR, DOCKER_PATHS.plugin],
      [RUN_PROMPT_FILE, DOCKER_PATHS.prompt],
      [HELPER_CONTEXT_FILE, DOCKER_PATHS.helperContext],
    ]);
  });

  it("finds the run dirs the traces came from, and their plugins' changes", () => {
    const root = mkdtempSync(join(tmpdir(), 'scan-additions-'));
    const write = (path: string, text: string) => {
      mkdirSync(join(root, path, '..'), { recursive: true });
      writeFileSync(join(root, path), text);
    };
    for (const file of ['skills/security-scan/SKILL.md', 'schemas/draft.json'])
      write(`upstream/${file}`, `upstream's ${file}`);
    for (const run of ['state/averlon/scans/r1', 'state/averlon/scans/r1/preflight']) {
      write(`${run}/prompt.md`, 'the scan prompt');
      write(`${run}/plugin/skills/security-scan/SKILL.md`, 'ours');
      write(`${run}/plugin/schemas/draft.json`, "upstream's schemas/draft.json");
      write(`${run}/plugin/scripts/ours.js`, 'ours');
    }

    // An unpacked debug bundle holds a copy of the run dir, with no traces.
    write('scans/bundle/run/prompt.md', 'the scan prompt');
    write('scans/bundle/run/plugin/skills/security-scan/SKILL.md', 'ours');
    const traced = (...runs: string[]) =>
      runDirs(
        root,
        runs.map(run => join(root, run, 'state/codex-home/sessions/2026/11/20'))
      ).map(r => r.slice(root.length));
    // The scan's traces are its run dir's, not its preflight's inside it nor the bundle's copy.
    expect(traced('state/averlon/scans/r1')).toEqual(['/state/averlon/scans/r1']);
    expect(traced('state/averlon/scans/r1/preflight')).toEqual([
      '/state/averlon/scans/r1/preflight',
    ]);
    const changes = pluginChanges(
      join(root, 'state/averlon/scans/r1/preflight/plugin'),
      join(root, 'upstream')
    );
    expect(changes).toEqual([
      { path: 'scripts/ours.js', change: 'added' },
      { path: 'skills/security-scan/SKILL.md', change: 'replaced' },
    ]);
    rmSync(root, { recursive: true, force: true });
  });

  it("finds a native run's dir by the sessions that started in its scan dir", () => {
    // The native runtime's sessions are in upstream's shared state dir, beside other scans'.
    const root = mkdtempSync(join(tmpdir(), 'scan-additions-'));
    const sessions = join(root, 'state', 'codex-home', 'sessions', '2026', '11', '20');
    mkdirSync(sessions, { recursive: true });
    const session = (name: string, cwd: string) =>
      writeFileSync(
        join(sessions, `rollout-${name}.jsonl`),
        record('session_meta', { id: name, cwd }) + '\n'
      );
    for (const run of ['r1', 'r2']) {
      const stage = join(root, 'state', 'averlon', 'scans', run);
      mkdirSync(join(stage, 'plugin'), { recursive: true });
      writeFileSync(join(stage, 'prompt.md'), 'the scan prompt');
      writeFileSync(
        join(stage, 'run.json'),
        JSON.stringify({ scan_dir: join(root, 'scans', run) })
      );
    }
    session('lead', join(root, 'scans', 'r2'));
    session('other', '/elsewhere');
    expect(runDirs(root, [sessions]).map(r => r.slice(root.length))).toEqual([
      '/state/averlon/scans/r2',
    ]);
    rmSync(root, { recursive: true, force: true });
  });
});
