import { describe, expect, it } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { REPLACED_WORKFLOW_SHA256 } from '../constants';
import { promptVariables, renderPrompt, withParts } from '../prompt-template';
import { DOCKER_PATHS } from '../runtime/docker';

const PROMPT = resolve(import.meta.dir, '../../assets/scan-prompt');
const SCRIPTS = join(PROMPT, 'scripts');
/** The end of both start scripts' knowledge-base command: the briefs, at the docker runtime's paths. */
const BRIEFS = 'echo "=== BRIEFS ==="; ls -1 "/scan/kb/packets"';
const HELPERS = `${DOCKER_PATHS.promptScanDir}/artifacts/helpers`;

/** What a fake code mode answers: shell commands by their text, MCP tools by their name. */
interface Answers {
  exec?: (cmd: string) => string;
  mcp?: Record<string, (args: Record<string, unknown>) => unknown>;
}

/**
 * Code mode, faked: a script runs as an `exec` body with `tools`, `text`, `store` and `load`, as
 * the lead runs it. Values are stored as copies, as they would be between `exec` calls, and the
 * same `stored` map can be passed to the next run.
 */
async function run(
  name: string,
  answers: Answers,
  stored = new Map<string, unknown>(),
  edit = (body: string) => body
) {
  const output: string[] = [];
  const commands: string[] = [];
  const calls: { tool: string; args: Record<string, unknown> }[] = [];
  const tools = new Proxy(
    {},
    {
      get: (_target, tool: string) => async (args: Record<string, unknown>) => {
        if (tool === 'exec_command') {
          const cmd = String(args['cmd']);
          commands.push(cmd);
          return { output: answers.exec?.(cmd) ?? '' };
        }
        const name = tool.replace(/^mcp__codex_security__/, '');
        calls.push({ tool: name, args });
        const answer = answers.mcp?.[name];
        if (!answer) throw new Error(`unexpected tool ${tool}`);
        return answer(args);
      },
    }
  );
  const body = renderPrompt(
    edit(readFileSync(join(SCRIPTS, name), 'utf8')),
    promptVariables(DOCKER_PATHS, DOCKER_PATHS.promptScanDir)
  );
  const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor as new (
    ...args: string[]
  ) => (...values: unknown[]) => Promise<void>;
  await new AsyncFunction('tools', 'text', 'store', 'load', body)(
    tools,
    (value: string) => output.push(value),
    (key: string, value: unknown) => stored.set(key, structuredClone(value)),
    (key: string) => structuredClone(stored.get(key))
  );
  return { output: output.join('\n'), commands, calls, stored };
}

/** A helper's saved result, as its instructions ask for it. */
const result = (findings: unknown[], reviewed: string[]) =>
  JSON.stringify({ findings, resolved_questions: [], fully_reviewed_files: reviewed });

describe('the workflows and their scripts', () => {
  const workflows = [
    ...new Set(Object.values(REPLACED_WORKFLOW_SHA256).flatMap(files => Object.keys(files))),
  ].map(f => readFileSync(join(PROMPT, f), 'utf8'));

  // The helpers' sections are parts their documents include.
  const parts = readdirSync(join(PROMPT, 'parts')).map(f =>
    readFileSync(join(PROMPT, 'parts', f), 'utf8')
  );

  it('print every script some workflow or part names, and name only scripts that exist', () => {
    const named = new Set(
      [...workflows, ...parts].flatMap(p =>
        [...p.matchAll(/^\{\{SCRIPT (.+)\}\}$/gm)].map(m => m[1])
      )
    );
    expect([...named].sort()).toEqual(
      readdirSync(SCRIPTS)
        .filter(f => f.endsWith('.js'))
        .sort()
    );
  });

  it('put a script where its line is, as the lead runs it', () => {
    const part = withParts('Run this:\n\n```js\n{{SCRIPT read-helper-results.js}}\n```\n', PROMPT);
    expect(part).toStartWith('Run this:\n\n```js\n// @exec: ');
    expect(part).toEndWith('text(`REVIEWED ${reviewed.size}`);\n```\n');
    expect(() => withParts('{{SCRIPT missing.js}}', PROMPT)).toThrow('ENOENT');
  });

  it('put a shared section where a document includes it', () => {
    const part = withParts('# Workflow\n\n{{INCLUDE drafts.md}}\n\n## Next\n', PROMPT);
    expect(part).toStartWith('# Workflow\n\n## Drafts and finishing\n');
    expect(part).toEndWith('`provenance.previousFindings`).\n\n## Next\n');
    expect(() => withParts('{{INCLUDE missing.md}}', PROMPT)).toThrow('ENOENT');
  });
});

describe('read-helper-results.js', () => {
  const helpers = (files: Record<string, string>): Answers => ({
    exec: cmd => {
      if (cmd === `ls -1 ${HELPERS}`) return Object.keys(files).join('\n');
      const file = cmd.startsWith(`cat ${HELPERS}/`) ? cmd.slice(`cat ${HELPERS}/`.length) : '';
      if (!(file in files)) throw new Error(`unexpected command: ${cmd}`);
      return files[file]!;
    },
  });

  it('reads every helper each time, prints only what changed, and only files named like a task', async () => {
    const files = {
      'packet_auth.json': result([{ title: 'a' }], ['a.py']),
      'baseline_auditor.json': result([], ['b.py']),
      // Names that would leave the directory or are no task's: never put into a command.
      '../escape.json': '{}',
      'Bad.json': '{}',
      'notes.txt': '',
    };
    const first = await run('read-helper-results.js', helpers(files));
    expect(first.commands).toEqual([
      `ls -1 ${HELPERS}`,
      `cat ${HELPERS}/packet_auth.json`,
      `cat ${HELPERS}/baseline_auditor.json`,
    ]);
    expect(first.stored.get('helper_names')).toEqual(['packet_auth', 'baseline_auditor']);
    expect(first.output).toContain('packet_auth: findings=1 reviewed=1');

    // The next read reads every result again and prints only the one that is new.
    const next = await run(
      'read-helper-results.js',
      helpers({ ...files, 'packet_db.json': result([], ['c.py']) }),
      first.stored
    );
    expect(next.commands).toEqual([
      `ls -1 ${HELPERS}`,
      `cat ${HELPERS}/packet_auth.json`,
      `cat ${HELPERS}/baseline_auditor.json`,
      `cat ${HELPERS}/packet_db.json`,
    ]);
    expect(next.output).toContain('packet_db: findings=0');
    expect(next.output).not.toContain('packet_auth:');
    expect(next.output).toContain('REVIEWED 3');
  });

  it('takes the findings a running helper saved after its result was first read', async () => {
    const early = await run(
      'read-helper-results.js',
      helpers({ 'packet_auth.json': result([{ title: 'a' }], ['a.py']) })
    );
    const later = await run(
      'read-helper-results.js',
      helpers({ 'packet_auth.json': result([{ title: 'a' }, { title: 'b' }], ['a.py', 'b.py']) }),
      early.stored
    );
    expect(later.output).toContain('packet_auth: findings=2 reviewed=2');
    expect(
      (later.stored.get('helper_packet_auth') as { findings: unknown[] }).findings
    ).toHaveLength(2);
    expect(later.stored.get('helper_names')).toEqual(['packet_auth']);
  });

  it('reports a result that is not JSON, and reads it again next time', async () => {
    const half = await run(
      'read-helper-results.js',
      helpers({ 'packet_x.json': '{"findings": [' })
    );
    expect(half.output).toContain('packet_x: not JSON');
    expect(half.stored.get('helper_names')).toEqual([]);
    const whole = await run(
      'read-helper-results.js',
      helpers({ 'packet_x.json': result([], []) }),
      half.stored
    );
    expect(whole.stored.get('helper_names')).toEqual(['packet_x']);
  });

  it("counts only a diff's review items as reviewed, and every file in a full scan", async () => {
    const files = { 'packet_a.json': result([], ['a.py', 'lib/support.py']) };
    const diff = new Map<string, unknown>([['reviewItems', [{ path: 'a.py' }, { path: 'b.py' }]]]);
    expect((await run('read-helper-results.js', helpers(files), diff)).output).toContain(
      'REVIEWED 1'
    );
    expect((await run('read-helper-results.js', helpers(files))).output).toContain('REVIEWED 2');
  });
});

describe('diff-scan-start.js', () => {
  const threatModel = { summary: 'A gateway.', trustBoundaries: ['Client -> handler (a.py:3)'] };
  const answers = (pages: Record<string, { items: { path: string }[]; nextCursor?: string }>) => ({
    exec: (cmd: string) =>
      cmd.includes('threat-model.json')
        ? `${JSON.stringify({ threatModel, effectiveResources: [] })}\n`
        : cmd.includes('code-graph.md')
          ? '# Knowledge base index: a diff'
          : 'references',
    mcp: {
      update_codex_security_scan_progress: (args: Record<string, unknown>) => ({
        structuredContent: {
          scan: { userContext: args['phase'] === 'discovery' ? 'Focus on tenants.' : '' },
        },
      }),
      record_codex_security_scan_draft: () => ({ accepted: true }),
      prepare_codex_security_review_items: () => ({ prepared: 3 }),
      list_codex_security_review_items: (args: Record<string, unknown>) => ({
        structuredContent: pages[String(args['cursor'] ?? '')],
      }),
    },
  });

  it('keeps the threat model in a draft, reads every page of review items, then enters discovery', async () => {
    const { calls, stored, output } = await run(
      'diff-scan-start.js',
      answers({
        '': { items: [{ path: 'a.py' }], nextCursor: 'c1' },
        c1: { items: [{ path: 'b.py' }], nextCursor: 'c2' },
        c2: { items: [{ path: 'c.py' }] },
      })
    );
    expect(calls.map(c => c.tool)).toEqual([
      'update_codex_security_scan_progress',
      'record_codex_security_scan_draft',
      'prepare_codex_security_review_items',
      'list_codex_security_review_items',
      'list_codex_security_review_items',
      'list_codex_security_review_items',
      'update_codex_security_scan_progress',
    ]);
    expect(calls.filter(c => c.tool.includes('progress')).map(c => c.args['phase'])).toEqual([
      'threat_model',
      'discovery',
    ]);
    expect(calls[1]!.args).toMatchObject({ complete: false, threatModel, findings: [] });
    expect(stored.get('threatModel')).toEqual(threatModel);
    expect((stored.get('reviewItems') as { path: string }[]).map(i => i.path)).toEqual([
      'a.py',
      'b.py',
      'c.py',
    ]);
    expect(stored.get('discoveryContext')).toBe('Focus on tenants.');
    expect(output).toContain('ITEMS 3: a.py, b.py, c.py');
  });

  it('reads the index and the threat model from the knowledge base by name', async () => {
    const { commands } = await run('diff-scan-start.js', answers({ '': { items: [] } }));
    expect(commands).toContain('cat "/scan/knowledge-base/threat-model.json"');
    expect(commands.some(c => c.includes('cat "/scan/knowledge-base/code-graph.md";'))).toBe(true);
    // The briefs, listed so the lead starts helpers without checking them; the helpers'
    // instructions are theirs alone.
    expect(commands.some(c => c.endsWith(BRIEFS))).toBe(true);
  });
});

describe('full-scan-start.js', () => {
  it('reads the references and the index in one script, and calls no scan tool', async () => {
    const { calls, commands } = await run('full-scan-start.js', { exec: () => 'text', mcp: {} });
    // Upstream's runtime setup; not core-scan.md, the workflow the lead has just read. Its
    // preflight and the Daybreak advisory are not a cynos scan's (upstream retired the one; an
    // API-key session skips the other).
    expect(commands[0]).toContain(
      'for f in scan-prologue.md scan-runtime.md access-advisory.md finding-detail-fields.md;'
    );
    expect(commands[1]).toContain('cat "$CODEX_SECURITY_KNOWLEDGE_BASE"/*code-graph*;');
    // The briefs, listed so the lead starts helpers without checking them; the helpers'
    // instructions are theirs alone.
    expect(commands[1]).toEndWith(BRIEFS);
    expect(calls).toEqual([]);
  });
});

describe('merge-helper-results.js', () => {
  const finding = (path: string, line: number, cwe: unknown, evidence = 1) => ({
    title: `${path}:${line}`,
    taxonomy: { cwe },
    locations: [{ path, startLine: line, role: 'root_control' }],
    codeEvidence: Array.from({ length: evidence }, () => ({})),
  });
  const helpers = (all: Record<string, ReturnType<typeof finding>[]>) =>
    new Map<string, unknown>([
      ['helper_names', Object.keys(all)],
      ...Object.entries(all).map(
        ([n, findings]) =>
          [
            `helper_${n}`,
            {
              findings,
              fully_reviewed_files: findings.map(f => f.locations[0]!.path),
              resolved_questions: [`about ${n}`],
            },
          ] as [string, unknown]
      ),
    ]);

  it('keeps one copy of a duplicate, the one with more evidence, and every other finding', async () => {
    const { stored } = await run(
      'merge-helper-results.js',
      {},
      helpers({
        packet_a: [finding('a.py', 10, ['CWE-89']), finding('a.py', 30, ['CWE-89'])],
        baseline_auditor: [
          // packet_a's first finding again, with more evidence: it replaces that one.
          finding('a.py', 10, ['CWE-89'], 3),
          // Two lines away is a sibling operation, not the same one.
          finding('a.py', 12, ['CWE-89']),
          // The same line with another CWE is another finding.
          finding('a.py', 10, ['CWE-79']),
        ],
      })
    );
    const merged = stored.get('merged') as { title: string; _helper: string }[];
    expect(merged.map(f => `${f._helper} ${f.title}`)).toEqual([
      'baseline_auditor a.py:10',
      'packet_a a.py:30',
      'baseline_auditor a.py:12',
      'baseline_auditor a.py:10',
    ]);
  });

  it("compares sink lines when the findings have them, and keeps both copies' locations", async () => {
    const withSink = (line: number, sink: number, evidence = 1) => {
      const f = finding('a.py', line, ['CWE-79'], evidence);
      f.locations.push({ path: 'a.py', startLine: sink, role: 'sink' });
      return f;
    };
    const { stored } = await run(
      'merge-helper-results.js',
      {},
      helpers({
        packet_a: [withSink(5, 20), withSink(6, 21)],
        baseline_auditor: [withSink(8, 20, 2)],
      })
    );
    const merged = stored.get('merged') as {
      title: string;
      locations: { startLine: number; role: string }[];
    }[];
    // One sink at line 20 (two reports of it), one at line 21.
    expect(merged.map(f => f.title)).toEqual(['a.py:8', 'a.py:6']);
    expect(merged[0]?.locations.map(l => `${l.role}:${l.startLine}`)).toEqual([
      'root_control:8',
      'sink:20',
      'root_control:5',
    ]);
  });

  it("gives every finding a CWE list and the plugin's source, and keeps what the helpers reviewed and asked", async () => {
    const { stored } = await run(
      'merge-helper-results.js',
      {},
      helpers({
        packet_a: [finding('a.py', 1, 'CWE-22')],
        packet_b: [finding('b.py', 1, ['CWE-78'])],
      })
    );
    const merged = stored.get('merged') as {
      taxonomy: { cwe: string[] };
      provenance: { source: string };
    }[];
    expect(merged.map(f => f.taxonomy.cwe)).toEqual([['CWE-22'], ['CWE-78']]);
    expect(merged.every(f => f.provenance.source === 'local_plugin')).toBe(true);
    expect(stored.get('reviewed')).toEqual(['a.py', 'b.py']);
    expect(stored.get('questions')).toEqual([
      'packet_a: about packet_a',
      'packet_b: about packet_b',
    ]);
  });

  it("makes every identity a slug the draft tool takes, as upstream's workbench makes one", async () => {
    // The draft tool's pattern for identity.anchor and identity.instance.
    const SLUG = /^[a-z0-9][a-z0-9._/-]*$/;
    const identified = (line: number, ruleId: string, identity: Record<string, string>) => ({
      ...finding('a.py', line, ['CWE-89']),
      ruleId,
      identity,
    });
    const { stored } = await run(
      'merge-helper-results.js',
      {},
      helpers({
        packet_a: [
          // Values the draft tool rejected in real scans: a path and a code name.
          identified(1, 'ci-injection', { anchor: '.github/workflows/cynos-pr.yml' }),
          identified(2, 'key-overwrite', {
            anchor: 'provider-key-store',
            instance: 'UpdateProviderKey-store-not-found-creates-key',
          }),
          identified(3, 'ssrf', { anchor: 'Résumé URL', instance: '***' }),
          // Two that are one identity once slugged, and one already taking the split's first name.
          identified(4, 'sqli', { anchor: 'LoginQuery' }),
          identified(5, 'sqli', { anchor: 'loginquery' }),
          identified(6, 'sqli', { anchor: 'loginquery', instance: 'saved-2' }),
        ],
      })
    );
    const merged = stored.get('merged') as { ruleId: string; identity: Record<string, string> }[];
    expect(merged.map(f => f.identity)).toEqual([
      { anchor: 'github/workflows/cynos-pr.yml' },
      { anchor: 'provider-key-store', instance: 'updateproviderkey-store-not-found-creates-key' },
      { anchor: 'resume-url', instance: 'finding-3' },
      { anchor: 'loginquery' },
      { anchor: 'loginquery', instance: 'saved-3' },
      { anchor: 'loginquery', instance: 'saved-2' },
    ]);
    for (const { identity } of merged)
      for (const value of Object.values(identity)) expect(value).toMatch(SLUG);
    const keys = merged.map(f => JSON.stringify([f.ruleId, f.identity]));
    expect(new Set(keys).size).toBe(keys.length);
  });
});

describe('save-helper-result.js', () => {
  /** The shells a helper's commands may run in: zsh on macOS and Kali, sh or bash elsewhere. */
  const SHELLS = ['sh', 'bash', 'zsh'].filter(shell => Bun.which(shell));
  /** Linux's limit on one argument (MAX_ARG_STRLEN), which the shell's whole command is. */
  const ARGUMENT = 128 * 1024;

  /** A scan dir of its own, which the script's commands run in as the docker runtime's. */
  const scanDir = () => mkdtempSync(join(tmpdir(), 'helper-result-'));
  const shell =
    (dir: string, name = 'sh') =>
    (cmd: string): string => {
      const run = spawnSync(name, ['-c', cmd.replaceAll(DOCKER_PATHS.promptScanDir, dir)], {
        encoding: 'utf8',
      });
      return run.stdout + run.stderr;
    };
  /** The script as a helper runs it: its task name in place. */
  const as = (task: string) => (body: string) =>
    body.replace("const task = '<task name>';", `const task = '${task}';`);
  const save = (dir: string, result: unknown, name = 'sh', task = 'packet_auth') =>
    run(
      'save-helper-result.js',
      { exec: shell(dir, name) },
      new Map([['result', result]]),
      as(task)
    );
  const saved = (dir: string, task = 'packet_auth') =>
    JSON.parse(readFileSync(join(dir, 'artifacts/helpers', `${task}.json`), 'utf8'));

  /** A whole result whose text a shell would read as more than text, if it could. */
  const awkward = {
    findings: [
      {
        title: "Path traversal in the user's upload: ../ and \\ é 中文 😀",
        summary: "It runs $(id) and `id`; prints %s %d \\n; quotes \" and ' and '\\''",
        locations: [{ path: 'app/up load.py', startLine: 3 }],
      },
    ],
    resolved_questions: ['Line one\nline two\ttabbed, and EOF'],
    fully_reviewed_files: ['app/up load.py'],
  };

  for (const name of SHELLS)
    it(`saves the stored result where the lead reads it, whatever its text holds (${name})`, async () => {
      const dir = scanDir();
      try {
        const { output, calls } = await save(dir, awkward, name);
        expect(saved(dir)).toEqual(awkward);
        expect(output).toBe(
          'saved artifacts/helpers/packet_auth.json: findings=1 resolved_questions=1 fully_reviewed_files=1'
        );
        // The scan's tools refuse a helper; nothing but its shell writes the file.
        expect(calls).toEqual([]);
        expect(readdirSync(join(dir, 'artifacts/helpers'))).toEqual(['packet_auth.json']);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

  it('writes a large result in pieces each shorter than one argument, and replaces the last save', async () => {
    const dir = scanDir();
    try {
      await save(dir, awkward);
      const large = {
        ...awkward,
        findings: Array.from({ length: 300 }, (_, i) => ({
          ...awkward.findings[0],
          id: i,
          code: "x'é".repeat(400),
        })),
      };
      const { commands } = await save(dir, large);
      expect(commands.length).toBeGreaterThan(3);
      for (const cmd of commands) expect(Buffer.byteLength(cmd)).toBeLessThan(ARGUMENT);
      expect(saved(dir)).toEqual(large);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('leaves the last whole save in place when a save is cut short', async () => {
    const dir = scanDir();
    try {
      await save(dir, awkward);
      const large = {
        ...awkward,
        findings: Array.from({ length: 100 }, () => ({ code: 'y'.repeat(2000) })),
      };
      // Every piece after the first is lost, as when the helper is stopped mid-save.
      const lossy = (cmd: string) => (cmd.includes(' >> ') ? '' : shell(dir)(cmd));
      const cut = run(
        'save-helper-result.js',
        { exec: lossy },
        new Map([['result', large]]),
        as('packet_auth')
      );
      await expect(cut).rejects.toThrow('Not saved; the last one stays in place');
      expect(saved(dir)).toEqual(awkward);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('runs no command without its task name, or without a whole stored result', async () => {
    const commands: string[] = [];
    const exec = (cmd: string) => (commands.push(cmd), '');
    await expect(
      run('save-helper-result.js', { exec }, new Map([['result', awkward]]))
    ).rejects.toThrow('Put your task name in the script\'s second line, not "<task name>".');
    // A name the lead does not read, or that would leave the directory.
    await expect(save('/nowhere', awkward, 'sh', '../packet_auth')).rejects.toThrow(
      'Put your task name'
    );
    await expect(
      run(
        'save-helper-result.js',
        { exec },
        new Map([['result', { findings: [] }]]),
        as('packet_auth')
      )
    ).rejects.toThrow("First store('result', ...) your whole result");
    await expect(
      run('save-helper-result.js', { exec }, new Map(), as('packet_auth'))
    ).rejects.toThrow('First store');
    expect(commands).toEqual([]);
  });

  it("is what the lead's read-helper-results.js reads, and a partial file is not", async () => {
    const dir = scanDir();
    try {
      await save(dir, awkward, 'sh', 'packet_auth');
      await save(
        dir,
        { findings: [], resolved_questions: [], fully_reviewed_files: ['b.py'] },
        'sh',
        'baseline_auditor'
      );
      spawnSync('sh', [
        '-c',
        `printf '{"findings": [' > '${dir}/artifacts/helpers/.packet_db.json.partial'`,
      ]);
      const { stored, output } = await run('read-helper-results.js', { exec: shell(dir) });
      expect(stored.get('helper_packet_auth')).toEqual(awkward);
      expect(stored.get('helper_names')).toEqual(['baseline_auditor', 'packet_auth']);
      expect(output).not.toContain('packet_db');
      expect(output).toContain('REVIEWED 2');
      expect(existsSync(join(dir, 'artifacts/helpers/.packet_db.json.partial'))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
