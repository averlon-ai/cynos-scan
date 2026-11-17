import { describe, expect, it } from 'bun:test';
import { spawnSync } from 'node:child_process';
import {
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { PROMPT_DIR, REPLACED_WORKFLOW_SHA256 } from '../constants';
import type { ScanKind } from '../knowledge-base';
import { promptVariables, readScanPrompt, renderParts, renderPrompt } from '../prompt-template';
import { DOCKER_PATHS } from '../runtime/docker';
import { expectGolden } from './golden';
import { nativeEnvironment } from '../runtime/native';
import { stagePlugin } from '../scan-plugin';
import { bundledPluginRoot, resolveUpstream } from '../upstream';

const ASSETS = resolve(import.meta.dir, '../../assets');
const FIXTURES = join(import.meta.dir, 'fixtures');
const KINDS = ['full', 'diff'] as const;
/** Upstream's plugin at the pin, which every scan's plugin is copied from. */
const UPSTREAM = bundledPluginRoot();

/** A kind's documents, rendered at the docker runtime's paths. */
const rendered = (kind: ScanKind) => {
  const variables = promptVariables(DOCKER_PATHS, DOCKER_PATHS.promptScanDir);
  return renderParts(readScanPrompt(ASSETS, kind), text => renderPrompt(text, variables));
};
/** A kind's workflow files. */
const workflow = (kind: ScanKind): Record<string, string> => rendered(kind).workflow;
/** A kind's helpers' instructions. */
const helper = (kind: ScanKind): string => rendered(kind).helper;

/** A kind's scan plugin, staged in a fresh directory. */
const staged = (kind: ScanKind, source = UPSTREAM): string => {
  const destination = join(mkdtempSync(join(tmpdir(), 'scan-plugin-')), 'plugin');
  stagePlugin(source, destination, kind, workflow(kind));
  return destination;
};

/** Every file under a directory, relative to it. */
const files = (root: string, under = ''): string[] =>
  readdirSync(join(root, under), { withFileTypes: true }).flatMap(entry =>
    entry.isDirectory() ? files(root, join(under, entry.name)) : [join(under, entry.name)]
  );

/**
 * The workflow files that stay upstream's text with a few lines changed: the full scan's skill,
 * which only sends the lead to core-scan.md. The others are written for this scan (POLICY).
 */
const EDITED = ['skills/security-scan/SKILL.md'];

/** The documents a scan's lead and helpers read. */
type Reader = 'full lead' | 'full helper' | 'diff lead' | 'diff helper';

/** One of upstream's policy passages: the plugin file it is in, and how to cut it out. */
interface Passage {
  from: string;
  file: string;
  passage: (text: string) => string;
  in: Reader[];
}

const CORE = 'references/core-scan.md';
const DIFF = 'skills/security-diff-scan/SKILL.md';
const DISCOVERY = 'skills/finding-discovery/SKILL.md';
const RUBRIC = 'references/default-severity-rubric.md';

/** A passage that is a whole section's body. */
const whole = (file: string, heading: string, readers: Reader[]): Passage => ({
  from: `${file} ${heading}`,
  file,
  passage: text => section(text, heading),
  in: readers,
});

/** A passage that runs from `start` to the end of its line, or, with `sentence`, of its sentence. */
const line = (file: string, start: string, readers: Reader[], sentence = false): Passage => ({
  from: `${file} "${start}"`,
  file,
  passage: text => {
    const from = text.indexOf(start);
    if (from < 0) return '';
    const rest = text.slice(from, text.indexOf('\n', from));
    const end = sentence ? rest.search(/\. [A-Z]/) : -1;
    return end < 0 ? rest : rest.slice(0, end + 1);
  },
  in: readers,
});

/**
 * upstream's policy: what a finding's severity is, the secrets standard, what validation and
 * discovery establish, the helpers' tasks, and the diff workflow's setup and phase rules. Our
 * documents are written for this scan, but each of these passages is upstream's word for word, in
 * every document that holds it: the judgement stays upstream's, and a pin that changes one of them
 * fails here until ours follows.
 */
const POLICY: Passage[] = [
  whole(CORE, 'Source And Policy', ['full lead']),
  whole(CORE, 'Secrets Exposed In Source', ['full lead', 'full helper', 'diff helper']),
  whole(CORE, 'Finding Severity', ['full lead', 'full helper', 'diff helper']),
  {
    ...whole(CORE, 'Baseline Auditor Prompt', ['full helper']),
    passage: text => fenced(section(text, 'Baseline Auditor Prompt')),
  },
  {
    ...whole(CORE, 'Focused Investigator Prompt', ['full helper', 'diff helper']),
    passage: text => fenced(section(text, 'Focused Investigator Prompt')),
  },
  {
    ...whole(CORE, 'Shared Worker Instructions', ['full helper', 'diff helper']),
    passage: text => fenced(section(text, 'Shared Worker Instructions')).split('\n\n')[0] ?? '',
  },
  line(CORE, 'Knowledge-base facts override generated assumptions', ['full lead'], true),
  line(
    CORE,
    'Review only the authorized current source, read-only and offline. Supplied',
    ['full lead'],
    true
  ),
  line(CORE, 'Read reviewer feedback supplied by the caller', ['full lead']),
  line(CORE, 'Independently validate each unique finding against local source.', ['full lead']),
  line(CORE, 'Group observations only when they share the broken control', ['full lead']),
  line(CORE, 'Follow `finding-detail-fields.md` for rich evidence', ['full lead'], true),
  line(CORE, 'Without delegation, perform the audit in the parent', ['full lead']),
  line(CORE, 'Architecture mapping alone does not establish completed audit coverage.', [
    'full lead',
  ]),
  {
    ...line(CORE, 'findings retain `provenance.candidateId`', ['full lead']),
    passage: text => {
      const from = text.indexOf('findings retain `provenance.candidateId`');
      const end = text.indexOf(' on a `rejected` coverage surface', from);
      return from < 0 || end < 0 ? '' : text.slice(from, end) + ' on a `rejected` coverage surface';
    },
  },
  line(CORE, 'Keep discovery, validation, and attack-path reasoning', ['full lead']),
  line(DIFF, 'Review every changed text file, including deleted files.', ['diff lead']),
  ...[
    'Resolve the exact Git range or local patch',
    'Continue an existing `scanId`',
    'Read `../../references/scan-runtime.md` before source review',
    'Preserve any existing or host-supplied investigation time allowance',
    'Persist requested context changes',
    'Use `cancel_codex_security_scan` only',
    'The inventory includes changed text files',
    'Every changed file and candidate must be accounted for',
    'The host writes `threatmodel.md`',
    'Review supporting unchanged files only as needed',
    'Keep independently vulnerable instances addressable',
    'If candidates exist, run `$validation` once',
    'Read `../../references/final-report.md` for the finding',
    'Call `complete_codex_security_scan` once',
  ].map(start => line(DIFF, start, ['diff lead'])),
  line(
    DIFF,
    'Preserve a supplied schema-valid canonical `threatModel` object unchanged.',
    ['diff lead'],
    true
  ),
  line(DISCOVERY, 'For a diff, inspect the actual changed behavior', ['diff helper']),
  {
    ...whole(DISCOVERY, 'Evidence Criteria', ['diff helper']),
    passage: text => section(text, 'Evidence Criteria').split('\n\n')[0] ?? '',
  },
];

/** A section's body, after its heading, to the next one. */
function section(text: string, heading: string): string {
  const start = text.indexOf(`\n## ${heading}\n`);
  if (start < 0) return '';
  const end = text.indexOf('\n## ', start + 1);
  return text.slice(start + heading.length + 5, end < 0 ? undefined : end).trim();
}

/** The text inside a section's ```markdown fence. */
function fenced(body: string): string {
  const start = body.indexOf('```markdown\n') + '```markdown\n'.length;
  return body.slice(start, body.indexOf('\n```', start)).trim();
}

/**
 * Our copy of a workflow file against upstream's, as `git diff` prints it, without the developer's
 * git settings (color, prefixes) and with the files named upstream/ and cynos/. Ours is the asset
 * as written: its `{{SCRIPT}}`, `{{INCLUDE}}` and path variables are rendered elsewhere.
 */
const workflowDiff = (path: string): string => {
  const dir = mkdtempSync(join(tmpdir(), 'scan-workflow-diff-'));
  for (const [side, text] of [
    ['upstream', readFileSync(join(UPSTREAM, path), 'utf8')],
    ['cynos', readFileSync(join(ASSETS, PROMPT_DIR, path), 'utf8')],
  ] as const) {
    mkdirSync(join(dir, side, dirname(path)), { recursive: true });
    writeFileSync(join(dir, side, path), text);
  }
  const run = spawnSync(
    'git',
    [
      'diff',
      '--no-index',
      '--no-color',
      '--no-ext-diff',
      join('upstream', path),
      join('cynos', path),
    ],
    {
      cwd: dir,
      encoding: 'utf8',
      env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' },
    }
  );
  // 1 is git's answer for files that differ; anything else is a failure to compare.
  if (run.status !== 1) throw new Error(`git diff failed: ${run.stderr}`);
  return run.stdout.replace(/^index .*\n/m, '');
};

/** A workflow file's fixture: skills/security-scan/SKILL.md -> security-scan.SKILL.md.diff. */
const fixture = (path: string): string =>
  join(FIXTURES, `${path.split('/').slice(1).join('.')}.diff`);

describe('our workflow files', () => {
  // The diff is the review. A change to either side shows here; UPDATE_GOLDEN=1 rewrites the
  // fixture to the new diff (golden.ts).
  for (const path of EDITED)
    it(`differ from upstream's ${path} by the reviewed lines only`, () => {
      expectGolden(fixture(path), workflowDiff(path));
    });

  it("hold upstream's policy word for word", () => {
    const documents: Record<Reader, string> = {
      'full lead': workflow('full')['references/core-scan.md'] ?? '',
      'full helper': helper('full'),
      'diff lead': workflow('diff')['skills/security-diff-scan/SKILL.md'] ?? '',
      'diff helper': helper('diff'),
    };
    // Every passage that is gone from upstream or missing from a document, not just the first: a
    // pin that rewrites several shows them all at once.
    const differ = POLICY.flatMap(({ from, file, passage, in: readers }) => {
      const text = passage(readFileSync(join(UPSTREAM, file), 'utf8'));
      if (text.length <= 60) return [`${from}: not in upstream's file`];
      return readers.filter(r => !documents[r].includes(text)).map(r => `${from}: not in ${r}`);
    });
    expect(differ).toEqual([]);
  });

  // The lead reads the diff's SKILL.md with a plain `cat`, before it knows of the `// @exec:`
  // header: Codex returns 10,000 tokens of an exec's output without one, and drops the middle.
  it('keep the diff skill short enough for an exec without a header', () => {
    expect((workflow('diff')['skills/security-diff-scan/SKILL.md'] ?? '').length).toBeLessThan(
      34000
    );
  });

  // upstream grades with --rubric's file, else its bundled default, else (only with
  // CODEX_SECURITY_ENABLE_REMOTE_SEVERITY_RUBRIC=1) a remote one, and tells the lead to pass that
  // snapshot to its workers. cynos passes --rubric only with the caller's file, which each
  // helper's first exec then prints, and neither runtime passes the switch; so without one the
  // snapshot is the bundled default: the plugin's own file, which each helper prints instead.
  it('give the helpers the rubric upstream gives a cynos scan without --rubric', async () => {
    const { defaultSeverityRubric } = (await import(
      join(resolveUpstream().root, 'dist/default-severity-rubric.js')
    )) as { defaultSeverityRubric: string };
    expect(defaultSeverityRubric).toBe(readFileSync(join(UPSTREAM, RUBRIC), 'utf8'));
    expect(
      nativeEnvironment({ PATH: '/bin', CODEX_SECURITY_ENABLE_REMOTE_SEVERITY_RUBRIC: '1' })
    ).not.toHaveProperty('CODEX_SECURITY_ENABLE_REMOTE_SEVERITY_RUBRIC');
  });
});

describe('stagePlugin', () => {
  for (const kind of KINDS)
    it(`puts our ${kind} workflow in place of upstream's, and changes nothing else`, () => {
      const plugin = staged(kind);
      const ours = workflow(kind);
      for (const [path, text] of Object.entries(ours))
        expect(readFileSync(join(plugin, path), 'utf8')).toBe(text);
      // Every other file is upstream's, byte for byte, and none is a link (upstream refuses one).
      expect(files(plugin).sort()).toEqual(files(UPSTREAM).sort());
      for (const file of files(plugin)) {
        expect(lstatSync(join(plugin, file)).isSymbolicLink()).toBe(false);
        if (!(file in ours))
          expect(readFileSync(join(plugin, file)).equals(readFileSync(join(UPSTREAM, file)))).toBe(
            true
          );
      }
    });

  it("is a plugin upstream's own check accepts", async () => {
    const runtime = (await import(join(resolveUpstream().root, 'dist', 'runtime.js'))) as {
      pluginMetadata: (root: string) => Promise<{ name: string; version: string }>;
    };
    const upstream = await runtime.pluginMetadata(UPSTREAM);
    for (const kind of KINDS) expect(await runtime.pluginMetadata(staged(kind))).toEqual(upstream);
  });

  for (const path of Object.keys(REPLACED_WORKFLOW_SHA256.full))
    it(`throws when upstream's ${path} is not the one ours were written against, and stages nothing`, () => {
      const source = join(mkdtempSync(join(tmpdir(), 'scan-plugin-source-')), 'plugin');
      cpSync(UPSTREAM, source, { recursive: true });
      writeFileSync(join(source, path), '# changed\n');
      const destination = join(mkdtempSync(join(tmpdir(), 'scan-plugin-')), 'plugin');
      expect(() => stagePlugin(source, destination, 'full', workflow('full'))).toThrow(
        `upstream's ${path} is not the one this scan's workflow was written against`
      );
      expect(existsSync(destination)).toBe(false);
    });

  it("throws on a workflow that is not exactly the kind's files", () => {
    const destination = join(mkdtempSync(join(tmpdir(), 'scan-plugin-')), 'plugin');
    expect(() => stagePlugin(UPSTREAM, destination, 'diff', workflow('full'))).toThrow(
      "A diff scan's workflow is skills/security-diff-scan/SKILL.md."
    );
    expect(existsSync(destination)).toBe(false);
  });
});

describe('the workflow against the plugin at the pin', () => {
  // A file upstream renamed or retired prints "No such file" in the lead's first exec, and nothing
  // else fails: the e2e's mock scan never runs the model (the preflight's config_preflight.py did
  // this from 0.8 until this test).
  for (const kind of KINDS)
    it(`names only plugin files the ${kind} scan's plugin has`, () => {
      const plugin = staged(kind);
      const named = Object.entries(workflow(kind)).flatMap(([path, text]) => [
        // "$CODEX_SECURITY_PLUGIN_ROOT/<path>" anywhere in the file and its scripts.
        ...[...text.matchAll(/\$CODEX_SECURITY_PLUGIN_ROOT\/([\w./-]+)/g)].map(m => m[1] ?? ''),
        // `cd "$CODEX_SECURITY_PLUGIN_ROOT[/<dir>]" && for f in <files>;` in the start scripts.
        ...[
          ...text.matchAll(/cd "\$CODEX_SECURITY_PLUGIN_ROOT(\/[\w-]+)?" && for f in ([^;]+);/g),
        ].flatMap(m =>
          (m[2] ?? '')
            .trim()
            .split(/\s+/)
            .map(f => join(m[1]?.slice(1) ?? '', f))
        ),
        // `references/...` and `../../references/...`, from the file's own directory.
        ...[...text.matchAll(/`((?:\.\.\/)*references\/[\w.-]+\.md)`/g)].map(m =>
          join(dirname(path), m[1] ?? '')
        ),
      ]);
      expect(named.length).toBeGreaterThan(5);
      for (const path of named)
        expect([path, existsSync(join(plugin, path))]).toEqual([path, true]);
    });
});
