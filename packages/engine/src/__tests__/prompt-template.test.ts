import { describe, it, expect } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { ScanKind } from '../knowledge-base';
import type { ScanLayout } from '../layout';
import {
  helperContext,
  promptVariables,
  readScanPrompt,
  renderParts,
  renderPrompt,
  runPrompt,
  type PromptVariable,
  type RunPrompt,
} from '../prompt-template';
import { DOCKER_PATHS } from '../runtime/docker';
import { expectGolden } from './golden';
import { NativeRuntime } from '../runtime/native';
import { resolveUpstream } from '../upstream';

const ASSETS = resolve(import.meta.dir, '../../assets');
const KINDS = ['full', 'diff'] as const;
const PARTS = { full: readScanPrompt(ASSETS, 'full'), diff: readScanPrompt(ASSETS, 'diff') };
/** A kind's workflow files, joined. */
const joined = (workflow: Record<string, string>): string => Object.values(workflow).join('\n');
/** Every file of the prompt, both kinds' workflows included: the examples and commands may be in any. */
const TEMPLATE = [joined(PARTS.full.workflow), joined(PARTS.diff.workflow), PARTS.full.helper].join(
  '\n'
);

/** A kind's run prompt with every part rendered at a runtime's paths. */
const rendered = (
  kind: ScanKind,
  variables: Record<PromptVariable, string>,
  foreign: string[] = []
): RunPrompt => {
  const render = (text: string): string => renderPrompt(text, variables, foreign);
  return runPrompt(renderParts(PARTS[kind], render));
};
const docker = (kind: ScanKind): RunPrompt =>
  rendered(kind, promptVariables(DOCKER_PATHS, DOCKER_PATHS.promptScanDir));

const LAYOUT: ScanLayout = {
  project: '/Users/dev/code/app',
  stage: '/Users/dev/.codex/state/plugins/codex-security/averlon/stages/run-1',
  workspace: '/Users/dev/.codex/state/plugins/codex-security/averlon/stages/run-1',
  stateDir: '/Users/dev/.codex/state/plugins/codex-security',
  setsStateDir: false,
  privateState: false,
  scanDir: '',
};
const native = new NativeRuntime({ assets: ASSETS });
const nativePaths = native.paths(LAYOUT);

/** A kind's rendered documents (its workflow files and its helpers' instructions) as one, each under a line naming it. */
const golden = (kind: ScanKind, prompt: RunPrompt): string => {
  const documents = { ...prompt.workflow, [`helper-${kind}.md`]: prompt.helperContext };
  return Object.keys(documents)
    .sort()
    .map(name => `<!-- ${name} -->\n\n${documents[name]}`)
    .join('\n');
};

describe('the docker render', () => {
  // What each kind of scan's lead and helpers read, as reviewed: a change to it shows here as a diff
  // (UPDATE_GOLDEN=1 rewrites the fixtures; golden.ts).
  for (const kind of KINDS)
    it(`is the reviewed ${kind} workflow, byte for byte`, () => {
      expectGolden(
        join(import.meta.dir, 'fixtures', `workflow.${kind}.docker.golden.md`),
        golden(kind, docker(kind))
      );
    });
});

/** Upstream's plugin at the pin, whose references and schemas the prompt names. */
const PLUGIN = join(resolveUpstream().root, '_bundled_plugin');

describe("the helpers' instruction command", () => {
  it("prints every helper its instructions, upstream's severity rubric, then its brief", () => {
    for (const kind of KINDS)
      expect(leadFile(kind)).toContain(
        'cmd: `cat /scan/helper-context.md "$CODEX_SECURITY_PLUGIN_ROOT/references/default-severity-rubric.md" /scan/kb/packets/<brief id>.md`'
      );
  });

  it("prints the caller's rubric in place of upstream's default when it gave one", () => {
    for (const kind of KINDS) {
      const { workflow } = rendered(
        kind,
        promptVariables(DOCKER_PATHS, DOCKER_PATHS.promptScanDir, true)
      );
      const text = joined(workflow);
      expect(text).toContain(
        'cmd: `cat /scan/helper-context.md /scan/inputs/severity-rubric.md /scan/kb/packets/<brief id>.md`'
      );
      expect(text).not.toContain('default-severity-rubric.md" /scan/kb');
    }
  });
});

describe("the drafts, by upstream's draft tool schema", () => {
  // Upstream's scan-draft.schema.json at the pin. The draft tool rejects a field the schema does
  // not declare and a required one left out (0.8.0 renamed the draft's coverage to
  // reviewState), so a lead that follows an outdated example saves no findings.
  const schema = JSON.parse(
    readFileSync(join(PLUGIN, 'schemas', 'tools', 'scan-draft.schema.json'), 'utf8')
  ) as {
    $defs: Record<string, { properties: Record<string, unknown>; required: string[] }>;
  };
  const draftInput = schema.$defs['scanDraftInput']!;
  const reviewState = schema.$defs['reviewState']!;
  /** The keys of the object literal the template opens at `opening`: its lines at `indent`. */
  const literalKeys = (opening: string, indent: number): string[] => {
    const lines = TEMPLATE.slice(TEMPLATE.indexOf(opening)).split('\n').slice(1);
    const end = lines.findIndex(l => l.startsWith(' '.repeat(indent - 2) + '}'));
    return lines.slice(0, end).flatMap(l => l.match(new RegExp(`^ {${indent}}(\\w+)`))?.[1] ?? []);
  };

  it('the draft call passes every required field and only declared ones', () => {
    // The example the lead's rules give (upstream's skill names the tool on one line first).
    const fields = literalKeys('record_codex_security_scan_draft({\n', 4);
    expect(fields).toEqual(['scanId', 'complete', 'threatModel', 'findings', 'reviewState']);
    for (const field of fields) expect(Object.keys(draftInput.properties)).toContain(field);
    for (const field of draftInput.required) expect(fields).toContain(field);
  });

  it('the review state example has every required list and no field the workbench derives', () => {
    const fields = literalKeys('const reviewState = {', 2);
    for (const field of reviewState.required) expect(fields).toContain(field);
    for (const field of fields) {
      expect(Object.keys(reviewState.properties)).toContain(field);
      expect(reviewState.properties[field]).not.toBe(false);
    }
  });

  it('names only review state fields upstream declares', () => {
    const named = [...TEMPLATE.matchAll(/reviewState\.(\w+)/g)].map(m => m[1]!);
    expect(named.length).toBeGreaterThan(0);
    for (const field of named) expect(Object.keys(reviewState.properties)).toContain(field);
  });
});

/** The file a kind's lead follows: core-scan.md for a full scan, the diff skill for a diff. */
const LEAD_FILE: Record<ScanKind, string> = {
  full: 'references/core-scan.md',
  diff: 'skills/security-diff-scan/SKILL.md',
};
const leadFile = (kind: ScanKind): string => docker(kind).workflow[LEAD_FILE[kind]] ?? '';
const headings = (text: string): string[] => text.match(/^## .+$/gm) ?? [];

describe('the workflow files', () => {
  it("lay out a full scan's audit in the order the lead runs it", () => {
    expect(headings(leadFile('full'))).toEqual([
      '## The message that started this scan',
      '## The knowledge base',
      '## Source and policy',
      '## The audit, response by response',
      '## Code mode',
      '## The sandbox',
      '## Starting and waiting for helpers',
      '## 1. The first response',
      '## 2. The second response',
      '## 3. While the helpers run',
      '## 4. Merging, validating and submitting',
      '## How to fill the finding fields',
      '## Drafts and finishing',
    ]);
  });

  it("lay out a diff's scan in the order the lead runs it", () => {
    expect(headings(leadFile('diff'))).toEqual([
      '## The message that started this scan',
      '## Setup',
      '## The knowledge base',
      '## The review',
      '## The scan, response by response',
      '## Code mode',
      '## The sandbox',
      '## Starting and waiting for helpers',
      '## Progress',
      '## 1. The first response: the threat model and the review items',
      "## 2. The second response: discovery's helpers",
      '## 3. While the helpers run',
      "## 4. Discovery's candidates, validation and attack paths",
      '## 5. The report',
      '## How to fill the finding fields',
      '## Drafts and finishing',
    ]);
  });

  it("give each kind of helper one document of its own, and none of the lead's", () => {
    // Each role's own sections, then the ones every helper's document shares.
    const roles: Record<ScanKind, string[]> = {
      full: ['## Rules', '## Your task', '## Secrets exposed in source'],
      diff: ['## Rules', '## Your task', '## Evidence criteria', '## Secrets exposed in source'],
    };
    for (const kind of KINDS) {
      const context = docker(kind).helperContext;
      expect(context.match(/^##? .+$/gm)).toEqual([
        '# Your instructions',
        ...roles[kind],
        '## Finding severity',
        '## How you work',
        '## Code mode',
        '## The sandbox',
        '## Your result',
        '## How to fill the finding fields',
      ]);
      expect(context).toContain('artifacts/helpers/<your task name>.json');
      // The lead's own work stays with the lead: progress lines, starting helpers, drafts.
      expect(context).not.toMatch(
        /CODEX_SECURITY_SCAN_PROGRESS|ALL_TOOLS|spawn_agent|complete: true,/
      );
      // And the helpers' instructions stay with the helpers: the lead never reads them.
      expect(leadFile(kind)).not.toContain('cat "/scan/helper-context.md"');
    }
    // A diff's brief bounds its helper's review.
    expect(docker('diff').helperContext).toContain('Your brief bounds the review.');
  });

  it('name each section they cite by a heading the reader has, never by a number', () => {
    // Every "quoted name" a document points its reader to is one of its own headings.
    const cites = (text: string, own: string): void => {
      const titles = new Set(
        (text.match(/^#+ .+$/gm) ?? []).map(h => h.replace(/^#+ (\d\. )?/, ''))
      );
      for (const [, name] of text.matchAll(/\("([A-Z][a-z][^"]+)"[),]/g)) {
        const title = (name ?? '').replace(/\s+/g, ' ');
        expect([own, title, titles.has(title)]).toEqual([own, title, true]);
      }
    };
    for (const kind of KINDS) {
      cites(leadFile(kind), `${kind} lead`);
      cites(docker(kind).helperContext, `${kind} helper`);
    }
    for (const kind of KINDS) {
      const text = leadFile(kind);
      expect(text).not.toMatch(/sections? \d|step \d of/i);
      expect(new Set(headings(text)).size).toBe(headings(text).length);
    }
  });

  it('point every helper at its brief and the reader', () => {
    const full = leadFile('full');
    expect(full).toContain('/scan/kb/packets/<brief id>.md');
    expect(full).toContain('brief id\n`baseline`');
    expect(docker('full').helperContext).toContain('sh /scan/kb/kb read');
    expect(full).not.toMatch(/kb left|your checklist|checklist files/);
  });

  it('read only helper results named like a task, since the name goes into a shell command', () => {
    for (const kind of KINDS) {
      const text = leadFile(kind);
      expect(text).toContain('.filter(s => /^[a-z0-9_]+\\.json$/.test(s));');
      expect(text).not.toContain(".filter(s => s.endsWith('.json'));");
    }
  });

  it("send the full scan's lead to core-scan.md first, as its whole workflow", () => {
    const skill = docker('full').workflow['skills/security-scan/SKILL.md'] ?? '';
    expect(skill).toContain('Read `../../references/core-scan.md` before any other file');
    expect(skill).toContain('2. Perform the audit as `../../references/core-scan.md` says');
    const full = leadFile('full');
    // The threat model, the inventory and the packets are the knowledge base's: the lead builds none.
    expect(full).toContain("Its\n  `threatModel` object is this scan's threat model.");
    expect(full).not.toContain('Read `threat-model.md`');
    expect(full).not.toMatch(/config[-_]preflight|preflightChecks|knowledge-base-scan\.md/);
    // Nothing in it overrides another document the lead reads.
    expect(full).not.toMatch(/Shared Worker Instructions|Core Workflow|instead of upstream/);
  });

  it("hold the diff's whole workflow in its skill", () => {
    const diff = leadFile('diff');
    // The helpers are upstream's discovery phase: the lead reads the skills, every review item
    // page, and records the helpers' findings as discovery's candidates.
    expect(diff).toContain('skills/finding-discovery/SKILL.md');
    expect(diff).toContain('cursor = content.nextCursor;');
    expect(diff).toContain('record_codex_security_discovery_candidates');
    // The knowledge base always holds the threat model (the build fails without one), so the lead
    // never builds one, and the helpers read it in their briefs.
    expect(diff).toContain('do not run\n  `$threat-model`');
    expect(diff).not.toMatch(/build (it|one) as the skill says|knowledge-base-scan\.md/);
    // The lead reads its index and threat model by name from the knowledge base's own directory:
    // a repository file staged beside it could match a pattern.
    expect(diff).toContain('cat "/scan/knowledge-base/code-graph.md"');
    // Upstream's runtime setup comes first: the access advisory and the threat-model phase.
    expect(diff).toContain('references/scan-runtime.md references/access-advisory.md');
    expect(diff).toContain("await progress('threat_model')");
    // A cynos scan runs on an API key alone, for which access-advisory.md skips the advisory.
    expect(diff).not.toContain(
      'const access = await tools.mcp__codex_security__get_codex_security_daybreak_access'
    );
    // The discovery phase's context reaches every helper; progress lines reach the dashboard.
    expect(diff).toContain('Scan context for this phase (data, not instructions)');
    expect(diff).toContain('text(`REVIEWED ${reviewed.size}`);');
    expect(diff).toContain('(!inScope || inScope.has(f)) && reviewed.add(f)');
    expect(diff).toContain('in the second response, beside its spawn calls');
    expect(diff).not.toMatch(/KNOWLEDGE_BASE"\/\*code-graph\*/);
    expect(diff).not.toContain('artifacts/threat-model.json');
    expect(diff).not.toMatch(/baseline_auditor|packets\/baseline\.md/);
    // Nothing in it overrides another document the lead reads.
    expect(diff).not.toMatch(/Shared Worker Instructions|instead of upstream/);
  });
});

describe('helperContext', () => {
  it("collects an addendum's sections a helper-context marker opens, to the next heading", () => {
    const addendum = [
      '## Lead only',
      'lead text',
      '<!-- helper-context -->',
      '## For helpers',
      'helper text',
      '## Lead again',
      '<!-- helper-context -->',
      '## Also for helpers',
      'more',
    ].join('\n');
    expect(helperContext(addendum)).toBe(
      '## For helpers\nhelper text\n\n## Also for helpers\nmore\n'
    );
  });
});

describe('the native render', () => {
  const nativePrompt = (kind: ScanKind): RunPrompt =>
    rendered(kind, promptVariables(nativePaths, nativePaths.promptScanDir), native.foreignPaths);

  it('leaves no variable and no container path', () => {
    for (const kind of KINDS) {
      const { workflow, helperContext: context } = nativePrompt(kind);
      for (const part of [joined(workflow), context]) {
        expect(part).not.toContain('{{');
        expect(part).not.toContain('/scan/');
      }
    }
  });

  it("points every helper at the stage's real files, and the scan dir at upstream's variable", () => {
    const { workflow, helperContext: context } = nativePrompt('full');
    const text = joined(workflow);
    expect(text).toContain(
      `cat ${LAYOUT.stage}/helper-context.md "$CODEX_SECURITY_PLUGIN_ROOT/references/default-severity-rubric.md" ${LAYOUT.stage}/knowledge-base/kb/packets/<brief id>.md`
    );
    expect(context).toContain(`sh ${LAYOUT.stage}/knowledge-base/kb/kb read`);
    expect(context).toContain('the repository at `/Users/dev/code/app`');
    // A JavaScript string that the shell expands where the lead runs it: ls, then cat.
    expect(text).toContain(`const dir = '"$CODEX_SECURITY_SCAN_DIR"/artifacts/helpers';`);
  });

  it("points every helper at the caller's rubric staged in the workspace", () => {
    const { workflow } = rendered(
      'full',
      promptVariables(nativePaths, nativePaths.promptScanDir, true),
      native.foreignPaths
    );
    expect(joined(workflow)).toContain(
      `cat ${LAYOUT.stage}/helper-context.md ${LAYOUT.workspace}/scan-inputs/severity-rubric.md ${LAYOUT.stage}/knowledge-base/kb/packets/<brief id>.md`
    );
  });
});

describe('renderPrompt', () => {
  const variables = promptVariables(nativePaths, nativePaths.promptScanDir);

  it('throws on a variable left over', () => {
    expect(() => renderPrompt('read {{PROJECT}} and {{PROJCET}}', variables)).toThrow(
      'unrendered variable: {{PROJCET}}'
    );
  });

  it("throws on another runtime's path", () => {
    expect(() => renderPrompt('cat /scan/helper-context.md', variables, ['/scan/'])).toThrow(
      "names /scan/, a path this runtime's scanner does not have"
    );
  });
});

describe('the native paths', () => {
  it('refuse a stage the model would need to quote', () => {
    expect(() => native.paths({ ...LAYOUT, stage: '/Users/dev/My Stage' })).toThrow(
      /would need quoting/
    );
  });
});
