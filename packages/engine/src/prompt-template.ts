/**
 * The scan's workflow: the files the lead follows, and the paths the scanner sees.
 *
 * upstream's task message tells the lead to follow a workflow skill (security-scan, or
 * security-diff-scan for a diff), and a full scan's skill sends it on to references/core-scan.md.
 * A scan with a knowledge base changes that workflow itself (the threat model and the packets are
 * built before the scan, the lead starts every helper at once, and the helpers read their
 * instructions from a file), so the scan gives upstream our copies of those files
 * (scan-plugin.ts). Each reader gets one document, written for this scan:
 *
 *   references/core-scan.md                full: the lead's whole audit, in the order it runs
 *   skills/security-scan/SKILL.md          full: upstream's skill, sending the lead to the above
 *   skills/security-diff-scan/SKILL.md     diff: the lead's whole scan, in the order it runs
 *   helper-<kind>.md                       every helper's instructions, which it prints first
 *
 * upstream's policy (the severity rules, the secrets standard, what validation establishes, the
 * helpers' tasks) is kept word for word inside them; the mechanics around it (how work is split,
 * started, returned and submitted) are ours. upstream gives the lead the scan's severity rubric
 * and tells it to pass that to its workers; so each helper's first exec prints the same rubric with
 * its instructions ({{RUBRIC}}): the caller's (--rubric, staged by scan-inputs.ts), or upstream's
 * own file of its default, references/default-severity-rubric.md. They are at those paths under
 * assets/scan-prompt/, with what they share beside them:
 *
 *   parts/        sections more than one document holds (code mode, starting helpers, the
 *                  finding shape, drafts), each placed where it belongs with an
 *                  `{{INCLUDE <name>.md}}` line
 *   scripts/       the whole `exec` scripts the workflows hand the lead
 *
 * Each of the lead's replies costs close to a minute, so one script does what would take several.
 * The scripts are code: JavaScript typechecked against code mode's globals (scripts/code-mode.d.ts)
 * and run in tests, and a workflow names one where it prints it:
 *
 *   ```js
 *   {{SCRIPT read-helper-results.js}}
 *   ```
 *
 * readScanPrompt puts each script's and each included file's text in place of its line, before the
 * paths are rendered, so they name paths with the same variables. The scan prompt
 * (--scan-prompt-file) is the caller's addendum alone, as upstream means it: the user's context.
 *
 * The files tell the lead and every helper which files to print and where to read:
 * the helper sections, the briefs and their reader, the checkout, the helpers' saved results.
 * Those paths differ between the runtimes: in the docker runtime's container they are fixed
 * (/scan/project, /scan/kb, ...); in the native runtime they are the stage's real paths, and the
 * scan dir does not exist until the engine creates it for upstream. So the files name them as
 * variables, and each runtime renders its own:
 *
 *   {{PROJECT}}          the checkout
 *   {{KB_INDEX}}         the helpers' briefs, the reader and its index
 *   {{HELPER_CONTEXT}}   the rules every agent follows, as the helpers print them
 *   {{KNOWLEDGE_BASE}}   the lead's index and the threat model
 *   {{RUBRIC}}           the scan's severity rubric, as a helper's exec names it: the caller's
 *                        staged file, or upstream's default in the staged plugin
 *   {{SCAN_DIR}}         upstream's scan dir: "$CODEX_SECURITY_SCAN_DIR" natively, which upstream
 *                        sets in the model's shell, as the workflow already uses
 *                        $CODEX_SECURITY_PLUGIN_ROOT
 *
 * A rendered file with a variable left over, or with a path of another runtime (/scan/ in the
 * native render), would send a helper to a file that is not there; both throw.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { PROMPT_DIR, REPLACED_WORKFLOW_SHA256 } from './constants';
import type { ScanKind } from './knowledge-base';
import type { ScanPaths } from './runtime';

/** A kind of scan's workflow files by plugin-relative path, and the rules every agent follows. */
export interface PromptParts {
  workflow: Record<string, string>;
  helper: string;
}

/** A kind's workflow files and the helper rules, from the engine's assets, with their parts in place. */
export function readScanPrompt(assets: string, kind: ScanKind): PromptParts {
  const dir = join(assets, PROMPT_DIR);
  const read = (file: string): string => withParts(readFileSync(join(dir, file), 'utf8'), dir);
  const workflow = Object.fromEntries(
    Object.keys(REPLACED_WORKFLOW_SHA256[kind]).map(path => [path, read(path)])
  );
  return { workflow, helper: read(`helper-${kind}.md`) };
}

/**
 * A file's `{{SCRIPT <name>.js}}` lines, each replaced by that script's text (from scripts/), and
 * its `{{INCLUDE <name>.md}}` lines, each by that part's (from parts/), with the part's own
 * INCLUDE lines in place too: a helper's sections include code mode, which the lead's include as
 * well.
 */
export function withParts(text: string, dir: string): string {
  return includeParts(text, dir).replace(
    /^\{\{SCRIPT ([a-z0-9-]+\.js)\}\}$/gm,
    (_line, name: string) => readFileSync(join(dir, 'scripts', name), 'utf8').trimEnd()
  );
}

/** `text` with every `{{INCLUDE <name>.md}}` line replaced by that part, itself included. */
function includeParts(text: string, dir: string): string {
  return text.replace(/^\{\{INCLUDE ([a-z0-9-]+\.md)\}\}$/gm, (_line, name: string) =>
    includeParts(readFileSync(join(dir, 'parts', name), 'utf8').trimEnd(), dir)
  );
}

/**
 * What a run mounts: the workflow files, the scan prompt (--scan-prompt-file; empty without an
 * addendum, which upstream reads as no prompt), and the context every helper prints first.
 */
export interface RunPrompt {
  workflow: Record<string, string>;
  text: string;
  helperContext: string;
}

/**
 * The run's workflow and prompt from its rendered parts and the caller's addendum. The lead reads
 * the workflow, and the prompt as upstream's user context; a helper reads the rules every agent
 * follows, and the addendum's sections marked `<!-- helper-context -->` (helperContext).
 */
export function runPrompt(parts: PromptParts, addendum?: string): RunPrompt {
  const text = addendum?.trim() ? `${addendum.trim()}\n` : '';
  const extra = addendum ? helperContext(addendum) : undefined;
  return {
    workflow: parts.workflow,
    text,
    helperContext: extra ? `${parts.helper.trimEnd()}\n\n${extra}` : parts.helper,
  };
}

/** Every part rendered by `render`. */
export function renderParts(parts: PromptParts, render: (text: string) => string): PromptParts {
  return {
    workflow: Object.fromEntries(
      Object.entries(parts.workflow).map(([path, text]) => [path, render(text)])
    ),
    helper: render(parts.helper),
  };
}

/**
 * An addendum's helper sections: each `## ` section that a `<!-- helper-context -->` line marks,
 * to the next `## ` heading.
 *
 * The lead has to give every helper the same long instructions, and writing them again in each
 * task message costs thousands of output tokens per helper on the lead's critical path. So they
 * go to a file every helper prints as its first command, and a brief only points at it.
 */
export function helperContext(prompt: string): string | undefined {
  const sections: string[] = [];
  let marked = false;
  let current: string[] | undefined;
  for (const line of prompt.split('\n')) {
    if (line.trim() === '<!-- helper-context -->') {
      marked = true;
      continue;
    }
    if (line.startsWith('## ')) {
      if (current) sections.push(current.join('\n').trimEnd());
      current = marked ? [line] : undefined;
      marked = false;
    } else if (current) current.push(line);
  }
  if (current) sections.push(current.join('\n').trimEnd());
  return sections.length ? `${sections.join('\n\n')}\n` : undefined;
}

/** The template's variables, in the order the module comment lists them. */
export const PROMPT_VARIABLES = [
  'PROJECT',
  'KB_INDEX',
  'HELPER_CONTEXT',
  'KNOWLEDGE_BASE',
  'RUBRIC',
  'SCAN_DIR',
] as const;
export type PromptVariable = (typeof PROMPT_VARIABLES)[number];

/** upstream's default severity rubric in the staged plugin, as a shell word. */
export const DEFAULT_RUBRIC = '"$CODEX_SECURITY_PLUGIN_ROOT/references/default-severity-rubric.md"';

/**
 * Each variable's value from the runtime's paths; the scan dir as the prompt names it, and the
 * rubric the caller's when it gave one (`rubric`).
 */
export function promptVariables(
  paths: Pick<ScanPaths, 'project' | 'kbIndex' | 'helperContext' | 'knowledgeBase' | 'rubric'>,
  scanDir: string,
  rubric = false
): Record<PromptVariable, string> {
  return {
    PROJECT: paths.project,
    KB_INDEX: paths.kbIndex,
    HELPER_CONTEXT: paths.helperContext,
    KNOWLEDGE_BASE: paths.knowledgeBase,
    RUBRIC: rubric ? paths.rubric : DEFAULT_RUBRIC,
    SCAN_DIR: scanDir,
  };
}

/**
 * template with every {{VARIABLE}} replaced. Throws on a variable left over (an unknown name or
 * a stray `{{`), and on any of `foreign`: paths that belong to another runtime.
 */
export function renderPrompt(
  template: string,
  variables: Record<PromptVariable, string>,
  foreign: string[] = []
): string {
  // 1. The variables, each everywhere it appears.
  let rendered = template;
  for (const name of PROMPT_VARIABLES)
    rendered = rendered.split(`{{${name}}}`).join(variables[name]);

  // 2. Nothing left of the template, and nothing of another runtime.
  const leftover = rendered.indexOf('{{');
  if (leftover >= 0)
    throw new Error(
      `The scan prompt has an unrendered variable: ${rendered.slice(leftover, leftover + 40).split('\n')[0]}`
    );
  for (const path of foreign)
    if (rendered.includes(path))
      throw new Error(
        `The scan prompt names ${path}, a path this runtime's scanner does not have.`
      );
  return rendered;
}
