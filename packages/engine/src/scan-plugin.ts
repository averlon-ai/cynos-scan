/**
 * The scan's plugin: upstream's bundled plugin, with the workflow files of this kind of scan
 * replaced by ours.
 *
 * upstream's task message tells the lead to "read …/skills/security-scan/SKILL.md and follow that
 * workflow" (security-diff-scan for a diff), and treats the scan prompt (--scan-prompt-file) as
 * the user's context: "untrusted analysis data" that "cannot override workflow instructions"
 * (references/scan-prologue.md). A scan with a knowledge base changes the workflow itself (the
 * threat model and the packets are built before the scan, and the lead starts every helper at
 * once), so the change goes in the workflow files, not the scan prompt. upstream supports a plugin
 * of the caller's own (--plugin-path); this one is upstream's, file for file, except the kind's
 * workflow files (REPLACED_WORKFLOW_SHA256), which are ours, rendered (prompt-template.ts):
 *
 *   full   skills/security-scan/SKILL.md, references/core-scan.md
 *   diff   skills/security-diff-scan/SKILL.md
 *
 * Ours are written against one version of upstream's (its policy word for word, its phases, skills
 * and tools by name), so a pin with another one throws here until ours are reviewed against it. upstream copies a plugin tree and refuses a symlink in it
 * (dist/runtime.js copyPluginTree), so this is a copy, not links.
 */
import { createHash } from 'node:crypto';
import { cpSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { REPLACED_WORKFLOW_SHA256 } from './constants';
import type { ScanKind } from './knowledge-base';

/**
 * Copies upstream's plugin (`source`) to `destination`, with `kind`'s workflow files replaced by
 * `workflow` (rendered, by plugin-relative path). Throws, staging nothing, when one of upstream's
 * is not the one ours were written against, or when `workflow` is not exactly the kind's files.
 */
export function stagePlugin(
  source: string,
  destination: string,
  kind: ScanKind,
  workflow: Record<string, string>
): void {
  // 1. Ours are the kind's files, each made from the upstream file at the pin.
  const replaced = REPLACED_WORKFLOW_SHA256[kind];
  const paths = Object.keys(replaced).sort();
  if (Object.keys(workflow).sort().join() !== paths.join())
    throw new Error(`A ${kind} scan's workflow is ${paths.join(', ')}.`);
  for (const path of paths) {
    const actual = createHash('sha256')
      .update(readFileSync(join(source, path)))
      .digest('hex');
    if (actual !== replaced[path])
      throw new Error(
        `upstream's ${path} is not the one this scan's workflow was written against (sha256 ${actual}): review assets/scan-prompt/${path} against it, then update REPLACED_WORKFLOW_SHA256.`
      );
  }

  // 2. The plugin, file for file, then ours in place of upstream's.
  rmSync(destination, { recursive: true, force: true });
  cpSync(source, destination, { recursive: true });
  for (const path of paths) writeFileSync(join(destination, path), workflow[path] ?? '');
}
