import { describe, expect, test } from 'bun:test';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mockEngine } from './engine-mock';

mockEngine();
const { knowledgeBaseSummary } = await import('../commands/history');
const { createTerminal } = await import('../terminal');

/** The summary of a run dir whose run.json records a diff's knowledge base with this threat model. */
function diffSummary(threatModel: Record<string, unknown>): string {
  const runDir = mkdtempSync(join(tmpdir(), 'cynos-history-'));
  writeFileSync(
    join(runDir, 'run.json'),
    JSON.stringify({
      knowledge_base_build: {
        kind: 'diff',
        changed_files: 2,
        changed_functions: 1,
        path_functions: 3,
        briefs: [],
        jev_calls: 4,
        cost_usd: 0.01,
        threat_model: threatModel,
      },
    })
  );
  return knowledgeBaseSummary(createTerminal({ color: false, env: {} }), runDir);
}

describe("a diff's threat model in the history", () => {
  test('says whether the diff reused, updated or built it', () => {
    expect(diffSummary({ from: { source: 'stored' }, gate: [], updated: false })).toContain(
      "threat model: the last full scan's, unchanged"
    );
    expect(diffSummary({ from: { source: 'stored' }, gate: ['a', 'b'], updated: true })).toContain(
      'threat model: updated for the change (2 reasons)'
    );
    expect(diffSummary({ from: { source: 'built' }, gate: [], updated: false })).toContain(
      'threat model: built for this diff: no full scan stored one'
    );
  });
});
