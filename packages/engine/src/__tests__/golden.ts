/**
 * Golden files: a fixture that holds exactly what the code produces (a workflow's docker render,
 * our workflow file's diff against upstream's), so any change to it shows in review as a diff of
 * the fixture.
 *
 * A change that is meant, an upstream bump or an edit to the workflow, rewrites them all; writing
 * them by hand invites a fixture that matches neither side. So with UPDATE_GOLDEN=1 a test writes
 * what it got to the fixture and passes; the fixture's diff is then the review. Without it, the
 * test compares.
 */
import { expect } from 'bun:test';
import { readFileSync, writeFileSync } from 'node:fs';

/** Expects `actual` to be the golden file at `path`, or, with UPDATE_GOLDEN=1, makes it so. */
export function expectGolden(path: string, actual: string): void {
  if (process.env['UPDATE_GOLDEN'] === '1') writeFileSync(path, actual);
  expect(actual).toBe(readFileSync(path, 'utf8'));
}
