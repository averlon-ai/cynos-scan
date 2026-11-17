/**
 * Hypotheses: questions the build asks before the scan, from facts no single file shows.
 *
 * Static analysers stop a path at a `longjmp` or an `exit`, and know a request's start and
 * teardown only from hand-written models of each framework, so bugs that span an interruption or
 * two requests are out of their reach. A template here replaces the hand-written model with
 * questions a decision model answers about every function (does it exit without returning? does
 * it touch state a later request uses? when does it run?), joins those answers over the code
 * graph, and hands an investigator a question, not a verdict. See types.ts for the interface.
 *
 * This directory imports nothing from the rest of the engine (hypotheses.test.ts checks it), so
 * it can move to a package of its own unchanged. The engine runs it in four steps:
 *
 *   1  labelQuestions      the questions every template needs, asked with the engine's own
 *   2  computeHypotheses   every template's hypotheses, once the answers are in
 *   3  hypothesisPackets   the hypotheses shared out between hypothesis packets: investigation
 *                          packets that each settle the hypotheses they are given
 *   4  briefSections       each brief's facts, for the files it covers
 */
import { HALF_BUILT, STALE_STATE } from './templates/interrupted-request';
import type { Hypothesis, LabelQuestion, HypothesisInput, HypothesisTemplate } from './types';

export type { Label, Labels } from './labels';
export type { SourceFunction } from './source';
export type {
  Hypothesis,
  LabelQuestion,
  HypothesisBrief,
  HypothesisInput,
  HypothesisTemplate,
} from './types';

/** Every template the build runs, in the order their hypotheses are listed. */
export const TEMPLATES: HypothesisTemplate[] = [STALE_STATE, HALF_BUILT];

/**
 * Step 1: the templates' questions, each once. Templates that share facts share questions; two
 * templates that name one question differently would get two answers that disagree, so that is
 * an error.
 */
export function labelQuestions(templates: HypothesisTemplate[]): LabelQuestion[] {
  const byName = new Map<string, LabelQuestion>();
  for (const t of templates)
    for (const q of t.questions) {
      const seen = byName.get(q.name);
      if (seen && seen !== q && JSON.stringify(seen) !== JSON.stringify(q))
        throw new Error(`hypothesis templates define question ${q.name} twice, differently`);
      byName.set(q.name, seen ?? q);
    }
  return [...byName.values()];
}

/** Step 2: every template's hypotheses, in template order. */
export function computeHypotheses(
  templates: HypothesisTemplate[],
  input: HypothesisInput
): Hypothesis[] {
  return templates.flatMap(t => t.hypotheses(input));
}

/**
 * Step 3: the hypotheses shared out between at most `packets` investigation packets.
 *
 * Each hypothesis needs a focused investigation, so they are shared out as evenly as the packets
 * allow, and a template's hypotheses stay together where the sizes allow, since they ask about
 * the same kind of code: they are ordered by template, then cut into consecutive runs whose sizes
 * differ by at most one. Four hypotheses of templates S and H in three packets: [S1 S2] [H1] [H2].
 */
export function hypothesisPackets(hypotheses: Hypothesis[], packets: number): Hypothesis[][] {
  const n = Math.min(packets, hypotheses.length);
  if (n <= 0) return [];
  const ordered = byTemplate(hypotheses);
  const out: Hypothesis[][] = [];
  for (let i = 0, from = 0; i < n; i++) {
    // The first `hypotheses % n` packets take one hypothesis more.
    const size = Math.floor(ordered.length / n) + (i < ordered.length % n ? 1 : 0);
    out.push(ordered.slice(from, from + size));
    from += size;
  }
  return out;
}

/** The hypotheses grouped by template, in the order each template first appears; stable within one. */
function byTemplate(hypotheses: Hypothesis[]): Hypothesis[] {
  const first = new Map<string, number>();
  hypotheses.forEach((h, i) => first.has(h.template) || first.set(h.template, i));
  return hypotheses
    .map((hypothesis, i) => ({ hypothesis, i }))
    .sort(
      (a, b) =>
        (first.get(a.hypothesis.template) ?? 0) - (first.get(b.hypothesis.template) ?? 0) ||
        a.i - b.i
    )
    .map(({ hypothesis }) => hypothesis);
}

/** Step 4: the facts for a brief that covers `files`, each section once. */
export function briefSections(
  templates: HypothesisTemplate[],
  input: HypothesisInput,
  files: ReadonlySet<string>
): string[] {
  const sections = new Set(templates.map(t => t.briefSection).filter(s => s !== undefined));
  return [...sections].flatMap(section => section(input, files));
}
