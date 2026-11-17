import { describe, expect, test } from 'bun:test';
import pc from 'picocolors';
import { mockEngine } from './engine-mock';

mockEngine();
const { PhaseTimings } = await import('../progress/timings');

const plain = pc.createColors(false);
const tokens = (input: number, cached: number, output: number, reasoning: number) => ({
  input_tokens: input,
  cached_input_tokens: cached,
  output_tokens: output,
  reasoning_output_tokens: reasoning,
});

describe('the summary after a scan', () => {
  test("lists the scan's tokens and the architecture review's, under the timings", () => {
    const timings = new PhaseTimings(() => 0);
    timings.record({ type: 'usage', source: 'review', tokens: tokens(12_000, 4_000, 900, 0) });
    timings.record({
      type: 'usage',
      source: 'scan',
      tokens: tokens(2_495_756, 1_958_656, 88_286, 35_413),
    });
    const summary = timings.summary(plain).split('\n');
    expect(summary.slice(summary.indexOf('Tokens'))).toEqual([
      'Tokens',
      '  scan       2,495,756 in (1,958,656 cached) · 88,286 out (35,413 reasoning)',
      '  review     12,000 in (4,000 cached) · 900 out',
    ]);
  });

  test("shows a knowledge base's Jev cost below a cent to four places", () => {
    const timings = new PhaseTimings(() => 0);
    timings.record({ type: 'cost', source: 'knowledge-base', usd: 0.002 });
    expect(timings.summary(plain)).toContain('Knowledge base (Jev): $0.0020');
    expect(timings.toJSON()['knowledge_base_usd']).toBe(0.002);
    timings.record({ type: 'cost', source: 'knowledge-base', usd: 1.234 });
    expect(timings.summary(plain)).toContain('Knowledge base (Jev): $1.23');
  });

  test('has no tokens section when the scan reported no usage', () => {
    expect(new PhaseTimings(() => 0).summary(plain)).not.toContain('Tokens');
  });

  test('a mock or dry run, which used no tokens, has no tokens line', () => {
    const timings = new PhaseTimings(() => 0);
    timings.record({ type: 'usage', source: 'scan', tokens: tokens(0, 0, 0, 0) });
    expect(timings.summary(plain)).not.toContain('Tokens');
  });

  test("leaves out the scan's tokens when upstream printed its own, never the review's", () => {
    const timings = new PhaseTimings(() => 0);
    timings.record({
      type: 'usage',
      source: 'scan',
      tokens: tokens(4_341_650, 3_033_680, 336_601, 0),
    });
    timings.record({ type: 'usage', source: 'review', tokens: tokens(146_192, 52_992, 28_964, 0) });
    const summary = timings.summary(plain, { upstreamPrintedTokens: true }).split('\n');
    expect(summary.slice(summary.indexOf('Tokens'))).toEqual([
      'Tokens',
      '  review     146,192 in (52,992 cached) · 28,964 out',
    ]);
  });
});
