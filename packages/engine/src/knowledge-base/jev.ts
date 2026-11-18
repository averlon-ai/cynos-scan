/**
 * Jev for the knowledge base: decisions about files and functions, in Jev's own terms.
 *
 * Jev (typesafe/jev-1.14) answers a fixed set of questions about one piece of state with a
 * probability per answer, for about $0.04 per million input tokens and no charge for output. The
 * build asks it thousands of small questions. The build reaches Jev through cynos's Decisions API
 * (CynosDecisions in cynos.ts, which maps these questions and answers onto OpenAI's Decisions
 * shape); this module holds what does not depend on the wire:
 *
 *   questions  name-keyed, as the build writes them: a yes/no `noul` or a `choice`, each with the
 *              meaning of every answer
 *   state      a value too large for one call is asked in chunks, and the chunks' answers merged
 *   many       askMany asks about every item at once, CONCURRENCY at a time; one item that fails
 *              is counted, not fatal, and the cost cap stops the whole build
 */
import type { CynosDecisions } from './cynos';

/**
 * Jev, as cynos's catalog names it for decisions (its `openrouter/typesafe/jev-1.14|decisions`
 * row). cynos refuses a decision model its catalog does not price, and 1.14 is the Jev it prices.
 */
export const JEV = 'openrouter/typesafe/jev-1.14';
/** That row's rates in USD per token: cynos's spend on Jev, for the build's cost cap. */
export const JEV_USD_PER_INPUT_TOKEN = 4.2e-8;
export const JEV_USD_PER_OUTPUT_TOKEN = 0;
/**
 * About 30K tokens of code at 3 characters per token: the state size the questions were tuned on,
 * well inside Jev's 131K-token window, with room for the questions.
 */
export const MAX_STATE_CHARS = 90_000;
const CONCURRENCY = 16;

/** One question: a yes/no `noul`, or a `choice` among the options its criteria name. */
export interface Question {
  type: 'noul' | 'choice';
  instructions: string;
  /** What each answer means: `true` and `false` for a noul, every option for a choice. */
  criteria: Record<string, string>;
}
export type Questions = Record<string, Question>;

/** One Jev answer: a yes/no probability, or a choice with a probability per option. */
export type Answer =
  | { type: 'noul'; noul: number }
  | {
      type: 'choice';
      choice: string;
      probabilities?: Record<string, number>;
      confidence?: number;
    };
export type Answers = Record<string, Answer>;

export class CostCapReached extends Error {}

/**
 * The text split into pieces that fit one Jev call, on line boundaries where it can be. A line
 * longer than one call (a minified script, a regenerated document on one line) is cut within the
 * line, so every character of the text reaches some chunk: the chunks joined are the text.
 */
export function chunks(text: string): string[] {
  if (text.length <= MAX_STATE_CHARS) return [text];
  const out: string[] = [];
  let current = '';
  for (const piece of text.split(/(?<=\n)/).flatMap(linePieces)) {
    if (current && current.length + piece.length > MAX_STATE_CHARS) {
      out.push(current);
      current = '';
    }
    current += piece;
  }
  if (current) out.push(current);
  return out;
}

/** One line cut into pieces of at most MAX_STATE_CHARS, the whole line when it fits. */
function linePieces(line: string): string[] {
  const pieces: string[] = [];
  for (let start = 0; start < line.length; start += MAX_STATE_CHARS)
    pieces.push(line.slice(start, start + MAX_STATE_CHARS));
  return pieces;
}

/**
 * One answer for a state asked in several chunks: a fact holds if any chunk shows it. A chunk can
 * leave a question unanswered (a refusal), so every question any chunk answered is merged, not
 * only the first chunk's.
 */
export function mergeAnswers(parts: Answers[]): Answers {
  if (parts.length === 1) return parts[0] as Answers;
  const out: Answers = {};
  for (const name of new Set(parts.flatMap(part => Object.keys(part)))) {
    const answers = parts.map(part => part[name]).filter((a): a is Answer => !!a);
    if (answers[0]?.type === 'noul') {
      out[name] = {
        type: 'noul',
        noul: Math.max(...answers.map(a => (a.type === 'noul' ? a.noul : 0))),
      };
      continue;
    }
    const probabilities: Record<string, number> = {};
    for (const a of answers) {
      if (a.type !== 'choice') continue;
      for (const [k, v] of Object.entries(a.probabilities ?? { [a.choice]: 1 }))
        probabilities[k] = Math.max(probabilities[k] ?? 0, v);
    }
    const best = Object.entries(probabilities).sort((x, y) => y[1] - x[1])[0];
    if (best) out[name] = { type: 'choice', choice: best[0], probabilities, confidence: best[1] };
  }
  return out;
}

/**
 * The fields that hold a state's text: a file's `content`, and the `code` of a function or of the
 * lines a hunk removed (diff.ts's removedCode), which has no size of its own: one hunk of a
 * regenerated document removed 256 KB, and cynos refuses a decision past 256 KiB.
 */
const TEXT_FIELDS = ['content', 'code'] as const;

/** A state whose text is a string larger than one call is asked in chunks. */
function chunked(state: unknown): unknown[] {
  if (typeof state === 'string') return chunks(state).map(content => ({ content }));
  for (const field of TEXT_FIELDS) {
    const text = (state as Record<string, unknown> | null)?.[field];
    if (typeof text === 'string' && text.length > MAX_STATE_CHARS)
      return chunks(text).map(part => ({ ...(state as object), [field]: part }));
  }
  return [state];
}

/**
 * Asks `questions` about every (key, state) item, CONCURRENCY at a time. Returns the answers by key
 * and the number of items that failed; a failed item is left out. The cost cap stops the whole
 * build: it is rethrown, not counted.
 */
export async function askMany(
  client: Pick<CynosDecisions, 'decide'>,
  items: [string, unknown][],
  questions: Questions,
  log: (message: string) => void = () => {}
): Promise<{ answers: Map<string, Answers>; failed: number }> {
  const answers = new Map<string, Answers>();
  let failed = 0;
  let next = 0;
  let capped: unknown;
  const worker = async (): Promise<void> => {
    while (next < items.length && !capped) {
      const item = items[next++];
      if (!item) break;
      const [key, state] = item;
      try {
        const parts: Answers[] = [];
        for (const part of chunked(state)) parts.push(await client.decide(part, questions));
        answers.set(key, mergeAnswers(parts));
      } catch (error) {
        if (error instanceof CostCapReached) capped = error;
        else {
          failed += 1;
          log(`  ! ${(error instanceof Error ? error.message : String(error)).slice(0, 200)}`);
        }
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, items.length) }, worker));
  if (capped) throw capped;
  return { answers, failed };
}

/** The probability of a yes/no answer, 0 when the question went unanswered. */
export function noul(answers: Answers | undefined, name: string): number {
  const answer = answers?.[name];
  return answer?.type === 'noul' ? answer.noul : 0;
}

/** The chosen option of a choice answer, 'none' when the question went unanswered. */
export function choice(answers: Answers | undefined, name: string): string {
  const answer = answers?.[name];
  return answer?.type === 'choice' ? answer.choice : 'none';
}
