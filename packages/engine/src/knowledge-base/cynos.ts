/**
 * cynos for the knowledge base's model calls: Jev's decisions, and the strong-model calls.
 *
 * Every model call the build makes goes through cynos with the scan's key, so it shares the
 * scan's budget and gateway logs and needs no second key:
 *
 *   decisions  Jev's labels (jev.ts), through cynos's Decisions API, which takes OpenAI's
 *              Decisions request and answers with its Decision object whichever provider serves
 *              the model (OpenRouter for Jev). CynosDecisions maps Jev's questions onto that shape
 *              and the answers back, keeps the answer cache, and counts the spend against a cap
 *   chat       the architecture review's calls (over the evidence pack, per part, combining,
 *              repairing) and the packet design, with the two switches the review agent uses,
 *              for this traffic alone: no task routing (each call asks for one model) and no
 *              quality judge (it would re-read every 100K-token pack). cynos never routes or
 *              judges a decision, so decisions are sent without them
 *
 * Both retry rate limits and gateway errors with backoff; the key stays in this process and is
 * never logged or written.
 */
import { BASE_URL } from '../constants';
import { pause } from '../processes';
import { AGENT_HEADERS } from './architecture-agent';
import { hashKey, type AnswerCache } from './cache';
import {
  CostCapReached,
  JEV,
  JEV_USD_PER_INPUT_TOKEN,
  JEV_USD_PER_OUTPUT_TOKEN,
  type Answer,
  type Answers,
  type Question,
  type Questions,
} from './jev';

const TRANSIENT_HTTP = new Set([429, 500, 502, 503, 504, 524, 529]);

type Fetch = (url: string, init: RequestInit) => Promise<Response>;
/** A backoff's wait: ms, or less when the run's signal fires first (processes.ts pause). */
type Sleep = (ms: number, signal?: AbortSignal) => Promise<void>;
const wait: Sleep = pause;

/** How a client retries: attempts, each one's timeout, and the first backoff, doubled each time. */
interface Retries {
  attempts: number;
  timeoutMs: number;
  backoffMs: number;
}

/**
 * One POST to cynos, retried on rate limits, gateway errors and dropped connections; any other
 * status is a request bug worth surfacing, so it fails at once. Returns the parsed body.
 *
 * The run's signal (a caller's stop or time limit) ends it: no attempt starts once it has fired,
 * the attempt in flight is cut, a backoff ends early, and a stopped call is not retried, so a
 * stopped run spends nothing more here and waits for nothing.
 */
async function post(
  what: string,
  url: string,
  key: string,
  body: unknown,
  headers: Record<string, string>,
  retries: Retries,
  fetchImpl: Fetch,
  sleep: Sleep,
  signal?: AbortSignal
): Promise<Record<string, unknown>> {
  let last = '';
  for (let attempt = 0; attempt < retries.attempts; attempt++) {
    stopIfAborted(what, signal);
    try {
      const timeout = AbortSignal.timeout(retries.timeoutMs);
      const response = await fetchImpl(url, {
        method: 'POST',
        headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json', ...headers },
        body: JSON.stringify(body),
        signal: signal ? AbortSignal.any([timeout, signal]) : timeout,
      });
      if (response.ok) return (await response.json()) as Record<string, unknown>;
      last = `HTTP ${response.status}: ${(await response.text()).slice(0, 300)}`;
      if (!TRANSIENT_HTTP.has(response.status)) break;
    } catch (error) {
      last = error instanceof Error ? error.message : String(error);
    }
    stopIfAborted(what, signal);
    if (attempt < retries.attempts - 1) await sleep(2 ** attempt * retries.backoffMs, signal);
  }
  throw new Error(`cynos ${what} failed: ${last}`);
}

/** Throws once the run's signal has fired: a stopped run makes no more calls. */
function stopIfAborted(what: string, signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new Error(`cynos ${what} stopped: ${String(signal.reason)}`);
}

// --------------------------------------------------------------------------- //
// Decisions
// --------------------------------------------------------------------------- //

/** Six attempts back off 2+4+8+16+32 s: a minute, enough for a dropped connection to come back. */
const DECISION_RETRIES: Retries = { attempts: 6, timeoutMs: 300_000, backoffMs: 2000 };

/** OpenAI's Decisions request, as cynos's `POST /v1/decisions` takes it. */
export interface DecisionRequest {
  model: string;
  input: string | DecisionInputItem[];
  questions: DecisionQuestion[];
}
interface DecisionInputItem {
  type: 'message';
  role: 'user';
  content: { type: 'input_json'; data: unknown }[];
}
type DecisionQuestion =
  | { type: 'predicate'; name: string; instructions: string }
  | {
      type: 'choice';
      name: string;
      instructions: string;
      choices: { value: string; description: string }[];
    };

/** OpenAI's Decision object as cynos answers it: answers in question order, and token usage. */
export interface Decision {
  model?: string;
  answers?: DecisionAnswer[];
  usage?: { input_tokens?: number; output_tokens?: number };
}
interface DecisionAnswer {
  type: 'predicate' | 'choice' | 'score' | 'refusal';
  name?: string | null;
  probability?: number;
  choice?: string | boolean;
  probabilities?: { value: string | boolean | number; probability: number }[];
  confidence?: number;
}

/**
 * Jev's questions as OpenAI's Decisions request.
 *
 * The two shapes differ where Jev's are name-keyed and OpenAI's ordered, and in what a yes/no
 * question carries:
 *
 *   state      a text state is OpenAI's text input; a structured one ({path, code, ...}) is one
 *              input_json part, which cynos passes on to Jev as a JSON value, not as text
 *   noul       a `predicate`, which has no criteria: what true and false mean is appended to its
 *              instructions, so Jev still reads the definitions it was given as criteria
 *   choice     a `choice`, each criterion one choice with its description as the value's meaning
 *   order      questions are sent in the order Object.keys gives, under their own names, so
 *              decisionAnswers can match each answer to its question by position
 */
export function decisionRequest(state: unknown, questions: Questions): DecisionRequest {
  return {
    model: JEV,
    input: decisionInput(state),
    questions: Object.entries(questions).map(([name, question]) =>
      decisionQuestion(name, question)
    ),
  };
}

function decisionInput(state: unknown): DecisionRequest['input'] {
  if (typeof state === 'string') return state;
  return [{ type: 'message', role: 'user', content: [{ type: 'input_json', data: state }] }];
}

function decisionQuestion(name: string, question: Question): DecisionQuestion {
  if (question.type === 'noul') {
    const meanings = Object.entries(question.criteria).map(
      ([answer, means]) => `${answer}: ${means}`
    );
    return {
      type: 'predicate',
      name,
      instructions: [question.instructions, ...meanings].join('\n'),
    };
  }
  return {
    type: 'choice',
    name,
    instructions: question.instructions,
    choices: Object.entries(question.criteria).map(([value, description]) => ({
      value,
      description,
    })),
  };
}

/**
 * The Decision's answers as Jev's, keyed by question name.
 *
 * OpenAI's answers come in question order, one per question; each is checked to be the answer to
 * the question at its position (same count, and its name when it carries one), and anything else
 * means the Decision is not laid out as the request was and the item fails. A predicate's
 * probability is a noul; a choice keeps its value and its probability per value. A refusal, or
 * an answer of another type, leaves its question unanswered, as noul() and choice() read it.
 */
export function decisionAnswers(questions: Questions, decision: Decision): Answers {
  const names = Object.keys(questions);
  const answers = decision.answers ?? [];
  if (answers.length !== names.length)
    throw new Error(
      `cynos returned ${answers.length} decision answers for ${names.length} questions`
    );
  const out: Answers = {};
  answers.forEach((answer, i) => {
    const name = names[i] as string;
    if (answer.name != null && answer.name !== name)
      throw new Error(`cynos decision answer ${i} is named ${answer.name}; expected ${name}`);
    const jev = jevAnswer(answer);
    if (jev) out[name] = jev;
  });
  return out;
}

function jevAnswer(answer: DecisionAnswer): Answer | undefined {
  if (answer.type === 'predicate' && typeof answer.probability === 'number')
    return { type: 'noul', noul: answer.probability };
  if (answer.type !== 'choice' || answer.choice === undefined) return undefined;
  return {
    type: 'choice',
    choice: String(answer.choice),
    probabilities: Object.fromEntries(
      (answer.probabilities ?? []).map(p => [String(p.value), p.probability])
    ),
    ...(answer.confidence !== undefined ? { confidence: answer.confidence } : {}),
  };
}

/**
 * What a Decision cost: its tokens at cynos's catalog rate for Jev. The Decision carries tokens,
 * not cost; cynos bills what OpenRouter reports, at most this rate for every input token.
 */
export function decisionCost(usage: Decision['usage']): number {
  return (
    (usage?.input_tokens ?? 0) * JEV_USD_PER_INPUT_TOKEN +
    (usage?.output_tokens ?? 0) * JEV_USD_PER_OUTPUT_TOKEN
  );
}

export class CynosDecisions {
  cost = 0;
  calls = 0;
  /** Answers reused from an earlier build of the same content (cache.ts); none when unset. */
  cache: AnswerCache | undefined;

  constructor(
    private readonly key: string,
    private readonly maxCost: number,
    private readonly fetchImpl: Fetch = fetch,
    private readonly sleep: Sleep = wait,
    /** The cynos endpoint; BASE_URL unless a benchmark gives its own gateway. */
    private readonly baseUrl: string = BASE_URL,
    /** The run's signal: no call starts after it fires, and the one in flight is cut. */
    private readonly signal?: AbortSignal
  ) {}

  /**
   * One Jev decision; returns {question: answer}. A stored answer is given without a call, even
   * past the cap; a call that would start after the cap is reached throws CostCapReached instead.
   */
  async decide(state: unknown, questions: Questions): Promise<Answers> {
    const request = decisionRequest(state, questions);
    const cacheKey = hashKey('decide', request);
    const stored = this.cache?.get<Answers>(cacheKey);
    if (stored) return stored;
    if (this.cost >= this.maxCost)
      throw new CostCapReached(
        `Jev spend $${this.cost.toFixed(4)} reached the cap $${this.maxCost.toFixed(2)}`
      );
    const decision = (await post(
      'decisions',
      `${this.baseUrl}/decisions`,
      this.key,
      request,
      {},
      DECISION_RETRIES,
      this.fetchImpl,
      this.sleep,
      this.signal
    )) as Decision;
    this.calls += 1;
    this.cost += decisionCost(decision.usage);
    const answers = decisionAnswers(questions, decision);
    this.cache?.set(cacheKey, answers);
    return answers;
  }
}

// --------------------------------------------------------------------------- //
// Chat
// --------------------------------------------------------------------------- //

const CHAT_RETRIES: Retries = { attempts: 4, timeoutMs: 600_000, backoffMs: 3000 };

/** The calls the review makes: a JSON answer to one system and one user message. */
export interface ReviewModel {
  chatJson(model: string, system: string, user: string): Promise<string>;
}

export class CynosChat implements ReviewModel {
  calls = 0;
  inputTokens = 0;
  outputTokens = 0;

  constructor(
    private readonly key: string,
    private readonly fetchImpl: Fetch = fetch,
    private readonly sleep: Sleep = wait,
    /** The cynos endpoint; BASE_URL unless a benchmark gives its own gateway. */
    private readonly baseUrl: string = BASE_URL,
    /** The run's signal: no call starts after it fires, and the one in flight is cut. */
    private readonly signal?: AbortSignal
  ) {}

  async chatJson(model: string, system: string, user: string): Promise<string> {
    const result = (await post(
      'chat',
      `${this.baseUrl}/chat/completions`,
      this.key,
      {
        model,
        max_tokens: 64000,
        reasoning_effort: 'high',
        response_format: { type: 'json_object' },
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: user },
        ],
      },
      AGENT_HEADERS,
      CHAT_RETRIES,
      this.fetchImpl,
      this.sleep,
      this.signal
    )) as {
      choices?: { message?: { content?: string } }[];
      usage?: { prompt_tokens?: number; completion_tokens?: number };
    };
    this.calls += 1;
    this.inputTokens += result.usage?.prompt_tokens ?? 0;
    this.outputTokens += result.usage?.completion_tokens ?? 0;
    return result.choices?.[0]?.message?.content ?? '';
  }
}
