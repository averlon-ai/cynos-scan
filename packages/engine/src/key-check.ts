/**
 * One tiny request to cynos with the key, before the scan.
 *
 * codex-security reports any refusal (an unknown key, a model the key may not use, a spent
 * budget) as "cannot access the configured model"; this returns cynos's own answer instead,
 * with the key redacted, before the scan spends anything.
 *
 * A refusal is not always the key's fault, and its fix differs with the cause, so the check also
 * says which refusal it was, from the HTTP status cynos answered with:
 *
 *   key          401, 403   the key is unknown, revoked, or for another gateway
 *   budget       402        the key's budget is spent
 *   model        400, 404, 422   the gateway cannot serve this model for the key
 *   unreachable  no answer  network, proxy or base URL
 *   gateway      any other  cynos failed (429, 5xx)
 *
 * keyCheckFailure turns a refusal into the sentence and the fix that the scan's preflight, doctor
 * and login all report, so the three never disagree.
 */
import { BASE_URL } from './constants';

export type KeyRefusal = 'key' | 'budget' | 'model' | 'unreachable' | 'gateway';

export interface KeyCheck {
  accepted: boolean;
  answer: string;
  /** Why cynos refused, when it did. */
  refusal?: KeyRefusal;
}

export type Fetch = (url: string, init: RequestInit) => Promise<Response>;

/**
 * Sends one 16-token request to cynos's Responses endpoint for model: the scan's own endpoint,
 * BASE_URL, unless a benchmark runs the scan through its own gateway (baseUrl).
 */
export async function checkKey(
  key: string,
  model: string,
  fetcher: Fetch = fetch,
  baseUrl: string = BASE_URL,
  /** The run's signal: a stop cuts the check short, as its own timeout does. */
  signal?: AbortSignal
): Promise<KeyCheck> {
  const body = JSON.stringify({
    model,
    input: 'Reply with the single word: ok',
    max_output_tokens: 16,
  });
  try {
    // The scan's own endpoint: the action has no input that changes it (a test pins it). No cynos
    // override headers: the check needs no verdict, so it does not turn the judge on as a scan
    // turn does.
    const response = await fetcher(`${baseUrl}/responses`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
      body,
      signal: signal
        ? AbortSignal.any([AbortSignal.timeout(120_000), signal])
        : AbortSignal.timeout(120_000),
    });
    if (response.ok) return { accepted: true, answer: `HTTP ${response.status}` };
    const detail = (await response.text()).split(/\s+/).join(' ').split(key).join('***');
    return {
      accepted: false,
      answer: `HTTP ${response.status}: ${detail.slice(0, 1000)}`,
      refusal: refusalOf(response.status),
    };
  } catch (error) {
    return {
      accepted: false,
      answer: `unreachable: ${(error as Error).message}`,
      refusal: 'unreachable',
    };
  }
}

/** The refusal an HTTP status means (the table in this module's comment). */
function refusalOf(status: number): KeyRefusal {
  if (status === 401 || status === 403) return 'key';
  if (status === 402) return 'budget';
  if (status === 400 || status === 404 || status === 422) return 'model';
  return 'gateway';
}

/**
 * What a refused check reports: the failure, naming its cause, and the fix for that cause. The
 * failure's wording is what the CLI classifies error.kind by (auth, budget, model, network,
 * gateway), so each cause keeps its own phrase.
 */
export function keyCheckFailure(
  check: KeyCheck,
  model: string,
  baseUrl: string = BASE_URL
): { failure: string; fix: string } {
  switch (check.refusal ?? 'key') {
    case 'budget':
      return {
        failure: `cynos refused the request for ${model}: the key's budget is spent (${check.answer})`,
        fix: "Raise the key's budget in cynos, or use another key.",
      };
    case 'model':
      return {
        failure: `cynos cannot serve the model ${model} for this key (${check.answer})`,
        fix: 'Choose a model the key may use, or ask for this one on the key.',
      };
    case 'unreachable':
      return {
        failure: `cynos is unreachable at ${baseUrl} (${check.answer})`,
        fix: 'Check the network, the proxy and the endpoint (CYNOS_BASE_URL names another).',
      };
    case 'gateway':
      return {
        failure: `cynos could not answer the key check for ${model} (${check.answer})`,
        fix: 'Retry later; cynos itself failed, not the key.',
      };
    case 'key':
      return {
        failure: `cynos refused the key for ${model} (${check.answer})`,
        fix: `Check the key, and the endpoint: a key belongs to one cynos gateway, and this check used ${baseUrl} (CYNOS_BASE_URL names another).`,
      };
  }
}
