import { describe, expect, it } from 'bun:test';
import type { KnowledgeBaseStore } from '../knowledge-base/store';
import {
  ERROR_MESSAGE_LIMIT,
  repoHash,
  repositoryIdentity,
  ScanTelemetry,
  telemetryMessage,
  type TelemetryOptions,
} from '../telemetry';

const KEY = 'sk-cy-synthetic-telemetry-key';

/** A telemetry whose events are kept instead of sent, on a clock the test moves. */
function recorded(options: Partial<TelemetryOptions> = {}) {
  const sent: { url: string; init: RequestInit; body: Record<string, unknown> }[] = [];
  let clock = 1_000;
  const telemetry = new ScanTelemetry({
    key: KEY,
    client: 'cli',
    clientVersion: '9.9.9',
    kind: 'diff',
    runtime: 'docker',
    repository: 'github.com/acme/api',
    checkout: '/home/dev/src/api',
    home: '/home/dev',
    runId: 'run-0001-abcd',
    now: () => clock,
    fetch: async (url, init) => {
      sent.push({ url, init, body: JSON.parse(String(init.body)) });
      return new Response(null, { status: 202 });
    },
    ...options,
  });
  return { telemetry, sent, tick: (ms: number) => (clock += ms) };
}

/** A store that answers restore with key and keeps no errors of its own. */
function storeAnswering(
  key: string | undefined,
  onCall: () => void = () => {}
): KnowledgeBaseStore {
  return {
    restore: async () => {
      onCall();
      return key;
    },
    save: async () => onCall(),
  };
}

describe('ScanTelemetry', () => {
  it("sends run_started, then run_finished with each phase's status and the run's duration", async () => {
    const { telemetry, sent, tick } = recorded();
    await telemetry.started();
    telemetry.progress({ type: 'phase', phase: 'stage', status: 'start' });
    telemetry.progress({ type: 'phase', phase: 'stage', status: 'end', seconds: 1.2 });
    telemetry.progress({ type: 'phase', phase: 'knowledge', status: 'skipped', detail: 'diff' });
    telemetry.progress({ type: 'phase', phase: 'scan', status: 'end', seconds: 300 });
    tick(301_500);
    await telemetry.finished({ outcome: 'completed', changedFiles: 14 });

    expect(sent.map(event => event.body['event'])).toEqual(['run_started', 'run_finished']);
    expect(sent[0]!.url).toBe(
      `https://api.cynos.averlon.ai/v1/scan-events/${repoHash('github.com/acme/api')}`
    );
    expect(new Headers(sent[0]!.init.headers).get('authorization')).toBe(`Bearer ${KEY}`);
    const finished = sent[1]!.body;
    expect(finished).toMatchObject({
      run_id: 'run-0001-abcd',
      client: 'cli',
      kind: 'diff',
      outcome: 'completed',
      duration_ms: 301_500,
      changed_files: 14,
    });
    expect(finished).not.toHaveProperty('repo_hash');
    expect(finished['steps']).toEqual({
      stage: { status: 'ok', ms: 1200 },
      knowledge: { status: 'skipped', ms: 0 },
      scan: { status: 'ok', ms: 300_000 },
    });
    expect(finished).not.toHaveProperty('error');
    expect(finished).not.toHaveProperty('product_files');
  });

  it("reports the failed phase and its message, without the key or the checkout's path", async () => {
    const { telemetry, sent } = recorded();
    telemetry.progress({
      type: 'phase',
      phase: 'knowledge',
      status: 'failed',
      seconds: 4,
      detail: `The knowledge base could not be built: /home/dev/src/api/app.py with ${KEY} in /home/dev/.cache`,
    });
    await telemetry.finished({
      outcome: 'failed',
      errorKind: 'knowledge-base',
      error: new Error('x'),
    });

    expect(sent[0]!.body['error']).toEqual({
      step: 'knowledge',
      kind: 'knowledge-base',
      message: 'The knowledge base could not be built: <checkout>/app.py with *** in ~/.cache',
    });
  });

  it('reports a failure before the first phase as the run', async () => {
    const { telemetry, sent } = recorded();
    await telemetry.finished({
      outcome: 'failed',
      error: new Error('The reasoning effort must be one of'),
    });
    expect(sent[0]!.body['error']).toEqual({
      step: 'run',
      kind: 'internal',
      message: 'The reasoning effort must be one of',
    });
  });

  it('sends run_finished once, so the post step does not repeat the main step', async () => {
    const { telemetry, sent } = recorded();
    await telemetry.finished({ outcome: 'completed' });
    await telemetry.finished({ outcome: 'cancelled' });
    expect(sent.map(event => event.body['outcome'])).toEqual(['completed']);
  });

  it('tells a cache hit from a miss, and a failure the store kept to itself from both', async () => {
    const hit = recorded();
    await hit.telemetry
      .measureStore(storeAnswering('v1-abc', () => hit.tick(800)))
      .restore('d', 's', [], () => false);
    await hit.telemetry.measureStore(storeAnswering(undefined)).save('d', 's', undefined);
    await hit.telemetry.finished({ outcome: 'completed' });
    expect(hit.sent[0]!.body['steps']).toEqual({
      cache_restore: { status: 'hit', ms: 800 },
      cache_save: { status: 'ok', ms: 0 },
    });

    const miss = recorded();
    await miss.telemetry.measureStore(storeAnswering(undefined)).restore('d', 's', [], () => false);
    await miss.telemetry.finished({ outcome: 'completed' });
    expect(miss.sent[0]!.body['steps']).toEqual({ cache_restore: { status: 'miss', ms: 0 } });

    // The action's GitHub cache logs a failed restore and answers undefined, as a miss does.
    const kept = recorded();
    await kept.telemetry
      .measureStore(storeAnswering(undefined, () => kept.telemetry.cacheFailed('cache_restore')))
      .restore('d', 's', [], () => false);
    await kept.telemetry.finished({ outcome: 'completed' });
    expect(kept.sent[0]!.body['steps']).toEqual({ cache_restore: { status: 'error', ms: 0 } });
  });

  it('records a store that throws as an error and lets the error through', async () => {
    const { telemetry, sent } = recorded();
    const failing: KnowledgeBaseStore = {
      restore: async () => undefined,
      save: async () => {
        throw new Error('disk full');
      },
    };
    await expect(telemetry.measureStore(failing).save('d', 's', undefined)).rejects.toThrow(
      'disk full'
    );
    await telemetry.finished({ outcome: 'completed' });
    expect(sent[0]!.body['steps']).toEqual({ cache_save: { status: 'error', ms: 0 } });
  });

  it('sends nothing when disabled by the host, or without a key', async () => {
    for (const options of [{ enabled: false }, { key: undefined }]) {
      const { telemetry, sent } = recorded(options);
      await telemetry.started();
      await telemetry.finished({ outcome: 'completed' });
      expect(telemetry.enabled).toBe(false);
      expect(sent).toEqual([]);
    }
  });

  it('never fails the scan when cynos cannot be reached', async () => {
    const { telemetry } = recorded({
      fetch: async () => {
        throw new TypeError('fetch failed');
      },
    });
    await telemetry.started();
    await telemetry.finished({ outcome: 'completed' });
  });
});

describe('repositoryIdentity', () => {
  it('reads every spelling of a remote as one identity', () => {
    // A remote with a token in it, built here: the engine package ships its tests, and the
    // release's secret scan of the package fails on any user:password@host URL, a placeholder too.
    const withToken = ['https://x-access-token', 'secret@github.com/acme/api.git'].join(':');
    for (const remote of [
      'git@github.com:Acme/API.git',
      'https://github.com/acme/api',
      withToken,
      'ssh://git@github.com:22/acme/api.git',
    ])
      expect(repositoryIdentity(remote)).toBe('github.com/acme/api');
  });

  it('is undefined for a remote that is not a URL', () => {
    expect(repositoryIdentity('/srv/mirrors/api.git')).toBeUndefined();
  });

  // The loop that drops them replaces a regex that took quadratic time on Node for a long run of
  // slashes inside the path. bun:test runs on JavaScriptCore, where that regex is fast, so the
  // timing is CodeQL's check (js/polynomial-redos), not this test's.
  it('drops trailing slashes', () => {
    expect(repositoryIdentity('https://github.com/acme/api//')).toBe('github.com/acme/api');
    expect(repositoryIdentity('https://github.com/acme/api.git/')).toBe('github.com/acme/api');
    expect(repositoryIdentity('https://github.com/acme//api')).toBe('github.com/acme//api');
  });
});

describe('telemetryMessage', () => {
  const key = 'sk-cy-0123456789abcdefghijklmnopqrstuv';

  // Upstream's reason is cut at 500 characters and a cynos error body at 300 before they reach
  // telemetry, so a key there can arrive cut short, and then no longer matches whole.
  it('removes a key that arrives cut short, at the end of a message or inside it', () => {
    expect(telemetryMessage(`HTTP 401: {"detail":"invalid key ${key.slice(0, 20)}`, { key })).toBe(
      'HTTP 401: {"detail":"invalid key ***'
    );
    expect(telemetryMessage(`cynos call failed: ${key.slice(0, 12)}. Retrying`, { key })).toBe(
      'cynos call failed: ***. Retrying'
    );
    expect(telemetryMessage(`token=${key} and ${key}`, { key })).toBe('token=*** and ***');
  });

  it("keeps words that tell nothing of the key: too short, or not the key's start", () => {
    expect(telemetryMessage('keys start with sk-cy- and must be valid', { key })).toBe(
      'keys start with sk-cy- and must be valid'
    );
    expect(telemetryMessage('sk-cy-ffffffffff is another key', { key })).toBe(
      'sk-cy-ffffffffff is another key'
    );
  });

  it('is cut to its limit', () => {
    expect(telemetryMessage('x'.repeat(2 * ERROR_MESSAGE_LIMIT), {})).toHaveLength(
      ERROR_MESSAGE_LIMIT
    );
  });
});
