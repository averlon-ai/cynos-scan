import { describe, expect, test } from 'bun:test';
import { mockEngine } from './engine-mock';

mockEngine();
const { cynosKey, fingerprint, takeEnvKey, cynosBaseUrl, CYNOS_ACCOUNT } =
  await import('../auth/keys');
const { run } = await import('../cli');

const saved = (entries: Record<string, string>) => ({
  get: (account: string) =>
    entries[account] ? { value: entries[account]!, source: 'keychain' as const } : undefined,
});

describe('key lookup order', () => {
  test('CYNOS_API_KEY wins over the saved login', () => {
    const store = saved({ [CYNOS_ACCOUNT]: 'saved-key' });
    expect(cynosKey('env-key', store)).toEqual({ value: 'env-key', source: 'env' });
    expect(cynosKey(undefined, store)).toEqual({ value: 'saved-key', source: 'keychain' });
    expect(cynosKey(undefined, saved({}))).toBeUndefined();
  });
});

describe('takeEnvKey', () => {
  test('reads a key once and deletes it from the environment', () => {
    const env: NodeJS.ProcessEnv = { CYNOS_API_KEY: 'abc123' };
    expect(takeEnvKey('CYNOS_API_KEY', env)).toBe('abc123');
    expect('CYNOS_API_KEY' in env).toBe(false);
    expect(takeEnvKey('CYNOS_API_KEY', env)).toBeUndefined();
  });

  test('an empty value is no key, and is deleted too', () => {
    const env: NodeJS.ProcessEnv = { CYNOS_API_KEY: '' };
    expect(takeEnvKey('CYNOS_API_KEY', env)).toBeUndefined();
    expect('CYNOS_API_KEY' in env).toBe(false);
  });

  test('a key with a line break is refused', () => {
    expect(() => takeEnvKey('CYNOS_API_KEY', { CYNOS_API_KEY: 'abc\n' })).toThrow(/line break/);
  });

  test('a CLI run removes the key from the environment before any command runs', async () => {
    const env: NodeJS.ProcessEnv = {
      CYNOS_API_KEY: 'cynos-0123456789abcdef',
      CYNOS_CREDENTIAL_STORE: 'file',
      XDG_CONFIG_HOME: '/nonexistent-config',
      CI: '1',
    };
    const writeOut = process.stdout.write.bind(process.stdout);
    process.stdout.write = (() => true) as typeof process.stdout.write;
    try {
      await run(['--version'], env);
    } finally {
      process.stdout.write = writeOut;
    }
    expect(env['CYNOS_API_KEY']).toBeUndefined();
  });
});

describe('endpoint and fingerprints', () => {
  test('CYNOS_BASE_URL, then the engine default', () => {
    expect(cynosBaseUrl({ CYNOS_BASE_URL: 'https://e/v1/' }, 'https://d')).toBe('https://e/v1');
    expect(cynosBaseUrl({}, 'https://d')).toBe('https://d');
  });

  test('there are no profiles: --profile is an unknown option', async () => {
    for (const args of [
      ['login', '--profile', 'x'],
      ['logout', '--all'],
      ['scan', '--profile', 'x'],
    ]) {
      const writeErr = process.stderr.write;
      process.stderr.write = () => true;
      try {
        expect(await run(args, { CI: '1', NO_COLOR: '1' })).toBe(2);
      } finally {
        process.stderr.write = writeErr;
      }
    }
  });

  test('a fingerprint never holds the key', () => {
    const key = 'sk-live-0123456789abcdefghij';
    const shown = fingerprint(key);
    expect(shown).not.toContain(key);
    expect(shown).toMatch(/^sk-l…ghij \(sha256:[0-9a-f]{8}\)$/);
    expect(fingerprint('short')).toMatch(/^\*\*\*\* /);
  });
});
