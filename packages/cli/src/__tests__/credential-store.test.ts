import { describe, expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mockEngine } from './engine-mock';

mockEngine();
const { Credentials, FileStore, MacKeychainStore, SecretToolStore, openCredentials, SERVICE } =
  await import('../auth/credential-store');
type RunResult = import('../auth/credential-store').RunResult;

const KEY = 'sk-cynos-test-0123456789abcdef';

/** A fake `security` / `secret-tool`: an in-memory keychain, recording every call. */
function fakeKeychain(options: { failStore?: boolean } = {}) {
  const items = new Map<string, string>();
  const calls: { command: string; args: string[]; input?: string }[] = [];
  const run = (command: string, args: string[], input?: string): RunResult => {
    calls.push({ command, args, ...(input !== undefined ? { input } : {}) });
    const ok = (stdout = ''): RunResult => ({ status: 0, stdout, stderr: '' });
    const missing: RunResult = { status: 44, stdout: '', stderr: 'could not be found' };
    if (command === 'security' && args[0] === '-i') {
      if (options.failStore) return ok();
      const match = /-a "([^"]+)" -s "([^"]+)" .*-w "([^"]+)"/.exec(input ?? '');
      if (match) items.set(`${match[2]}/${match[1]}`, match[3]!);
      return ok();
    }
    if (command === 'security') {
      const account = args[args.indexOf('-a') + 1];
      const service = args[args.indexOf('-s') + 1];
      const id = `${service}/${account}`;
      if (args[0] === 'find-generic-password')
        return items.has(id) ? ok(`${items.get(id)}\n`) : missing;
      if (args[0] === 'delete-generic-password') return items.delete(id) ? ok() : missing;
    }
    if (command === 'secret-tool') {
      const id = `${args[args.indexOf('service') + 1]}/${args[args.indexOf('account') + 1]}`;
      if (args[0] === '--version') return ok('0.20');
      if (args[0] === 'store') {
        if (options.failStore) return { status: 1, stdout: '', stderr: 'Cannot autolaunch D-Bus' };
        items.set(id, input ?? '');
        return ok();
      }
      if (args[0] === 'lookup')
        return items.has(id) ? ok(items.get(id)) : { status: 1, stdout: '', stderr: '' };
      if (args[0] === 'clear') {
        items.delete(id);
        return ok();
      }
    }
    return { status: null, stdout: '', stderr: 'ENOENT' };
  };
  return { run, items, calls };
}

const tempDir = (): string => mkdtempSync(join(tmpdir(), 'cynos-scan-credentials-'));

describe('MacKeychainStore', () => {
  test('writes the key through security -i on stdin, never in argv', () => {
    const keychain = fakeKeychain();
    const store = new MacKeychainStore(keychain.run);
    store.set('cynos', KEY);
    expect(store.get('cynos')).toBe(KEY);
    for (const call of keychain.calls) expect(call.args.join(' ')).not.toContain(KEY);
    expect(keychain.calls[0]).toMatchObject({ command: 'security', args: ['-i'] });
    expect(keychain.calls[0]!.input).toContain(`-s "${SERVICE}"`);
  });

  test('reads the write back, since security -i exits 0 when a command in it failed', () => {
    const store = new MacKeychainStore(fakeKeychain({ failStore: true }).run);
    expect(() => store.set('cynos', KEY)).toThrow(/could not save/);
  });

  test('refuses a key security -i cannot quote', () => {
    const store = new MacKeychainStore(fakeKeychain().run);
    expect(() => store.set('cynos', 'has"quote')).toThrow(/cannot take on stdin/);
    expect(() => store.set('cynos', 'has space')).toThrow(/cannot take on stdin/);
  });

  test('deletes', () => {
    const store = new MacKeychainStore(fakeKeychain().run);
    store.set('other', KEY);
    expect(store.delete('other')).toBe(true);
    expect(store.get('other')).toBeUndefined();
    expect(store.delete('other')).toBe(false);
  });
});

describe('SecretToolStore', () => {
  test('passes the key on stdin', () => {
    const keychain = fakeKeychain();
    const store = new SecretToolStore(keychain.run);
    store.set('other', KEY);
    expect(store.get('other')).toBe(KEY);
    const stored = keychain.calls.find(call => call.args[0] === 'store')!;
    expect(stored.input).toBe(KEY);
    expect(stored.args.join(' ')).not.toContain(KEY);
  });
});

describe('FileStore', () => {
  test('keeps keys in a 0600 file in a 0700 dir', () => {
    const dir = join(tempDir(), 'cynos');
    const store = new FileStore(dir);
    store.set('cynos', KEY);
    expect(store.get('cynos')).toBe(KEY);
    expect(statSync(store.path).mode & 0o777).toBe(0o600);
    expect(statSync(dir).mode & 0o777).toBe(0o700);
    expect(JSON.parse(readFileSync(store.path, 'utf8'))).toEqual({ cynos: KEY });
    expect(store.delete('cynos')).toBe(true);
    expect(store.get('cynos')).toBeUndefined();
  });

  test('an unreadable file is an empty store', () => {
    const store = new FileStore(tempDir());
    expect(store.get('anything')).toBeUndefined();
  });
});

describe('Credentials', () => {
  test('saves to the keychain, and reads it back with its source', () => {
    const keychain = fakeKeychain();
    const credentials = new Credentials(
      new MacKeychainStore(keychain.run),
      new FileStore(tempDir())
    );
    expect(credentials.set('cynos', KEY).source).toBe('keychain');
    expect(credentials.get('cynos')).toEqual({ value: KEY, source: 'keychain' });
    expect(credentials.fellBack).toBeUndefined();
  });

  test('falls back to the file when the keychain refuses, and says why', () => {
    const file = new FileStore(tempDir());
    const credentials = new Credentials(
      new SecretToolStore(fakeKeychain({ failStore: true }).run),
      file
    );
    expect(credentials.set('cynos', KEY).source).toBe('file');
    expect(credentials.fellBack).toContain('D-Bus');
    expect(credentials.get('cynos')).toEqual({ value: KEY, source: 'file' });
    expect(credentials.delete('cynos')).toBe(true);
    expect(credentials.get('cynos')).toBeUndefined();
  });

  test('a keychain save removes an older fallback copy from the file', () => {
    const file = new FileStore(tempDir());
    file.set('cynos', 'old-key-0123456789');
    const credentials = new Credentials(new MacKeychainStore(fakeKeychain().run), file);
    credentials.set('cynos', KEY);
    expect(file.get('cynos')).toBeUndefined();
  });
});

describe('openCredentials', () => {
  test('macOS uses security, Linux secret-tool when installed, else the file', () => {
    const keychain = fakeKeychain();
    const configDir = tempDir();
    expect(
      openCredentials({ configDir, platform: 'darwin', env: {}, run: keychain.run }).keychain
    ).toBeInstanceOf(MacKeychainStore);
    expect(
      openCredentials({ configDir, platform: 'linux', env: {}, run: keychain.run }).keychain
    ).toBeInstanceOf(SecretToolStore);
    const noTool = (): RunResult => ({ status: null, stdout: '', stderr: 'ENOENT' });
    expect(
      openCredentials({ configDir, platform: 'linux', env: {}, run: noTool }).keychain
    ).toBeUndefined();
    expect(
      openCredentials({ configDir, platform: 'win32', env: {}, run: keychain.run }).keychain
    ).toBeUndefined();
  });

  test('CYNOS_CREDENTIAL_STORE=file forces the file', () => {
    const credentials = openCredentials({
      configDir: tempDir(),
      platform: 'darwin',
      env: { CYNOS_CREDENTIAL_STORE: 'file' },
      run: fakeKeychain().run,
    });
    expect(credentials.keychain).toBeUndefined();
  });
});
