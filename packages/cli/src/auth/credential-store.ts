/**
 * Where a login keeps its keys: the OS keychain when there is one, else a private file.
 *
 * The CLI has no native modules (install stays a plain `npm i -g`), so it reaches the keychain
 * by spawning the OS's own tool. The catch is that a key must never appear in a process's argv,
 * where any user on the machine can read it with `ps`:
 *
 *   macOS   `security add-generic-password -w KEY` takes the key in argv, so the command is
 *           written to `security -i` on stdin instead; reading (`find-generic-password -w`)
 *           and deleting take no secret
 *   Linux   `secret-tool store` reads the key from stdin already
 *   else    a 0600 JSON file in the config dir (~/.config/averlon/cynos/credentials.json)
 *
 * A keychain can still be missing or locked (no Secret Service on a headless Linux box, a key
 * `security -i` cannot quote), so the keychain store falls back to the file and says why, and
 * every read looks in both.
 */
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/** The keychain service every item is filed under. */
export const SERVICE = 'cynos';

/** Where a key was found. */
export type CredentialSource = 'keychain' | 'file';

export interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

/** Runs a command with optional stdin; injected so tests never touch a real keychain. */
export type Runner = (command: string, args: string[], input?: string) => RunResult;

export const spawnRunner: Runner = (command, args, input) => {
  const run = spawnSync(command, args, {
    encoding: 'utf8',
    ...(input !== undefined ? { input } : {}),
    stdio: ['pipe', 'pipe', 'pipe'],
    timeout: 30_000,
  });
  return {
    status: run.error ? null : run.status,
    stdout: run.stdout ?? '',
    stderr: run.stderr ?? (run.error ? run.error.message : ''),
  };
};

export interface Stored {
  value: string;
  source: CredentialSource;
}

/** One place keys are kept, each under an account name (the cynos key's is `cynos`). */
export interface CredentialStore {
  readonly source: CredentialSource;
  /** Where, for `auth status`: "macOS keychain", or the file's path. */
  readonly description: string;
  get(account: string): string | undefined;
  set(account: string, secret: string): void;
  /** Whether anything was deleted. */
  delete(account: string): boolean;
}

/** The macOS login keychain, through `security`. */
export class MacKeychainStore implements CredentialStore {
  readonly source = 'keychain';
  readonly description = 'macOS keychain';

  constructor(private readonly run: Runner = spawnRunner) {}

  get(account: string): string | undefined {
    const found = this.run('security', [
      'find-generic-password',
      '-a',
      account,
      '-s',
      SERVICE,
      '-w',
    ]);
    return found.status === 0 ? found.stdout.replace(/\n$/, '') || undefined : undefined;
  }

  set(account: string, secret: string): void {
    // security -i reads whitespace-separated words with double quotes; a key it cannot quote
    // (a quote, a backslash, whitespace) would be mangled, so it goes to the file instead.
    if (!/^[\x21-\x7e]+$/.test(secret) || /["\\]/.test(secret))
      throw new Error('the key holds characters `security -i` cannot take on stdin');
    const command = `add-generic-password -U -a "${account}" -s "${SERVICE}" -l "${SERVICE} ${account}" -w "${secret}"\n`;
    const added = this.run('security', ['-i'], command);
    // security -i exits 0 even when a command in it failed, so the write is read back.
    if (added.status !== 0 || this.get(account) !== secret)
      throw new Error(
        `security could not save it: ${added.stderr.trim() || 'not found afterwards'}`
      );
  }

  delete(account: string): boolean {
    return (
      this.run('security', ['delete-generic-password', '-a', account, '-s', SERVICE]).status === 0
    );
  }
}

/** The Secret Service (GNOME Keyring, KWallet), through libsecret's `secret-tool`. */
export class SecretToolStore implements CredentialStore {
  readonly source = 'keychain';
  readonly description = 'Secret Service (secret-tool)';

  constructor(private readonly run: Runner = spawnRunner) {}

  get(account: string): string | undefined {
    const found = this.run('secret-tool', ['lookup', 'service', SERVICE, 'account', account]);
    return found.status === 0 ? found.stdout.replace(/\n$/, '') || undefined : undefined;
  }

  set(account: string, secret: string): void {
    const label = `--label=${SERVICE} ${account}`;
    const stored = this.run(
      'secret-tool',
      ['store', label, 'service', SERVICE, 'account', account],
      secret
    );
    if (stored.status !== 0)
      throw new Error(
        `secret-tool could not save it: ${stored.stderr.trim() || 'no Secret Service'}`
      );
  }

  delete(account: string): boolean {
    const had = this.get(account) !== undefined;
    this.run('secret-tool', ['clear', 'service', SERVICE, 'account', account]);
    return had;
  }
}

/** A private JSON file: the directory 0700, the file 0600, replaced whole on every write. */
export class FileStore implements CredentialStore {
  readonly source = 'file';
  readonly path: string;

  constructor(private readonly dir: string) {
    this.path = join(dir, 'credentials.json');
  }

  get description(): string {
    return this.path;
  }

  get(account: string): string | undefined {
    const value = this.read()[account];
    return typeof value === 'string' && value ? value : undefined;
  }

  set(account: string, secret: string): void {
    this.write({ ...this.read(), [account]: secret });
  }

  delete(account: string): boolean {
    const all = this.read();
    if (!(account in all)) return false;
    delete all[account];
    this.write(all);
    return true;
  }

  private read(): Record<string, unknown> {
    if (!existsSync(this.path)) return {};
    try {
      const value: unknown = JSON.parse(readFileSync(this.path, 'utf8'));
      return value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
    } catch {
      return {};
    }
  }

  private write(all: Record<string, unknown>): void {
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    chmodSync(this.dir, 0o700);
    // Written beside the file with 0600 from the start, then renamed: never readable by others,
    // never half-written.
    const pending = `${this.path}.${process.pid}.tmp`;
    writeFileSync(pending, `${JSON.stringify(all, null, 2)}\n`, { mode: 0o600 });
    renameSync(pending, this.path);
  }
}

/**
 * The keychain first, the file as the fallback. `fellBack` says why the last save went to the
 * file, for the login to tell the user.
 */
export class Credentials {
  fellBack: string | undefined;

  constructor(
    readonly keychain: CredentialStore | undefined,
    readonly file: FileStore
  ) {}

  /** Where a save goes first, for `auth status` and the login's message. */
  get description(): string {
    return this.keychain?.description ?? this.file.description;
  }

  get(account: string): Stored | undefined {
    const fromKeychain = this.keychain?.get(account);
    if (fromKeychain) return { value: fromKeychain, source: 'keychain' };
    const fromFile = this.file.get(account);
    return fromFile ? { value: fromFile, source: 'file' } : undefined;
  }

  /** Saves the key, and returns where it went. */
  set(account: string, secret: string): Stored {
    this.fellBack = undefined;
    if (this.keychain) {
      try {
        this.keychain.set(account, secret);
        // A key an earlier fallback left in the file would outlive the next logout; drop it.
        this.file.delete(account);
        return { value: secret, source: 'keychain' };
      } catch (error) {
        this.fellBack = `${this.keychain.description}: ${(error as Error).message}`;
      }
    }
    this.file.set(account, secret);
    return { value: secret, source: 'file' };
  }

  delete(account: string): boolean {
    const fromKeychain = this.keychain?.delete(account) ?? false;
    const fromFile = this.file.delete(account);
    return fromKeychain || fromFile;
  }
}

/**
 * The credential store for this machine: `security` on macOS, `secret-tool` on Linux when it is
 * installed, the file otherwise or when CYNOS_CREDENTIAL_STORE=file.
 */
export function openCredentials(options: {
  configDir: string;
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  run?: Runner;
}): Credentials {
  const { configDir, platform = process.platform, env = process.env, run = spawnRunner } = options;
  const file = new FileStore(configDir);
  if (env['CYNOS_CREDENTIAL_STORE'] === 'file') return new Credentials(undefined, file);
  if (platform === 'darwin') return new Credentials(new MacKeychainStore(run), file);
  if (platform === 'linux' && run('secret-tool', ['--version']).status !== null)
    return new Credentials(new SecretToolStore(run), file);
  return new Credentials(undefined, file);
}
