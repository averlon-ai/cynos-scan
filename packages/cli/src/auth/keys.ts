/**
 * Which cynos key a command uses, and where it came from.
 *
 * The key reaches the CLI one of two ways, and the environment wins so CI and one-off runs need no
 * login: CYNOS_API_KEY, then the saved login (keychain or file). A key in the
 * environment would be inherited by every child process (upstream, Codex, git, docker), so it is
 * read once at startup and deleted from process.env; the engine hands it on only where the scan
 * needs it, by name. Keys never go in argv or in a log line; `auth status` shows a fingerprint.
 */
import { createHash } from 'node:crypto';
import { CliError } from '../exit-codes';
import type { CredentialSource, Credentials } from './credential-store';
import { withoutTrailing } from '../text.js';

export const CYNOS_KEY_VARIABLE = 'CYNOS_API_KEY';
/** The keychain account the one saved cynos key is kept under. */
export const CYNOS_ACCOUNT = 'cynos';

/** A key and where it was found. */
export interface KeyInUse {
  value: string;
  source: 'env' | CredentialSource;
}

/** Reads a key from the environment and deletes it there, so no child process inherits it. */
export function takeEnvKey(name: string, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const value = env[name];
  delete env[name];
  if (value === undefined || value === '') return undefined;
  if (/[\s\u0000]/.test(value.trim()) || value.trim() !== value)
    throw new CliError('auth', `${name} holds whitespace or a line break; set it to the key alone`);
  return value;
}

/** The cynos key: CYNOS_API_KEY (taken at startup), then the saved login. */
export function cynosKey(
  fromEnv: string | undefined,
  credentials: Pick<Credentials, 'get'>
): KeyInUse | undefined {
  if (fromEnv) return { value: fromEnv, source: 'env' };
  const saved = credentials.get(CYNOS_ACCOUNT);
  return saved ? { value: saved.value, source: saved.source } : undefined;
}

/** A key as `auth status` shows it: the ends and a hash prefix, never enough to use. */
export function fingerprint(key: string): string {
  const hash = createHash('sha256').update(key).digest('hex').slice(0, 8);
  const ends = key.length >= 16 ? `${key.slice(0, 4)}…${key.slice(-4)}` : '****';
  return `${ends} (sha256:${hash})`;
}

/** The cynos endpoint: CYNOS_BASE_URL, else the engine's default. */
export function cynosBaseUrl(env: NodeJS.ProcessEnv, fallback: string): string {
  return withoutTrailing(env['CYNOS_BASE_URL'] || fallback, '/');
}
