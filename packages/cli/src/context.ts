/**
 * What every command shares: the environment, the terminal, the login and the CLI's own dirs.
 *
 * Keys are taken out of the environment once, at startup (keys.ts), so the context holds the only
 * copy of an environment key; commands look a key up through it rather than in process.env.
 */
import packageJson from '../package.json';
import { openCredentials, type Credentials } from './auth/credential-store';
import { engine, type Fetch } from './engine';
import { cacheDir, configDir } from './settings';
import { createTerminal, type Terminal } from './terminal';

export const CLI_NAME = 'cynos';
export const PACKAGE_NAME = packageJson.name;
export const CLI_VERSION = packageJson.version;

export interface Context {
  env: NodeJS.ProcessEnv;
  configDir: string;
  cacheDir: string;
  credentials: Credentials;
  /** The keys the environment held at startup, now deleted from it. */
  envKeys: { cynos?: string };
  /** Replaced once the global options (--quiet, --verbose) are parsed. */
  terminal: Terminal;
  fetch: Fetch;
  /** The command's result format: a failure is then reported on stdout in it too. */
  output?: 'pretty' | 'json' | 'jsonl';
}

export function createContext(env: NodeJS.ProcessEnv = process.env): Context {
  const config = configDir(env);
  return {
    env,
    configDir: config,
    cacheDir: cacheDir(env),
    credentials: openCredentials({ configDir: config, env }),
    envKeys: {},
    terminal: createTerminal({ env }),
    fetch: (url, init) => fetch(url, init),
  };
}

/**
 * The engine's default model, unless CYNOS_SCAN_MODEL names another. The engine's DEFAULT_MODEL is
 * the only copy: a second one here drifted from it before.
 */
export function defaultModel(env: NodeJS.ProcessEnv): string {
  return env['CYNOS_SCAN_MODEL'] || engine().DEFAULT_MODEL;
}

/** The engine's cynos endpoint, the default unless CYNOS_BASE_URL names another. */
export function engineBaseUrl(): string {
  return engine().BASE_URL;
}
