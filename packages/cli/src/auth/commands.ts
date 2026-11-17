/**
 * login, logout and auth status: the cynos key is the login.
 *
 * A key is only worth saving if cynos takes it, and cynos reports a refused key during a scan
 * only as "cannot access the configured model", minutes in. So `login` sends the engine's
 * 16-token key check first and saves nothing cynos refused. There is one saved key, checked against
 * the endpoint every command uses (CYNOS_BASE_URL, else the default); `auth status` says which
 * key a scan would use and where it came from, without ever printing it.
 */
import type { Command } from 'commander';
import { CLI_NAME, defaultModel, engineBaseUrl, type Context } from '../context';
import { engine } from '../engine';
import { CliError, refusalKind } from '../exit-codes';
import { withExamples } from '../help';
import { askSecret, readStdin } from '../prompts';
import { CYNOS_ACCOUNT, cynosBaseUrl, cynosKey, fingerprint } from './keys';

interface LoginOptions {
  withApiKey?: boolean;
}

export function registerAuth(program: Command, ctx: Context): void {
  const login = program
    .command('login')
    .description('Sign in to cynos with an API key (checked before it is saved).')
    .option('--with-api-key', 'read the key from stdin instead of prompting')
    .action(async (options: LoginOptions) => loginCynos(ctx, options));
  withExamples(login, [
    `${CLI_NAME} login`,
    `printf %s "$CYNOS_API_KEY" | ${CLI_NAME} login --with-api-key`,
  ]);

  const logout = program
    .command('logout')
    .description('Remove the saved key.')
    .action(async () => logoutCommand(ctx));
  withExamples(logout, [`${CLI_NAME} logout`]);

  const auth = program.command('auth').description('Show which keys a scan would use.');
  withExamples(auth, [`${CLI_NAME} auth status`, `${CLI_NAME} auth status --json`]);
  const status = auth
    .command('status')
    .description('Which key is in use, where it came from, and the endpoint.')
    .option('--json', 'print JSON')
    .action(async (options: { json?: boolean }) => authStatus(ctx, options));
  withExamples(status, [`${CLI_NAME} auth status`, `${CLI_NAME} auth status --json`]);
}

/** Reads the key, checks it against the endpoint, then saves it. */
async function loginCynos(ctx: Context, options: LoginOptions): Promise<void> {
  const { terminal, env } = ctx;
  const baseUrl = cynosBaseUrl(env, engineBaseUrl());

  // 1. The key, from stdin or typed masked; never from argv.
  const key = options.withApiKey
    ? await readStdin()
    : await askSecret(
        terminal,
        `cynos API key for ${baseUrl}`,
        `Pipe it in: printf %s "$KEY" | ${CLI_NAME} login --with-api-key`
      );
  if (!key) throw new CliError('usage', 'The key is empty.');

  // 2. The engine's key check: one 16-token request, so a refused key is never saved.
  const model = defaultModel(env);
  terminal.info(terminal.c.dim(`Checking the key with ${baseUrl} (${model}) …`));
  const answer = await engine().checkKey(key, model, ctx.fetch, baseUrl);
  if (!answer.accepted) {
    const { failure, fix } = engine().keyCheckFailure(answer, model, baseUrl);
    throw new CliError(refusalKind(answer.refusal), failure, fix);
  }

  // 3. Save the key, in place of any key saved before.
  const stored = ctx.credentials.set(CYNOS_ACCOUNT, key);
  if (ctx.credentials.fellBack)
    terminal.warn(
      `The key went to ${ctx.credentials.file.description} (mode 0600) instead of the keychain: ${ctx.credentials.fellBack}`
    );
  const where =
    stored.source === 'file' ? ctx.credentials.file.description : ctx.credentials.description;
  terminal.info(
    `${terminal.c.green('✓')} Logged in to ${baseUrl}; key ${fingerprint(key)} saved in ${where}.`
  );
  if (ctx.envKeys.cynos)
    terminal.warn('CYNOS_API_KEY is set in this environment and takes precedence over the login.');
}

async function logoutCommand(ctx: Context): Promise<void> {
  const { terminal } = ctx;
  if (ctx.credentials.delete(CYNOS_ACCOUNT)) terminal.info(`${terminal.c.green('✓')} Logged out.`);
  else terminal.info('No saved key to remove.');
  if (ctx.envKeys.cynos) terminal.warn('CYNOS_API_KEY is still set in this environment.');
}

/** The status as --json prints it. */
export function authState(ctx: Context): Record<string, unknown> {
  const key = cynosKey(ctx.envKeys.cynos, ctx.credentials);
  return {
    baseUrl: cynosBaseUrl(ctx.env, engineBaseUrl()),
    cynos: {
      set: Boolean(key),
      source: key?.source ?? null,
      fingerprint: key ? fingerprint(key.value) : null,
    },
    credentialStore: ctx.credentials.description,
  };
}

async function authStatus(ctx: Context, options: { json?: boolean }): Promise<void> {
  const state = authState(ctx);
  const { terminal } = ctx;
  if (options.json) return terminal.json(state);
  const cynos = state['cynos'] as { set: boolean; source: string; fingerprint: string };
  const c = terminal.out;
  const mark = (set: boolean): string => (set ? c.green('✓') : c.yellow('⚠'));
  terminal.result(
    [
      `${c.bold('Endpoint')}    ${String(state['baseUrl'])}`,
      `${mark(cynos.set)} cynos key   ${cynos.set ? `${cynos.fingerprint} from ${cynos.source}` : `not set: run ${CLI_NAME} login`}`,
      `${c.dim(`A saved key goes to ${String(state['credentialStore'])}.`)}`,
    ].join('\n')
  );
}
