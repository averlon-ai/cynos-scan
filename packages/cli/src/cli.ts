/**
 * One run of the CLI, once main.ts has checked the Node version.
 *
 *   keys     CYNOS_API_KEY out of the environment, before anything can spawn a child that
 *            would inherit it
 *   parse    commander dispatches to the command; the global flags (--quiet, --verbose,
 *            --no-color, CYNOS_LOG_LEVEL) set up the terminal and upstream's log level first
 *   errors   every failure becomes upstream's exit code (exit-codes.ts): a line on stderr with
 *            the fix, and the error on stdout too when the command's output is JSON
 *   notice   the update notice, after the command's own output (update/notice.ts)
 */
import { CommanderError } from 'commander';
import { CYNOS_KEY_VARIABLE, takeEnvKey } from './auth/keys';
import { createContext, type Context } from './context';
import { errorKind, exitCodeFor, CliError, EXIT, StoppedError } from './exit-codes';
import { redact } from './local-io';
import { buildProgram, commandManifest } from './program';
import { upstreamLogLevel } from './settings';
import { createTerminal } from './terminal';
import { noticeAllowed, prepareNotice } from './update/notice';

/** Commands after which no update notice is printed: their output is code, or the update itself. */
const NO_NOTICE = new Set(['update', 'completion', 'help']);

export async function run(argv: string[], env: NodeJS.ProcessEnv = process.env): Promise<number> {
  const ctx = createContext(env);
  try {
    // 1. The keys, out of the environment first.
    ctx.envKeys = { cynos: takeEnvKey(CYNOS_KEY_VARIABLE, env) };
  } catch (error) {
    return reportError(ctx, error);
  }
  const program = buildProgram(ctx);

  // 2. No command: the help, on stdout. --llms: the manifest.
  if (!argv.length) {
    program.outputHelp();
    return EXIT.ok;
  }
  if (argv.includes('--llms') && argv.every(arg => arg.startsWith('-'))) {
    process.stdout.write(`${JSON.stringify(commandManifest(program), null, 2)}\n`);
    return EXIT.ok;
  }

  // 3. The global flags, before the command's action runs.
  program.hook('preAction', () => {
    const options = program.opts<{ quiet?: boolean; verbose?: boolean; color?: boolean }>();
    ctx.terminal = createTerminal({
      env,
      quiet: Boolean(options.quiet),
      verbose: Boolean(options.verbose),
      color: options.color !== false,
    });
    const level = upstreamLogLevel(env, Boolean(options.verbose));
    if (level) env['CODEX_SECURITY_LOG_LEVEL'] = level;
  });

  // 4. The update check starts now; its notice prints after the command.
  const commandName = argv.find(arg => !arg.startsWith('-'));
  const notice =
    commandName &&
    !NO_NOTICE.has(commandName) &&
    noticeAllowed({
      env,
      stdoutIsTTY: Boolean(process.stdout.isTTY),
      stderrIsTTY: Boolean(process.stderr.isTTY),
    })
      ? prepareNotice(ctx.cacheDir)
      : undefined;

  // 5. The command.
  let code: number;
  try {
    process.exitCode = undefined;
    await program.parseAsync(argv, { from: 'user' });
    code = typeof process.exitCode === 'number' ? process.exitCode : EXIT.ok;
  } catch (error) {
    code = reportError(ctx, error);
  }
  if (notice) ctx.terminal.info(`\n${ctx.terminal.c.yellow(notice)}`);
  return code;
}

/** The failure on stderr (and stdout for JSON output); returns its exit code. */
export function reportError(ctx: Context, error: unknown): number {
  const code = exitCodeFor(error);
  // commander has printed its own message (with a did-you-mean suggestion) already.
  if (error instanceof CommanderError) return code === EXIT.ok ? EXIT.ok : EXIT.failure;
  const keys = [ctx.envKeys.cynos];
  const message = redact(error instanceof Error ? error.message : String(error), keys);
  const hint = error instanceof CliError ? error.hint : undefined;
  const kind = errorKind(error);
  const { terminal } = ctx;
  terminal.error(message);
  if (hint) terminal.info(terminal.c.dim(`  ${hint}`));
  if (kind === 'internal' && terminal.verbose && error instanceof Error && error.stack)
    terminal.debug(redact(error.stack, keys));
  else if (kind === 'internal')
    terminal.info(
      terminal.c.dim('  -v shows the stack trace; `cynos debug bundle` collects the rest.')
    );
  const failure = {
    status: 'failed',
    scanId: null,
    scanStatus: 'failed',
    scanDir: null,
    counts: null,
    exitCode: code,
    // Why a stop ended the run, as a finished scan's result says it.
    stopped: error instanceof StoppedError ? error.stopped : null,
    error: { kind, message, ...(hint ? { hint } : {}) },
  };
  if (ctx.output === 'json') terminal.json(failure);
  else if (ctx.output === 'jsonl') terminal.result(JSON.stringify({ type: 'result', ...failure }));
  return code;
}
