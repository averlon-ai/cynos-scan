/**
 * The command tree, grouped by task in the root help as upstream's is:
 *
 *   Scan                 scan
 *   Review results       scans, findings, export, logs
 *   Sign in              login, logout, auth
 *   Setup and support    doctor, update, info, debug, gc
 *   Shell and help       completion, help
 *
 * Each command registers itself (src/commands/*, src/auth/commands.ts) with its examples.
 * Commander suggests the nearest command or option on a typo; its errors become exit code 2
 * in cli.ts.
 */
import { Command } from 'commander';
import { registerAuth } from './auth/commands';
import { CLI_NAME, CLI_VERSION, type Context } from './context';
import { registerCompletion } from './commands/completion';
import { registerDebug } from './commands/debug-bundle';
import { registerDoctor } from './commands/doctor';
import { registerGc } from './commands/gc';
import { registerHelpTopics, TOPICS } from './commands/help-topics';
import { registerHistory } from './commands/history';
import { registerInfo } from './commands/info';
import { registerScan } from './commands/scan';
import { registerUpdate } from './commands/update';
import { allCommands, examplesOf, GET_STARTED, upstreamOf } from './help';
import { ENVIRONMENT } from './settings';

export const DESCRIPTION =
  'Find security issues in your code on this machine: upstream Codex Security through cynos, with a knowledge base.';

export function buildProgram(ctx: Context): Command {
  const program = new Command(CLI_NAME)
    .description(DESCRIPTION)
    .usage('<command> [options]')
    .version(CLI_VERSION, '-V, --version', 'show the version')
    .helpOption('-h, --help', 'show help')
    .option('-q, --quiet', 'only warnings and errors on stderr')
    .option('-v, --verbose', 'debug diagnostics on stderr (and upstream at debug level)')
    .option('--no-color', 'no colour (also NO_COLOR)')
    .option('--llms', 'print a JSON manifest of every command, for agents')
    .showSuggestionAfterError(true)
    .exitOverride()
    .configureOutput({
      writeOut: text => process.stdout.write(text),
      writeErr: text => process.stderr.write(text),
      outputError: (text, write) => write(ctx.terminal.c.red(text)),
    })
    .addHelpText('beforeAll', `${CLI_NAME}@${CLI_VERSION}`)
    .addHelpText('before', `${DESCRIPTION}\n\n${GET_STARTED}\n`);
  // The root's description is in its opening lines, above; a subcommand's stays in its help.
  program.configureHelp({
    commandDescription: command => (command === program ? '' : command.description()),
  });

  program.commandsGroup('Scan:');
  registerScan(program, ctx);
  program.commandsGroup('Review results:');
  registerHistory(program, ctx);
  program.commandsGroup('Sign in:');
  registerAuth(program, ctx);
  program.commandsGroup('Setup and support:');
  registerDoctor(program, ctx);
  registerUpdate(program, ctx);
  registerInfo(program, ctx);
  registerDebug(program, ctx);
  registerGc(program, ctx);
  program.commandsGroup('Shell and help:');
  registerCompletion(program);
  registerHelpTopics(program);

  // Every command, however deep, reports usage errors the same way and suggests on typos.
  for (const { command } of allCommands(program))
    command
      .exitOverride()
      .showSuggestionAfterError(true)
      .configureOutput(program.configureOutput());
  return program;
}

interface OptionInfo {
  flags: string;
  description: string;
  default?: unknown;
  choices?: readonly string[];
}

function optionsOf(command: Command): OptionInfo[] {
  return command.options.map(option => ({
    flags: option.flags,
    description: option.description,
    ...(option.defaultValue !== undefined ? { default: option.defaultValue } : {}),
    ...(option.argChoices ? { choices: option.argChoices } : {}),
  }));
}

/** --llms: every command with its usage, arguments, options and examples, as one JSON object. */
export function commandManifest(program: Command): Record<string, unknown> {
  return {
    name: CLI_NAME,
    version: CLI_VERSION,
    description: DESCRIPTION,
    usage: `${CLI_NAME} <command> [options]`,
    output:
      'Results go to stdout, progress and diagnostics to stderr. scan --format json prints one JSON object.',
    globalOptions: optionsOf(program),
    commands: allCommands(program).map(({ name, command }) => ({
      name,
      description: command.description(),
      usage: `${CLI_NAME} ${name} ${command.usage()}`.trim(),
      arguments: command.registeredArguments.map(argument => ({
        name: argument.name(),
        description: argument.description,
        required: argument.required,
        variadic: argument.variadic,
      })),
      options: optionsOf(command),
      subcommands: command.commands.map(child => child.name()),
      examples: examplesOf(command),
      ...(upstreamOf(command) ? { passesThroughTo: upstreamOf(command) } : {}),
    })),
    exitCodes: {
      0: 'completed, or passes the severity policy',
      1: 'severity policy violation (--fail-on-severity)',
      2: 'every failure; error.kind in --format json says which',
      130: 'interrupted (Ctrl-C)',
      143: 'terminated (SIGTERM)',
    },
    environment: Object.fromEntries(ENVIRONMENT),
    helpTopics: Object.fromEntries(
      Object.entries(TOPICS).map(([name, topic]) => [name, topic.summary])
    ),
  };
}
