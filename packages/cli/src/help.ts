/**
 * Help that reads like upstream's: commands grouped by task, examples in every command's help.
 *
 * Commander knows a command's options and arguments but not how it is used, so each command
 * registers its examples here; the same list feeds `--help`, the --llms manifest and the test
 * that every command has some.
 */
import type { Command } from 'commander';
import { CLI_NAME } from './context';

const EXAMPLES = new WeakMap<Command, string[]>();
const PASS_THROUGH = new WeakMap<Command, string>();

/** Adds examples to a command's help (after its options, as `Examples:`). */
export function withExamples(command: Command, examples: string[]): Command {
  EXAMPLES.set(command, examples);
  command.addHelpText(
    'after',
    () => `\nExamples:\n${examples.map(example => `  ${example}`).join('\n')}\n`
  );
  return command;
}

export function examplesOf(command: Command): string[] {
  return EXAMPLES.get(command) ?? [];
}

/** Marks a command whose options are upstream's own (history pass-through). */
export function passesThrough(command: Command, upstreamCommand: string): Command {
  PASS_THROUGH.set(command, upstreamCommand);
  command.addHelpText(
    'after',
    `\nEvery other option is upstream's own and passes through unchanged: \`${upstreamCommand}\`\n` +
      `(see https://learn.chatgpt.com/docs/security/cli). The state dir is upstream's, shared with \`cs\`.\n`
  );
  return command;
}

export function upstreamOf(command: Command): string | undefined {
  return PASS_THROUGH.get(command);
}

/** Every command under root, depth first, with its full name (`scans list`). */
export function allCommands(root: Command): { name: string; command: Command }[] {
  const found: { name: string; command: Command }[] = [];
  const walk = (command: Command, prefix: string): void => {
    for (const child of command.commands) {
      const name = prefix ? `${prefix} ${child.name()}` : child.name();
      found.push({ name, command: child });
      walk(child, name);
    }
  };
  walk(root, '');
  return found;
}

/** The root help's opening lines, before the command groups. */
export const GET_STARTED = `Get started:
  ${CLI_NAME} login
  ${CLI_NAME} doctor
  ${CLI_NAME} scan .`;
