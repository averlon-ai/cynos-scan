/**
 * Questions the CLI asks: a masked key, and yes/no before anything irreversible or privileged.
 *
 * A prompt needs someone to answer it. In CI or with piped stdin it would hang or read garbage,
 * so it fails at once instead, naming the flag that answers it non-interactively.
 */
import { cancel, confirm as clackConfirm, isCancel, password } from '@clack/prompts';
import { CliError } from './exit-codes';
import type { Terminal } from './terminal';

/** A key typed with masked input. */
export async function askSecret(
  terminal: Terminal,
  message: string,
  otherwise: string
): Promise<string> {
  if (!terminal.canPrompt)
    throw new CliError('usage', 'There is no terminal to type a key in.', otherwise);
  const answer = await password({
    message,
    mask: '•',
    validate: value => (value?.trim() ? undefined : 'The key is empty'),
  });
  if (isCancel(answer)) {
    cancel('Login cancelled.');
    throw new CliError('interrupted', 'Login cancelled.');
  }
  return answer.trim();
}

/** Yes or no; `yes` answers it in advance (--yes). */
export async function confirm(
  terminal: Terminal,
  message: string,
  options: { yes?: boolean; otherwise: string; initial?: boolean }
): Promise<boolean> {
  if (options.yes) return true;
  if (!terminal.canPrompt)
    throw new CliError('usage', `${message} (no terminal to ask in)`, options.otherwise);
  const answer = await clackConfirm({ message, initialValue: options.initial ?? false });
  return !isCancel(answer) && answer === true;
}

/** All of stdin, for `login --with-api-key`: the key alone, trailing newline dropped. */
export async function readStdin(stdin: NodeJS.ReadStream = process.stdin): Promise<string> {
  if (stdin.isTTY)
    throw new CliError(
      'usage',
      '--with-api-key reads the key from stdin, and stdin is a terminal.',
      'Pipe it in: printf %s "$KEY" | cynos login --with-api-key'
    );
  const chunks: Buffer[] = [];
  for await (const chunk of stdin) chunks.push(Buffer.from(chunk as Buffer));
  return Buffer.concat(chunks).toString('utf8').trim();
}
