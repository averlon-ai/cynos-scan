/**
 * Where the CLI writes, as upstream does: results on stdout, progress and diagnostics on stderr.
 *
 * A script that pipes `cynos scan --format json` must read exactly one JSON value from
 * stdout, whatever the scan logged along the way, so nothing but a command's result ever goes
 * there. Colour follows the stream it is written to, and NO_COLOR / TERM=dumb turn it off;
 * --quiet keeps only warnings and errors, --verbose adds debug lines.
 */
import pc from 'picocolors';

export type Colors = ReturnType<typeof pc.createColors>;

export interface TerminalOptions {
  quiet?: boolean;
  verbose?: boolean;
  color?: boolean;
  env?: NodeJS.ProcessEnv;
  stdout?: NodeJS.WriteStream;
  stderr?: NodeJS.WriteStream;
  stdin?: NodeJS.ReadStream;
}

export interface Terminal {
  readonly quiet: boolean;
  readonly verbose: boolean;
  /** Colours for stderr (diagnostics). */
  readonly c: Colors;
  /** Colours for stdout (results). */
  readonly out: Colors;
  readonly stdout: NodeJS.WriteStream;
  readonly stderr: NodeJS.WriteStream;
  /** A prompt can be answered: stdin and stdout (where @clack/prompts draws) are terminals. */
  readonly canPrompt: boolean;
  /** stderr is a terminal: a live view can be drawn there. */
  readonly stderrIsTTY: boolean;
  /** A result line on stdout. */
  result(text: string): void;
  /** A JSON result on stdout. */
  json(value: unknown): void;
  info(text: string): void;
  debug(text: string): void;
  warn(text: string): void;
  error(text: string): void;
}

export const SYMBOLS = { ok: '✓', warn: '⚠', fail: '✗', skip: '–', bullet: '·', arrow: '▸' };

/** Whether colour is wanted on a stream: a terminal, without NO_COLOR or TERM=dumb. */
export function colorWanted(stream: { isTTY?: boolean }, env: NodeJS.ProcessEnv): boolean {
  if ('NO_COLOR' in env || env['TERM'] === 'dumb') return false;
  if (env['FORCE_COLOR'] && env['FORCE_COLOR'] !== '0') return true;
  return Boolean(stream.isTTY);
}

export function createTerminal(options: TerminalOptions = {}): Terminal {
  const env = options.env ?? process.env;
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  const stdin = options.stdin ?? process.stdin;
  const quiet = options.quiet ?? false;
  const verbose = options.verbose ?? false;
  const c = pc.createColors(options.color !== false && colorWanted(stderr, env));
  const out = pc.createColors(options.color !== false && colorWanted(stdout, env));
  const line = (stream: NodeJS.WriteStream, text: string): void => {
    stream.write(text.endsWith('\n') ? text : `${text}\n`);
  };
  return {
    quiet,
    verbose,
    c,
    out,
    stdout,
    stderr,
    canPrompt: Boolean(stdin.isTTY && stdout.isTTY),
    stderrIsTTY: Boolean(stderr.isTTY),
    result: text => line(stdout, text),
    json: value => line(stdout, JSON.stringify(value, null, 2)),
    info: text => {
      if (!quiet) line(stderr, text);
    },
    debug: text => {
      if (verbose) line(stderr, c.dim(text));
    },
    warn: text => line(stderr, `${c.yellow(SYMBOLS.warn)} ${text}`),
    error: text => line(stderr, `${c.red(SYMBOLS.fail)} ${text}`),
  };
}

/** Seconds as people read them: 0.4s, 12s, 3m02s, 1h04m. */
export function duration(seconds: number): string {
  if (seconds < 10) return `${seconds.toFixed(1)}s`;
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m${String(Math.round(seconds % 60)).padStart(2, '0')}s`;
  return `${Math.floor(minutes / 60)}h${String(minutes % 60).padStart(2, '0')}m`;
}
