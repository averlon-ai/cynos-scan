/**
 * How a scan's progress looks on stderr: a live full-screen view, or plain lines.
 *
 * In an interactive terminal two dashboards share one screen, one after the other. Before
 * upstream starts, the phases are ours (stage, preflight, knowledge, brief), and some take
 * minutes, so they get a live view in the style of upstream's: one line per phase with a
 * spinner, its elapsed time and its current step. Then upstream draws its own dashboard, with its
 * own keys, which we must not copy or fight over: on the engine's `handoff` event the live view
 * leaves the alternate screen and prints what it showed as plain lines, so they stay in the
 * scrollback, and upstream takes the terminal. Until the scan phase ends nothing of ours is
 * written there, not even the five-minute "still running" line: it would land in upstream's
 * dashboard, or under the question upstream asks after the scan (whether to patch the findings).
 * Warnings wait, and are printed once upstream is done. After upstream exits, the report phase is
 * plain lines too.
 *
 *   live view   stage ⠋ preflight ✓ knowledge ⠙ brief   →  handoff  →  upstream's dashboard
 *   headless    the same events as plain lines (CI, pipes, --headless, --verbose, --format json)
 *
 * Both renderers take the same calls; the scan command picks one.
 */
import type { ScanEvent, ScanPhase } from '../engine';
import { duration, SYMBOLS, type Terminal } from '../terminal';
import type { PhaseTimings } from './timings';

export interface ProgressRenderer {
  event(event: ScanEvent): void;
  /** An engine log line (already redacted). */
  log(message: string): void;
  warn(message: string): void;
  error(message: string): void;
  /** The scan is over, or failed: give the terminal back. */
  close(): void;
}

/** The phases the live view draws: everything before upstream's own dashboard. */
const LIVE_PHASES: ScanPhase[] = ['stage', 'preflight', 'knowledge', 'brief'];
const SPINNER = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const ESC = '\u001b[';
const SCREEN = {
  enter: `${ESC}?1049h${ESC}?25l`,
  leave: `${ESC}?25h${ESC}?1049l`,
  home: `${ESC}H${ESC}2J`,
};

/** A phase's line, as both renderers print it once it is over. */
function phaseLine(terminal: Terminal, timings: PhaseTimings, phase: ScanPhase): string {
  const { c } = terminal;
  const record = timings.phases.get(phase)!;
  const seconds = timings.elapsed(phase);
  const time = seconds !== undefined ? duration(seconds) : '';
  const mark = {
    pending: c.dim(' '),
    running: c.cyan(SYMBOLS.arrow),
    done: c.green(SYMBOLS.ok),
    failed: c.red(SYMBOLS.fail),
    skipped: c.dim(SYMBOLS.skip),
    cancelled: c.yellow(SYMBOLS.skip),
  }[record.status];
  const detail = record.detail ? c.dim(record.detail) : '';
  return `${mark} ${phase.padEnd(10)} ${time.padStart(7)}  ${detail}`.trimEnd();
}

/** Plain lines on stderr, one per phase change, step and upstream progress line. */
export class HeadlessRenderer implements ProgressRenderer {
  private lastStep = '';
  private lastHeartbeat = 0;

  constructor(
    private readonly terminal: Terminal,
    private readonly timings: PhaseTimings
  ) {}

  event(event: ScanEvent): void {
    const { terminal } = this;
    if (event.type === 'phase') {
      if (event.status === 'start')
        terminal.info(`${terminal.c.cyan(SYMBOLS.arrow)} ${event.phase}`);
      else terminal.info(phaseLine(terminal, this.timings, event.phase));
    } else if (event.type === 'step') {
      this.lastStep = event.message;
      terminal.info(`  ${event.message}`);
    } else if (event.type === 'upstream')
      terminal.info(`  ${terminal.c.dim('upstream:')} ${event.message}`);
    else if (event.type === 'heartbeat' && event.elapsedSeconds - this.lastHeartbeat >= 300) {
      // A long scan prints that it is alive every five minutes, not on every heartbeat.
      this.lastHeartbeat = event.elapsedSeconds;
      terminal.info(
        terminal.c.dim(`  … ${event.phase} running for ${duration(event.elapsedSeconds)}`)
      );
    }
  }

  log(message: string): void {
    // say() emits a step's event and its log line together: the line was printed already.
    if (message === this.lastStep) return;
    this.terminal.debug(`  ${message}`);
  }

  warn(message: string): void {
    this.terminal.warn(message);
  }

  error(message: string): void {
    this.terminal.error(message);
  }

  close(): void {}
}

/**
 * The live view on the alternate screen, until the handoff; then silence while upstream has the
 * terminal; afterwards it is a HeadlessRenderer for the report phase.
 */
export class LiveRenderer implements ProgressRenderer {
  private active = false;
  /** From the handoff to the end of the scan phase: the terminal is upstream's. */
  private upstreamHasTerminal = false;
  private frame = 0;
  private timer: NodeJS.Timeout | undefined;
  private readonly warnings: string[] = [];
  private readonly after: HeadlessRenderer;
  private readonly restore = (): void => this.leaveScreen();

  constructor(
    private readonly terminal: Terminal,
    private readonly timings: PhaseTimings,
    private readonly title: string
  ) {
    this.after = new HeadlessRenderer(terminal, timings);
  }

  /** Takes the screen and starts the spinner. */
  start(): void {
    this.active = true;
    this.terminal.stderr.write(SCREEN.enter);
    // However the process ends, the terminal must come back usable.
    process.once('exit', this.restore);
    this.timer = setInterval(() => this.draw(), 100);
    this.timer.unref();
    this.draw();
  }

  event(event: ScanEvent): void {
    if (this.active) {
      if (event.type === 'handoff') {
        this.release();
        this.upstreamHasTerminal = true;
      } else this.draw();
      return;
    }
    if (this.upstreamHasTerminal) {
      // Only the end of the scan phase gives the terminal back; every other event is dropped.
      if (event.type !== 'phase' || event.phase !== 'scan' || event.status === 'start') return;
      this.giveBackTerminal();
    }
    this.after.event(event);
  }

  log(message: string): void {
    if (!this.active && !this.upstreamHasTerminal) this.after.log(message);
  }

  warn(message: string): void {
    if (this.active || this.upstreamHasTerminal) this.warnings.push(message);
    else this.after.warn(message);
  }

  error(message: string): void {
    if (this.active || this.upstreamHasTerminal) this.warnings.push(`error: ${message}`);
    else this.after.error(message);
  }

  close(): void {
    if (this.active) this.release();
    if (this.upstreamHasTerminal) this.giveBackTerminal();
  }

  /** upstream is done with the terminal: the warnings held while it had it. */
  private giveBackTerminal(): void {
    this.upstreamHasTerminal = false;
    for (const warning of this.warnings.splice(0)) this.terminal.warn(warning);
  }

  /** Leaves the screen and prints what it showed, so the lines stay in the scrollback. */
  private release(): void {
    this.leaveScreen();
    const { terminal } = this;
    terminal.info(terminal.c.bold(this.title));
    for (const phase of LIVE_PHASES)
      if (this.timings.phases.get(phase)?.status !== 'pending')
        terminal.info(phaseLine(terminal, this.timings, phase));
    for (const warning of this.warnings.splice(0)) terminal.warn(warning);
  }

  private leaveScreen(): void {
    if (!this.active) return;
    this.active = false;
    clearInterval(this.timer);
    process.off('exit', this.restore);
    this.terminal.stderr.write(SCREEN.leave);
  }

  private draw(): void {
    if (!this.active) return;
    const { terminal } = this;
    const { c } = terminal;
    const width = terminal.stderr.columns || 100;
    this.frame = (this.frame + 1) % SPINNER.length;
    const lines = [` ${c.bold('cynos')}  ${c.dim(this.title)}`, ''];
    for (const phase of LIVE_PHASES) {
      const running = this.timings.phases.get(phase)?.status === 'running';
      const line = phaseLine(terminal, this.timings, phase);
      lines.push(
        ` ${running ? c.cyan(SPINNER[this.frame]) + line.slice(line.indexOf(' ')) : line}`
      );
    }
    lines.push(` ${c.dim('  scan        upstream’s dashboard takes over here')}`, '');
    if (this.warnings.length)
      lines.push(
        ` ${c.yellow(`${SYMBOLS.warn} ${this.warnings.length} warning(s), shown when the scan starts`)}`
      );
    lines.push(` ${c.dim('Ctrl-C stops the scan; press it twice to exit at once.')}`);
    const clipped = lines.map(line => clip(line, width));
    terminal.stderr.write(`${SCREEN.home}${clipped.join('\n')}\n`);
  }
}

/** A line cut to the terminal's width, counting only visible characters. */
function clip(line: string, width: number): string {
  let visible = 0;
  let out = '';
  for (let i = 0; i < line.length; i++) {
    if (line[i] === '\u001b') {
      const end = line.indexOf('m', i);
      if (end !== -1) {
        out += line.slice(i, end + 1);
        i = end;
        continue;
      }
    }
    if (visible >= width - 1) break;
    out += line[i];
    visible++;
  }
  // A line cut inside a coloured span must not colour the next one.
  return out.includes('\u001b[') ? `${out}\u001b[0m` : out;
}
