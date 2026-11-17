import { describe, expect, test } from 'bun:test';
import { mockEngine } from './engine-mock';

mockEngine();
const { LiveRenderer } = await import('../progress/renderers');
const { PhaseTimings } = await import('../progress/timings');
const { createTerminal } = await import('../terminal');

/** A live view writing to a recorded stderr. */
function liveView() {
  const written: string[] = [];
  const stderr = { write: (text: string) => written.push(text), columns: 100, isTTY: true };
  const terminal = createTerminal({
    color: false,
    env: {},
    stderr: stderr as unknown as NodeJS.WriteStream,
  });
  const timings = new PhaseTimings(() => 0);
  const renderer = new LiveRenderer(terminal, timings, 'full scan of app');
  return { renderer, timings, written };
}

describe('the live view while upstream has the terminal', () => {
  test('writes nothing between the handoff and the end of the scan phase', () => {
    const { renderer, timings, written } = liveView();
    renderer.start();
    renderer.event({ type: 'handoff', phase: 'scan' });
    const atHandoff = written.length;

    // upstream's dashboard, then its question after the scan: none of ours may land there.
    renderer.event({ type: 'heartbeat', phase: 'scan', elapsedSeconds: 600 });
    renderer.event({ type: 'upstream', message: 'Running scan: discovery' });
    renderer.log('Security scan is still running; elapsed: 10m.');
    renderer.warn('the knowledge-base cache was not saved');
    expect(written.length).toBe(atHandoff);

    // The end of the scan phase gives the terminal back: the held warning, then our lines.
    const end = { type: 'phase', phase: 'scan', status: 'end', seconds: 553 } as const;
    timings.record(end);
    renderer.event(end);
    const after = written.slice(atHandoff).join('');
    expect(after).toContain('⚠ the knowledge-base cache was not saved');
    expect(after).toContain('scan');
    expect(after).not.toContain('running for');
    renderer.close();
  });

  test('a scan that ends without its phase event still prints the held warnings on close', () => {
    const { renderer, written } = liveView();
    renderer.start();
    renderer.event({ type: 'handoff', phase: 'scan' });
    renderer.warn('upstream exited early');
    renderer.close();
    expect(written.join('')).toContain('⚠ upstream exited early');
  });
});
