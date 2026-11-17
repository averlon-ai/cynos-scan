import { describe, it, expect } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ProcessRegistry, spawnTracked, stopProcess, stopProcesses, pause } from '../processes';

/** Whether a pid (or, negative, a process group) still exists. */
function alive(target: number): boolean {
  try {
    process.kill(target, 0);
    return true;
  } catch {
    return false;
  }
}

const exited = (child: ReturnType<typeof spawnTracked>): Promise<void> =>
  new Promise(resolve =>
    child.exitCode !== null || child.signalCode ? resolve() : child.once('exit', () => resolve())
  );

describe('pause', () => {
  it('ends when the run is stopped, and at once when it was stopped already', async () => {
    const controller = new AbortController();
    setTimeout(() => controller.abort('stopped'), 20);
    const started = Date.now();
    await pause(60_000, controller.signal);
    await pause(60_000, controller.signal);
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it('leaves no timer behind a stop to keep the process alive', () => {
    // A process whose only work is a stopped minute-long pause exits as soon as it stops.
    const script = `import { pause } from ${JSON.stringify(join(import.meta.dir, '../processes.ts'))};
      const controller = new AbortController();
      setTimeout(() => controller.abort('stopped'), 20);
      await pause(60_000, controller.signal);`;
    // Killed (status null) if it is still alive after 3 s: the pause's timer would hold it a minute.
    expect(spawnSync(process.execPath, ['-e', script], { timeout: 3_000 }).status).toBe(0);
  });
});

describe('spawnTracked', () => {
  it('starts a process group of its own and keeps it in the registry until it exits', async () => {
    const registry = new ProcessRegistry();
    const child = spawnTracked(['sh', '-c', 'exit 0'], {
      name: 'quick',
      registry,
      env: { PATH: process.env['PATH'] ?? '' },
      stdio: 'ignore',
    });
    expect(registry.get('quick')).toEqual({ name: 'quick', pid: child.pid as number, group: true });
    await exited(child);
    expect(registry.get('quick')).toBeUndefined();
  });

  it('keeps a child that reads the terminal in this process group', async () => {
    const registry = new ProcessRegistry();
    const child = spawnTracked(['sh', '-c', 'exit 0'], {
      name: 'dashboard',
      registry,
      env: {},
      stdio: 'ignore',
      detached: false,
    });
    expect(registry.get('dashboard')?.group).toBe(false);
    await exited(child);
  });
});

describe('stopProcess', () => {
  it('stops the whole group: the child and what it started', async () => {
    const registry = new ProcessRegistry();
    // The shell starts a grandchild and waits for it, as upstream starts Codex.
    const child = spawnTracked(['sh', '-c', 'sleep 30 & wait'], {
      name: 'scan',
      registry,
      env: { PATH: process.env['PATH'] ?? '' },
      stdio: 'ignore',
    });
    const pid = child.pid as number;
    await new Promise(resolve => setTimeout(resolve, 200));
    expect(alive(-pid)).toBe(true);
    await stopProcesses(registry, 2_000);
    await exited(child);
    // The group is gone: no member of it is left.
    expect(alive(-pid)).toBe(false);
  });

  it('kills a group that ignores SIGTERM once the grace period is over', async () => {
    const child = spawnTracked(['sh', '-c', "trap '' TERM; sleep 30 & wait; sleep 30"], {
      name: 'stubborn',
      env: { PATH: process.env['PATH'] ?? '' },
      stdio: 'ignore',
    });
    const pid = child.pid as number;
    await new Promise(resolve => setTimeout(resolve, 200));
    const started = Date.now();
    await stopProcess({ name: 'stubborn', pid, group: true }, 500);
    await exited(child);
    expect(Date.now() - started).toBeGreaterThanOrEqual(450);
    expect(child.signalCode).toBe('SIGKILL');
  });

  it('does nothing for a process that is gone', async () => {
    await expect(
      stopProcess({ name: 'gone', pid: 2 ** 22 + 12345, group: true }, 100)
    ).resolves.toBeUndefined();
  });
});

describe('ProcessRegistry', () => {
  it('is kept in a file another process can load, and stop from', async () => {
    const file = join(mkdtempSync(join(tmpdir(), 'registry-')), 'processes.json');
    const registry = new ProcessRegistry(file);
    const child = spawnTracked(['sleep', '30'], {
      name: 'cs-run',
      registry,
      env: { PATH: process.env['PATH'] ?? '' },
      stdio: 'ignore',
    });
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual([
      { name: 'cs-run', pid: child.pid, group: true },
    ]);
    await stopProcesses(ProcessRegistry.load(file), 2_000);
    await exited(child);
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual([]);
    expect(ProcessRegistry.load(join(file, 'none')).list()).toEqual([]);
  });

  it('lets only the process that holds a name remove it', () => {
    const registry = new ProcessRegistry();
    registry.add({ name: 'x', pid: 2, group: true });
    registry.remove('x', 1);
    expect(registry.get('x')?.pid).toBe(2);
  });
});
