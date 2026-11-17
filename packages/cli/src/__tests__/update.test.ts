import { describe, expect, test } from 'bun:test';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mockEngine } from './engine-mock';

mockEngine();
const { detectInstall } = await import('../update/install-method');
const { newerVersion, noticeAllowed, prepareNotice, readUpdateCache, updateCachePath } =
  await import('../update/notice');

const HOME = '/Users/dev';
const SCRIPT = 'node_modules/@averlon-ai/cynos/dist/cynos.mjs';

describe('detectInstall', () => {
  test('npm global: under <prefix>/lib/node_modules', () => {
    const install = detectInstall({
      script: `/usr/local/lib/${SCRIPT}`,
      home: HOME,
      npmPrefix: () => '/usr/local',
      platform: 'darwin',
    });
    expect(install).toEqual({
      method: 'npm',
      command: ['npm', 'install', '-g', '@averlon-ai/cynos@latest'],
    });
  });

  test('npm global under nvm', () => {
    const prefix = `${HOME}/.nvm/versions/node/v24.5.0`;
    expect(
      detectInstall({ script: `${prefix}/lib/${SCRIPT}`, home: HOME, npmPrefix: () => prefix })
        .method
    ).toBe('npm');
  });

  test('pnpm global', () => {
    const install = detectInstall({
      script: `${HOME}/Library/pnpm/global/5/.pnpm/x/${SCRIPT}`,
      home: HOME,
      npmPrefix: () => '/usr/local',
    });
    expect(install.method).toBe('pnpm');
    expect(install.command).toEqual(['pnpm', 'add', '-g', '@averlon-ai/cynos@latest']);
  });

  test('bun global', () => {
    const install = detectInstall({ script: `${HOME}/.bun/install/global/${SCRIPT}`, home: HOME });
    expect(install.method).toBe('bun');
    expect(install.command).toEqual(['bun', 'add', '-g', '@averlon-ai/cynos@latest']);
  });

  test('npx: no command, an explanation', () => {
    const install = detectInstall({
      script: `${HOME}/.npm/_npx/1a2b3c/${SCRIPT}`,
      home: HOME,
      npmPrefix: () => '/usr/local',
    });
    expect(install.method).toBe('npx');
    expect(install.command).toBeUndefined();
    expect(install.explanation).toContain('npx @averlon-ai/cynos@latest');
  });

  test("a project's node_modules or a checkout is unknown", () => {
    const install = detectInstall({
      script: `/work/app/${SCRIPT}`,
      home: HOME,
      npmPrefix: () => '/usr/local',
    });
    expect(install.method).toBe('unknown');
    expect(install.explanation).toContain('not a global install');
  });
});

describe('the update notice', () => {
  const tty = { stdoutIsTTY: true, stderrIsTTY: true };

  test('is off in CI, without a terminal, and when turned off', () => {
    expect(noticeAllowed({ env: {}, ...tty })).toBe(true);
    expect(noticeAllowed({ env: { CI: 'true' }, ...tty })).toBe(false);
    expect(noticeAllowed({ env: { NO_UPDATE_NOTIFIER: '1' }, ...tty })).toBe(false);
    expect(noticeAllowed({ env: { CYNOS_NO_UPDATE_NOTICE: '1' }, ...tty })).toBe(false);
    expect(noticeAllowed({ env: {}, stdoutIsTTY: false, stderrIsTTY: true })).toBe(false);
    expect(noticeAllowed({ env: {}, stdoutIsTTY: true, stderrIsTTY: false })).toBe(false);
  });

  test('starts one background check a day, and records it at once', () => {
    const cacheDir = mkdtempSync(join(tmpdir(), 'cynos-scan-update-'));
    const started: string[] = [];
    const startCheck = (dir: string): void => void started.push(dir);
    const now = 1_000_000_000_000;
    prepareNotice(cacheDir, { now, current: '0.1.0', startCheck });
    prepareNotice(cacheDir, { now: now + 60_000, current: '0.1.0', startCheck });
    expect(started).toHaveLength(1);
    expect(readUpdateCache(cacheDir).checkedAt).toBe(now);
    prepareNotice(cacheDir, { now: now + 25 * 3600_000, current: '0.1.0', startCheck });
    expect(started).toHaveLength(2);
  });

  test('prints a newer version from an earlier check, at most once a day', () => {
    const cacheDir = mkdtempSync(join(tmpdir(), 'cynos-scan-update-'));
    const now = 1_000_000_000_000;
    writeFileSync(updateCachePath(cacheDir), JSON.stringify({ checkedAt: now, latest: '0.2.0' }));
    const options = { now: now + 1000, current: '0.1.0', startCheck: () => {} };
    expect(prepareNotice(cacheDir, options)).toBe(
      'Update available 0.1.0 → 0.2.0 · run `cynos update`'
    );
    expect(prepareNotice(cacheDir, { ...options, now: now + 2000 })).toBeUndefined();
    expect(prepareNotice(cacheDir, { ...options, now: now + 25 * 3600_000 })).toContain('0.2.0');
  });

  test('says nothing when this is the latest', () => {
    const cacheDir = mkdtempSync(join(tmpdir(), 'cynos-scan-update-'));
    writeFileSync(
      updateCachePath(cacheDir),
      JSON.stringify({ checkedAt: Date.now(), latest: '0.1.0' })
    );
    expect(prepareNotice(cacheDir, { current: '0.1.0', startCheck: () => {} })).toBeUndefined();
  });

  test('compares versions', () => {
    expect(newerVersion('0.2.0', '0.1.9')).toBe(true);
    expect(newerVersion('0.10.0', '0.9.0')).toBe(true);
    expect(newerVersion('1.0.0', '1.0.0')).toBe(false);
    expect(newerVersion('1.0.0', '1.0.0-rc.1')).toBe(true);
    expect(newerVersion('1.0.0-rc.1', '1.0.0')).toBe(false);
  });
});
