import { describe, it, expect } from 'bun:test';
import { mkdtempSync, realpathSync, statSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { createScanDir, engineAssets, expandHome, resolveStateDir, safePrefix } from '../layout';

describe('resolveStateDir', () => {
  it("follows upstream's rule: CODEX_SECURITY_STATE_DIR, else $CODEX_HOME/state/plugins/codex-security", () => {
    expect(resolveStateDir({ CODEX_SECURITY_STATE_DIR: '/srv/state', CODEX_HOME: '/x' })).toBe(
      '/srv/state'
    );
    expect(resolveStateDir({ CODEX_HOME: '/srv/codex' })).toBe(
      '/srv/codex/state/plugins/codex-security'
    );
    expect(resolveStateDir({})).toBe(
      join(homedir(), '.codex', 'state', 'plugins', 'codex-security')
    );
  });

  it('expands ~ against HOME, and treats a blank setting as unset, as upstream does', () => {
    expect(resolveStateDir({ HOME: '/home/u', CODEX_SECURITY_STATE_DIR: '~/s' })).toBe('/home/u/s');
    expect(resolveStateDir({ HOME: '/home/u', CODEX_HOME: '~' })).toBe(
      '/home/u/state/plugins/codex-security'
    );
    expect(resolveStateDir({ CODEX_SECURITY_STATE_DIR: '  ', CODEX_HOME: '/c' })).toBe(
      '/c/state/plugins/codex-security'
    );
    expect(expandHome('~x', { HOME: '/h' })).toBe('~x');
  });
});

describe('createScanDir', () => {
  it('creates the scan dir where upstream would, private to this user', () => {
    const state = join(realpathSync(mkdtempSync(join(tmpdir(), 'state-'))), 'state');
    const scanDir = createScanDir(state, '/work/my repo');
    expect(dirname(scanDir)).toBe(join(state, 'scans', 'my-repo'));
    expect(basename(scanDir)).toMatch(/^codex-security-my-repo-[A-Za-z0-9]{6}$/);
    for (const dir of [state, join(state, 'scans'), dirname(scanDir), scanDir])
      expect(statSync(dir).mode & 0o777).toBe(0o700);
    // A second scan of the same repository gets a directory of its own.
    expect(createScanDir(state, '/work/my repo')).not.toBe(scanDir);
  });

  it("names a repository as upstream's safePrefix does", () => {
    expect(safePrefix('/a/b/c d$e')).toBe('c-d-e');
    expect(safePrefix('/')).toBe('repository');
  });
});

describe('engineAssets', () => {
  it("is the package's assets directory for unbundled use", () => {
    expect(
      statSync(join(engineAssets(), 'scan-prompt', 'references', 'core-scan.md')).isFile()
    ).toBe(true);
  });
});
