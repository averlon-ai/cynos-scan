import { describe, it, expect } from 'bun:test';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { ENGINE_VERSION } from '../constants';
import {
  nodeExecutable,
  resolveUpstream,
  upstreamCommand,
  UPSTREAM_PIN,
  verifyUpstream,
} from '../upstream';

const PLATFORM = `${process.platform === 'android' ? 'linux' : process.platform}-${process.arch}`;

/** A node_modules tree laid out as npm installs upstream: its exports hide package.json. */
function fixture(
  options: { version?: string; codexVersion?: string; platform?: boolean; nested?: boolean } = {}
): { root: string; from: string } {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'upstream-')));
  const from = join(root, 'app', 'dist');
  mkdirSync(from, { recursive: true });
  const modules = options.nested ? join(root, 'app', 'node_modules') : join(root, 'node_modules');
  const pkg = (name: string, manifest: Record<string, unknown>): string => {
    const dir = join(modules, ...name.split('/'));
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name, ...manifest }));
    return dir;
  };
  const upstream = pkg('@openai/codex-security', {
    version: options.version ?? UPSTREAM_PIN.version,
    exports: { '.': './dist/index.js' },
    bin: { 'codex-security': './bin/codex-security.mjs' },
  });
  mkdirSync(join(upstream, 'bin'));
  writeFileSync(join(upstream, 'bin', 'codex-security.mjs'), '');
  pkg('@openai/codex', { version: options.codexVersion ?? UPSTREAM_PIN.codexVersion });
  if (options.platform !== false) {
    const platform = pkg(`@openai/codex-${PLATFORM}`, {
      version: `${UPSTREAM_PIN.codexVersion}-x`,
    });
    mkdirSync(join(platform, 'vendor', 'some-triple', 'bin'), { recursive: true });
    mkdirSync(join(platform, 'vendor', 'some-triple', 'codex-path'));
    writeFileSync(join(platform, 'vendor', 'some-triple', 'bin', 'codex'), '#!/bin/sh\n');
    chmodSync(join(platform, 'vendor', 'some-triple', 'bin', 'codex'), 0o755);
  }
  return { root, from };
}

describe('resolveUpstream', () => {
  it("finds upstream's root past its exports, and Codex's platform binary and tools", () => {
    const { root, from } = fixture();
    const upstream = resolveUpstream(from);
    const base = join(root, 'node_modules', '@openai');
    expect(upstream.root).toBe(join(base, 'codex-security'));
    expect(upstream.bin).toBe(join(base, 'codex-security', 'bin', 'codex-security.mjs'));
    expect(upstream.version).toBe(UPSTREAM_PIN.version);
    expect(upstream.codex).toEqual({
      executable: join(base, `codex-${PLATFORM}`, 'vendor', 'some-triple', 'bin', 'codex'),
      toolsDir: join(base, `codex-${PLATFORM}`, 'vendor', 'some-triple', 'codex-path'),
      version: UPSTREAM_PIN.codexVersion,
    });
    expect(() => verifyUpstream(upstream)).not.toThrow();
  });

  it('finds an install beside a bundled host, as in <global>/node_modules/<cli>/node_modules', () => {
    const { root, from } = fixture({ nested: true });
    expect(resolveUpstream(from).root).toBe(
      join(root, 'app', 'node_modules', '@openai', 'codex-security')
    );
  });

  it('says what is missing: upstream itself, or the platform package', () => {
    const empty = mkdtempSync(join(tmpdir(), 'no-upstream-'));
    expect(() => resolveUpstream(empty)).toThrow(/is not installed/);
    const { from } = fixture({ platform: false });
    expect(() => resolveUpstream(from)).toThrow(/platform package @openai\/codex-/);
  });

  it('refuses another upstream or another Codex', () => {
    expect(() => verifyUpstream(resolveUpstream(fixture({ version: '999.0.0' }).from))).toThrow(
      `is 999.0.0, not the pinned ${UPSTREAM_PIN.version}`
    );
    expect(() =>
      verifyUpstream(resolveUpstream(fixture({ codexVersion: '999.0.0' }).from))
    ).toThrow(`is 999.0.0, not the pinned ${UPSTREAM_PIN.codexVersion}`);
  });

  it('resolves the pinned upstream installed beside the engine', () => {
    const upstream = resolveUpstream(resolve(import.meta.dir, '..'));
    expect(() => verifyUpstream(upstream)).not.toThrow();
    expect(upstream.bin.endsWith('bin/codex-security.mjs')).toBe(true);
    expect(upstream.codex.executable).toMatch(/vendor\/[^/]+\/bin\/codex$/);
  });
});

describe('upstreamCommand', () => {
  it("runs upstream's bin on Node, with the arguments after it", () => {
    const upstream = resolveUpstream(fixture().from);
    expect(upstreamCommand(['scan', '.'], upstream)).toEqual([
      nodeExecutable(),
      upstream.bin,
      'scan',
      '.',
    ]);
    // Bun runs the tests; upstream still gets a Node.
    expect(nodeExecutable()).toMatch(/node$/);
  });
});

describe('ENGINE_VERSION', () => {
  it("is the package's version", () => {
    const manifest = JSON.parse(
      readFileSync(resolve(import.meta.dir, '../../package.json'), 'utf8')
    );
    expect(ENGINE_VERSION).toBe(manifest.version);
    expect(manifest.dependencies['@openai/codex-security']).toBe(UPSTREAM_PIN.version);
  });
});
