import { describe, expect, it } from 'bun:test';
import { bumpReport, rewritePins, type Pin } from '../upstream-bump';

const FROM: Pin = {
  version: '1.2.0',
  codexVersion: '0.9.0-alpha.1',
  tarballSha256: 'a'.repeat(64),
};
const TO: Pin = { version: '1.3.0', codexVersion: '0.9.5', tarballSha256: 'b'.repeat(64) };

describe('rewritePins', () => {
  it('replaces every pinned version that a prefix names', () => {
    const text = [
      '"@openai/codex-security": "1.2.0"',
      `ARG CODEX_SECURITY_VERSION=1.2.0`,
      `ARG CODEX_SECURITY_SHA256=${'a'.repeat(64)}`,
      '/** docker/ at tag npm-v1.2.0, in cynos-scan-scanner:1.2.0 (codex-security 1.2.0) */',
      "throw new Error(`not Codex rust-v0.9.0-alpha.1's prompt.md`);",
    ].join('\n');
    expect(rewritePins(text, FROM, TO).split('\n')).toEqual([
      '"@openai/codex-security": "1.3.0"',
      `ARG CODEX_SECURITY_VERSION=1.3.0`,
      `ARG CODEX_SECURITY_SHA256=${'b'.repeat(64)}`,
      '/** docker/ at tag npm-v1.3.0, in cynos-scan-scanner:1.3.0 (codex-security 1.3.0) */',
      "throw new Error(`not Codex rust-v0.9.5's prompt.md`);",
    ]);
  });

  it('leaves a bare version alone: it may be a version of something else', () => {
    const text = "writeFileSync(cache, JSON.stringify({ latest: '1.2.0' }));";
    expect(rewritePins(text, FROM, TO)).toBe(text);
  });
});

describe('bumpReport', () => {
  it('links both releases and names each vendored file that changed or went missing', () => {
    const report = bumpReport(
      FROM,
      TO,
      [
        { path: 'assets/a.json', source: 'https://example.invalid/a', status: 'changed' },
        { path: 'assets/b.md', source: 'https://example.invalid/b', status: 'missing at source' },
      ],
      ['packages/engine/package.json']
    );
    expect(report).toContain('from 1.2.0 to 1.3.0');
    expect(report).toContain('/compare/npm-v1.2.0...npm-v1.3.0');
    expect(report).toContain('/compare/rust-v0.9.0-alpha.1...rust-v0.9.5');
    expect(report).toContain('- `assets/a.json`: changed');
    expect(report).toContain('- `assets/b.md`: missing at source');
  });
});
