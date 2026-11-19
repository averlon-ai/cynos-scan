import { describe, expect, it } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const SCRIPT = resolve(import.meta.dir, '../../../../scripts/assert-image-tag-absent.sh');
const REFERENCE = 'ghcr.io/example/scanner:v0.3.0';

function inspect(output: string, status: number) {
  const directory = mkdtempSync(join(tmpdir(), 'release-image-'));
  try {
    writeFileSync(
      join(directory, 'docker'),
      '#!/bin/sh\nprintf "%s\\n" "$INSPECT_OUTPUT" >&2\nexit "$INSPECT_STATUS"\n',
      { mode: 0o700 }
    );
    return spawnSync('bash', [SCRIPT, REFERENCE], {
      encoding: 'utf8',
      env: {
        ...process.env,
        PATH: `${directory}:${process.env['PATH'] ?? ''}`,
        INSPECT_OUTPUT: output,
        INSPECT_STATUS: String(status),
      },
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

describe('release image immutability', () => {
  it('refuses an existing tag', () => {
    const result = inspect('Name: ' + REFERENCE, 0);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('already exists');
  });

  it.each([`${REFERENCE}: not found`, `ERROR: ${REFERENCE}: not found`])(
    'allows only the explicit missing manifest: %s',
    output => expect(inspect(output, 1).status).toBe(0)
  );

  it.each([
    'ERROR: unauthorized: authentication required',
    'ERROR: denied: permission denied',
    'ERROR: 429 Too Many Requests',
    'ERROR: 500 Internal Server Error',
    'ERROR: i/o timeout',
    'ERROR: ghcr.io/example/other:v0.3.0: not found',
    'docker: command not found',
    `ERROR: ${REFERENCE}: not found\nERROR: connection reset`,
    '',
  ])('refuses inspection failures: %s', output => {
    const result = inspect(output, 1);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('refusing to publish');
  });
});
