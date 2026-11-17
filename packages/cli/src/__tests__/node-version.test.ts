import { describe, expect, test } from 'bun:test';
import { unsupportedRuntime } from '../node-version';

describe('where cynos runs', () => {
  test('a supported Node on macOS or Linux runs it', () => {
    expect(unsupportedRuntime('24.5.0', '', 'darwin')).toBeUndefined();
    expect(unsupportedRuntime('22.13.0', '', 'linux')).toBeUndefined();
  });

  test('Windows is refused before anything else, with WSL 2 as the way to run it', () => {
    const problem = unsupportedRuntime('24.5.0', '', 'win32');
    expect(problem).toContain('cynos runs on macOS and Linux, not Windows.');
    expect(problem).toContain('WSL 2');
  });

  test('an older Node and Bun are refused, as before', () => {
    expect(unsupportedRuntime('20.20.2', '', 'darwin')).toContain('needs Node.js 22.13');
    expect(unsupportedRuntime('24.5.0', '1.3.0', 'linux')).toContain('not Bun');
  });
});
