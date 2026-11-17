/**
 * External text (the scanner's diagnostics, model output) made safe to print in a CI log: GitHub
 * runs a log line that starts with `::` as a command, and terminal and bidirectional control
 * characters can hide what a line says.
 */

/** Strips control and bidirectional-override characters, and truncates. */
export function plain(value: string, limit?: number): string {
  const text = value.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f‪-‮⁦-⁩]/g, '');
  return limit === undefined ? text : text.slice(0, limit);
}

/**
 * Lines of external text (the scanner's diagnostics) that are safe to log: upstream's
 * safeLogLines. Each line is prefixed, so none starts a `::` runner command, legacy `##[`
 * commands, which match anywhere, are escaped, and terminal and bidirectional control
 * characters are removed.
 */
export function safeLogLines(value: string): string[] {
  const clean = value
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, '')
    .replace(/[\u2028\u2029]/g, '\n')
    .replace(/##\[/g, '##\\[');
  return clean
    .split('\n')
    .filter(Boolean)
    .map(line => `[codex-security] ${line}`);
}
