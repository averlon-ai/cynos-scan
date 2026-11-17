/**
 * Where cynos runs: Node.js in upstream's own range (^22.13 || ^24 || ^26), on macOS or Linux.
 *
 * The check runs before anything else is loaded, because on an older Node the failure would
 * otherwise surface as an obscure syntax or API error deep inside upstream. Bun is refused too:
 * upstream and Codex's sandbox launcher are only tested under Node. Windows is refused because
 * no scan can start there: the native runtime's sandbox check runs /usr/bin/true, the knowledge
 * base's code graph has no Windows build, and Docker Desktop refuses the docker runtime's seccomp
 * profile. WSL 2 is Linux, and runs it.
 */

export const SUPPORTED_NODE = '^22.13 || ^24 || ^26';

/** Why this runtime cannot run cynos, or undefined when it can. */
export function unsupportedRuntime(
  version: string = process.versions.node,
  bun: string | undefined = process.versions['bun'],
  platform: NodeJS.Platform = process.platform
): string | undefined {
  if (platform === 'win32')
    return [
      'cynos runs on macOS and Linux, not Windows.',
      'On Windows, install and run it inside WSL 2 (for example Ubuntu): https://learn.microsoft.com/windows/wsl/install',
    ].join('\n');
  if (bun)
    return `cynos runs on Node.js, not Bun (${bun}). Run it with node: node $(which cynos) ...`;
  const [major = 0, minor = 0] = version.split('.').map(Number);
  const supported = (major === 22 && minor >= 13) || major === 24 || major === 26;
  if (supported) return undefined;
  return [
    `cynos needs Node.js 22.13 or later in 22.x, 24.x or 26.x; this is Node.js v${version}.`,
    'Install a supported version (for example `nvm install 24`), then reinstall:',
    '  npm i -g @averlon-ai/cynos',
  ].join('\n');
}
