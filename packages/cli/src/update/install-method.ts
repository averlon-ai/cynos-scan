/**
 * How this copy of cynos was installed, so `update` runs the matching install command.
 *
 * Each package manager keeps global packages in its own place, and an update through the wrong
 * one installs a second copy that the first keeps shadowing on PATH. The running script's real
 * path (through the bin symlink) says which one it is:
 *
 *   …/_npx/…                          npx: a cache, nothing to update in place
 *   ~/.bun/install/global/…           bun add -g
 *   …/pnpm/global/…                   pnpm add -g
 *   <npm prefix>/lib/node_modules/…   npm install -g (node_modules/ under the prefix on Windows)
 *   anything else                     a project's node_modules or a source checkout
 */
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { join, sep } from 'node:path';
import { PACKAGE_NAME } from '../context';

export type InstallMethod = 'npm' | 'pnpm' | 'bun' | 'npx' | 'unknown';

export interface Install {
  method: InstallMethod;
  /** The command that installs the latest version, or undefined when there is none to run. */
  command?: string[];
  /** Why there is no command, or what the user should do instead. */
  explanation?: string;
}

export interface InstallProbe {
  /** The real path of the running script. */
  script: string;
  home?: string;
  /** `npm prefix -g`; looked up only when nothing else matched. */
  npmPrefix?: () => string | undefined;
  platform?: NodeJS.Platform;
}

export function npmGlobalPrefix(): string | undefined {
  const run = spawnSync('npm', ['prefix', '-g'], { encoding: 'utf8', timeout: 15_000 });
  return run.status === 0 ? run.stdout.trim() || undefined : undefined;
}

export function detectInstall(probe: InstallProbe): Install {
  const { script, home = homedir(), platform = process.platform } = probe;
  const latest = `${PACKAGE_NAME}@latest`;
  const normalized = script.split(sep).join('/');
  if (normalized.includes('/_npx/'))
    return {
      method: 'npx',
      explanation: `npx runs a cached copy. Run the newest with \`npx ${latest} …\`, or install it for good: \`npm i -g ${PACKAGE_NAME}\`.`,
    };
  if (normalized.startsWith(`${join(home, '.bun', 'install', 'global').split(sep).join('/')}/`))
    return { method: 'bun', command: ['bun', 'add', '-g', latest] };
  if (/\/pnpm\/global\//.test(normalized) || /\/\.pnpm-global\//.test(normalized))
    return { method: 'pnpm', command: ['pnpm', 'add', '-g', latest] };
  const prefix = probe.npmPrefix?.();
  if (prefix) {
    const globalModules = (
      platform === 'win32' ? join(prefix, 'node_modules') : join(prefix, 'lib', 'node_modules')
    )
      .split(sep)
      .join('/');
    if (normalized.startsWith(`${globalModules}/`))
      return { method: 'npm', command: ['npm', 'install', '-g', latest] };
  }
  return {
    method: 'unknown',
    explanation: `This copy is not a global install (${script}): update it where it was installed, for example \`npm i ${latest}\` in that project.`,
  };
}
