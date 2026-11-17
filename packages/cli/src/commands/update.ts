/**
 * `cynos update [--check]`: install the latest cynos the way this one was installed.
 *
 *   detect   the install method from the running script's real path (install-method.ts)
 *   compare  this version with the registry's latest
 *   install  the matching global install of @averlon-ai/cynos@latest
 *   check    `cynos doctor --quick`, run by the new copy, so a broken update shows at once
 *
 * The scanner image is the docker runtime's, pinned by the engine: `doctor --runtime docker
 * --fix` pulls it.
 */
import { spawnSync } from 'node:child_process';
import { realpathSync } from 'node:fs';
import type { Command } from 'commander';
import { CLI_NAME, CLI_VERSION, PACKAGE_NAME, type Context } from '../context';
import { CliError, EXIT } from '../exit-codes';
import { withExamples } from '../help';
import { defaultRuntime } from '../settings';
import { detectInstall, npmGlobalPrefix } from '../update/install-method';
import { latestVersion, newerVersion } from '../update/notice';

export function registerUpdate(program: Command, ctx: Context): void {
  const command = program
    .command('update')
    .description('Update cynos to the latest version (npm, pnpm or bun global installs).')
    .option('--check', 'only say whether an update is available')
    .action(async (options: { check?: boolean }) => {
      process.exitCode = await updateCommand(ctx, options);
    });
  withExamples(command, [`${CLI_NAME} update --check`, `${CLI_NAME} update`]);
}

export function runningScript(): string {
  const script = process.argv[1] ?? '';
  try {
    return realpathSync(script);
  } catch {
    return script;
  }
}

async function updateCommand(ctx: Context, options: { check?: boolean }): Promise<number> {
  const { terminal } = ctx;
  const c = terminal.out;

  // 1. How this copy was installed, and the registry's latest.
  const install = detectInstall({ script: runningScript(), npmPrefix: npmGlobalPrefix });
  const latest = latestVersion();
  if (!latest)
    throw new CliError(
      'upstream',
      `The registry did not answer for ${PACKAGE_NAME}.`,
      `Check your network and npm registry configuration (https://registry.npmjs.org).`
    );
  const available = newerVersion(latest, CLI_VERSION);
  terminal.result(
    available
      ? `${c.yellow('⚠')} ${CLI_VERSION} installed; ${c.bold(latest)} is available (${install.method} install).`
      : `${c.green('✓')} ${CLI_VERSION} is the latest.`
  );
  if (options.check || !available) return EXIT.ok;

  // 2. The install, through the package manager that owns this copy.
  if (!install.command) {
    terminal.info(install.explanation ?? '');
    return EXIT.ok;
  }
  terminal.info(c.dim(`$ ${install.command.join(' ')}`));
  const [command, ...args] = install.command;
  const installed = spawnSync(command!, args, { stdio: 'inherit' });
  if (installed.status !== 0)
    throw new CliError(
      'upstream',
      `${install.command.join(' ')} failed (exit ${installed.status ?? 'signal'}).`
    );

  // 3. The new copy checks itself.
  terminal.info(c.dim(`$ ${CLI_NAME} doctor --quick`));
  const doctor = spawnSync(
    process.execPath,
    [runningScript(), 'doctor', '--quick', '--runtime', defaultRuntime(ctx.env)],
    {
      stdio: 'inherit',
    }
  );
  if (defaultRuntime(ctx.env) === 'docker')
    terminal.info(`Pull the new scanner image with \`${CLI_NAME} doctor --runtime docker --fix\`.`);
  return doctor.status === 0 ? EXIT.ok : EXIT.failure;
}
