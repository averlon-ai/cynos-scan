/**
 * `cynos doctor`: will my next scan work, and if not, what do I do about it?
 *
 * What a scan needs differs by runtime: the native runtime needs Python, git and Codex's OS
 * sandbox on the host; the docker runtime needs a daemon, the seccomp profile and the image. So
 * doctor checks the runtime the next `scan` would use (--runtime, else CYNOS_SCAN_RUNTIME, else
 * native), or both with --runtime all. The checks themselves are the engine's (checkHost, the
 * same ones the scan's preflight runs, so the two can never disagree); the CLI adds what only
 * an installed CLI has:
 *
 *   login             a cynos key, the only one a scan needs
 *   update            whether a newer cynos is published
 *
 * Output is grouped (common, native, docker) with ✓ / ⚠ / ✗ and the fix for each problem.
 * --fix runs the engine's fixHost for the selected runtime, asking before anything that needs
 * sudo. Exit 0 when nothing failed, else 2.
 */
import type { Command } from 'commander';
import { cynosBaseUrl, cynosKey } from '../auth/keys';
import {
  CLI_NAME,
  CLI_VERSION,
  defaultModel,
  engineBaseUrl,
  PACKAGE_NAME,
  type Context,
} from '../context';
import {
  assetsDir,
  engine,
  EngineUnavailable,
  hasEngine,
  RUNTIMES,
  type CheckHostOptions,
  type HostCheck,
  type Runtime,
} from '../engine';
import { CliError, EXIT } from '../exit-codes';
import { withExamples } from '../help';
import { confirm } from '../prompts';
import { defaultRuntime, parseRuntime } from '../settings';
import { SYMBOLS, type Terminal } from '../terminal';
import { latestVersion, newerVersion, readUpdateCache } from '../update/notice';

export interface DoctorOptions {
  runtime?: string;
  fix?: boolean;
  json?: boolean;
  quick?: boolean;
  yes?: boolean;
}

export function registerDoctor(program: Command, ctx: Context): void {
  const command = program
    .command('doctor')
    .description('Check that this machine can run a scan, with a fix for every problem.')
    .option('--runtime <runtime>', 'native, docker or all (default: the runtime scan would use)')
    .option('--fix', 'fix what can be fixed (asks before sudo)')
    .option('--json', 'print the checks as JSON')
    .option('--quick', 'skip the slow checks (network, sandbox probe)')
    .option('--yes', 'answer yes to --fix prompts')
    .action(async (options: DoctorOptions) => {
      process.exitCode = await doctorCommand(ctx, options);
    });
  withExamples(command, [
    `${CLI_NAME} doctor`,
    `${CLI_NAME} doctor --runtime all`,
    `${CLI_NAME} doctor --runtime docker --fix`,
    `${CLI_NAME} doctor --json`,
  ]);
}

export async function doctorCommand(ctx: Context, options: DoctorOptions): Promise<number> {
  const { terminal } = ctx;
  if (options.json) ctx.output = 'json';
  const runtimes = selectedRuntimes(options.runtime, ctx.env);

  // 1. The checks: the engine's for each runtime, then the CLI's own.
  let checks = await collectChecks(ctx, runtimes, options);

  // 2. --fix: each failing or warning check with a fix, then the checks again.
  if (options.fix) {
    await fixChecks(ctx, checks, runtimes, options);
    checks = await collectChecks(ctx, runtimes, options);
  }

  // 3. The report, and the exit code: any fail is a 2.
  const failed = checks.some(check => check.status === 'fail');
  if (options.json) terminal.json({ ok: !failed, runtimes, checks });
  else terminal.result(renderChecks(terminal, checks, runtimes));
  return failed ? EXIT.failure : EXIT.ok;
}

export function selectedRuntimes(option: string | undefined, env: NodeJS.ProcessEnv): Runtime[] {
  if (option === 'all') return [...RUNTIMES];
  return [option ? parseRuntime(option) : defaultRuntime(env)];
}

/** The engine's checks for each runtime (common ones once), then the CLI's. */
export async function collectChecks(
  ctx: Context,
  runtimes: Runtime[],
  options: Pick<DoctorOptions, 'quick'>
): Promise<HostCheck[]> {
  const seen = new Set<string>();
  const checks: HostCheck[] = [];
  for (const runtime of runtimes) {
    for (const check of await engineChecks(ctx, runtime, options)) {
      if (check.group === 'common' && seen.has(check.id)) continue;
      seen.add(check.id);
      checks.push(check);
    }
  }
  checks.push(loginCheck(ctx));
  checks.push(updateCheck(ctx, Boolean(options.quick)));
  return checks;
}

function hostOptions(
  ctx: Context,
  runtime: Runtime,
  options: Pick<DoctorOptions, 'quick'>
): CheckHostOptions {
  const cynos = cynosKey(ctx.envKeys.cynos, ctx.credentials);
  return {
    scope: 'doctor',
    runtime,
    assets: assetsDir(),
    project: process.cwd(),
    ...(hasEngine('resolveStateDir') ? { stateDir: engine().resolveStateDir(ctx.env) } : {}),
    ...(cynos ? { cynosKey: cynos.value } : {}),
    baseUrl: cynosBaseUrl(ctx.env, engineBaseUrl()),
    model: defaultModel(ctx.env),
    quick: Boolean(options.quick),
  };
}

/** checkHost for one runtime; an engine without it, or a check that throws, is a fail. */
async function engineChecks(
  ctx: Context,
  runtime: Runtime,
  options: Pick<DoctorOptions, 'quick'>
): Promise<HostCheck[]> {
  if (!hasEngine('checkHost'))
    return [
      {
        id: 'engine',
        group: 'common',
        status: 'fail',
        title: 'Scan engine',
        detail: new EngineUnavailable('checkHost').message,
      },
    ];
  try {
    return await engine().checkHost(hostOptions(ctx, runtime, options));
  } catch (error) {
    return [
      {
        id: `host-check-${runtime}`,
        group: runtime,
        status: 'fail',
        title: `${runtime} runtime checks`,
        detail: `the checks could not run: ${(error as Error).message}`,
      },
    ];
  }
}

function loginCheck(ctx: Context): HostCheck {
  const cynos = cynosKey(ctx.envKeys.cynos, ctx.credentials);
  if (!cynos)
    return {
      id: 'login',
      group: 'common',
      status: 'warn',
      title: 'Login',
      detail: 'no cynos key (only --dry-run scans work)',
      fix: `${CLI_NAME} login`,
    };
  return {
    id: 'login',
    group: 'common',
    status: 'ok',
    title: 'Login',
    detail: `cynos key from ${cynos.source}`,
  };
}

/** A newer version: the update cache's answer, or the registry's with a full check. */
function updateCheck(ctx: Context, quick: boolean): HostCheck {
  const base = { id: 'update', group: 'common' as const, title: 'cynos version' };
  const latest = quick
    ? readUpdateCache(ctx.cacheDir).latest
    : (latestVersion() ?? readUpdateCache(ctx.cacheDir).latest);
  if (!latest)
    return {
      ...base,
      status: 'ok',
      detail: `${CLI_VERSION} (the registry was not asked or not reachable)`,
    };
  if (newerVersion(latest, CLI_VERSION))
    return {
      ...base,
      status: 'warn',
      detail: `${CLI_VERSION}; ${latest} is available`,
      fix: `${CLI_NAME} update`,
    };
  return { ...base, status: 'ok', detail: `${CLI_VERSION}, the latest ${PACKAGE_NAME}` };
}

/** The checks the engine's fixHost repairs, when the engine does not list them itself. */
const FIXABLE = ['state-dir', 'code-graph', 'docker-image', 'docker-apparmor'];

/** A fix that runs sudo: loading an AppArmor profile, or one whose fix text says so. */
function needsSudo(check: HostCheck): boolean {
  return /apparmor/.test(check.id) || /\bsudo\b/.test(check.fix ?? '');
}

/**
 * Runs fixHost for each failing or warning check it can repair, in the selected runtimes. A fix
 * that needs sudo asks first (or takes --yes); the rest keep their fix hint for the user.
 */
async function fixChecks(
  ctx: Context,
  checks: HostCheck[],
  runtimes: Runtime[],
  options: DoctorOptions
): Promise<void> {
  const { terminal } = ctx;
  if (!hasEngine('fixHost')) throw new EngineUnavailable('fixHost');
  const fixable = hasEngine('FIXABLE_CHECKS') ? engine().FIXABLE_CHECKS : FIXABLE;
  for (const check of checks) {
    if (check.status === 'ok' || !fixable.includes(check.id)) continue;
    const runtime: Runtime = check.group === 'common' ? runtimes[0]! : check.group;
    if (!runtimes.includes(runtime)) continue;
    const allowSudo =
      needsSudo(check) &&
      (await confirm(
        terminal,
        `${check.title} needs sudo to fix (${check.fix ?? check.id}). Run it?`,
        {
          ...(options.yes ? { yes: true } : {}),
          otherwise: 'Pass --yes to allow sudo, or run the fix yourself.',
        }
      ));
    if (needsSudo(check) && !allowSudo) {
      terminal.info(`${terminal.c.dim(SYMBOLS.skip)} skipped: ${check.title}`);
      continue;
    }
    terminal.info(`${terminal.c.cyan(SYMBOLS.arrow)} fixing: ${check.title}`);
    try {
      await engine().fixHost(check.id, { ...hostOptions(ctx, runtime, options), allowSudo });
    } catch (error) {
      if (error instanceof CliError) throw error;
      terminal.warn(`${check.title} could not be fixed: ${(error as Error).message}`);
    }
  }
}

const GROUP_TITLES: Record<HostCheck['group'], string> = {
  common: 'Common',
  native: 'Native runtime',
  docker: 'Docker runtime',
};

/** The checks as people read them: by group, a mark per check, the fix under each problem. */
export function renderChecks(terminal: Terminal, checks: HostCheck[], runtimes: Runtime[]): string {
  const c = terminal.out;
  const mark = { ok: c.green(SYMBOLS.ok), warn: c.yellow(SYMBOLS.warn), fail: c.red(SYMBOLS.fail) };
  const width = Math.min(28, Math.max(...checks.map(check => check.title.length)) + 2);
  const lines: string[] = [];
  for (const group of ['common', ...runtimes] as HostCheck['group'][]) {
    const inGroup = checks.filter(check => check.group === group);
    if (!inGroup.length) continue;
    lines.push(c.bold(GROUP_TITLES[group]));
    for (const check of inGroup) {
      lines.push(`  ${mark[check.status]} ${check.title.padEnd(width)} ${c.dim(check.detail)}`);
      if (check.status !== 'ok' && check.fix)
        for (const [i, line] of check.fix.split('\n').entries())
          lines.push(`      ${i ? '   ' : c.cyan('fix:')} ${line}`);
    }
    lines.push('');
  }
  const fails = checks.filter(check => check.status === 'fail').length;
  const warns = checks.filter(check => check.status === 'warn').length;
  lines.push(
    fails
      ? c.red(
          `${fails} problem${fails === 1 ? '' : 's'} to fix before a ${runtimes.join('/')} scan${warns ? `, ${warns} warning${warns === 1 ? '' : 's'}` : ''}.`
        )
      : c.green(
          `Ready for a ${runtimes.join(' or ')} scan${warns ? ` (${warns} warning${warns === 1 ? '' : 's'})` : ''}.`
        )
  );
  if (fails)
    lines.push(c.dim(`Try \`${CLI_NAME} doctor --fix\`; for help, \`${CLI_NAME} debug bundle\`.`));
  return lines.join('\n');
}
