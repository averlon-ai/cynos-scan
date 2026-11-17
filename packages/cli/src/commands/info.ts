/**
 * `cynos info [--json]`: the versions and paths this copy runs with, for a bug report.
 *
 * Every engine-provided value is read on its own, so an engine without one of them still prints
 * the rest, with what is missing named in its place.
 */
import type { Command } from 'commander';
import { cynosBaseUrl } from '../auth/keys';
import {
  CLI_NAME,
  CLI_VERSION,
  defaultModel,
  engineBaseUrl,
  PACKAGE_NAME,
  type Context,
} from '../context';
import { assetsDir, engine } from '../engine';
import { withExamples } from '../help';
import { averlonDir, defaultRuntime, knowledgeBaseCacheDir, runsDir } from '../settings';
import { detectInstall, npmGlobalPrefix } from '../update/install-method';
import { updateCachePath } from '../update/notice';
import { runningScript } from './update';

export function registerInfo(program: Command, ctx: Context): void {
  const command = program
    .command('info')
    .description('Show versions, the runtime, the model, the endpoint and the paths in use.')
    .option('--json', 'print JSON')
    .action(async (options: { json?: boolean }) => infoCommand(ctx, options));
  withExamples(command, [`${CLI_NAME} info`, `${CLI_NAME} info --json`]);
}

/** value(), or what made it unavailable. */
function guarded<T>(value: () => T): T | { unavailable: string } {
  try {
    return value();
  } catch (error) {
    return { unavailable: (error as Error).message };
  }
}

export function collectInfo(ctx: Context): Record<string, unknown> {
  const stateDir = guarded(() => engine().resolveStateDir(ctx.env));
  const state = typeof stateDir === 'string' ? stateDir : undefined;
  return {
    cli: {
      package: PACKAGE_NAME,
      version: CLI_VERSION,
      script: runningScript(),
      install: detectInstall({ script: runningScript(), npmPrefix: npmGlobalPrefix }).method,
    },
    engine: { version: guarded(() => engine().ENGINE_VERSION), assets: assetsDir() },
    upstream: {
      pin: guarded(() => engine().UPSTREAM_PIN),
      installed: guarded(() => engine().resolveUpstream()),
    },
    node: { version: process.version, platform: process.platform, arch: process.arch },
    runtime: defaultRuntime(ctx.env),
    model: defaultModel(ctx.env),
    baseUrl: cynosBaseUrl(ctx.env, engineBaseUrl()),
    paths: {
      stateDir,
      averlon: state ? averlonDir(state) : null,
      runDirs: state ? runsDir(state) : null,
      knowledgeBaseCache: state ? knowledgeBaseCacheDir(state) : null,
      config: ctx.configDir,
      credentials: ctx.credentials.description,
      updateCache: updateCachePath(ctx.cacheDir),
    },
  };
}

async function infoCommand(ctx: Context, options: { json?: boolean }): Promise<void> {
  const info = collectInfo(ctx);
  if (options.json) return ctx.terminal.json(info);
  const c = ctx.terminal.out;
  const show = (value: unknown): string => {
    if (value && typeof value === 'object' && 'unavailable' in value)
      return c.yellow(`unavailable: ${String((value as { unavailable: string }).unavailable)}`);
    if (value && typeof value === 'object') return JSON.stringify(value);
    return String(value);
  };
  const lines: string[] = [];
  for (const [section, value] of Object.entries(info)) {
    if (value && typeof value === 'object' && !('unavailable' in value)) {
      lines.push(c.bold(section));
      for (const [key, inner] of Object.entries(value))
        lines.push(`  ${key.padEnd(20)} ${show(inner)}`);
    } else lines.push(`${c.bold(section.padEnd(22))} ${show(value)}`);
  }
  ctx.terminal.result(lines.join('\n'));
}
