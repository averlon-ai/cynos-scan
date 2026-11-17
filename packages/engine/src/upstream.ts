/**
 * The pinned upstream on this machine: @openai/codex-security and the Codex it runs.
 *
 * The native runtime runs upstream from node_modules, exactly as installed, so it has to find
 * the package and the native Codex binary it ships, as upstream itself does. Two things make
 * that more than `require.resolve`:
 *
 *   - upstream's package.json `exports` hides ./package.json (and its bin), so neither can be
 *     resolved by name; its root is found by walking the directories Node would search
 *     (`require.resolve.paths`) for @openai/codex-security/package.json;
 *   - Codex is a launcher (@openai/codex) plus one platform package per os and architecture
 *     (@openai/codex-<os>-<arch>, holding vendor/<target triple>/bin/codex and the bundled rg in
 *     vendor/<target triple>/codex-path). Upstream resolves it that way (resolveCodexCommand in
 *     dist/runtime.js), so this does the same, from upstream's own root.
 *
 * Where to search from: a host that bundles the engine (the CLI, in
 * <global>/node_modules/@averlon-ai/cynos/dist/) installs upstream beside its bundle,
 * so the default is the directory of the script node runs (process.argv[1], through symlinks),
 * then the engine's own location for unbundled use.
 *
 * verifyUpstream checks the pins: a different upstream or Codex is not the scanner the engine was
 * built and tested against (its flags, outputs and outcome rules).
 */
import {
  accessSync,
  constants,
  existsSync,
  readdirSync,
  readFileSync,
  realpathSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { delimiter, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** The upstream this engine runs, and the Codex that upstream pins. */
export const UPSTREAM_PIN = {
  package: '@openai/codex-security',
  version: '0.9.1',
  codexPackage: '@openai/codex',
  codexVersion: '0.167.0',
} as const;

export interface Upstream {
  /** The package's root directory, through symlinks. */
  root: string;
  /** Its bin script, bin/codex-security.mjs. */
  bin: string;
  version: string;
  codex: {
    /** The platform binary, vendor/<target triple>/bin/codex. */
    executable: string;
    /** Codex's bundled tools (rg), vendor/<target triple>/codex-path. */
    toolsDir: string;
    version: string;
  };
}

function readJson(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
}

/** The directories to search from by default: the running script's, then the engine's own. */
export function defaultSearchRoots(): string[] {
  const roots: string[] = [];
  const script = process.argv[1];
  if (script) {
    try {
      roots.push(dirname(realpathSync(script)));
    } catch {
      // A script that is not a file (node -e): skip it.
    }
  }
  try {
    roots.push(dirname(fileURLToPath(import.meta.url)));
  } catch {
    // A bundle without a file URL: only the script's directory.
  }
  return roots;
}

/** upstream's root, found by walking the node_modules directories Node would search from `from`. */
function upstreamRoot(from: string): string | undefined {
  const paths = createRequire(join(from, 'noop.js')).resolve.paths(UPSTREAM_PIN.package) ?? [];
  for (const directory of paths) {
    const candidate = join(directory, ...UPSTREAM_PIN.package.split('/'));
    if (existsSync(join(candidate, 'package.json'))) return realpathSync(candidate);
  }
  return undefined;
}

/** Codex's platform binary and tools, resolved from upstream's root as upstream resolves them. */
function resolveCodex(root: string): Upstream['codex'] {
  const fromUpstream = createRequire(join(root, 'package.json'));
  const launcher = fromUpstream.resolve(`${UPSTREAM_PIN.codexPackage}/package.json`);
  const platform = process.platform === 'android' ? 'linux' : process.platform;
  const platformPackage = `${UPSTREAM_PIN.codexPackage}-${platform}-${process.arch}`;
  let platformJson: string;
  try {
    platformJson = createRequire(launcher).resolve(`${platformPackage}/package.json`);
  } catch {
    throw new Error(
      `Codex's platform package ${platformPackage} is not installed beside ${UPSTREAM_PIN.codexPackage}; reinstall with optional dependencies enabled.`
    );
  }
  // One target-triple directory per platform package (dist/runtime.js resolveCodexCommand).
  const vendor = join(dirname(platformJson), 'vendor');
  const triple = readdirSync(vendor, { withFileTypes: true }).find(entry => entry.isDirectory());
  const executable = join(vendor, triple?.name ?? '', 'bin', 'codex');
  if (!triple || !existsSync(executable))
    throw new Error(`${platformPackage} does not contain the Codex executable (${executable}).`);
  return {
    executable,
    toolsDir: join(vendor, triple.name, 'codex-path'),
    version: String(readJson(launcher)['version'] ?? ''),
  };
}

/**
 * upstream and its Codex, searched for from `from` (default: defaultSearchRoots, in order).
 * Throws when upstream is not installed there, or its Codex binary is missing.
 */
export function resolveUpstream(from?: string): Upstream {
  const roots = from ? [from] : defaultSearchRoots();
  for (const start of roots) {
    const root = upstreamRoot(start);
    if (!root) continue;
    const manifest = readJson(join(root, 'package.json'));
    const bins = manifest['bin'] as Record<string, string> | string | undefined;
    const bin = typeof bins === 'string' ? bins : bins?.['codex-security'];
    if (!bin) throw new Error(`${UPSTREAM_PIN.package} at ${root} declares no codex-security bin.`);
    return {
      root,
      bin: join(root, bin),
      version: String(manifest['version'] ?? ''),
      codex: resolveCodex(root),
    };
  }
  throw new Error(
    `${UPSTREAM_PIN.package} is not installed (searched from ${roots.join(', ') || 'nowhere'}); install ${UPSTREAM_PIN.package}@${UPSTREAM_PIN.version}.`
  );
}

/**
 * upstream's bundled plugin (_bundled_plugin/), searched for as resolveUpstream searches: the
 * native runtime's (NativeRuntime.bundledPlugin; the docker runtime copies its image's instead). A
 * scan's plugin is copied from it (scan-plugin.ts), so it must be the pin's: throws for another
 * version, or none.
 */
export function bundledPluginRoot(from?: string): string {
  const roots = from ? [from] : defaultSearchRoots();
  for (const start of roots) {
    const root = upstreamRoot(start);
    if (!root) continue;
    const version = String(readJson(join(root, 'package.json'))['version'] ?? '');
    if (version !== UPSTREAM_PIN.version)
      throw new Error(
        `${UPSTREAM_PIN.package} at ${root} is ${version}, not the pinned ${UPSTREAM_PIN.version}.`
      );
    return join(root, '_bundled_plugin');
  }
  throw new Error(
    `${UPSTREAM_PIN.package} is not installed (searched from ${roots.join(', ') || 'nowhere'}); install ${UPSTREAM_PIN.package}@${UPSTREAM_PIN.version}.`
  );
}

/** Throws unless upstream and its Codex are the pinned versions. */
export function verifyUpstream(upstream: Upstream): void {
  if (upstream.version !== UPSTREAM_PIN.version)
    throw new Error(
      `${UPSTREAM_PIN.package} at ${upstream.root} is ${upstream.version}, not the pinned ${UPSTREAM_PIN.version}.`
    );
  if (upstream.codex.version !== UPSTREAM_PIN.codexVersion)
    throw new Error(
      `${UPSTREAM_PIN.codexPackage} beside ${UPSTREAM_PIN.package} is ${upstream.codex.version}, not the pinned ${UPSTREAM_PIN.codexVersion}.`
    );
}

/** An executable file named `name` on PATH, or undefined. */
export function onPath(name: string, path = process.env['PATH'] ?? ''): string | undefined {
  for (const directory of path.split(delimiter).filter(Boolean)) {
    const candidate = join(directory, name);
    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch {
      // not here
    }
  }
  return undefined;
}

/**
 * The Node that runs upstream: this process's own, unless this process is Bun (the engine's
 * tests), in which case the first node on PATH. Upstream supports Node only.
 */
export function nodeExecutable(): string {
  if (!process.versions['bun']) return process.execPath;
  return onPath('node') ?? 'node';
}

/** argv for one upstream command: Node, upstream's bin script, then args. */
export function upstreamCommand(args: string[], upstream: Upstream = resolveUpstream()): string[] {
  return [nodeExecutable(), upstream.bin, ...args];
}
