/**
 * Bumps the pinned upstream to a newer @openai/codex-security (npm's latest by default), for the
 * upstream workflow's pull request.
 *
 * The engine runs upstream exactly as released and checks that it does, so the version is pinned
 * in more places than a dependency bump reaches:
 *
 *   - the dependency in both packages' package.json, and UPSTREAM_PIN in upstream.ts (upstream
 *     and the Codex it pins);
 *   - the scanner image's Dockerfile, which installs upstream's npm tarball by its sha256;
 *   - files vendored byte for byte and checked by their sha256 in constants.ts: upstream's seccomp
 *     and AppArmor profiles (docker/ at tag npm-v<version>), its scan plugin's packet and diff
 *     rules (plugins/codex-security/ at the same tag), and Codex's base instructions
 *     (codex-rs/models-manager/prompt.md at tag rust-v<codex version>);
 *   - the versions named in doc comments, messages and test fixtures, always with a prefix
 *     (`npm-v<version>`, `cynos-scan-scanner:<version>`, `rust-v<codex version>`), never bare.
 *
 * A new upstream can change any of them, so the bump rewrites them all from their sources and
 * reports what changed. Whether the engine still fits the new upstream (its flags, outputs,
 * outcome rules) is for the tests, the end to end run and the pull request's review to say.
 *
 *   bun packages/engine/src/upstream-bump.ts [--version X.Y.Z] [--report bump.md]
 *
 * Prints "up to date" and changes nothing when the pin is already that version.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { UPSTREAM_PIN } from './upstream';

const REPOSITORY = resolve(import.meta.dir, '../../..');
const ASSETS = 'packages/engine/assets';
const UPSTREAM_PIN_FILE = 'packages/engine/src/upstream.ts';
const DOCKERFILE = `${ASSETS}/Dockerfile`;
/** Where the vendored files' sha256 constants are. */
const VENDORED_HASHES = 'packages/engine/src/constants.ts';

/** One pinned upstream: codex-security, the Codex it pins, and its npm tarball's sha256. */
export interface Pin {
  version: string;
  codexVersion: string;
  tarballSha256: string;
}

/** A file vendored byte for byte from upstream or Codex, at the pinned tag. */
interface VendoredFile {
  path: string;
  source: (pin: Pin) => string;
}

const VENDORED_FILES: VendoredFile[] = [
  {
    path: `${ASSETS}/codex-security-seccomp.json`,
    source: pin =>
      `https://raw.githubusercontent.com/openai/codex-security/npm-v${pin.version}/docker/codex-security-seccomp.json`,
  },
  {
    path: `${ASSETS}/codex-security.apparmor`,
    source: pin =>
      `https://raw.githubusercontent.com/openai/codex-security/npm-v${pin.version}/docker/codex-security.apparmor`,
  },
  {
    path: `${ASSETS}/codex-base-instructions.md`,
    source: pin =>
      `https://raw.githubusercontent.com/openai/codex/rust-v${pin.codexVersion}/codex-rs/models-manager/prompt.md`,
  },
];

/** What a vendored file did in the bump: the report's table rows. */
interface VendoredChange {
  path: string;
  source: string;
  status: 'unchanged' | 'changed' | 'missing at source';
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: { version: { type: 'string' }, report: { type: 'string' } },
  });
  const from = currentPin();
  const to = releasedPin(values.version ?? 'latest');
  if (to.version === from.version) {
    console.log(`@openai/codex-security ${from.version} is up to date`);
    return;
  }
  // The vendored files first: their sha256 constants change with them, and a file that is not
  // at its source any more stays as it is, for the review to settle.
  const vendored: VendoredChange[] = [];
  for (const file of VENDORED_FILES) vendored.push(await updateVendoredFile(file, to));
  rewriteUpstreamPin(from, to);
  const rewritten = [UPSTREAM_PIN_FILE, ...rewriteRepository(from, to)];
  const report = bumpReport(from, to, vendored, rewritten);
  if (values.report) writeFileSync(values.report, report);
  console.log(report);
}

/** The pin as the checkout has it: UPSTREAM_PIN, and the tarball sha256 the Dockerfile checks. */
function currentPin(): Pin {
  const dockerfile = readFileSync(join(REPOSITORY, DOCKERFILE), 'utf8');
  const sha256 = /^ARG CODEX_SECURITY_SHA256=([0-9a-f]{64})$/m.exec(dockerfile)?.[1];
  if (!sha256) throw new Error(`${DOCKERFILE} has no ARG CODEX_SECURITY_SHA256=<sha256>`);
  return {
    version: UPSTREAM_PIN.version,
    codexVersion: UPSTREAM_PIN.codexVersion,
    tarballSha256: sha256,
  };
}

/**
 * A released upstream: its version and the Codex it pins, from npm, and the sha256 of its
 * tarball, which npm pack checks against the registry's integrity before writing it.
 */
function releasedPin(wanted: string): Pin {
  const npm = (args: string[], cwd = REPOSITORY): string =>
    execFileSync('npm', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });
  const spec = `${UPSTREAM_PIN.package}@${wanted}`;
  const manifest = JSON.parse(npm(['view', spec, 'version', 'dependencies', '--json'])) as {
    version: string;
    dependencies?: Record<string, string>;
  };
  const codexVersion = manifest.dependencies?.[UPSTREAM_PIN.codexPackage];
  if (!codexVersion) throw new Error(`${spec} does not depend on ${UPSTREAM_PIN.codexPackage}`);
  const directory = mkdtempSync(join(tmpdir(), 'upstream-bump-'));
  try {
    const [packed] = JSON.parse(
      npm(['pack', `${UPSTREAM_PIN.package}@${manifest.version}`, '--json'], directory)
    ) as { filename: string }[];
    const tarball = readFileSync(join(directory, packed?.filename ?? ''));
    return {
      version: manifest.version,
      codexVersion,
      tarballSha256: createHash('sha256').update(tarball).digest('hex'),
    };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

/**
 * Replaces a vendored file with its source at the new pin, and its sha256 constant with the
 * new file's. A source that is gone (a file moved between tags) leaves both as they are.
 */
async function updateVendoredFile(file: VendoredFile, to: Pin): Promise<VendoredChange> {
  const source = file.source(to);
  const response = await fetch(source);
  if (response.status === 404) return { path: file.path, source, status: 'missing at source' };
  if (!response.ok) throw new Error(`${source}: HTTP ${response.status}`);
  const next = Buffer.from(await response.arrayBuffer());
  const path = join(REPOSITORY, file.path);
  const previous = readFileSync(path);
  if (next.equals(previous)) return { path: file.path, source, status: 'unchanged' };
  writeFileSync(path, next);
  const hashes = join(REPOSITORY, VENDORED_HASHES);
  const sha256 = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');
  writeFileSync(hashes, readFileSync(hashes, 'utf8').replace(sha256(previous), sha256(next)));
  return { path: file.path, source, status: 'changed' };
}

/** Sets UPSTREAM_PIN's two versions in upstream.ts. */
function rewriteUpstreamPin(from: Pin, to: Pin): void {
  const path = join(REPOSITORY, UPSTREAM_PIN_FILE);
  const text = readFileSync(path, 'utf8');
  const next = text
    .replace(`  version: '${from.version}',`, `  version: '${to.version}',`)
    .replace(`  codexVersion: '${from.codexVersion}',`, `  codexVersion: '${to.codexVersion}',`);
  if (next === text) throw new Error(`${UPSTREAM_PIN_FILE}: UPSTREAM_PIN is not ${from.version}`);
  writeFileSync(path, next);
}

/** Rewrites every other tracked text file's pinned versions; returns the files it changed. */
function rewriteRepository(from: Pin, to: Pin): string[] {
  const files = execFileSync('git', ['ls-files'], { cwd: REPOSITORY, encoding: 'utf8' })
    .split('\n')
    .filter(file => file && file !== 'bun.lock' && file !== UPSTREAM_PIN_FILE);
  const changed: string[] = [];
  for (const file of files) {
    const path = join(REPOSITORY, file);
    let text: string;
    try {
      text = readFileSync(path, 'utf8');
    } catch {
      continue;
    }
    const next = rewritePins(text, from, to);
    if (next === text) continue;
    writeFileSync(path, next);
    changed.push(file);
  }
  return changed;
}

/**
 * One file's text with the old pin's versions replaced by the new one's.
 *
 * A version is replaced only where a prefix says what it is a version of, so an unrelated
 * "0.2.0" (the CLI's own version in a test) is left alone.
 */
export function rewritePins(text: string, from: Pin, to: Pin): string {
  const replacements: [string, string][] = [
    // package.json and the Dockerfile.
    [`"${UPSTREAM_PIN.package}": "${from.version}"`, `"${UPSTREAM_PIN.package}": "${to.version}"`],
    [`CODEX_SECURITY_VERSION=${from.version}`, `CODEX_SECURITY_VERSION=${to.version}`],
    [`CODEX_SECURITY_SHA256=${from.tarballSha256}`, `CODEX_SECURITY_SHA256=${to.tarballSha256}`],
    // Doc comments, messages and test fixtures.
    [`npm-v${from.version}`, `npm-v${to.version}`],
    [`cynos-scan-scanner:${from.version}`, `cynos-scan-scanner:${to.version}`],
    [`codex-security ${from.version}`, `codex-security ${to.version}`],
    [`rust-v${from.codexVersion}`, `rust-v${to.codexVersion}`],
  ];
  return replacements.reduce((current, [old, next]) => current.split(old).join(next), text);
}

/** The pull request's description: the versions, the vendored files, and what to review. */
export function bumpReport(
  from: Pin,
  to: Pin,
  vendored: VendoredChange[],
  rewritten: string[]
): string {
  const upstream = 'https://github.com/openai/codex-security';
  const codex = 'https://github.com/openai/codex';
  const codexRow =
    from.codexVersion === to.codexVersion
      ? `| Codex | ${to.codexVersion} | unchanged |`
      : `| Codex | ${from.codexVersion} → ${to.codexVersion} | [diff](${codex}/compare/rust-v${from.codexVersion}...rust-v${to.codexVersion}) |`;
  return [
    `Bumps \`${UPSTREAM_PIN.package}\` from ${from.version} to ${to.version}.`,
    '',
    '| | Version | |',
    '| --- | --- | --- |',
    `| codex-security | ${from.version} → ${to.version} | [release](${upstream}/releases/tag/npm-v${to.version}) · [diff](${upstream}/compare/npm-v${from.version}...npm-v${to.version}) |`,
    codexRow,
    `| tarball sha256 | \`${to.tarballSha256}\` | |`,
    '',
    '**Vendored files** (byte for byte from their source at the new tags):',
    '',
    ...vendored.map(file => `- \`${file.path}\`: ${file.status} ([source](${file.source}))`),
    '',
    `**Rewritten:** ${rewritten.map(file => `\`${file}\``).join(', ') || 'nothing'}.`,
    '',
    "To review: upstream's flags, `--json` result and outcome rules (scan-command.ts, results.ts),",
    "its dashboard's progress lines, the plugin's `skills/`, `references/` and `schemas/` against",
    "the scan's workflow and its scripts (assets/scan-prompt/; AGENTS.md says why), the workflow",
    'files it replaces (REPLACED_WORKFLOW_SHA256: scans stop until assets/scan-prompt/ is reviewed',
    "against upstream's new ones, its policy passages updated word for word, and the hashes",
    'updated), and any vendored file marked missing.',
  ].join('\n');
}

if (import.meta.main) await main();
