/**
 * The code-graph binary for the native runtime: codebase-memory-mcp, pinned, on this machine.
 *
 * The docker runtime's image carries the binary (assets/Dockerfile checks the linux release
 * against its sha256 before extracting it). The native runtime runs it on the host, for the
 * host's os and architecture, so it needs the same release for each platform, under the same
 * rule: the archive is downloaded once into a tool cache, and nothing is extracted from it until
 * its sha256 is the pinned one.
 *
 *   pin       CODE_GRAPH_PINS: the release asset and its sha256 per os/arch (GitHub's release
 *             checksums.txt for v0.11.0; the linux ones are the Dockerfile's)
 *   download  into <tool cache>/codebase-memory-mcp/<version>/<os>-<arch>/, checked, extracted,
 *             then renamed into place, so a binary appears whole or not at all
 *   check     the binary's own sha256, recorded at install, so a changed file is noticed
 *
 * A platform with no pin cannot run the native knowledge base; that fails with what to do.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export const CODE_GRAPH_VERSION = 'v0.11.0';
export const CODE_GRAPH_BINARY = 'codebase-memory-mcp';
const RELEASES = 'https://github.com/DeusData/codebase-memory-mcp/releases/download';

export interface CodeGraphPin {
  asset: string;
  sha256: string;
}

/** The pinned release asset per `${process.platform}-${process.arch}`. */
export const CODE_GRAPH_PINS: Record<string, CodeGraphPin> = {
  'linux-x64': {
    asset: 'codebase-memory-mcp-linux-amd64-portable.tar.gz',
    sha256: '1f9e8293eb2bc5c05cfa27a7e8fc033da6d729ffad525ccfcdaa3fd606306683',
  },
  'linux-arm64': {
    asset: 'codebase-memory-mcp-linux-arm64-portable.tar.gz',
    sha256: 'd62eeb224d5ee3eba3070938ec62cf1033f10b041ec1c4b2fb67f7aef390cc7b',
  },
  'darwin-x64': {
    asset: 'codebase-memory-mcp-darwin-amd64.tar.gz',
    sha256: 'dbf1c73bfcbde64e7dde4cd1320da7afc02e2c972ee1789ae039521411f5132e',
  },
  'darwin-arm64': {
    asset: 'codebase-memory-mcp-darwin-arm64.tar.gz',
    sha256: '4dee7f38b63740e6751d7a7ed7eb10291c1f2a3ea2415f599dc68370ca0a2d18',
  },
};

/** Where downloaded tools are kept: $XDG_CACHE_HOME/averlon/tools, else ~/.cache/averlon/tools. */
export function defaultToolCache(env: NodeJS.ProcessEnv = process.env): string {
  const cache = env['XDG_CACHE_HOME']?.trim() || join(homedir(), '.cache');
  return join(cache, 'averlon', 'tools');
}

/** This platform's key in CODE_GRAPH_PINS. */
export function platformKey(
  platform: string = process.platform,
  arch: string = process.arch
): string {
  return `${platform}-${arch}`;
}

/** This platform's pin; throws, saying what to do, when there is none. */
export function codeGraphPin(key: string = platformKey()): CodeGraphPin {
  const pin = CODE_GRAPH_PINS[key];
  if (!pin)
    throw new Error(
      `codebase-memory-mcp ${CODE_GRAPH_VERSION} has no pinned build for ${key}; the native runtime cannot build the knowledge base here. Use --runtime docker, or scan with --no-knowledge-base.`
    );
  return pin;
}

/** The directory one platform's binary is installed in. */
export function codeGraphDir(toolCache: string, key: string = platformKey()): string {
  return join(toolCache, CODE_GRAPH_BINARY, CODE_GRAPH_VERSION, key);
}

const sha256 = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');

export type CodeGraphState =
  | { status: 'ok'; binary: string }
  | { status: 'missing'; binary: string }
  | { status: 'changed'; binary: string; detail: string };

/** Whether the binary is installed and still the file that was installed. */
export function codeGraphBinaryState(
  toolCache: string = defaultToolCache(),
  key: string = platformKey()
): CodeGraphState {
  const dir = codeGraphDir(toolCache, key);
  const binary = join(dir, CODE_GRAPH_BINARY);
  if (!existsSync(binary)) return { status: 'missing', binary };
  let recorded = '';
  try {
    recorded = readFileSync(join(dir, 'binary.sha256'), 'utf8').trim();
  } catch {
    return { status: 'changed', binary, detail: 'no recorded sha256' };
  }
  const actual = sha256(readFileSync(binary));
  return actual === recorded
    ? { status: 'ok', binary }
    : { status: 'changed', binary, detail: `sha256 ${actual}, installed as ${recorded}` };
}

export type Download = (url: string) => Promise<Buffer>;

const fetchBytes: Download = async url => {
  const response = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(600_000) });
  if (!response.ok) throw new Error(`GET ${url}: HTTP ${response.status}`);
  return Buffer.from(await response.arrayBuffer());
};

/** Extracts one file from a .tar.gz into directory. */
export type Extract = (archive: string, directory: string, member: string) => void;

const tarExtract: Extract = (archive, directory, member) => {
  const result = spawnSync('tar', ['-xzf', archive, '-C', directory, member], { encoding: 'utf8' });
  if (result.status !== 0)
    throw new Error(`tar could not extract ${member}: ${(result.stderr || '').trim()}`);
};

/**
 * The binary's path, downloading and installing it first when it is missing or changed. The
 * archive is checked against the pin before anything is extracted from it.
 */
export async function ensureCodeGraphBinary(
  toolCache: string = defaultToolCache(),
  key: string = platformKey(),
  download: Download = fetchBytes,
  extract: Extract = tarExtract
): Promise<string> {
  // 1. Present and unchanged: nothing to do.
  const state = codeGraphBinaryState(toolCache, key);
  if (state.status === 'ok') return state.binary;
  const pin = codeGraphPin(key);

  // 2. The archive, checked before it is opened.
  const archive = await download(`${RELEASES}/${CODE_GRAPH_VERSION}/${pin.asset}`);
  const actual = sha256(archive);
  if (actual !== pin.sha256)
    throw new Error(
      `${pin.asset} has sha256 ${actual}, not the pinned ${pin.sha256}; nothing was installed.`
    );

  // 3. Extracted beside its final place, then renamed into it.
  const dir = codeGraphDir(toolCache, key);
  const parent = join(dir, '..');
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  const pending = mkdtempSync(join(parent, '.pending-'));
  try {
    writeFileSync(join(pending, pin.asset), archive, { mode: 0o600 });
    extract(join(pending, pin.asset), pending, CODE_GRAPH_BINARY);
    rmSync(join(pending, pin.asset), { force: true });
    const binary = join(pending, CODE_GRAPH_BINARY);
    chmodSync(binary, 0o755);
    writeFileSync(join(pending, 'binary.sha256'), `${sha256(readFileSync(binary))}\n`);
    writeFileSync(join(pending, 'archive.sha256'), `${pin.sha256}  ${pin.asset}\n`);
    rmSync(dir, { recursive: true, force: true });
    renameSync(pending, dir);
  } catch (error) {
    rmSync(pending, { recursive: true, force: true });
    throw error;
  }
  return join(dir, CODE_GRAPH_BINARY);
}
