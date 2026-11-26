import { describe, it, expect } from 'bun:test';
import { resolve } from 'node:path';
import { C_MODEL_CATALOG, PREFLIGHT_BASE_URL } from '../constants';
import type { ScanLayout } from '../layout';
import { DockerRuntime, DOCKER_PATHS } from '../runtime/docker';
import {
  FORBIDDEN_VARIABLES,
  NativeRuntime,
  nativeEnvironment,
  upstreamEnvironment,
} from '../runtime/native';
import type { ScanOptions } from '../scan-command';
import { nodeExecutable, resolveUpstream } from '../upstream';

const ASSETS = resolve(import.meta.dir, '../../assets');
const ENGINE = resolve(import.meta.dir, '..');
const upstream = resolveUpstream(ENGINE);

const OPTIONS: ScanOptions = {
  paths: [],
  diffBase: '',
  knowledgeBase: '',
  model: 'deepseek/deepseek-v4.1-flash',
  effort: 'xhigh',
  mode: 'standard',
  cyberAccessProgram: '',
  maxTimeHours: undefined,
  failOnSeverity: 'none',
  verbose: false,
  dryRun: false,
  mock: false,
  knowledgeBaseBuilt: true,
  helperContext: true,
  plugin: true,
  rubric: false,
  falsePositives: false,
  judge: true,
  taskRouting: true,
};
const STAGE = '/Users/dev/stages/run-1';
const runtime = new NativeRuntime({ assets: ASSETS, upstream: ENGINE, runName: 'cs-run' });
const layout: ScanLayout = {
  ...runtime.layout(STAGE, '/Users/dev/code/app', 'scan'),
  scanDir: '/Users/dev/.codex/state/plugins/codex-security/scans/app/codex-security-app-abc123',
};

function after(args: string[], flag: string): string | undefined {
  return args[args.indexOf(flag) + 1];
}

/** An environment holding every credential a caller might have, and some settings. */
const LEAKY: NodeJS.ProcessEnv = {
  PATH: '/usr/bin:/bin',
  HOME: '/Users/dev',
  LANG: 'en_US.UTF-8',
  LC_ALL: 'en_US.UTF-8',
  HTTPS_PROXY: 'http://proxy:3128',
  SSL_CERT_FILE: '/etc/ssl/cert.pem',
  TERM: 'xterm-256color',
  OPENAI_API_KEY: 'sk-openai',
  GITHUB_TOKEN: 'ghp_x',
  GH_TOKEN: 'gho_x',
  CYNOS_API_KEY: 'sk-cynos',
  INPUT_API_KEY: 'sk-input',
  ACTIONS_RUNTIME_TOKEN: 'actions',
  CODEX_CLI_PATH: '/tmp/evil-codex',
  AWS_SECRET_ACCESS_KEY: 'aws',
  CI: 'true',
};

describe('the native scan command', () => {
  const command = runtime.scanCommand(layout, OPTIONS, 'scan', 'sk-cynos');
  const args = command.argv;

  it("runs upstream's own bin on Node, from node_modules", () => {
    expect(args.slice(0, 4)).toEqual([
      nodeExecutable(),
      upstream.bin,
      'scan',
      '/Users/dev/code/app',
    ]);
    expect(command.name).toBe('cs-run');
  });

  it("gives upstream the stage's real paths and the scan dir made where upstream would", () => {
    expect(after(args, '--output-dir')).toBe(layout.scanDir);
    expect(after(args, '--scan-prompt-file')).toBe(`${STAGE}/prompt.md`);
    expect(after(args, '--plugin-path')).toBe(`${STAGE}/plugin`);
    expect(after(args, '--knowledge-base')).toBe(`${STAGE}/knowledge-base/output`);
    expect(args).toContain(`model_catalog_json="${STAGE}/model-catalog.json"`);
    expect(args.join(' ')).not.toContain('/scan/');
  });

  it('runs headless with --json unless upstream draws its dashboard', () => {
    expect(args).toContain('--headless');
    expect(args).toContain('--json');
    expect(command.stdio).toBeUndefined();
    const interactive = runtime.scanCommand(layout, { ...OPTIONS, interactive: true }, 'scan');
    expect(interactive.argv).not.toContain('--headless');
    expect(interactive.argv).not.toContain('--json');
    // stderr for its screen and stdout still captured; no keyboard, so upstream cannot end the
    // scan by asking to open its findings for patching.
    expect(interactive.stdio).toEqual(['ignore', 'pipe', 'inherit']);
  });

  it('runs the preflight against a port nothing listens on, in its own workspace', () => {
    const preflight = runtime.layout(STAGE, '/Users/dev/code/app', 'preflight');
    const check = runtime.scanCommand(preflight, OPTIONS, 'preflight', 'placeholder');
    expect(check.argv.join(' ')).toContain(`base_url="${PREFLIGHT_BASE_URL}"`);
    expect(check.argv).toContain('--headless');
    expect(after(check.argv, '--output-dir')).toBe(`${STAGE}/preflight/out/scan`);
    expect(check.env['CODEX_SECURITY_STATE_DIR']).toBe(`${STAGE}/preflight/state`);
    expect(check.name).toBe('cs-run-preflight');
  });

  it('builds the same arguments as the docker runtime but for the paths', () => {
    const docker = new DockerRuntime({ assets: ASSETS, runName: 'cs-run' });
    const inContainer = docker.scanCommand(
      docker.layout(STAGE, '/x', 'scan'),
      OPTIONS,
      'scan',
      'k'
    );
    const tail = inContainer.argv.slice(inContainer.argv.indexOf('scan'));
    const swap = (arg: string): string =>
      arg
        .replace(layout.scanDir, DOCKER_PATHS.scanDir)
        .replace(`${STAGE}/knowledge-base/output`, DOCKER_PATHS.knowledgeBase)
        .replace(`${STAGE}/model-catalog.json`, C_MODEL_CATALOG)
        .replace(`${STAGE}/prompt.md`, DOCKER_PATHS.prompt)
        .replace(`${STAGE}/plugin`, DOCKER_PATHS.plugin)
        .replace('/Users/dev/code/app', DOCKER_PATHS.project);
    expect(args.slice(2).map(swap)).toEqual(tail);
  });
});

describe("the native process's environment", () => {
  it('passes only the allow-list: no credential, no Actions or CI setting', () => {
    const env = nativeEnvironment(LEAKY);
    for (const name of [
      ...FORBIDDEN_VARIABLES,
      'INPUT_API_KEY',
      'ACTIONS_RUNTIME_TOKEN',
      'AWS_SECRET_ACCESS_KEY',
      'CI',
    ])
      expect(env[name]).toBeUndefined();
    expect(env).toEqual({
      PATH: '/usr/bin:/bin',
      HOME: '/Users/dev',
      LANG: 'en_US.UTF-8',
      LC_ALL: 'en_US.UTF-8',
      HTTPS_PROXY: 'http://proxy:3128',
      SSL_CERT_FILE: '/etc/ssl/cert.pem',
      TERM: 'xterm-256color',
    });
  });

  it('gives upstream the cynos key as CODEX_API_KEY only, and only when the scan calls the model', () => {
    const env = upstreamEnvironment(layout, 'sk-cynos', LEAKY);
    expect(env['CODEX_API_KEY']).toBe('sk-cynos');
    const values = Object.entries(env).filter(([, value]) => value === 'sk-cynos');
    expect(values.map(([name]) => name)).toEqual(['CODEX_API_KEY']);
    expect(upstreamEnvironment(layout, undefined, LEAKY)['CODEX_API_KEY']).toBeUndefined();
    // The scan command holds the key in its env, never in argv.
    const command = runtime.scanCommand(layout, OPTIONS, 'scan', 'sk-cynos');
    expect(command.argv.join(' ')).not.toContain('sk-cynos');
    for (const name of FORBIDDEN_VARIABLES) expect(command.env[name]).toBeUndefined();
  });

  it("sets upstream's state dir only for a path, and leaves upstream's default alone", () => {
    expect(
      upstreamEnvironment(layout, undefined, LEAKY)['CODEX_SECURITY_STATE_DIR']
    ).toBeUndefined();
    const own = new NativeRuntime({ assets: ASSETS, upstream: ENGINE, stateDir: '/srv/state' });
    const owned = own.layout(STAGE, '/Users/dev/code/app', 'scan');
    expect(owned.stateDir).toBe('/srv/state');
    expect(upstreamEnvironment(owned, undefined, LEAKY)['CODEX_SECURITY_STATE_DIR']).toBe(
      '/srv/state'
    );
    // A user's own setting passes through, so upstream and the engine agree on the default.
    expect(
      upstreamEnvironment(layout, undefined, { ...LEAKY, CODEX_SECURITY_STATE_DIR: '/mine' })[
        'CODEX_SECURITY_STATE_DIR'
      ]
    ).toBe('/mine');
  });
});

describe('the native review agent and code graph', () => {
  it("runs the pinned Codex's codex exec read-only in the checkout, its home in the stage", () => {
    const command = runtime.reviewAgentCommand(
      {
        name: 'cs-run-knowledge-base-review',
        project: '/Users/dev/code/app',
        work: `${STAGE}/knowledge-base/review`,
        cynosKey: 'sk-cynos',
        modelCatalog: `${STAGE}/model-catalog.json`,
      },
      false
    );
    expect(command.argv[0]).toBe(upstream.codex.executable);
    expect(command.argv.slice(1, 6)).toEqual([
      'exec',
      '--sandbox',
      'read-only',
      '-C',
      '/Users/dev/code/app',
    ]);
    expect(after(command.argv, '-o')).toBe(`${STAGE}/knowledge-base/review/answer.txt`);
    expect(command.argv).toContain(`model_catalog_json="${STAGE}/model-catalog.json"`);
    expect(command.env['CODEX_HOME']).toBe(`${STAGE}/knowledge-base/review/home`);
    expect(command.env['CODEX_API_KEY']).toBe('sk-cynos');
    expect(command.env['PATH']?.split(':')[0]).toBe(upstream.codex.toolsDir);
    expect(command.argv.join(' ')).not.toContain('sk-cynos');
  });

  it('serves the graph from the binary itself as an MCP server, its home in the stage, nothing to start or stop', () => {
    const plan = {
      name: 'g',
      project: '/Users/dev/code/app',
      home: `${STAGE}/knowledge-base/graph`,
    };
    expect(runtime.codeGraphStart()).toBeUndefined();
    expect(runtime.codeGraphStop()).toBeUndefined();
    const server = runtime.codeGraphServer(plan);
    expect(server.argv).toHaveLength(1);
    expect(server.argv[0]).toMatch(/codebase-memory-mcp\/v0\.11\.0\/[^/]+\/codebase-memory-mcp$/);
    expect(server.env['HOME']).toBe(plan.home);
    expect(server.cwd).toBe(plan.home);
  });

  it("probes Codex's sandbox as upstream's container check does", () => {
    expect(runtime.sandboxCheck().argv).toEqual([
      upstream.codex.executable,
      'sandbox',
      '--',
      '/usr/bin/true',
    ]);
  });

  it("exports SARIF with upstream's export, from the scan dir to the stage", () => {
    expect(runtime.exportSarif(layout).argv.slice(1)).toEqual([
      upstream.bin,
      'export',
      layout.scanDir,
      '--export-format',
      'sarif',
      '--source-root',
      '/Users/dev/code/app',
      '--output',
      `${STAGE}/out/results.sarif`,
    ]);
  });
});
