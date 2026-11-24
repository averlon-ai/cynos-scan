import { describe, it, expect } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import {
  AUTO_COMPACT_TOKEN_LIMIT,
  BASE_INSTRUCTIONS_SHA256,
  BASE_URL,
  C_CODEX_TMP,
  C_HELPER_CONTEXT,
  C_HOME,
  C_KB_INDEX,
  C_KNOWLEDGE_BASE,
  C_MODEL_CATALOG,
  C_PLUGIN,
  C_RUBRIC,
  C_FALSE_POSITIVES,
  C_PROJECT,
  C_PROMPT,
  C_STATE,
  C_UPSTREAM,
  COMPACT_PROMPT,
  DEFAULT_MODEL,
  JUDGE_HEADER,
  TASK_ROUTE_HEADER,
  KEY_VARIABLE,
  KNOWLEDGE_BASE_MAX_THREADS,
  KNOWLEDGE_BASE_MODEL,
  MODEL_CONTEXT_WINDOW,
} from '../constants';
import { REVIEW_MODEL } from '../knowledge-base/architecture';
import { discardWorkspace, prepareWorkspace } from '../layout';
import {
  appArmorProfileLoaded,
  copyBundledPlugin,
  dockerScanCommand,
  provideImage,
  type ContainerPlan,
} from '../runtime/docker';
import { writeModelCatalog, type ScanOptions } from '../scan-command';
import { checkKey, keyCheckFailure } from '../key-check';
import { UPSTREAM_PIN } from '../upstream';

const PLAN: ContainerPlan = {
  name: 'cs-test',
  image: 'cynos-scan-scanner:0.9.1',
  actionRoot: '/action',
  project: '/workspace/repository',
  workspace: '/stage',
  apparmor: true,
  uid: 1001,
  gid: 1001,
};
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
  verbose: true,
  dryRun: false,
  mock: false,
  knowledgeBaseBuilt: false,
  helperContext: false,
  plugin: false,
  rubric: false,
  falsePositives: false,
  judge: true,
  taskRouting: true,
};

function command(
  options: Partial<ScanOptions> = {},
  kind: 'scan' | 'preflight' = 'scan'
): string[] {
  return dockerScanCommand(PLAN, { ...OPTIONS, ...options }, kind);
}

function after(args: string[], flag: string): string | undefined {
  return args[args.indexOf(flag) + 1];
}

describe('writeModelCatalog', () => {
  const actionRoot = resolve(import.meta.dir, '../../assets');

  it("vendors the pinned Codex's prompt.md byte for byte", () => {
    const actual = createHash('sha256')
      .update(readFileSync(join(actionRoot, 'codex-base-instructions.md')))
      .digest('hex');
    expect(actual).toBe(BASE_INSTRUCTIONS_SHA256);
  });

  it("writes Codex's fallback metadata for the scan model and the knowledge base's, with their real window", () => {
    const workspace = mkdtempSync(join(tmpdir(), 'cs-catalog-'));
    writeModelCatalog(actionRoot, workspace, 'z-ai/glm-5.3-flash');
    const catalog = JSON.parse(readFileSync(join(workspace, 'model-catalog.json'), 'utf8'));
    expect(catalog.models.map((m: { slug: string }) => m.slug)).toEqual([
      'z-ai/glm-5.3-flash',
      KNOWLEDGE_BASE_MODEL,
    ]);
    for (const entry of catalog.models) {
      expect(entry.context_window).toBe(MODEL_CONTEXT_WINDOW);
      expect(entry.max_context_window).toBe(MODEL_CONTEXT_WINDOW);
      expect(entry.effective_context_window_percent).toBe(95);
      expect(entry.model_messages.instructions_template).toBe(
        readFileSync(join(actionRoot, 'codex-base-instructions.md'), 'utf8')
      );
    }
  });

  it("lists the architecture agent's model beside the default scan model's, and a shared one once", () => {
    const slugs = (scanModel: string): string[] => {
      const workspace = mkdtempSync(join(tmpdir(), 'cs-catalog-'));
      writeModelCatalog(actionRoot, workspace, scanModel);
      const catalog = JSON.parse(readFileSync(join(workspace, 'model-catalog.json'), 'utf8'));
      return catalog.models.map((m: { slug: string }) => m.slug);
    };
    expect(slugs(DEFAULT_MODEL)).toEqual([DEFAULT_MODEL, REVIEW_MODEL]);
    expect(slugs(REVIEW_MODEL)).toEqual([REVIEW_MODEL]);
  });

  it('refuses modified base instructions', () => {
    const root = mkdtempSync(join(tmpdir(), 'cs-root-'));
    writeFileSync(join(root, 'codex-base-instructions.md'), 'You are a different agent.');
    expect(() => writeModelCatalog(root, root, 'm')).toThrow(
      `not Codex rust-v${UPSTREAM_PIN.codexVersion}`
    );
  });
});

describe('dockerScanCommand', () => {
  it('passes the key by name only', () => {
    const args = command();
    expect(after(args, '-e') === KEY_VARIABLE || args.includes(KEY_VARIABLE)).toBe(true);
    expect(args[args.indexOf(KEY_VARIABLE) - 1]).toBe('-e');
    expect(args.join(' ')).not.toContain(`${KEY_VARIABLE}=`);
  });

  it('turns the judge on with its one HTTP header by default', () => {
    const table = command().find(arg => arg.startsWith('model_providers.cynos='));
    expect(table).toContain(`http_headers={"${JUDGE_HEADER}"="on"}`);
    expect(table!.match(/x-(cy|bf)-/g)).toHaveLength(1);
  });

  it.each(['x-bf-', 'route', 'routing', '"off"', 'judge-off'])(
    'sends no other cynos override by default (%s)',
    forbidden =>
      expect(command().join(' ').toLowerCase().replaceAll(JUDGE_HEADER, '')).not.toContain(
        forbidden
      )
  );

  it('switches the judge and task routing off only when asked', () => {
    const table = (options: Partial<ScanOptions>) =>
      command(options).find(arg => arg.startsWith('model_providers.cynos='));
    expect(table({ judge: false })).toContain(`http_headers={"${JUDGE_HEADER}"="off"}`);
    expect(table({ judge: false, taskRouting: false })).toContain(
      `http_headers={"${JUDGE_HEADER}"="off","${TASK_ROUTE_HEADER}"="off"}`
    );
  });

  it("gives Codex the model's window through a read-only catalog", () => {
    const args = command();
    expect(args).toContain(`/stage/model-catalog.json:${C_MODEL_CATALOG}:ro`);
    const overrides = args.filter((_, i) => args[i - 1] === '--codex');
    expect(overrides).toContain(`model_catalog_json="${C_MODEL_CATALOG}"`);
    // Codex clamps model_context_window to the fallback's 272k, so it is not set.
    expect(overrides.some(override => override.startsWith('model_context_window='))).toBe(false);
  });

  it('writes no shell snapshot, which would hold the key and outlive a stopped scan', () => {
    const overrides = command().filter((_, i, args) => args[i - 1] === '--codex');
    expect(overrides).toContain('features.shell_snapshot=false');
  });

  it("keeps the key out of every command's environment, where the model could print it", () => {
    const overrides = command().filter((_, i, args) => args[i - 1] === '--codex');
    expect(overrides).toContain('shell_environment_policy.ignore_default_excludes=false');
  });

  it("compacts with the scan compaction prompt, below the model's window", () => {
    const overrides = command().filter((_, i, args) => args[i - 1] === '--codex');
    expect(overrides).toContain(`model_auto_compact_token_limit=${AUTO_COMPACT_TOKEN_LIMIT}`);
    expect(AUTO_COMPACT_TOKEN_LIMIT).toBeLessThan(MODEL_CONTEXT_WINDOW);
    const prompt = overrides.find(override => override.startsWith('compact_prompt='));
    // codex-security reads the value as TOML; these are the only escapes JSON and TOML share.
    const literal = prompt!.slice('compact_prompt='.length);
    expect(literal.replace(/\\[n"\\]/g, '')).not.toContain('\\');
    expect(JSON.parse(literal)).toBe(COMPACT_PROMPT);
    expect(COMPACT_PROMPT).toContain('do not call a tool');
    expect(COMPACT_PROMPT).toContain('NEW_TASK');
  });

  it("keeps upstream's hardening and a read-only project", () => {
    const args = command();
    expect(after(args, '--cap-drop')).toBe('ALL');
    expect(args).toContain('no-new-privileges');
    expect(args).toContain('seccomp=/action/codex-security-seccomp.json');
    expect(args).toContain('apparmor=codex-security-container');
    expect(args).toContain(`/workspace/repository:${C_PROJECT}:ro`);
  });

  it('works in a directory the runner uid owns', () => {
    // Codex's sandbox creates .codex under the working directory; /home/node belongs to `node`.
    const args = command();
    expect(after(args, '--user')).toBe('1001:1001');
    expect(after(args, '--workdir')).toBe(C_HOME);
    expect(args).toContain(`HOME=${C_HOME}`);
    expect(C_HOME.startsWith(`${C_STATE}/`)).toBe(true);
  });

  it("keeps Codex's sandbox launchers on a tmpfs private to the runner, where their locks hold", () => {
    // On a bind mount from Docker Desktop for Mac, a Codex process that starts deleted the
    // running scan's codex-linux-sandbox, and every command after that failed.
    for (const kind of ['scan', 'preflight'] as const)
      expect(after(command({}, kind), '--tmpfs')).toBe(
        `${C_CODEX_TMP}:uid=1001,gid=1001,mode=0700`
      );
    expect(C_CODEX_TMP).toBe(`${C_STATE}/codex-home/tmp`);
  });

  it("builds upstream's scan arguments", () => {
    const args = command({
      paths: ['-dash', 'functions'],
      failOnSeverity: 'high',
      cyberAccessProgram: 'standard',
    });
    expect(args).toContain('--path=./-dash');
    expect(args).toContain('--path=./functions');
    expect(args).toContain('--model=deepseek/deepseek-v4.1-flash');
    expect(after(args, '--fail-on-severity')).toBe('high');
    expect(after(args, '--cyber-access-program')).toBe('standard');
    expect(after(args, '--auth')).toBe('api-key');
    expect(args).toContain('--verbose');
    expect(args).not.toContain('--network');
  });

  it("mounts this run's prompt from its workspace, read-only", () => {
    expect(command()).toContain(`/stage/prompt.md:${C_PROMPT}:ro`);
  });

  it('reads a built knowledge base read-only, with its helper sections and a higher thread cap', () => {
    const args = command({ knowledgeBaseBuilt: true, helperContext: true });
    expect(args).toContain(`/stage/knowledge-base/output:${C_KNOWLEDGE_BASE}:ro`);
    expect(args).toContain(`/stage/knowledge-base/kb:${C_KB_INDEX}:ro`);
    expect(args).toContain(`/stage/helper-context.md:${C_HELPER_CONTEXT}:ro`);
    expect(after(args, '--knowledge-base')).toBe(C_KNOWLEDGE_BASE);
    expect(args).toContain(
      `features.multi_agent_v2.max_concurrent_threads_per_session=${KNOWLEDGE_BASE_MAX_THREADS}`
    );
  });

  it('mounts the helper sections for a diff that has no knowledge base', () => {
    const args = command({ diffBase: 'abc123', helperContext: true });
    expect(after(args, '--diff')).toBe('abc123');
    expect(args).toContain(`/stage/helper-context.md:${C_HELPER_CONTEXT}:ro`);
    expect(args.join(' ')).not.toContain(C_KNOWLEDGE_BASE);
  });

  it("mounts the scan's plugin read-only and gives it to upstream", () => {
    const args = command({ plugin: true });
    expect(args).toContain(`/stage/plugin:${C_PLUGIN}:ro`);
    expect(after(args, '--plugin-path')).toBe(C_PLUGIN);
    expect(command()).not.toContain('--plugin-path');
  });

  it("mounts the caller's rubric and dismissals read-only, and gives upstream the rubric", () => {
    const args = command({ rubric: true, falsePositives: true });
    expect(args).toContain(`/stage/scan-inputs/severity-rubric.md:${C_RUBRIC}:ro`);
    expect(args).toContain(`/stage/scan-inputs/false-positives.json:${C_FALSE_POSITIVES}:ro`);
    expect(after(args, '--rubric')).toBe(C_RUBRIC);
    // upstream has no flag for dismissals: the scan prompt names the file.
    expect(args.join(' ')).not.toContain('--false-positives');
    const plain = command();
    expect(plain).not.toContain('--rubric');
    expect(plain.join(' ')).not.toContain('scan-inputs');
  });

  it('mounts no knowledge base and keeps the thread cap without one', () => {
    const args = command();
    expect(args.join(' ')).not.toContain(C_KNOWLEDGE_BASE);
    expect(args.join(' ')).not.toContain(C_HELPER_CONTEXT);
    expect(args.join(' ')).not.toContain('max_concurrent_threads_per_session');
  });

  it('scans the diff and reads the knowledge base from the mounted checkout', () => {
    const args = command({ diffBase: 'abc123', knowledgeBase: 'docs/threatmodel.md' });
    expect(after(args, '--diff')).toBe('abc123');
    expect(after(args, '--knowledge-base')).toBe(`${C_PROJECT}/docs/threatmodel.md`);
  });

  it("gives upstream both a diff's knowledge base and the repository's own threat model", () => {
    const args = command({
      diffBase: 'abc123',
      knowledgeBase: 'docs/threatmodel.md',
      knowledgeBaseBuilt: true,
    });
    const bases = args.flatMap((a, i) => (args[i - 1] === '--knowledge-base' ? [a] : []));
    expect(bases).toEqual([C_KNOWLEDGE_BASE, `${C_PROJECT}/docs/threatmodel.md`]);
  });

  it('runs a mock scan with no key and no network', () => {
    const args = command({ mock: true });
    expect(args).not.toContain(KEY_VARIABLE);
    expect(args).not.toContain('--auth');
    expect(after(args, '--network')).toBe('none');
    expect(args).toContain('--mock');
  });

  it('runs a dry run with no key and no network, as upstream does', () => {
    const args = command({ dryRun: true });
    expect(args).not.toContain(KEY_VARIABLE);
    expect(args).toContain('--dry-run');
    expect(after(args, '--auth')).toBe('auto');
    expect(after(args, '--network')).toBe('none');
  });

  it('runs the preflight as the real scan with no network', () => {
    const args = command({}, 'preflight');
    expect(args).toContain(KEY_VARIABLE);
    expect(after(args, '--network')).toBe('none');
    expect(after(args, '--auth')).toBe('api-key');
  });

  it('omits verbose when asked', () => {
    expect(command({ verbose: false })).not.toContain('--verbose');
  });
});

describe('prepareWorkspace', () => {
  it("makes the tmpfs's mountpoint and Codex's home the runner's, so Docker does not make them root's", () => {
    // Upstream refuses a Codex home its user does not own.
    const workspace = join(mkdtempSync(join(tmpdir(), 'cs-prepare-')), 'stage');
    prepareWorkspace(workspace);
    const state = join(workspace, 'state');
    for (const directory of ['home', 'codex-home', relative(C_STATE, C_CODEX_TMP)])
      expect(statSync(join(state, directory)).mode & 0o777).toBe(0o700);
  });
});

describe('discardWorkspace', () => {
  // Codex's state holds session transcripts, which can hold credentials: it never outlives the run.
  function stage(): string {
    const workspace = join(mkdtempSync(join(tmpdir(), 'cs-discard-')), 'stage');
    for (const directory of ['state/codex-home', 'out/scan', 'reports'])
      mkdirSync(join(workspace, directory), { recursive: true });
    writeFileSync(join(workspace, 'state', 'codex-home', 'rollout.jsonl'), 'transcript');
    writeFileSync(join(workspace, 'reports', 'results.sarif'), '{}');
    writeFileSync(join(workspace, 'stderr.log'), '');
    // Codex's sandbox can leave read-only directories behind.
    mkdirSync(join(workspace, 'state', 'codex-home', 'sandbox'));
    writeFileSync(join(workspace, 'state', 'codex-home', 'sandbox', 'x'), '');
    chmodSync(join(workspace, 'state', 'codex-home', 'sandbox'), 0o500);
    return workspace;
  }

  it('keeps only the validated reports', () => {
    const workspace = stage();
    discardWorkspace(workspace, true);
    expect(readdirSync(workspace)).toEqual(['reports']);
    expect(readdirSync(join(workspace, 'reports'))).toEqual(['results.sarif']);
  });

  it('deletes everything when the reports held the key', () => {
    const workspace = stage();
    discardWorkspace(workspace, false);
    expect(existsSync(workspace)).toBe(false);
    expect(() => discardWorkspace(workspace, false)).not.toThrow();
  });
});

describe('entrypoint.sh', () => {
  // A codex-security stub shows what the entrypoint would run, and with which key.
  const bin = mkdtempSync(join(tmpdir(), 'cs-entrypoint-'));
  writeFileSync(
    join(bin, 'codex-security'),
    '#!/bin/sh\necho "ran $* key=${CODEX_API_KEY:-none} original=${CYNOS_API_KEY:-unset}"\n'
  );
  chmodSync(join(bin, 'codex-security'), 0o755);
  const entrypoint = resolve(import.meta.dir, '../../assets/entrypoint.sh');
  const run = (args: string[], key?: string) =>
    spawnSync('sh', [entrypoint, ...args], {
      encoding: 'utf8',
      env: { PATH: `${bin}:/usr/bin:/bin`, ...(key ? { CYNOS_API_KEY: key } : {}) },
    });

  it.each([
    ['export', '/scan/out/scan'],
    ['scan', '--mock'],
    ['scan', '--dry-run'],
  ])('runs %s %s without a key', (...args) => {
    const result = run(args);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('key=none');
  });

  it('refuses a scan without a key before codex-security starts', () => {
    const result = run(['scan', '/scan/project']);
    expect(result.status).toBe(2);
    expect(result.stdout).toBe('');
  });

  it('hands the key over as CODEX_API_KEY only', () => {
    expect(run(['scan', '/scan/project'], 'sk-test').stdout).toContain(
      'key=sk-test original=unset'
    );
  });
});

describe('checkKey', () => {
  const calls: { url: string; init: RequestInit }[] = [];
  const answer = (status: number, body: string) => async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Response(body, { status });
  };

  it("posts to the scan's own endpoint with no override headers", async () => {
    calls.length = 0;
    expect(await checkKey('sk-test', 'm', answer(200, '{}'))).toEqual({
      accepted: true,
      answer: 'HTTP 200',
    });
    expect(calls[0]?.url).toBe(`${BASE_URL}/responses`);
    expect(
      Object.keys(calls[0]?.init.headers as Record<string, string>)
        .map(name => name.toLowerCase())
        .sort()
    ).toEqual(['authorization', 'content-type']);
  });

  it('is cut short when the run is stopped', async () => {
    const controller = new AbortController();
    controller.abort('timed out after 1s');
    const signals: (AbortSignal | null | undefined)[] = [];
    const result = await checkKey(
      'sk-test',
      'm',
      async (_url: string, init: RequestInit) => {
        signals.push(init.signal);
        throw new Error('This operation was aborted');
      },
      BASE_URL,
      controller.signal
    );
    expect(signals[0]?.aborted).toBe(true);
    expect(result.accepted).toBe(false);
  });

  it("reports cynos's refusal without the key", async () => {
    const result = await checkKey(
      'sk-test',
      'm',
      answer(403, '{"error": {"message": "Virtual key not found: sk-test"}}')
    );
    expect(result).toEqual({
      accepted: false,
      answer: 'HTTP 403: {"error": {"message": "Virtual key not found: ***"}}',
      refusal: 'key',
    });
  });

  // cynos's own answers, as the production and dev gateways gave them.
  it.each([
    [
      401,
      '{"type":"virtual_key_not_found"}',
      'key',
      /refused the key/,
      /a key belongs to one cynos gateway, and this check used https:\/\/api\.cynos\.averlon\.ai\/v1 \(CYNOS_BASE_URL names another\)/,
    ],
    [
      402,
      '{"type":"budget_exceeded","error":{"message":"Budget exceeded: 0.0000 >= 0.0000 dollars"}}',
      'budget',
      /the key's budget is spent/,
      /Raise the key's budget/,
    ],
    [
      400,
      '{"error":{"message":"could not auto resolve a provider for the request"}}',
      'model',
      /cannot serve the model m/,
      /Choose a model the key may use/,
    ],
    [503, 'upstream connect error', 'gateway', /could not answer the key check/, /Retry later/],
  ] as const)('names HTTP %i (%s) a %s refusal', async (status, body, refusal, failure, fix) => {
    const result = await checkKey('sk-test', 'm', answer(status, body));
    expect(result.refusal).toBe(refusal);
    const reported = keyCheckFailure(result, 'm');
    expect(reported.failure).toMatch(failure);
    expect(reported.failure).toContain(`HTTP ${status}`);
    expect(reported.fix).toMatch(fix);
  });

  it('names a gateway it cannot reach, with the base URL', async () => {
    const result = await checkKey(
      'sk-test',
      'm',
      async () => {
        throw new Error('getaddrinfo ENOTFOUND gw');
      },
      'https://gw/v1'
    );
    expect(result.refusal).toBe('unreachable');
    expect(keyCheckFailure(result, 'm', 'https://gw/v1').failure).toBe(
      'cynos is unreachable at https://gw/v1 (unreachable: getaddrinfo ENOTFOUND gw)'
    );
  });
});

describe("whether upstream's AppArmor profile is loaded", () => {
  const PROFILE = 'codex-security-container (enforce)';
  const probes: string[][] = [];
  const docker = (status: number) => (command: string, args: string[]) => {
    probes.push([command, ...args]);
    return { status, stdout: '', stderr: '' };
  };

  it("reads the kernel's list when it can", () => {
    probes.length = 0;
    expect(
      appArmorProfileLoaded('img', docker(1), () => `docker-default (enforce)\n${PROFILE}\n`)
    ).toBe(true);
    expect(appArmorProfileLoaded('img', docker(0), () => 'docker-default (enforce)\n')).toBe(false);
    expect(probes).toEqual([]);
  });

  it("asks Docker when the list is root's to read: it refuses a profile that is not loaded", () => {
    probes.length = 0;
    expect(appArmorProfileLoaded('img', docker(0), () => undefined)).toBe(true);
    expect(appArmorProfileLoaded('img', docker(125), () => undefined)).toBe(false);
    expect(probes[0]).toContain('apparmor=codex-security-container');
    expect(probes[0]?.slice(-1)).toEqual(['img']);
  });
});

describe("the scanner image is the Docker host's platform", () => {
  // Docker Desktop on Apple silicon, with DOCKER_DEFAULT_PLATFORM=linux/amd64 in the shell: an
  // amd64 image would run emulated, and Codex's sandbox cannot install its seccomp filter there.
  const appleSilicon = (calls: string[][]) => (command: string, args: string[]) => {
    calls.push([command, ...args]);
    const version = args[0] === 'version';
    return { status: 0, stdout: version ? 'linux/arm64\n' : '', stderr: '' };
  };

  it('builds it for that platform', () => {
    const calls: string[][] = [];
    const assets = mkdtempSync(join(tmpdir(), 'cynos-scan-assets-'));
    provideImage(assets, appleSilicon(calls));
    expect(calls.find(c => c[1] === 'build')?.slice(0, 4)).toEqual([
      'docker',
      'build',
      '--platform',
      'linux/arm64',
    ]);
  });

  it("pulls the release's image for that platform", () => {
    const calls: string[][] = [];
    const assets = mkdtempSync(join(tmpdir(), 'cynos-scan-assets-'));
    writeFileSync(
      join(assets, 'image.json'),
      JSON.stringify({ image: 'ghcr.io/example/scanner', digest: `sha256:${'a'.repeat(64)}` })
    );
    provideImage(assets, appleSilicon(calls));
    expect(calls.find(c => c[1] === 'pull')).toEqual([
      'docker',
      'pull',
      '--platform',
      'linux/arm64',
      `ghcr.io/example/scanner@sha256:${'a'.repeat(64)}`,
    ]);
  });
});

describe("upstream's bundled plugin comes from the image", () => {
  // The GitHub action bundles the engine without @openai/codex-security: its runner has upstream
  // only in the image, so the scan's plugin cannot come from the host.
  const image =
    (version: string, failing?: string) =>
    (calls: string[][]) =>
    (command: string, args: string[]) => {
      calls.push([command, ...args]);
      const [verb, from, to] = args;
      if (verb === 'cp' && from?.endsWith(`/${failing}`))
        return { status: 1, stdout: '', stderr: 'no such path' };
      if (verb === 'cp' && to && from?.endsWith('/package.json'))
        writeFileSync(to, JSON.stringify({ version }));
      if (verb === 'cp' && to && from?.endsWith('/_bundled_plugin')) {
        mkdirSync(join(to, 'skills'), { recursive: true });
        writeFileSync(join(to, 'skills', 'marker'), '');
      }
      return { status: 0, stdout: '', stderr: '' };
    };

  it('copies it out of a container that is created, never started, and removed', () => {
    const calls: string[][] = [];
    const dir = join(mkdtempSync(join(tmpdir(), 'cynos-scan-stage-')), 'upstream-plugin');
    const plugin = copyBundledPlugin('img', dir, 'run-plugin', image(UPSTREAM_PIN.version)(calls));
    expect(plugin).toBe(join(dir, '_bundled_plugin'));
    expect(existsSync(join(plugin, 'skills', 'marker'))).toBe(true);
    expect(calls).toEqual([
      ['docker', 'create', '--name', 'run-plugin', 'img'],
      ['docker', 'cp', `run-plugin:${C_UPSTREAM}/package.json`, join(dir, 'package.json')],
      ['docker', 'cp', `run-plugin:${C_UPSTREAM}/_bundled_plugin`, join(dir, '_bundled_plugin')],
      ['docker', 'rm', '--force', 'run-plugin'],
    ]);
  });

  it('removes the container when a copy fails', () => {
    const calls: string[][] = [];
    const dir = join(mkdtempSync(join(tmpdir(), 'cynos-scan-stage-')), 'upstream-plugin');
    expect(() =>
      copyBundledPlugin(
        'img',
        dir,
        'run-plugin',
        image(UPSTREAM_PIN.version, '_bundled_plugin')(calls)
      )
    ).toThrow("docker cp of upstream's _bundled_plugin failed: no such path");
    expect(calls.at(-1)).toEqual(['docker', 'rm', '--force', 'run-plugin']);
  });

  it("refuses an image whose upstream is not the pin's", () => {
    const dir = join(mkdtempSync(join(tmpdir(), 'cynos-scan-stage-')), 'upstream-plugin');
    expect(() => copyBundledPlugin('img', dir, 'run-plugin', image('0.0.1')([]))).toThrow(
      `${UPSTREAM_PIN.package} in img is 0.0.1, not the pinned ${UPSTREAM_PIN.version}.`
    );
  });
});
