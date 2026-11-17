import { describe, it, expect } from 'bun:test';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  checkHost,
  fixHost,
  LINUX_SANDBOX_FIX,
  nodeInRange,
  type HostCheck,
  type HostDeps,
} from '../host-check';
import type { Run } from '../processes';
import { UPSTREAM_PIN, type Upstream } from '../upstream';

const ASSETS = resolve(import.meta.dir, '../../assets');
const UPSTREAM: Upstream = {
  root: '/opt/cli/node_modules/@openai/codex-security',
  bin: '/opt/cli/node_modules/@openai/codex-security/bin/codex-security.mjs',
  version: UPSTREAM_PIN.version,
  codex: {
    executable: '/opt/codex',
    toolsDir: '/opt/codex-path',
    version: UPSTREAM_PIN.codexVersion,
  },
};

type Answer = Partial<Run>;
/** A runner that answers by command line ("git -C /p status --porcelain"), recording each call. */
function runner(answers: Record<string, Answer>, calls: string[] = []): HostDeps['run'] {
  return (command, args) => {
    const line = [command, ...args].join(' ');
    calls.push(line);
    const key = Object.keys(answers).find(prefix => line.startsWith(prefix));
    const answer = key ? answers[key] : { status: 127, stderr: `${command}: not found` };
    return { status: 0, stdout: '', stderr: '', ...answer };
  };
}

/** A healthy macOS laptop with everything installed. */
function laptop(
  overrides: Partial<HostDeps> = {},
  answers: Record<string, Answer> = {}
): Partial<HostDeps> {
  return {
    run: runner({
      'git -C /work/app rev-parse --is-inside-work-tree': { stdout: 'true\n' },
      'git -C /work/app status --porcelain': { stdout: '' },
      'git -C /work/app rev-parse --is-shallow-repository': { stdout: 'false\n' },
      'git --version': { stdout: 'git version 2.44.0\n' },
      'python3 --version': { stdout: 'Python 3.12.1\n' },
      'python3 -I -c': { stdout: 'codex-security-python-ok\n' },
      '/opt/codex sandbox -- /usr/bin/true': { status: 0 },
      'docker version --format {{.Server.Os}}/{{.Server.Arch}}': { stdout: 'linux/arm64\n' },
      'docker version': { stdout: '27.3.1\n' },
      'docker info --format {{.OperatingSystem}}': { stdout: 'Docker Desktop|8|8589934592\n' },
      'docker image inspect': { stdout: 'sha256:0123456789abcdef0123 linux/arm64\n' },
      'docker run': { status: 0 },
      ...answers,
    }),
    fetch: async () => new Response('{}', { status: 200 }),
    env: { HOME: '/Users/dev' },
    platform: 'darwin',
    isBun: false,
    nodeVersion: () => 'v24.5.0',
    resolveUpstream: () => UPSTREAM,
    stat: () => ({ mode: 0o40700, uid: 501, isDirectory: true }),
    realpath: path => path,
    readFile: () => undefined,
    codeGraphState: () => ({ status: 'ok', binary: '/Users/dev/.cache/averlon/tools/cbm' }),
    uid: 501,
    ...overrides,
  };
}

const byId = (checks: HostCheck[]): Record<string, HostCheck> =>
  Object.fromEntries(checks.map(check => [check.id, check]));

describe('checkHost for the native runtime', () => {
  const doctor = {
    scope: 'doctor' as const,
    runtime: 'native' as const,
    project: '/work/app',
    assets: ASSETS,
  };

  it('passes a healthy machine, common checks first', async () => {
    const checks = await checkHost(doctor, laptop());
    expect(checks.map(c => `${c.group}:${c.id}:${c.status}`)).toEqual([
      'common:node:ok',
      'common:upstream:ok',
      'common:state-dir:ok',
      'common:checkout:ok',
      'native:python:ok',
      'native:git:ok',
      'native:sandbox:ok',
      'native:code-graph:ok',
    ]);
    // upstream defaults CODEX_HOME to the OS home, as resolveStateDir does.
    expect(byId(checks)['state-dir']?.detail).toBe(
      join(homedir(), '.codex/state/plugins/codex-security')
    );
    expect(byId(checks)['sandbox']?.title).toContain('Seatbelt');
  });

  it("fails a Node outside upstream's engines range, and warns when the host is Bun", async () => {
    expect([
      nodeInRange('v20.20.2'),
      nodeInRange('v22.12.0'),
      nodeInRange('v22.13.0'),
      nodeInRange('v26.1.0'),
    ]).toEqual([false, false, true, true]);
    expect(
      byId(await checkHost(doctor, laptop({ nodeVersion: () => 'v20.20.2' })))['node']?.status
    ).toBe('fail');
    // The docker runtime's scan runs the image's Node.
    const docker = { ...doctor, runtime: 'docker' as const };
    expect(
      byId(await checkHost(docker, laptop({ nodeVersion: () => 'v20.20.2' })))['node']?.status
    ).toBe('warn');
    const bun = byId(await checkHost(doctor, laptop({ isBun: true })))['node'];
    expect(bun?.status).toBe('warn');
    expect(bun?.fix).toContain('Node, not Bun');
  });

  it('fails a missing or unpinned upstream natively, and only warns for docker', async () => {
    const missing = laptop({
      resolveUpstream: () => {
        throw new Error('@openai/codex-security is not installed');
      },
    });
    expect(byId(await checkHost(doctor, missing))['upstream']?.status).toBe('fail');
    expect(
      byId(await checkHost({ ...doctor, runtime: 'docker' }, missing))['upstream']?.status
    ).toBe('warn');
    const wrong = laptop({ resolveUpstream: () => ({ ...UPSTREAM, version: '999.0.0' }) });
    expect(byId(await checkHost(doctor, wrong))['upstream']?.detail).toContain(
      `not the pinned ${UPSTREAM_PIN.version}`
    );
  });

  it('fails a state dir inside the checkout, under /tmp on macOS, or shared', async () => {
    const state = async (stateDir: string, overrides: Partial<HostDeps> = {}) =>
      byId(await checkHost({ ...doctor, stateDir }, laptop(overrides)))['state-dir'];
    expect((await state('/work/app/.state'))?.status).toBe('fail');
    expect((await state('/tmp/state'))?.detail).toContain('openai/codex#32395');
    expect((await state('/var/s', { realpath: () => '/private/tmp/s' }))?.status).toBe('fail');
    expect(
      (await state('/srv/s', { stat: () => ({ mode: 0o40755, uid: 501, isDirectory: true }) }))?.fix
    ).toBe('chmod 700 /srv/s');
    expect(
      (await state('/srv/s', { stat: () => ({ mode: 0o40700, uid: 0, isDirectory: true }) }))
        ?.status
    ).toBe('fail');
    expect((await state('/srv/s', { stat: () => undefined }))?.status).toBe('ok');
  });

  it('warns about a dirty or shallow checkout, and fails one that is not git', async () => {
    const dirty = laptop(
      {},
      { 'git -C /work/app status --porcelain': { stdout: ' M a.py\n?? b.py\n' } }
    );
    expect(byId(await checkHost(doctor, dirty))['checkout']?.detail).toContain(
      '2 uncommitted changes'
    );
    const shallow = laptop(
      {},
      { 'git -C /work/app rev-parse --is-shallow-repository': { stdout: 'true\n' } }
    );
    expect(byId(await checkHost(doctor, shallow))['checkout']?.fix).toContain('--unshallow');
    const none = laptop(
      {},
      { 'git -C /work/app rev-parse --is-inside-work-tree': { status: 128 } }
    );
    expect(byId(await checkHost(doctor, none))['checkout']?.status).toBe('fail');
  });

  it("fails a Python upstream's plugin cannot use, with the fix for it", async () => {
    const old = laptop(
      {},
      { 'python3 --version': { stdout: 'Python 3.9.6\n' }, 'python3 -I -c': { status: 1 } }
    );
    expect(byId(await checkHost(doctor, old))['python']?.fix).toBe('Install Python 3.11 or later.');
    const noTomli = laptop(
      {},
      { 'python3 --version': { stdout: 'Python 3.10.12\n' }, 'python3 -I -c': { status: 1 } }
    );
    expect(byId(await checkHost(doctor, noTomli))['python']?.fix).toBe(
      'python3 -m pip install tomli'
    );
  });

  it('names what stops Bubblewrap on Linux, with the exact fix', async () => {
    const linux = laptop(
      {
        platform: 'linux',
        readFile: path =>
          path === '/proc/sys/kernel/apparmor_restrict_unprivileged_userns' ? '1\n' : undefined,
      },
      {
        '/opt/codex sandbox -- /usr/bin/true': {
          status: 1,
          stderr: 'bwrap: setting up uid map: Permission denied',
        },
        'bwrap --version': { stdout: 'bubblewrap 0.9.0' },
      }
    );
    const sandbox = byId(await checkHost(doctor, linux))['sandbox'];
    expect(sandbox?.status).toBe('fail');
    expect(sandbox?.detail).toContain('kernel.apparmor_restrict_unprivileged_userns=1');
    expect(sandbox?.fix).toBe(LINUX_SANDBOX_FIX);
    expect(LINUX_SANDBOX_FIX).toContain('apt-get install --yes bubblewrap apparmor-profiles');
    expect(LINUX_SANDBOX_FIX).toContain(
      'apparmor_parser -r /usr/share/apparmor/extra-profiles/bwrap-userns-restrict'
    );
  });

  it('offers to download a missing code-graph binary', async () => {
    const missing = laptop({ codeGraphState: () => ({ status: 'missing', binary: '/c/cbm' }) });
    const check = byId(await checkHost(doctor, missing))['code-graph'];
    expect([check?.status, check?.fix]).toEqual(['warn', 'cynos doctor --fix']);
  });

  it("checks the key with cynos's 16-token request, and makes no other call", async () => {
    const urls: string[] = [];
    const fetch: HostDeps['fetch'] = async url => {
      urls.push(url);
      return new Response('{"error":"Virtual key not found: sk-bad"}', { status: 401 });
    };
    const checks = byId(
      await checkHost(
        { ...doctor, cynosKey: 'sk-bad', baseUrl: 'https://gw/v1' },
        laptop({ fetch })
      )
    );
    expect(urls).toEqual(['https://gw/v1/responses']);
    expect(checks['cynos']?.status).toBe('fail');
    expect(checks['cynos']?.detail).not.toContain('sk-bad');
  });

  it('gives a spent budget its own fix, not a new key', async () => {
    const fetch: HostDeps['fetch'] = async () =>
      new Response('{"type":"budget_exceeded"}', { status: 402 });
    const checks = byId(await checkHost({ ...doctor, cynosKey: 'sk-ok' }, laptop({ fetch })));
    expect(checks['cynos']?.status).toBe('fail');
    expect(checks['cynos']?.detail).toContain("the key's budget is spent");
    expect(checks['cynos']?.fix).toBe("Raise the key's budget in cynos, or use another key.");
  });

  it("leaves to the scan's preflight what it runs itself, and makes no network call", async () => {
    const calls: string[] = [];
    let fetched = 0;
    const checks = await checkHost(
      { ...doctor, scope: 'scan', cynosKey: 'k' },
      laptop({
        run: runner(
          {
            'git -C /work/app rev-parse --is-inside-work-tree': { stdout: 'true\n' },
            python3: { stdout: 'codex-security-python-ok\n' },
            'git --version': { stdout: 'git 2' },
          },
          calls
        ),
        fetch: async () => (fetched++, new Response('{}')),
      })
    );
    expect(checks.map(c => c.id)).toEqual([
      'node',
      'upstream',
      'state-dir',
      'checkout',
      'python',
      'git',
    ]);
    expect(fetched).toBe(0);
    expect(calls.some(c => c.includes('sandbox'))).toBe(false);
  });
});

describe('checkHost for the docker runtime', () => {
  const doctor = { scope: 'doctor' as const, runtime: 'docker' as const, assets: ASSETS };

  it('checks the daemon, the image and the seccomp profile', async () => {
    const checks = byId(await checkHost(doctor, laptop()));
    expect(checks['docker-daemon']?.detail).toBe('server 27.3.1, Docker Desktop, 8 CPUs, 8 GiB');
    expect(checks['docker-image']?.detail).toContain(`cynos-scan-scanner:${UPSTREAM_PIN.version}`);
    expect(checks['docker-seccomp']?.status).toBe('ok');
    expect(checks['docker-apparmor']).toBeUndefined();
  });

  it("fails when the image is another platform's than the Docker host's, which runs it emulated", async () => {
    const amd64 = laptop(
      {},
      { 'docker image inspect': { stdout: 'sha256:0123456789abcdef0123 linux/amd64\n' } }
    );
    const check = byId(await checkHost(doctor, amd64))['docker-image'];
    expect(check?.status).toBe('fail');
    expect(check?.detail).toContain('is linux/amd64, but this Docker host runs linux/arm64');
    expect(check?.fix).toBe('cynos doctor --runtime docker --fix');
  });

  it("runs upstream's container check without DOCKER_DEFAULT_PLATFORM, which names another platform's image", async () => {
    const saved = process.env['DOCKER_DEFAULT_PLATFORM'];
    process.env['DOCKER_DEFAULT_PLATFORM'] = 'linux/amd64';
    const envs: (NodeJS.ProcessEnv | undefined)[] = [];
    const deps = laptop();
    const run = deps.run!;
    try {
      await checkHost(doctor, {
        ...deps,
        run: (command, args, env) => {
          if (args[0] === 'run') envs.push(env);
          return run(command, args, env);
        },
      });
    } finally {
      if (saved === undefined) delete process.env['DOCKER_DEFAULT_PLATFORM'];
      else process.env['DOCKER_DEFAULT_PLATFORM'] = saved;
    }
    expect(envs.length).toBeGreaterThan(0);
    for (const env of envs) {
      expect(env).toBeDefined();
      expect(env?.['DOCKER_DEFAULT_PLATFORM']).toBeUndefined();
    }
  });

  it('fails when the daemon is down or the image is missing', async () => {
    const down = laptop(
      {},
      {
        'docker version': { status: 1, stderr: 'Cannot connect to the Docker daemon' },
        'docker image inspect': { status: 1 },
      }
    );
    const checks = byId(await checkHost(doctor, down));
    expect(checks['docker-daemon']?.status).toBe('fail');
    expect(checks['docker-image']?.fix).toContain('--fix');
  });

  it("asks for upstream's AppArmor profile on Linux when user namespaces are restricted", async () => {
    const linux = laptop(
      {
        platform: 'linux',
        readFile: path =>
          path === '/proc/sys/kernel/apparmor_restrict_unprivileged_userns' ? '1\n' : undefined,
      },
      {
        'docker info --format {{json .SecurityOptions}}': {
          stdout: '["name=apparmor","name=seccomp"]',
        },
      }
    );
    const check = byId(await checkHost(doctor, linux))['docker-apparmor'];
    expect(check?.status).toBe('fail');
    expect(check?.fix).toContain('sudo');
  });

  it("asks Docker whether the profile is loaded when the kernel's list is root's to read", async () => {
    const calls: string[] = [];
    const answers = {
      'docker info --format {{json .SecurityOptions}}': { stdout: '["name=apparmor"]' },
      'docker container run': { status: 0 },
    };
    // The list reads as nothing to the user; Docker starts a container under the profile.
    const linux = laptop({ platform: 'linux', readFile: () => undefined }, answers);
    const run = linux.run!;
    const recorded: HostDeps['run'] = (command, args) => {
      calls.push([command, ...args].join(' '));
      return run(command, args);
    };
    const checks = byId(await checkHost(doctor, { ...linux, run: recorded }));
    expect(checks['docker-apparmor']?.status).toBe('ok');
    expect(calls).toContainEqual(
      expect.stringContaining('--security-opt apparmor=codex-security-container')
    );
    // The seccomp check then runs upstream's container check under the profile, as a scan does.
    expect(
      calls.some(
        line => line.startsWith('docker run') && line.includes('apparmor=codex-security-container')
      )
    ).toBe(true);
  });
});

describe('fixHost', () => {
  it('never runs sudo unless the caller allows it', async () => {
    const calls: string[] = [];
    await expect(
      fixHost(
        'docker-apparmor',
        { scope: 'doctor', runtime: 'docker', assets: ASSETS },
        laptop({ run: runner({}, calls) })
      )
    ).rejects.toThrow('runs sudo');
    expect(calls.filter(c => c.startsWith('sudo'))).toEqual([]);
  });

  it('loads the profile through sudo when allowed', async () => {
    const calls: string[] = [];
    const run = runner(
      { 'docker info': { stdout: '["name=apparmor"]' }, sudo: { status: 0 } },
      calls
    );
    await fixHost(
      'docker-apparmor',
      { scope: 'doctor', runtime: 'docker', assets: ASSETS, allowSudo: true },
      laptop({ platform: 'linux', run })
    );
    expect(calls.filter(c => c.startsWith('sudo')).map(c => c.split(' ')[1])).toEqual([
      'install',
      'apparmor_parser',
      'grep',
    ]);
  });

  it('refuses a check it cannot fix', async () => {
    await expect(
      fixHost('python', { scope: 'doctor', runtime: 'native' }, laptop())
    ).rejects.toThrow('cannot be fixed automatically');
  });
});
