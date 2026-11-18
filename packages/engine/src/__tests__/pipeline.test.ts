import { describe, it, expect } from 'bun:test';
import type { ChildProcess } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { resolve } from 'node:path';
import { BASE_URL, C_HELPER_CONTEXT, C_OUT, C_PROJECT, REASONING_EFFORTS } from '../constants';
import { checkKey } from '../key-check';
import { readScanPrompt, runPrompt } from '../prompt-template';
import {
  agentCommand,
  bind,
  dockerScanCommand,
  graphContainerCommand,
  hostPath,
  type ContainerPlan,
  type DockerAgentPlan,
  type HostPaths,
} from '../runtime/docker';
import { providerOverrides, type ScanOptions } from '../scan-command';
import { CynosChat } from '../knowledge-base/cynos';
import {
  containerNames,
  knowledgePhase,
  redact,
  requireEffort,
  requireKeys,
  scanCheckout,
  scanOptions,
} from '../pipeline';
import type { ScanEvent } from '../progress';
import type { RuntimeCommand } from '../runtime';
import { scanReachesScanning } from '../sandbox';
import { DockerRuntime as Docker } from '../runtime/docker';
import type { KnowledgeBaseStore } from '../knowledge-base/store';
import { gitCheckout, gitCommit, gitHead } from './knowledge-base-fakes';

const ASSETS = resolve(import.meta.dir, '../../assets');
/** The harness sees its output mount at /srv/out; the Docker host has it at /data/arm/out. */
const HOST_PATHS: HostPaths = [['/srv/out', '/data/arm/out']];
const GATEWAY = 'https://gateway.example/openai/v1';

const PLAN: ContainerPlan = {
  name: 'rv-test',
  image: 'cynos-scan-scanner:0.9.1',
  actionRoot: '/opt/actions/assets',
  project: '/srv/out/stage/project',
  workspace: '/srv/out/stage/out',
  apparmor: false,
  uid: 10001,
  gid: 10001,
  hostPaths: HOST_PATHS,
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
  verbose: false,
  dryRun: false,
  mock: false,
  knowledgeBaseBuilt: true,
  helperContext: true,
  plugin: true,
  rubric: false,
  falsePositives: false,
  judge: false,
  taskRouting: false,
  baseUrl: GATEWAY,
};

/** The source of every bind mount in a docker command. */
function mountSources(args: string[]): string[] {
  return args.flatMap((arg, i) => (args[i - 1] === '-v' ? [arg.split(':')[0] ?? ''] : []));
}

describe('the preflight scan', () => {
  it('is stopped when the run is, as its own deadline would stop it', async () => {
    const controller = new AbortController();
    const stopped: string[] = [];
    const child = Object.assign(new EventEmitter(), { stderr: new EventEmitter() });
    const runtime = {
      spawn: () => {
        setTimeout(() => controller.abort('timed out after 1s'), 10);
        return child as unknown as ChildProcess;
      },
      stop: async (name: string) => {
        stopped.push(name);
        child.emit('close', 137);
      },
    };
    const command = { name: 'cs-run-preflight', argv: ['true'] } as RuntimeCommand;
    const result = await scanReachesScanning(command, runtime, controller.signal);
    expect(result.reached).toBe(false);
    expect(stopped).toEqual(['cs-run-preflight']);
  });
});

describe('mounts through the host', () => {
  it('rewrites a path under a mapped directory, and leaves any other path alone', () => {
    expect(hostPath('/srv/out/stage/project', HOST_PATHS)).toBe('/data/arm/out/stage/project');
    expect(hostPath('/srv/out', HOST_PATHS)).toBe('/data/arm/out');
    expect(hostPath('/srv/outside/x', HOST_PATHS)).toBe('/srv/outside/x');
    expect(hostPath('/srv/out/x')).toBe('/srv/out/x');
    // Either side may be the root.
    expect(hostPath('/out', [['/out', '/']])).toBe('/');
    expect(hostPath('/out/stage/project', [['/out', '/']])).toBe('/stage/project');
    expect(hostPath('/stage/project', [['/', '/host/root']])).toBe('/host/root/stage/project');
    expect(bind('/srv/out/a', '/scan/a', HOST_PATHS)).toEqual(['-v', '/data/arm/out/a:/scan/a:ro']);
    expect(bind('/srv/out/a', '/scan/a', HOST_PATHS, true)).toEqual([
      '-v',
      '/data/arm/out/a:/scan/a',
    ]);
  });

  it('mounts every source of the scan, the code graph and the review agent at its host path', () => {
    const scan = dockerScanCommand(PLAN, OPTIONS, 'scan');
    expect(scan).toContain(`/data/arm/out/stage/project:${C_PROJECT}:ro`);
    expect(scan).toContain(`/data/arm/out/stage/out/out:${C_OUT}`);
    expect(scan).toContain(`/data/arm/out/stage/out/helper-context.md:${C_HELPER_CONTEXT}:ro`);
    const graph = graphContainerCommand({ ...PLAN, home: '/srv/out/stage/out/kb/graph' });
    const agent: DockerAgentPlan = {
      ...PLAN,
      work: '/srv/out/stage/out/kb/review',
      cynosKey: 'sk-test-value',
      modelCatalog: '/srv/out/stage/out/model-catalog.json',
    };
    for (const args of [scan, graph, agentCommand(agent)]) {
      expect(mountSources(args).length).toBeGreaterThan(1);
      for (const source of mountSources(args))
        expect(source.startsWith('/data/arm/out/')).toBe(true);
    }
  });

  it('keeps the seccomp profile at its own path: the Docker CLI reads it, not the daemon', () => {
    const scan = dockerScanCommand(PLAN, OPTIONS, 'scan');
    expect(scan).toContain('seccomp=/opt/actions/assets/codex-security-seccomp.json');
  });

  it("gives the action's commands unchanged when nothing is mapped", () => {
    const { hostPaths: _, ...onHost } = PLAN;
    expect(dockerScanCommand(onHost, OPTIONS, 'scan')).toContain(
      `/srv/out/stage/project:${C_PROJECT}:ro`
    );
  });
});

describe("a benchmark's gateway", () => {
  it('reaches the scan, the review agent, the review calls and the key check', async () => {
    expect(providerOverrides(OPTIONS).join(' ')).toContain(`base_url="${GATEWAY}"`);
    expect(providerOverrides({ judge: true, taskRouting: true }).join(' ')).toContain(
      `base_url="${BASE_URL}"`
    );
    const agent: DockerAgentPlan = { ...PLAN, work: '/w', cynosKey: 'k', baseUrl: GATEWAY };
    expect(agentCommand(agent).join(' ')).toContain(`base_url="${GATEWAY}"`);
    const urls: string[] = [];
    const fetcher = async (url: string) => {
      urls.push(url);
      return new Response(JSON.stringify({ choices: [{ message: { content: '{}' } }] }));
    };
    await new CynosChat('k', fetcher, async () => {}, GATEWAY).chatJson('m', 's', 'u');
    await checkKey('k', 'm', fetcher, GATEWAY);
    expect(urls).toEqual([`${GATEWAY}/chat/completions`, `${GATEWAY}/responses`]);
  });

  it('switches the judge and task routing off as the benchmark asks', () => {
    const joined = providerOverrides(OPTIONS).join(' ');
    expect(joined).toContain('"x-cy-eh-domain-expert-judge"="off"');
    expect(joined).toContain('"x-cy-eh-task-route"="off"');
  });
});

describe('the run prompt', () => {
  const parts = readScanPrompt(ASSETS, 'full');
  // A benchmark's addendum: one section for the lead alone, two marked for every helper.
  const addendum = [
    '## Benchmark scan: the lead only',
    '',
    'Submit every merged finding.',
    '',
    '<!-- helper-context -->',
    '',
    '## Benchmark scan: what to report',
    '',
    '- Every vulnerable operation.',
    '',
    '<!-- helper-context -->',
    '',
    '## Benchmark scan: locate every affected line',
    '',
    '- A `sink` location at each dangerous call.',
    '',
  ].join('\n');

  it('is the full-scan plan alone without an addendum', () => {
    expect(runPrompt(parts).text).not.toContain('Benchmark scan');
  });

  it('ends with the addendum, whose marked section reaches every helper', () => {
    const prompt = runPrompt(parts, addendum);
    expect(prompt.text.endsWith(`${addendum.trim()}\n`)).toBe(true);
    expect(prompt.helperContext.startsWith(parts.helper.trimEnd())).toBe(true);
    expect(prompt.helperContext).toContain('## Benchmark scan: what to report');
    expect(prompt.helperContext).toContain('## Benchmark scan: locate every affected line');
    expect(prompt.helperContext).not.toContain('the lead only');
    expect(runPrompt(parts).helperContext).not.toContain('Benchmark scan');
  });
});

describe('scanCheckout', () => {
  const io = { log: () => {}, warn: () => {}, error: () => {} };
  const config = {
    ...OPTIONS,
    kind: 'full' as const,
    diffBase: '',
    project: '/nonexistent/project',
    stage: '/nonexistent/stage',
    runtime: 'docker' as const,
    stateDir: 'upstream-default',
    interactive: false,
    publishes: true,
    assets: ASSETS,
    runName: 'rv-test',
    scannedSha: 'c'.repeat(40),
    knowledgeBase: '',
    buildImage: false,
    loadAppArmor: false,
  };

  it('refuses a scan that calls the model without the cynos key, before touching anything', async () => {
    await expect(scanCheckout(config, io)).rejects.toThrow('needs the cynos key');
  });

  it('refuses an effort nothing downstream would reject, before touching anything', async () => {
    await expect(scanCheckout({ ...config, cynosKey: 'k', effort: 'bogus' }, io)).rejects.toThrow(
      'The reasoning effort must be one of none, minimal, low, medium, high, xhigh, max, not "bogus".'
    );
    for (const effort of REASONING_EFFORTS) expect(() => requireEffort(effort)).not.toThrow();
  });

  it("builds a full scan's knowledge base with the cynos key alone", () => {
    expect(requireKeys({ ...config, cynosKey: 'k' })).toEqual({
      cynos: 'k',
      callsModel: true,
      buildsBase: true,
      all: ['k'],
    });
  });

  it('runs a full scan without a knowledge base when asked', async () => {
    const off = { ...config, cynosKey: 'k', buildKnowledgeBase: false };
    expect(requireKeys(off)).toMatchObject({ callsModel: true, buildsBase: false });
    const events: ScanEvent[] = [];
    const runtime = new Docker({ assets: ASSETS });
    const knowledge = await knowledgePhase(
      off,
      runtime.layout(off.stage, off.project, 'scan'),
      runtime,
      requireKeys(off),
      { ...io, progress: event => events.push(event) }
    );
    expect(knowledge).toEqual({ summary: undefined, diffThreatModel: undefined });
    expect(events).toEqual([
      { type: 'phase', phase: 'knowledge', status: 'skipped', detail: 'disabled' },
    ]);
    // Our workflow reads the knowledge base's index and briefs: without one, upstream runs its own.
    expect(scanOptions(off, knowledge, true).plugin).toBe(false);
    expect(scanOptions(off, { ...knowledge, summary: {} as never }, true).plugin).toBe(true);
  });

  it("builds a diff's knowledge base too, and fails the run when the build fails", async () => {
    const diff = { ...config, kind: 'diff' as const, diffBase: 'a'.repeat(40), cynosKey: 'k' };
    expect(requireKeys(diff)).toMatchObject({ callsModel: true, buildsBase: true });
    const warnings: string[] = [];
    const runtime = new Docker({ assets: ASSETS });
    // No store, so no stored review: the build would review the whole repository, and fails on a
    // stage it cannot write.
    await expect(
      knowledgePhase(
        diff,
        runtime.layout(diff.stage, diff.project, 'scan'),
        runtime,
        requireKeys(diff),
        { ...io, warn: m => warnings.push(m) }
      )
    ).rejects.toThrow('The knowledge base could not be built, so no scan was started: ');
    expect(warnings).toEqual([]);
  });

  it("prefers a diff base's snapshot only when the base is in HEAD's history", async () => {
    // main at m1, the branch's base; the branch at head; main moved on to m2, outside its history.
    const project = gitCheckout({ 'a.py': 'a = 1\n' });
    const m1 = gitHead(project);
    const head = gitCommit(project, { 'a.py': 'a = 2\n' });
    const runtime = new Docker({ assets: ASSETS });
    const preferredFor = async (diffBase: string): Promise<string[]> => {
      const preferred: string[][] = [];
      const store: KnowledgeBaseStore = {
        restore: async (_dir, _sha, wanted) => {
          preferred.push(wanted);
          return undefined;
        },
        save: async () => {},
      };
      const diff = {
        ...config,
        kind: 'diff' as const,
        project,
        scannedSha: head,
        diffBase,
        cynosKey: 'k',
      };
      // The build then fails on the stage it cannot write; only the restore is checked.
      await knowledgePhase(
        diff,
        runtime.layout(diff.stage, diff.project, 'scan'),
        runtime,
        requireKeys(diff),
        { ...io, knowledgeBaseStore: store }
      ).catch(() => {});
      return preferred.flat();
    };
    expect(await preferredFor(m1)).toEqual([m1]);
    expect(await preferredFor('f'.repeat(40))).toEqual([]);
  });

  it('refuses a number of hypothesis packets that is not whole before anything starts', async () => {
    for (const maxHypothesisPackets of [-1, 1.5])
      await expect(
        scanCheckout({ ...config, cynosKey: 'k', maxHypothesisPackets }, io)
      ).rejects.toThrow('maxHypothesisPackets must be a whole number');
  });

  it('names every container it may start, so a stopped caller can stop them', () => {
    expect(containerNames('rv-test')).toEqual([
      'rv-test-preflight',
      'rv-test-knowledge-base',
      'rv-test-knowledge-base-review',
      'rv-test',
    ]);
  });

  it('redacts every key it holds', () => {
    expect(redact('a sk-1 b or-2 c', ['sk-1', undefined, 'or-2'])).toBe('a *** b *** c');
  });
});
