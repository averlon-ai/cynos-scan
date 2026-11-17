/**
 * The knowledge base: a full scan's code map, packets and helper briefs, built before the scan.
 *
 * A scan otherwise spends most of its turns finding and reading code. Its helpers list, search
 * and read in small pieces; the lead maps the repository before it starts any helper; and on a
 * larger repository it reads only part of the code while reporting complete coverage. Each turn
 * costs about 20 seconds at cynos however little it does. This step does that work once, outside
 * the model's turns:
 *
 *   1  files        every file of the checkout with its kind (inventory.ts)
 *   2  code graph   functions and calls from codebase-memory-mcp, on the scan's runtime
 *                   (code-graph.ts)
 *   3  plan         Jev labels, the architecture review and one packet design: entry points,
 *                   sinks, secret windows, packets, the baseline (plan.ts)
 *   4  output       the lead's index and the threat model in <work>/output, and every helper's
 *                   brief with the reader and its index in <work>/kb (briefing.ts); the scan
 *                   mounts both read-only
 *
 * The scan prompt plans the scan around it: every helper started in the first two replies, each
 * starting from its brief's core and loading the rest on demand.
 *
 * Every full scan that calls the model builds it (a mock or dry run makes none), and a failed
 * build fails the run. A diff builds its own, sized to the change (diff.ts). Every model call goes
 * through cynos with the scan's key (cynos.ts), as the scan's own do; the key stays in this
 * process and never reaches the scanner.
 *
 * Each step is reported as it ends (plan.step, the scan's progress events): files, graph, then
 * the plan's labels, review and packets, then briefs.
 */
import { chmodSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { KNOWLEDGE_BASE_INDEX, KNOWLEDGE_BASE_OUTPUT } from '../constants';
import type { JsonObject } from '../json';
import type { ScanStep } from '../progress';
import type { ScanPaths, ScanRuntime } from '../runtime';
import { briefing, productRows, type BriefSummary } from './briefing';
import { AnswerCache, checkoutHash, loadGraph, pruneGraphs, saveGraph } from './cache';
import { saveReview } from './stored-review';
import { CodeGraph, type FunctionNode, type GraphTransport, graphTransport } from './code-graph';
import { inventory } from './inventory';
import { CynosChat, CynosDecisions, type ReviewModel } from './cynos';
import type { ReviewStats } from './architecture';
import { planScan, tokens, type Repository } from './plan';

export { buildDiffKnowledgeBase, type DiffBuildPlan, type DiffKnowledgeBaseSummary } from './diff';

/**
 * Jev spend at which a build stops. A typical repository costs cents; php-src (28,623 functions,
 * 2,457 product files) costs about $5.15 from scratch with the hypothesis templates' questions.
 */
export const MAX_COST_USD = 10;
/** Where Jev's answers are kept in the cache. */
const ANSWERS_FILE = 'jev-answers.jsonl';

export interface BuildPlan {
  /** The build's name: its code graph's and its review agent's start with it. */
  name: string;
  /** The caller's checkout on this machine. */
  project: string;
  /** The runtime the graph and the review agent run on. */
  runtime: ScanRuntime;
  /** The checkout, the reader's directory and the agent's, as the scanner sees them. */
  paths: Pick<ScanPaths, 'project' | 'kbIndex' | 'review'>;
  /** The build's working directory on the runner; the knowledge base lands in its output/. */
  work: string;
  /** The cynos key: Jev's decisions, the review's and the packet design's calls, the review agent. */
  cynosKey: string;
  /** Run the architecture review as a Codex agent (the default); false reviews in calls. */
  reviewAgent?: boolean;
  /** The repository's own threat model (repository-relative), read as authoritative when present. */
  threatModelPath?: string;
  /** The run's model catalog, so the review agent knows the model's context window. */
  modelCatalog?: string;
  /** Where answers and code graphs are kept between builds (cache.ts); no cache when unset. */
  cacheDir?: string;
  /** The scanned commit; the review stored for later diff scans names it (stored-review.ts). */
  head?: string;
  /** The cynos endpoint for every call; BASE_URL unless a benchmark gives its own gateway. */
  baseUrl?: string;
  /** Reports a step as it ends (progress.ts): the scan's progress events. */
  step?: (step: ScanStep, message: string, data?: JsonObject) => void;
  /** The run's signal: once it fires, no step, call or review session starts, and those running stop. */
  signal?: AbortSignal;
  /** The most hypothesis packets: packets the hypotheses are shared out between; 0 for none. */
  maxHypothesisPackets: number;
}

/** Which step a line of the plan's log belongs to: the review's own lines, the packets, labels. */
function planStep(message: string): ScanStep {
  if (message.startsWith('architecture review')) return 'review';
  if (/\d+ packets\b/.test(message)) return 'packets';
  return 'labels';
}

/**
 * What a full scan's build made, as run.json records it. `kind` tells it from a diff's
 * (DiffKnowledgeBaseSummary), which a scan's result carries in the same field.
 */
export interface KnowledgeBaseSummary {
  kind: 'full';
  product_files: number;
  functions: number;
  entries: number;
  sinks: number;
  /** Every helper's brief: the packets', the hypothesis packets' and the baseline auditor's. */
  briefs: BriefSummary[];
  /** The hypotheses the templates computed, and the packets they were shared out between. */
  hypotheses: { computed: number; packets: number };
  secret_windows: number;
  /** What the cache saved: the code graph, and Jev answers given again without a call. */
  cache: { graph_reused: boolean; answers_reused: number };
  /** The architecture review's numbers, or null when it failed and the lead writes the model. */
  architecture_review: ReviewStats | null;
  jev_calls: number;
  cost_usd: number;
}

/** The build's model calls: Jev's decisions and the strong-model chat, both through cynos. */
export interface KnowledgeBaseModels {
  decisions: CynosDecisions;
  chat: ReviewModel;
}

/**
 * The build's model calls with the plan's key, endpoint and signal, decisions capped at
 * MAX_COST_USD.
 */
export function cynosModels(
  plan: Pick<BuildPlan, 'cynosKey' | 'baseUrl' | 'signal'>
): KnowledgeBaseModels {
  return {
    decisions: new CynosDecisions(
      plan.cynosKey,
      MAX_COST_USD,
      undefined,
      undefined,
      plan.baseUrl,
      plan.signal
    ),
    chat: new CynosChat(plan.cynosKey, undefined, undefined, plan.baseUrl, plan.signal),
  };
}

/** Throws once the run's signal has fired, so a stopped run starts no further step. */
function stopIfAborted(plan: BuildPlan): void {
  if (plan.signal?.aborted) throw new Error(`the build was stopped: ${String(plan.signal.reason)}`);
}

/** Builds the knowledge base into `<work>/output`; throws when any step fails. */
export async function buildKnowledgeBase(
  plan: BuildPlan,
  log: (message: string) => void,
  transport: GraphTransport = graphTransport,
  models: KnowledgeBaseModels = cynosModels(plan)
): Promise<KnowledgeBaseSummary> {
  const client = models.decisions;
  const home = join(plan.work, 'graph');
  const output = join(plan.work, KNOWLEDGE_BASE_OUTPUT);
  mkdirSync(home, { recursive: true, mode: 0o700 });
  mkdirSync(output, { recursive: true, mode: 0o700 });

  // 1. The files, and the product files a packet reviews.
  const rows = inventory(plan.project);
  const product = productRows(rows).filter(r => r.text);
  plan.step?.('files', `${rows.length} files, ${product.length} product files`, {
    files: rows.length,
    product_files: product.length,
  });

  // 2. The code graph, reused when the checkout is unchanged; the container is removed whatever
  // happens.
  if (plan.cacheDir) client.cache = new AnswerCache(join(plan.cacheDir, ANSWERS_FILE));
  const checkout = checkoutHash(rows);
  const storedGraph = plan.cacheDir ? loadGraph(plan.cacheDir, checkout) : undefined;
  let index: Record<string, unknown>;
  let functions: FunctionNode[];
  let calls: [string, string][];
  if (storedGraph) {
    ({ index, functions, calls } = storedGraph);
  } else {
    stopIfAborted(plan);
    const graph = new CodeGraph(
      {
        name: plan.name,
        project: plan.project,
        home,
        runtime: plan.runtime,
        paths: plan.paths,
        ...(plan.signal ? { signal: plan.signal } : {}),
      },
      transport
    );
    // The container is removed and the server ended whatever happens, a failed start included.
    try {
      await graph.start();
      index = await graph.index();
      functions = await graph.functions();
      calls = await graph.calls();
    } finally {
      await graph.stop();
    }
    if (plan.cacheDir) saveGraph(plan.cacheDir, checkout, { index, functions, calls });
  }
  const repo: Repository = {
    rows,
    product,
    functions,
    calls,
    tokens: new Map(product.map(r => [r.path, tokens(r.text ?? '')])),
  };
  const graphLine = `${product.length} product files, ${functions.length} functions, ${calls.length} calls${storedGraph ? ' (graph reused)' : ''}${client.cache ? `, ${client.cache.size} stored answers` : ''}`;
  log(graphLine);
  plan.step?.('graph', `code graph: ${functions.length} functions, ${calls.length} calls`, {
    functions: functions.length,
    calls: calls.length,
    reused: Boolean(storedGraph),
  });

  // 3. The plan, with the repository's own threat model when it keeps one.
  const maintainedRow = plan.threatModelPath
    ? rows.find(r => r.path === plan.threatModelPath)
    : undefined;
  const maintained =
    maintainedRow?.text !== undefined
      ? { path: maintainedRow.path, text: maintainedRow.text }
      : undefined;
  const agent =
    plan.reviewAgent !== false
      ? {
          name: `${plan.name}-review`,
          project: plan.project,
          runtime: plan.runtime,
          paths: { project: plan.paths.project, review: plan.paths.review },
          work: join(plan.work, 'review'),
          cynosKey: plan.cynosKey,
          ...(plan.modelCatalog ? { modelCatalog: plan.modelCatalog } : {}),
          ...(plan.baseUrl ? { baseUrl: plan.baseUrl } : {}),
          ...(plan.signal ? { signal: plan.signal } : {}),
        }
      : undefined;
  // The plan's log lines are its steps' progress: Jev's labels, the review, the packets.
  const planLog = (message: string): void => {
    log(message);
    plan.step?.(planStep(message), message);
  };
  stopIfAborted(plan);
  const scan = await planScan(client, models.chat, repo, planLog, maintained, agent);

  // 4. The lead's index, and every helper's brief with the reader and its index.
  const kb = briefing({
    paths: { project: plan.paths.project, kbIndex: plan.paths.kbIndex },
    rows,
    functions,
    calls,
    index,
    entries: scan.entries,
    sinks: scan.sinks,
    spec: scan.spec,
    baseline: scan.baseline,
    secretWindows: scan.secretWindows,
    review: scan.review?.review,
    fileLabels: scan.fileLabels,
    functionLabels: scan.functionLabels,
    roles: scan.roles,
    entryFiles: scan.entryFiles,
    hypotheses: {
      input: scan.hypothesisInput,
      computed: scan.hypotheses,
      packets: plan.maxHypothesisPackets,
    },
  });
  writeFileSync(join(output, 'code-graph.md'), kb.markdown);
  const kbDir = join(plan.work, KNOWLEDGE_BASE_INDEX);
  rmSync(kbDir, { recursive: true, force: true });
  mkdirSync(join(kbDir, 'packets'), { recursive: true, mode: 0o755 });
  for (const [name, text] of kb.files) writeFileSync(join(kbDir, name), text);
  chmodSync(join(kbDir, 'kb'), 0o755);
  // The lead submits this as the scan's threat model; the evidence pack stays outside the scan.
  if (scan.review) {
    writeFileSync(
      join(output, 'threat-model.json'),
      `${JSON.stringify(scan.review.review, null, 1)}\n`
    );
    writeFileSync(join(plan.work, 'architecture-pack.txt'), scan.review.pack);
    // Kept for the diff scans that follow this full scan: they adopt it as their threat model.
    if (plan.cacheDir && plan.head) saveReview(plan.cacheDir, plan.head, scan.review.review);
    writeFileSync(
      join(plan.work, 'architecture-review-debug.json'),
      `${JSON.stringify({ stats: scan.review.stats, ...scan.review.debug }, null, 1)}\n`
    );
  }
  plan.step?.('briefs', `${kb.briefs.length} helper briefs`, { briefs: kb.briefs.length });
  // The cache keeps what this checkout needs and nothing older, ready to be saved (the action's ci-cache.ts).
  if (plan.cacheDir) {
    client.cache?.compact();
    pruneGraphs(plan.cacheDir, checkout);
  }

  return {
    kind: 'full',
    product_files: product.length,
    functions: functions.length,
    entries: scan.entries.length,
    sinks: scan.sinks.size,
    briefs: kb.briefs,
    secret_windows: scan.secretWindows.length,
    hypotheses: {
      computed: scan.hypotheses.length,
      packets: Math.min(plan.maxHypothesisPackets, scan.hypotheses.length),
    },
    architecture_review: scan.review?.stats ?? null,
    cache: { graph_reused: Boolean(storedGraph), answers_reused: client.cache?.hits ?? 0 },
    jev_calls: client.calls,
    cost_usd: Math.round(client.cost * 10_000) / 10_000,
  };
}

/** The two kinds of scan the prompt plans (prompt-template.ts): a full repository scan, or a diff. */
export type ScanKind = 'full' | 'diff';
