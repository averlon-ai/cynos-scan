#!/usr/bin/env node
// Asks Codex whether a real scan's agent traces show tool calls failing because of the scan's
// workflow: e2e-real.sh runs it after the scan, and so does the release's real scan.
//
// A scan can complete, and find what it should, while its agents fight the workflow turn after
// turn: upstream's scan tools refused every helper's result save ("This scan requires its owning
// Codex thread"), and the draft tool refused the lead's findings for an identity copied from an
// example that was a file path (MCP error -32602). Every scan recovered, at one to three retry
// turns a failure, so nothing a scan's outcome shows ever failed. The agents' traces show it: the
// log Codex writes of each agent's session, every call it made and how it ended. Most failed calls
// in them are the agents' own ordinary misses, though (an rg with no match, a guessed path), so
// telling the two apart takes reading them. Left to find the failures itself, though, Codex
// passed v0.3.0's scan while the draft tool rejected the lead's first draft in every scan
// ("expected never ... at scope.includePaths"), and its pass said nothing of what it had seen. And
// what this check looks for is our prompts misleading the agents: the scan runs upstream's plugin
// with some of its files replaced by ours, and Codex cannot tell which instructions are ours, or
// what upstream's said in their place, without being shown both. So a script finds the failures
// and our prompts beside upstream's, and Codex judges each failure:
//
//   1  the traces        the folders Codex wrote them to, found under <dir>; none found fails
//                        the check, since a scan without traces would otherwise pass unread
//   2  the failed calls  every call the traces record as failed (a tool call, a shell command or
//                        an exec cell), numbered F1, F2, ... and printed; traces with no call at
//                        all fail the check, since that is a trace format it no longer reads
//   3  our prompts       in each run dir the traces came from, its plugin compared with
//                        upstream's own, file by file: the files ours replaced or added, beside
//                        upstream's, and the prompts only we give (the scan prompt, the helpers'
//                        instructions), with where a docker scan's agents saw each; none found
//                        fails the check, since Codex could then not compare them
//   4  Codex             reads the traces and answers which failed calls our prompts caused and
//                        which are the agents' own misses, accounting for every one, and for each
//                        pattern the file of ours it comes from: an answer that leaves one out is
//                        asked again. It is the Codex the scan ran (from the installed cynos's
//                        upstream), set up as the knowledge base's architecture agent is
//                        (agentOverrides in architecture-agent.ts): cynos without router or judge,
//                        in Codex's read-only sandbox, with the key from CYNOS_API_KEY in its
//                        environment alone
//
//   CYNOS_API_KEY=… node scripts/check-scan-traces.mjs <dir> --report <dir> --cynos <dir>
//
// <dir> holds the scan's traces at any depth (e2e-real.sh's work dir: the state dir is inside);
// --cynos is a directory of the cynos install the scan ran (its upstream and Codex are found from
// there, as Node would). Exits 1 when Codex reports such a pattern, or gives no answer it can be
// held to. A pass prints each failed call Codex dismissed and why. The report dir gets the failed
// calls, our prompts as Codex was shown them, Codex's answer and its session's log.
import { spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

/** The architecture agent's model and gateway (REVIEW_MODEL, BASE_URL in the engine). */
const MODEL = 'deepseek/deepseek-v4.1-flash';
const BASE_URL = 'https://api.cynos.averlon.ai/v1';
/** One Codex session's limit, as the architecture agent's (AGENT_TIMEOUT_MS). */
const TIMEOUT_MS = 20 * 60_000;

// 1. The traces

/**
 * The folders under `dir` that hold agent traces: Codex writes one file per agent session, as
 * sessions/YYYY/MM/DD/rollout-*.jsonl (rollout is Codex's name for a trace). Not those under
 * `report`: this check's own Codex sessions from an earlier run into the same report dir, which
 * may be inside `dir` (e2e-real.sh's is), are not the scan's.
 */
export function traceFolders(dir, report) {
  if (dir === report) return [];
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const here = entries.some(e => e.isFile() && /^rollout-.*\.jsonl$/.test(e.name));
  const below = entries
    .filter(e => e.isDirectory())
    .flatMap(e => traceFolders(join(dir, e.name), report));
  return here && dir.includes('/sessions/') ? [dir, ...below] : below;
}

/**
 * The model catalog of the run dirs the traces came from, which lists the architecture agent's
 * model with its context window (writeModelCatalog in the engine), or undefined when there is
 * none: without it Codex gives the model fallback metadata, a 272k window, and a long read
 * compacts early.
 */
function modelCatalog(runs) {
  return runs
    .map(run => join(run, 'model-catalog.json'))
    .find(path => existsSync(path) && readFileSync(path, 'utf8').includes(MODEL));
}

// 2. The failed calls

/**
 * Every call the traces in `folders` record as failed, in trace order, and the number of calls
 * they record at all. Codex logs each call's end as an item_completed event, and a tool call
 * (McpToolCall: upstream's scan tools, wherever they are called from) or a shell command
 * (CommandExecution) that failed has the status "failed". A code mode exec cell's failure is in
 * its result alone: "Script failed", or exec's own error ("exec pragma must be valid JSON ...")
 * in place of "Script completed", given by exec or, for a cell that ran past its yield time, by
 * the `wait` that ends it (execCells). The count of every call lets the check tell traces it
 * cannot read (no calls) from a scan with no failures.
 */
export function failedCalls(folders) {
  const failed = [];
  let calls = 0;
  for (const folder of folders)
    for (const name of readdirSync(folder)
      .filter(n => /^rollout-.*\.jsonl$/.test(n))
      .sort()) {
      // The session's first record names its agent; exec cells are followed to their end.
      let agent = name;
      const cells = execCells();
      const record = call => {
        calls++;
        if (call.error !== undefined)
          failed.push({ id: `F${failed.length + 1}`, agent, trace: name, ...call });
      };
      for (const line of readFileSync(join(folder, name), 'utf8').split('\n')) {
        if (!line) continue;
        const { type, payload = {} } = JSON.parse(line);
        if (type === 'session_meta') agent = agentName(payload);
        cells.started(payload);
        const call = endedCall(payload, cells);
        if (call) record(call);
      }
      // A cell no wait ended is a call whose result the trace never shows.
      cells.unfinished().forEach(record);
    }
  return { calls, failed };
}

/**
 * A session's agent: a helper's path (/root/baseline_auditor), the lead, or another Codex session
 * by what started it (the architecture agent's is a `codex exec` session).
 */
function agentName(session) {
  if (session.agent_path) return session.agent_path;
  if (session.thread_source === 'security_scan') return 'lead';
  return `${session.originator ?? 'Codex'} session`;
}

/**
 * The call one trace record ends, with its error when it failed, or undefined when the record
 * ends no call.
 */
function endedCall(payload, cells) {
  if (payload.type === 'item_completed') {
    const item = payload.item ?? {};
    const failed = item.status === 'failed';
    if (item.type === 'McpToolCall')
      return {
        kind: 'tool call',
        name: `${item.server}/${item.tool}`,
        error: failed ? errorText(contentText(item.result?.content)) : undefined,
      };
    if (item.type === 'CommandExecution')
      // The command is [shell, '-c', line]; an error is at the end of its output.
      return {
        kind: 'shell command',
        name: clip([item.command].flat().at(-1) ?? ''),
        error: failed
          ? clip(`exit ${item.exit_code}: …${(item.aggregated_output ?? '').slice(-300)}`)
          : undefined,
      };
    return undefined;
  }
  return cells.ended(payload);
}

/** What code mode answers while an exec cell is still running, naming the cell. */
const STILL_RUNNING = /^Script running with cell ID (\S+)/;

/**
 * A trace's exec cells, followed to their end. A cell that runs past its yield time answers with
 * "Script running with cell ID <id>" in place of its result; the agent then calls `wait` with that
 * cell_id, as many times as it takes, and the first answer that is not "Script running" is the
 * cell's result:
 *
 *   exec (call A)                     → Script running with cell ID 214
 *   wait (call B, {"cell_id": "214"}) → Script running with cell ID 214
 *   wait (call C, {"cell_id": "214"}) → Script failed …
 *
 * exec's call is a custom tool call and wait's a function call; each answer names only its call's
 * id. So the calls are known by id (exec's, or wait's with the cell it names) and the yielded cells
 * by cell id, and a cell is one call, ended by whichever answer gives its result.
 */
function execCells() {
  const calls = new Map(); // call id → the cell a wait names, or undefined for exec
  const running = new Set(); // cells that yielded and no answer has ended yet
  return {
    /** Notes a record that starts an exec or a wait. */
    started(payload) {
      if (payload.type === 'custom_tool_call' && payload.name === 'exec')
        calls.set(payload.call_id, undefined);
      if (payload.type === 'function_call' && payload.name === 'wait')
        calls.set(payload.call_id, String(jsonObject(payload.arguments ?? '')?.cell_id ?? ''));
    },
    /** The exec cell a record ends, with its error when it failed, or undefined. */
    ended(payload) {
      const answer = ['custom_tool_call_output', 'function_call_output'].includes(payload.type);
      if (!answer || !calls.has(payload.call_id)) return undefined;
      const cell = calls.get(payload.call_id);
      calls.delete(payload.call_id);
      const output = contentText(payload.output);
      const yielded = STILL_RUNNING.exec(output);
      if (yielded) {
        running.add(yielded[1]);
        return undefined;
      }
      running.delete(cell);
      return {
        kind: 'exec cell',
        name: cell === undefined ? 'exec' : `exec (cell ${cell})`,
        error: output.startsWith('Script completed') ? undefined : errorText(output),
      };
    },
    /** The cells still running when the trace ends, as failed calls. */
    unfinished() {
      return [...running].map(cell => ({
        kind: 'exec cell',
        name: `exec (cell ${cell})`,
        error: '(still running when the trace ends)',
      }));
    },
  };
}

/** The text of a tool result's content: a string, or a list of text parts. */
function contentText(content) {
  if (typeof content === 'string') return content;
  return (content ?? []).map(part => part.text ?? '').join('\n');
}

/** A failed call's error, clipped; a failure that says nothing is still a failure to account for. */
function errorText(text) {
  return clip(text) || '(no error text)';
}

/** A text on one line, at most 400 characters: enough to tell one error from another. */
function clip(text) {
  const line = text.replace(/\s+/g, ' ').trim();
  return line.length > 400 ? `${line.slice(0, 400)}…` : line;
}

// 3. Our prompts

/**
 * The files of ours a scan's agents read, by their path in the run dir, with where the docker
 * runtime mounts each (DOCKER_PATHS in runtime/docker.ts): a docker scan's traces name the
 * container's paths, which are not on this machine. The native runtime's traces name the run dir's.
 * The plugin holds upstream's prompts and ours (pluginChanges); the others are ours alone.
 */
export const OUR_PROMPTS = [
  { path: 'plugin', container: '/scan/plugin', what: "the scan's plugin" },
  { path: 'prompt.md', container: '/scan/prompt.md', what: "the scan prompt, the lead's context" },
  {
    path: 'helper-context.md',
    container: '/scan/helper-context.md',
    what: "the helpers' instructions",
  },
];

/**
 * The run dirs whose agents left the traces in `folders`. A run dir is the stage of one run of
 * upstream (the scan's, and its preflight's inside it), which holds the plugin and prompt cynos
 * staged for it. Its agents' traces are in one of two places:
 *
 *   inside it      a state dir of its own (the docker runtime's, the preflight's, the knowledge
 *                  base's architecture agent): the trace folder's innermost run dir
 *   a shared one   upstream's state dir on the native runtime, which holds other runs' sessions
 *                  too: the sessions that started in its scan dir (run.json's scan_dir), as the
 *                  engine counts a native scan's usage (sessionUsage)
 *
 * A copy of a run dir with no traces of its own, such as an unpacked debug bundle's, is not the
 * prompts any agent read.
 */
export function runDirs(dir, folders) {
  const stages = stagesUnder(dir);
  const innermost = folder =>
    stages.filter(stage => folder.startsWith(`${stage}/`)).sort((a, b) => b.length - a.length)[0];
  const shared = new Set(folders.filter(f => !innermost(f)).flatMap(sessionDirs));
  return stages.filter(
    stage => folders.some(f => innermost(f) === stage) || shared.has(scanDir(stage))
  );
}

/** The working directories the sessions in a trace folder started in (session_meta's cwd). */
function sessionDirs(folder) {
  return readdirSync(folder)
    .filter(n => /^rollout-.*\.jsonl$/.test(n))
    .map(n => {
      const first = readFileSync(join(folder, n), 'utf8').split('\n', 1)[0];
      const { type, payload } = jsonObject(first) ?? {};
      return type === 'session_meta' ? payload?.cwd : undefined;
    })
    .filter(Boolean);
}

/** A run dir's scan dir, as its run.json records it, or undefined. */
function scanDir(stage) {
  try {
    return JSON.parse(readFileSync(join(stage, 'run.json'), 'utf8')).scan_dir;
  } catch {
    return undefined;
  }
}

/** Every directory under `dir` that holds a staged plugin and prompt. */
function stagesUnder(dir) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const names = new Set(entries.map(e => e.name));
  const here = names.has('plugin') && names.has('prompt.md');
  const below = entries
    .filter(e => e.isDirectory() && !(here && e.name === 'plugin'))
    .flatMap(e => stagesUnder(join(dir, e.name)));
  return here ? [dir, ...below] : below;
}

/** Every file under `root`, by its path relative to it. */
function filesUnder(root, dir = root) {
  return readdirSync(dir, { withFileTypes: true }).flatMap(e =>
    e.isDirectory() ? filesUnder(root, join(dir, e.name)) : [relative(root, join(dir, e.name))]
  );
}

/**
 * The files of a staged plugin that are not upstream's own: replaced (upstream has the file, with
 * other content) or added. Computed rather than listed, so that it names what the scan really ran.
 */
export function pluginChanges(plugin, upstream) {
  const theirs = new Set(filesUnder(upstream));
  return filesUnder(plugin)
    .filter(
      path =>
        !theirs.has(path) ||
        !readFileSync(join(plugin, path)).equals(readFileSync(join(upstream, path)))
    )
    .map(path => ({ path, change: theirs.has(path) ? 'replaced' : 'added' }));
}

/** Each run dir's prompts of ours: its plugin's changes, and the files of ours it has. */
export function ourPrompts(runs, upstreamPlugin) {
  return runs.map(run => ({
    run,
    plugin: pluginChanges(join(run, 'plugin'), upstreamPlugin),
    files: OUR_PROMPTS.filter(f => existsSync(join(run, f.path))),
  }));
}

/** Our prompts beside upstream's, as the prompt and the log describe them. */
function describePrompts(prompts, upstreamPlugin) {
  return prompts
    .map(({ run, plugin, files }) =>
      [
        `Run dir ${run}:`,
        ...files.map(f => `- ${join(run, f.path)} (docker: ${f.container}): ${f.what}`),
        `  The plugin is upstream's (${upstreamPlugin}), file for file, except these of ours:`,
        ...plugin.map(p =>
          p.change === 'replaced'
            ? `  - ${p.path}: ours; upstream's is ${join(upstreamPlugin, p.path)}`
            : `  - ${p.path}: ours, upstream has none`
        ),
      ].join('\n')
    )
    .join('\n\n');
}

// 4. Codex

/**
 * What Codex is asked: which of the failed calls our prompts caused, and any other pattern of
 * failing calls they caused that the traces show.
 */
function prompt(folders, failed, prompts) {
  return `You are checking a security scan's agent traces for tool calls that fail because our
prompts misled the agents.

The scan has a lead agent and helper agents. They follow instructions written for them (the
workflow): which files to read, which scripts to run in code mode's \`exec\` cells, which tools
to call and with what arguments, which paths and commands exist, what the sandbox allows. The
workflow is upstream's (OpenAI's codex-security plugin) with some of its prompts replaced by ours,
and some prompts only we give:

${prompts}

Each agent session's trace is a JSONL file (rollout-*.jsonl) in these folders:

${folders.map(f => `- ${f}`).join('\n')}

Other Codex sessions (the knowledge base's architecture agent) may be there too; check them as
well. The files can be large: search them (rg, jq, head) rather than printing them whole.

A script has already listed every call the traces record as failed: a tool call (the scan tools
are codex-security's), a shell command or an exec cell, each with its id, the agent and the trace
file, and its error:

${failed.length ? failed.map(describe).join('\n') : '(none)'}

Read the traces around each one (what the agent was doing, what its instructions told it, whether
it retried), and look as well for failures the list cannot show, such as the same call retried
after an error a tool reported as a success. Then decide which failures our prompts caused,
comparing ours with upstream's where they replace one:

- Caused by our prompts: the agent did what ours say or show, or was confused by them (they leave
  out or contradict what upstream's say, or what upstream's tools and sandbox accept), or had no
  working way to do what they require, and it failed. Such errors usually repeat, across turns or
  across agents. Examples seen before: every helper's call to save_codex_security_artifact refused
  with "This scan requires its owning Codex thread"; record_codex_security_scan_draft rejecting
  findings with "MCP error -32602 ... must match pattern" for an identity shaped like our
  instructions' example; a heredoc failing because the sandbox's /tmp is read-only; a script ours
  give throwing.
- Not caused by our prompts: an agent's ordinary miss that points at no broken instruction, such
  as a search with no match, a path it guessed wrong, a mistake in its own code it then fixed; or
  a failure upstream's own prompts lead to as well, where ours say what upstream's do.

When you cannot tell, count it as caused by the workflow and say what you would need to know: a
person reviews every pattern you report. Report only errors you found in these traces, with the
number of calls you counted: the examples above show what such errors look like, and are not
errors to report.

Account for every listed failed call, each exactly once: in the "failures" of the pattern our
prompts caused, or in "dismissed" with the reason they did not. A pattern of
failures the list does not show has an empty "failures".

Answer with one JSON object and nothing else:
{"result": "pass" or "fail", "patterns": [{"error": "<the error, quoted>", "count": <how many calls>, "agents": "<which agents>", "file": "<the file of ours it comes from>", "cause": "<what ours say there, what upstream's say, and how that misled the agent>", "failures": ["<ids, such as F1>"]}], "dismissed": [{"failure": "<id>", "reason": "<why our prompts did not cause it>"}]}
"fail" when there is at least one pattern our prompts caused, listed in "patterns"; "pass" with
an empty list otherwise. If you cannot read the traces (your commands fail), answer
{"result": "unread", "reason": "<what failed>"} instead.
`;
}

/** A failed call on one line, as the prompt and the log list it. */
function describe(call) {
  return `${call.id} ${call.agent} (${call.trace}): ${call.kind} ${call.name}: ${call.error}`;
}

/** The first JSON object in a text, from its first { to its last }: models wrap it in prose. */
function jsonObject(text) {
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  try {
    return start >= 0 && end > start ? JSON.parse(text.slice(start, end + 1)) : undefined;
  } catch {
    return undefined;
  }
}

/** Codex's answer, or why it gives none the check can be held to. */
export function readAnswer(text, failed) {
  const answer = jsonObject(text);
  if (answer?.result === 'unread' && typeof answer.reason === 'string') return answer;
  if (!answer || !['pass', 'fail'].includes(answer.result) || !Array.isArray(answer.patterns))
    return 'it holds no JSON object with a result of pass or fail and a patterns list';
  if (answer.result === 'fail' && !answer.patterns.length) return 'it fails but lists no pattern';
  if (answer.result === 'pass' && answer.patterns.length) return 'it passes but lists patterns';
  // A pattern no call shows is not one Codex read in the traces (one that could not read them
  // listed the prompt's examples, at 0 calls each).
  if (answer.patterns.some(p => !(p?.count >= 1)))
    return 'it lists a pattern without the calls counted in the traces';
  // A pattern is fixed in the file of ours it comes from, so it must name one.
  if (answer.patterns.some(p => typeof p.file !== 'string' || !p.file.trim()))
    return 'it lists a pattern without the file of ours it comes from';
  return unaccounted(answer, failed) ?? answer;
}

/**
 * Why an answer does not account for each failed call exactly once, in a pattern's failures or
 * dismissed with a reason, or undefined when it does: a pass must say why it excused each one.
 */
function unaccounted(answer, failed) {
  // An answer may leave dismissed out when it dismisses nothing, but not give something else.
  if (answer.dismissed !== undefined && !Array.isArray(answer.dismissed))
    return 'its dismissed is not a list';
  const dismissed = answer.dismissed ?? [];
  if (dismissed.some(d => typeof d?.reason !== 'string' || !d.reason.trim()))
    return 'it dismisses a failed call without a reason';
  const named = [
    ...answer.patterns.flatMap(p => (Array.isArray(p.failures) ? p.failures : [])),
    ...dismissed.map(d => d.failure),
  ];
  const ids = failed.map(call => call.id);
  const missing = ids.filter(id => !named.includes(id));
  if (missing.length) return `it does not account for ${missing.join(', ')}`;
  const twice = ids.filter(id => named.indexOf(id) !== named.lastIndexOf(id));
  if (twice.length) return `it accounts for ${twice.join(', ')} more than once`;
  const unknown = named.filter(id => !ids.includes(id));
  if (unknown.length) return `it names failed calls the list does not have: ${unknown.join(', ')}`;
  return undefined;
}

/** A package's directory, found by walking the node_modules directories Node would search. */
function packageDir(from, name) {
  for (const dir of createRequire(join(from, 'noop.js')).resolve.paths(name) ?? []) {
    const candidate = join(dir, name);
    if (existsSync(join(candidate, 'package.json'))) return realpathSync(candidate);
  }
  throw new Error(`${name} is not installed where Node would find it from ${from}`);
}

/** The Codex the scan ran: upstream's, found from the cynos install. */
function codexLauncher(cynos) {
  const codex = packageDir(packageDir(cynos, '@openai/codex-security'), '@openai/codex');
  const bin = JSON.parse(readFileSync(join(codex, 'package.json'), 'utf8')).bin;
  return join(codex, typeof bin === 'string' ? bin : bin.codex);
}

/**
 * `codex exec` with the architecture agent's settings, in `dir` with a Codex home of its own in
 * the report dir. A resume asks the same session again. The key goes only into Codex's
 * environment, never into its arguments.
 */
function codexCommand(codex, dir, report, catalog, resume) {
  const baseUrl = process.env.CYNOS_BASE_URL || BASE_URL;
  const headers = '"x-cy-eh-task-route"="off","x-cy-eh-domain-expert-judge"="off"';
  const overrides = [
    'model_provider="cynos"',
    `model_providers.cynos={name="cynos",base_url="${baseUrl}",env_key="CODEX_API_KEY",wire_api="responses",http_headers={${headers}}}`,
    `model="${MODEL}"`,
    'model_reasoning_effort="xhigh"',
    'sandbox_mode="read-only"',
    'tool_output_token_limit=60000',
    'features.apps=false',
    'features.plugins=false',
    // No shell snapshot, and no key in a command's environment: either would put it in a file.
    'features.shell_snapshot=false',
    'shell_environment_policy.ignore_default_excludes=false',
    'analytics.enabled=false',
    ...(catalog ? [`model_catalog_json="${catalog}"`] : []),
  ];
  return [
    codex,
    'exec',
    ...(resume ? ['resume', '--last'] : ['--sandbox', 'read-only', '-C', dir, '--color', 'never']),
    '--skip-git-repo-check',
    '--ignore-user-config',
    '-o',
    join(report, 'answer.txt'),
    ...overrides.flatMap(o => ['-c', o]),
    '-',
  ];
}

/** Codex's answer on the traces, asked once more when its first holds none. */
function ask(folders, failed, prompts, dir, report, codex, catalog, key) {
  const home = join(report, 'codex-home');
  mkdirSync(home, { recursive: true, mode: 0o700 });
  const env = { ...process.env, CODEX_HOME: home, CODEX_API_KEY: key };
  let input = prompt(folders, failed, prompts);
  let problem = '';
  for (const resume of [false, true]) {
    const run = spawnSync(process.execPath, codexCommand(codex, dir, report, catalog, resume), {
      input,
      env,
      encoding: 'utf8',
      timeout: TIMEOUT_MS,
      maxBuffer: 64 * 1024 * 1024,
    });
    writeFileSync(join(report, `codex${resume ? '-again' : ''}.log`), run.stdout + run.stderr);
    if (run.status !== 0) return `codex exec exited ${run.status ?? run.signal}`;
    let text = '';
    try {
      text = readFileSync(join(report, 'answer.txt'), 'utf8');
    } catch {
      // No final message: the problem below says so.
    }
    const answer = readAnswer(text, failed);
    if (typeof answer !== 'string') return answer;
    problem = answer;
    input = `Your answer cannot be read: ${problem}. Answer again with the JSON object alone.`;
  }
  return `Codex's answer cannot be read: ${problem}`;
}

// The check

function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: { report: { type: 'string' }, cynos: { type: 'string' } },
  });
  const [dir] = positionals;
  if (!dir || !values.report || !values.cynos) {
    console.error('usage: check-scan-traces.mjs <dir> --report <dir> --cynos <dir>');
    process.exit(2);
  }
  // The key is read once and leaves this process's environment: only Codex's gets it.
  const key = process.env.CYNOS_API_KEY ?? '';
  delete process.env.CYNOS_API_KEY;
  const report = resolve(values.report);
  mkdirSync(report, { recursive: true, mode: 0o700 });

  // 1. The traces.
  const folders = traceFolders(resolve(dir), report);
  if (!folders.length) {
    console.error(`scan traces: none under ${dir}`);
    process.exit(1);
  }

  // 2. The failed calls, printed whatever Codex answers, so that the log shows what it judged.
  const { calls, failed } = failedCalls(folders);
  if (!calls) {
    console.error(`scan traces: no tool call or command in ${folders.length} trace folder(s):`);
    console.error('  a trace format this check does not read');
    process.exit(1);
  }
  writeFileSync(join(report, 'failed-calls.json'), `${JSON.stringify(failed, null, 2)}\n`);
  console.log(`scan traces: ${failed.length} of ${calls} calls failed`);
  for (const call of failed) console.log(`  ${describe(call)}`);
  console.log(`scan traces: asking Codex about ${folders.length} trace folder(s)`);

  // 3. Our prompts, beside those of the upstream the scan ran.
  const runs = runDirs(resolve(dir), folders);
  if (!runs.length) {
    console.error(`scan traces: no run dir (plugin/ and prompt.md) holds the traces under ${dir}`);
    process.exit(1);
  }
  const upstreamPlugin = join(
    packageDir(resolve(values.cynos), '@openai/codex-security'),
    '_bundled_plugin'
  );
  const prompts = describePrompts(ourPrompts(runs, upstreamPlugin), upstreamPlugin);
  writeFileSync(join(report, 'our-prompts.txt'), `${prompts}\n`);
  console.log(`scan traces: our prompts, in ${runs.length} run dir(s):`);
  console.log(prompts.replace(/^(?=.)/gm, '  '));

  // 4. Codex's answer, with the run's model catalog when the traces' run left one.
  const catalog = modelCatalog(runs);
  console.log(
    `scan traces: ${catalog ? `model catalog ${catalog}` : "no model catalog: Codex's fallback window"}`
  );
  if (!key) {
    console.error('check-scan-traces.mjs needs the cynos key in CYNOS_API_KEY to ask Codex');
    process.exit(1);
  }
  const codex = codexLauncher(resolve(values.cynos));
  const answer = ask(folders, failed, prompts, resolve(dir), report, codex, catalog, key);
  if (typeof answer === 'string') {
    console.error(`scan traces: ${answer}; see ${report}`);
    process.exit(1);
  }
  writeFileSync(join(report, 'answer.json'), `${JSON.stringify(answer, null, 2)}\n`);
  if (answer.result === 'unread') {
    console.error(`scan traces: Codex could not read them: ${answer.reason}; see ${report}`);
    process.exit(1);
  }
  // Whatever the result, what Codex excused and why, so that a pass can be checked.
  for (const d of answer.dismissed ?? []) console.log(`  ${d.failure} dismissed: ${d.reason}`);
  if (answer.result === 'fail') {
    console.error(
      `scan traces: ${answer.patterns.length} pattern(s) of tool calls our prompts made fail:`
    );
    for (const p of answer.patterns) {
      const ids = p.failures?.length ? ` [${p.failures.join(', ')}]` : '';
      console.error(
        `  ${p.error} (${p.count} calls, ${p.agents})${ids}\n    ${p.file}: ${p.cause}`
      );
    }
    console.error(`Codex's answer and session are in ${report}`);
    process.exit(1);
  }
  console.log('scan traces: no failing tool calls our prompts caused');
}

// Run as a script; imported (by its test), it only exports the steps. Not import.meta.main: Node
// 22.13 has none, and the check would then pass without running.
if (
  process.argv[1] &&
  realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))
)
  main();
