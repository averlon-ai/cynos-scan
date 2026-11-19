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
// telling the two apart takes reading them:
//
//   1  the traces   the folders Codex wrote them to, found under <dir>; none found fails the
//                   check, since a scan without traces would otherwise pass unread
//   2  Codex        reads them and answers whether they show a pattern of failing tool calls the
//                   workflow caused. It is the Codex the scan ran (from the installed cynos's
//                   upstream), set up as the knowledge base's architecture agent is
//                   (agentOverrides in architecture-agent.ts): cynos without router or judge, in
//                   Codex's read-only sandbox, with the key from CYNOS_API_KEY in its environment
//                   alone
//
//   CYNOS_API_KEY=… node scripts/check-scan-traces.mjs <dir> --report <dir> --cynos <dir>
//
// <dir> holds the scan's traces at any depth (e2e-real.sh's work dir: the state dir is inside);
// --cynos is a directory of the cynos install the scan ran (its upstream and Codex are found from
// there, as Node would). Exits 1 when Codex reports such a pattern, or gives no answer it can be
// held to; the report dir gets its answer and its session's log.
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
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';

/** The architecture agent's model and gateway (REVIEW_MODEL, BASE_URL in the engine). */
const MODEL = 'deepseek/deepseek-v4.1-flash';
const BASE_URL = 'https://api.cynos.averlon.ai/v1';
/** One Codex session's limit, as the architecture agent's (AGENT_TIMEOUT_MS). */
const TIMEOUT_MS = 20 * 60_000;

// 1. The traces

/**
 * The folders under `dir` that hold agent traces: Codex writes one file per agent session, as
 * sessions/YYYY/MM/DD/rollout-*.jsonl (rollout is Codex's name for a trace).
 */
function traceFolders(dir) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const here = entries.some(e => e.isFile() && /^rollout-.*\.jsonl$/.test(e.name));
  const below = entries.filter(e => e.isDirectory()).flatMap(e => traceFolders(join(dir, e.name)));
  return here && dir.includes('/sessions/') ? [dir, ...below] : below;
}

/**
 * The run's model catalog under `dir`, which lists the architecture agent's model with its context
 * window (writeModelCatalog in the engine), or undefined when there is none: without it Codex
 * gives the model fallback metadata, a 272k window, and a long read compacts early.
 */
function modelCatalog(dir) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return undefined;
  }
  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      const found = modelCatalog(path);
      if (found) return found;
    } else if (entry.name === 'model-catalog.json' && readFileSync(path, 'utf8').includes(MODEL))
      return path;
  }
  return undefined;
}

// 2. Codex

/** What Codex is asked: whether the traces show tool calls failing because of the workflow. */
function prompt(folders) {
  return `You are checking a security scan's agent traces for tool calls that fail because of the
scan's workflow.

The scan has a lead agent and helper agents. They follow instructions written for them (the
workflow): which files to read, which scripts to run in code mode's \`exec\` cells, which tools
to call and with what arguments, which paths and commands exist, what the sandbox allows. Each
agent session's trace is a JSONL file (rollout-*.jsonl) in these folders:

${folders.map(f => `- ${f}`).join('\n')}

Other Codex sessions (the knowledge base's architecture agent) may be there too; check them as
well. The files can be large: search them (rg, jq, head) rather than printing them whole.

Look for tool calls that fail: a scan tool (codex-security) that returns an error or refuses the
call, an exec cell that fails, a shell command that is refused or errors, the same call retried
after an error. Then decide which failures the workflow caused:

- Caused by the workflow: the agent did what its instructions say or show, or had no working way
  to do what they require, and it failed. Such errors usually repeat, across turns or across
  agents. Examples seen before: every helper's call to save_codex_security_artifact refused with
  "This scan requires its owning Codex thread"; record_codex_security_scan_draft rejecting
  findings with "MCP error -32602 ... must match pattern" for an identity shaped like the
  instructions' example; a heredoc failing because the sandbox's /tmp is read-only; a script the
  workflow gives throwing.
- Not caused by the workflow: an agent's ordinary miss that points at no broken instruction, such
  as a search with no match, a path it guessed wrong, a mistake in its own code it then fixed.

When you cannot tell, count it as caused by the workflow and say what you would need to know: a
person reviews every pattern you report. Report only errors you found in these traces, with the
number of calls you counted: the examples above show what such errors look like, and are not
errors to report.

Answer with one JSON object and nothing else:
{"result": "pass" or "fail", "patterns": [{"error": "<the error, quoted>", "count": <how many calls>, "agents": "<which agents>", "cause": "<why the workflow caused it>"}]}
"fail" when there is at least one pattern the workflow caused, listed in "patterns"; "pass" with
an empty list otherwise. If you cannot read the traces (your commands fail), answer
{"result": "unread", "reason": "<what failed>"} instead.
`;
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
function readAnswer(text) {
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
  return answer;
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
function ask(folders, dir, report, codex, catalog, key) {
  const home = join(report, 'codex-home');
  mkdirSync(home, { recursive: true, mode: 0o700 });
  const env = { ...process.env, CODEX_HOME: home, CODEX_API_KEY: key };
  let input = prompt(folders);
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
    const answer = readAnswer(text);
    if (typeof answer !== 'string') return answer;
    problem = answer;
    input = `Your answer cannot be read: ${problem}. Answer again with the JSON object alone.`;
  }
  return `Codex's answer cannot be read: ${problem}`;
}

// The check

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
const folders = traceFolders(resolve(dir));
if (!folders.length) {
  console.error(`scan traces: none under ${dir}`);
  process.exit(1);
}
console.log(`scan traces: asking Codex about ${folders.length} trace folder(s)`);

// 2. Codex's answer, with the run's model catalog when the traces' run left one.
const catalog = modelCatalog(resolve(dir));
console.log(
  `scan traces: ${catalog ? `model catalog ${catalog}` : "no model catalog: Codex's fallback window"}`
);
if (!key) {
  console.error('check-scan-traces.mjs needs the cynos key in CYNOS_API_KEY to ask Codex');
  process.exit(1);
}
const codex = codexLauncher(resolve(values.cynos));
const answer = ask(folders, resolve(dir), report, codex, catalog, key);
if (typeof answer === 'string') {
  console.error(`scan traces: ${answer}; see ${report}`);
  process.exit(1);
}
writeFileSync(join(report, 'answer.json'), `${JSON.stringify(answer, null, 2)}\n`);
if (answer.result === 'unread') {
  console.error(`scan traces: Codex could not read them: ${answer.reason}; see ${report}`);
  process.exit(1);
}
if (answer.result === 'fail') {
  console.error(`scan traces: ${answer.patterns.length} pattern(s) of failing tool calls:`);
  for (const p of answer.patterns)
    console.error(`  ${p.error} (${p.count} calls, ${p.agents})\n    ${p.cause}`);
  console.error(`Codex's answer and session are in ${report}`);
  process.exit(1);
}
console.log('scan traces: no failing tool calls the workflow caused');
