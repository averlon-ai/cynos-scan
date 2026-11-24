/** Constants shared by the codex-security pipeline's modules. */
import packageJson from '../package.json';
import { UPSTREAM_PIN } from './upstream';

/**
 * This engine's version, read from packages/engine/package.json so the release's version stamp
 * (`npm pkg set version` from the tag) reaches it; a literal here stayed 0.1.0 in every release.
 */
export const ENGINE_VERSION: string = packageJson.version;

/** The variable the scanner container receives the cynos key in, by name only. */
export const KEY_VARIABLE = 'CYNOS_API_KEY';
/** cynos's endpoint, the default: CYNOS_BASE_URL names another. */
export const BASE_URL = 'https://api.cynos.averlon.ai/v1';
/**
 * The native runtime's preflight endpoint: a port nothing listens on (discard), so the
 * preflight's first model request fails at once, as it does with no network in a container.
 */
export const PREFLIGHT_BASE_URL = 'http://127.0.0.1:9/v1';
export const PROVIDER_ID = 'cynos';
/**
 * The scan's model when the caller names none: DeepSeek V4 Pro, the dated snapshot cynos's catalog
 * and taskroute name, so a scan's model changes only when this does.
 */
export const DEFAULT_MODEL = 'deepseek/deepseek-v4-pro-0813';
/**
 * The knowledge base's own model, for the architecture review and the packet design: the
 * knowledge base reads the whole repository, so it stays on the cheaper flash model whatever model
 * the scan runs on.
 */
export const KNOWLEDGE_BASE_MODEL = 'deepseek/deepseek-v4.1-flash';

/**
 * The reasoning efforts a scan may ask for: the OpenAI API's `reasoning.effort` values, which
 * Codex sends as they are (Codex's own config also takes ultra and persistent, which the API does
 * not). Which of them a model accepts is the model's. Neither upstream, Codex nor cynos rejects
 * any other value: a scan with --effort bogus ran in full at a level nobody chose, so a typo costs
 * a whole scan unless it is caught here, before one starts.
 */
export const REASONING_EFFORTS = [
  'none',
  'minimal',
  'low',
  'medium',
  'high',
  'xhigh',
  'max',
] as const;
export const IMAGE = `cynos-scan-scanner:${UPSTREAM_PIN.version}`;

/**
 * The header that switches cynos's quality judge, sent with every model call. cynos judges a turn
 * on its own only when taskroute moved it to another model, and a scan's turns mostly stay on the
 * requested one, so without the header a scan is almost never judged: by default the action sends
 * it as "on". The suffix is the judge_override_header_key cynos's gateways, production and dev
 * alike, are configured with.
 * `cynos-judge: off` sends "off" instead.
 */
export const JUDGE_HEADER = 'x-cy-eh-domain-expert-judge';
/** The header that switches cynos's task routing; sent ("off") only for `cynos-task-routing: off`. */
export const TASK_ROUTE_HEADER = 'x-cy-eh-task-route';

/**
 * The scan model's context window, in tokens: deepseek-v4-pro-0813, deepseek-v4.1-flash,
 * glm-5.3-flash and gpt-5.6-sol all serve about 1M tokens on OpenRouter.
 *
 * Codex has no metadata for the cynos models and gives an unknown model fallback metadata whose
 * max_context_window is 272k, and it clamps model_context_window to that, so the setting alone
 * cannot raise the window; sessions compacted at 90% of 272k. The window reaches Codex through a
 * model catalog instead (C_MODEL_CATALOG, written by writeModelCatalog): the fallback metadata
 * with this window.
 */
export const MODEL_CONTEXT_WINDOW = 1048576;
/** The model catalog, as the docker runtime's scanner sees it (read-only). */
export const C_MODEL_CATALOG = '/scan/model-catalog.json';

/**
 * Codex's base instructions: openai/codex codex-rs/models-manager/prompt.md at tag
 * rust-v0.167.0 (the Codex that codex-security 0.9.1 pins), vendored byte for byte as
 * codex-base-instructions.md. A catalog entry must carry them, and they are what Codex gives a
 * model it has no metadata for, so the catalog changes the window and nothing else.
 */
export const BASE_INSTRUCTIONS_SHA256 =
  'ac8ae107a0d72fe3476b430afb161ea4e67da2e446d778aefc44828160559807';

/**
 * The context size, in tokens, at which Codex compacts a session, the lead's and each helper's.
 *
 * The compaction request carries the whole session, and cynos's quality judge reads it whole: its
 * input runs up to 1.23 times the turn it judges, in the 1M-token window of its model
 * (qwen/qwen3.8-27b). A request of up to about 813k tokens is judged. One that a large tool output
 * takes further past the limit (tool_output_token_limit allows 100k) does not fit, and the judge
 * fails open on it.
 */
export const AUTO_COMPACT_TOKEN_LIMIT = 800000;

/**
 * Codex's compaction prompt, with what a scan needs from the summary.
 *
 * - A compaction request offers no tools, and DeepSeek has answered one with tool-call markup in
 *   its text, which Codex then used as the summary.
 * - A helper's task arrives as a NEW_TASK agent message, which compaction drops, so the summary is
 *   the helper's only record of it. A helper whose summary lost its task carried on as the lead
 *   and completed the scan without the lead's findings.
 * - So the summary starts with the agent's role and its task as assigned, constraints included.
 */
export const COMPACT_PROMPT = `You are performing a CONTEXT CHECKPOINT COMPACTION. Create a handoff summary for another LLM that will resume the task.

This step only summarizes. Tools are not available in it: do not call a tool and do not write out a tool call. Reply with the summary text alone.

After this step the conversation is replaced by your summary. A task you were given by another agent (a NEW_TASK message) is not kept, so if you are working on a delegated task, your summary is the only record of it.

Begin with:
- Role and task: whether you are the lead agent or a helper another agent spawned, and the task exactly as it was assigned, with every constraint, prohibition and required output format. Quote them where the wording matters.

Then include:
- Current progress and key decisions made
- Results so far, with exact references (file paths, line numbers, identifiers, and the evidence for each finding)
- What remains to be done (clear next steps)
- Any critical data, examples, or references needed to continue

Be complete about the task and the results, and concise about everything else.
`;

/**
 * The proven benchmark configuration: all stock Codex flags, with the model catalog at the path
 * the scanner sees it at. analytics.enabled=false keeps Codex from sending usage metrics about a
 * private repository to OpenAI. features.shell_snapshot=false: Codex writes each session's shell
 * environment, CODEX_API_KEY included, to <CODEX_HOME>/shell_snapshots/ and deletes it only when
 * the session ends cleanly, so an interrupted or timed-out scan left the cynos key in plain text
 * in upstream's state dir (SHELL_SNAPSHOT_OFF); nor does any command the model runs see the key
 * (KEY_NOT_IN_COMMANDS). tool_output_token_limit is 100000: list_agents inlines every
 * finished helper's full result, and at 10000 its output was cut in the middle, which hid
 * still-running helpers from the lead and made it start duplicate ones.
 */
/**
 * No shell snapshots: Codex's snapshot of a session's shell holds its environment, the key
 * included, and outlives a session that is killed.
 */
export const SHELL_SNAPSHOT_OFF = 'features.shell_snapshot=false';

/**
 * No key in a command's environment: Codex reads the key from its own environment, but every
 * command the model runs inherits Codex's environment too, and a command's output is kept in the
 * session's rollout. Codex 0.167 stopped dropping variables named *KEY*, *SECRET* and *TOKEN*
 * from that environment unless told to: a scan's lead ran `env | grep -i codex` and its rollout
 * held CODEX_API_KEY in plain text (RealVuln hard10 on cynos 0.2.5, 8 of 10 repos). So the
 * default excludes are switched on by name, as upstream does for its own policy session.
 */
export const KEY_NOT_IN_COMMANDS = 'shell_environment_policy.ignore_default_excludes=false';

export function codexOverrides(modelCatalog: string): string[] {
  return [
    'tool_output_token_limit=100000',
    'features.code_mode=true',
    'features.code_mode_only=true',
    'suppress_unstable_features_warning=true',
    'features.apps=false',
    SHELL_SNAPSHOT_OFF,
    KEY_NOT_IN_COMMANDS,
    'features.multi_agent_v2.expose_spawn_agent_model_overrides=false',
    'analytics.enabled=false',
    `model_catalog_json="${modelCatalog}"`,
    `model_auto_compact_token_limit=${AUTO_COMPACT_TOKEN_LIMIT}`,
    // codex-security parses each value as TOML, and a JSON string is a valid TOML basic string.
    `compact_prompt=${JSON.stringify(COMPACT_PROMPT)}`,
  ];
}

/**
 * openai/codex-security plugins/codex-security at tag npm-v0.9.1: the workflow files a scan
 * replaces with ours (assets/scan-prompt/<path>, scan-plugin.ts), by plugin-relative path, for each
 * kind of scan. A full scan's lead follows security-scan's SKILL.md and its core-scan.md; a diff's,
 * security-diff-scan's SKILL.md. Ours are written against these: upstream's policy word for word,
 * the mechanics for a scan with a knowledge base. A pin with another one stops every scan of that
 * kind until ours is reviewed against it and its sha256 updated here.
 */
export const REPLACED_WORKFLOW_SHA256: Record<'full' | 'diff', Record<string, string>> = {
  full: {
    'skills/security-scan/SKILL.md':
      '99cfcbbaa9d5b0450881ec752a116888b05b7fe21ea7af28fd22d088882dcd46',
    'references/core-scan.md': '0e301a70d9f20acbb797f5eafcac84c09dd0513991714812d5c4f7b1f64a4a89',
  },
  diff: {
    'skills/security-diff-scan/SKILL.md':
      '09232fd5d96cfed2a5bdccd176c09b7e9ca53ebd7ac136d283bec884fde94b0d',
  },
};

/** openai/codex-security docker/ at tag npm-v0.9.1, vendored byte for byte. */
export const PROFILE_SHA256: Record<string, string> = {
  'codex-security-seccomp.json': '3a798a9ffc8e9d9743cdbd9e014b07265ff76a695a703049d62655de61f0bdbe',
  'codex-security.apparmor': 'bcfee32927deb02ce279b2d18e55b1780acdf8324232e7bc0424011eadd8c855',
};
export const APPARMOR_PROFILE_NAME = 'codex-security-container';
/** upstream's package in the scanner image: npm's global root on its node base image. */
export const C_UPSTREAM = '/usr/local/lib/node_modules/@openai/codex-security';
/** The Dockerfile asserts this path exists after install. */
export const CODEX_BIN = `${C_UPSTREAM}/node_modules/@openai/codex/bin/codex.js`;

/**
 * Helpers a scan with a knowledge base runs at once: one per packet (at most 8), the baseline
 * auditor and the hypothesis packets. The lead starts them all in two replies, so the cap must hold
 * them; helpers past it wait for a slot (the workflow's "full worker pool").
 */
export const KNOWLEDGE_BASE_MAX_THREADS = 12;
/**
 * Hypothesis packets: investigation packets that settle the hypotheses, shared out between them
 * (hypotheses/ hypothesisPackets). By default the thread cap less 8 packets and the baseline
 * auditor, so they start with the other helpers. On an interpreter where the packets alone never
 * found the two target bugs, one investigator per hypothesis found both.
 */
export const DEFAULT_HYPOTHESIS_PACKETS = 3;
/**
 * The scan's workflow files and their parts (prompt-template.ts readScanPrompt): our edited copies
 * of upstream's workflow files at their plugin paths, the lead's own rules they include, the rules
 * every agent follows, and the scripts.
 */
export const PROMPT_DIR = 'scan-prompt';
/** The directory a knowledge-base build writes what the scan reads into. */
export const KNOWLEDGE_BASE_OUTPUT = 'output';

// Paths as the docker runtime's containers see them (runtime/docker.ts).
export const C_PROJECT = '/scan/project';
export const C_PROMPT = '/scan/prompt.md';
/** The knowledge base the lead reads: its index of helpers and the threat model (read-only). */
export const C_KNOWLEDGE_BASE = '/scan/knowledge-base';
/** The helpers' briefs, the reader and its file and function index (read-only). */
export const C_KB_INDEX = '/scan/kb';
/** Where a build writes the helpers' directory, beside its output/. */
export const KNOWLEDGE_BASE_INDEX = 'kb';
/** The prompt's helper sections, which every helper prints as its first command (read-only). */
export const C_HELPER_CONTEXT = '/scan/helper-context.md';
/** upstream's plugin with this scan's skill (--plugin-path, read-only). */
export const C_PLUGIN = '/scan/plugin';
/** The caller's severity rubric and dismissals, when it gives them (scan-inputs.ts; read-only). */
export const C_RUBRIC = '/scan/inputs/severity-rubric.md';
export const C_FALSE_POSITIVES = '/scan/inputs/false-positives.json';
export const C_OUT = '/scan/out';
/** codex-security creates it itself; it must not exist yet. */
export const C_SCAN_OUT = `${C_OUT}/scan`;
export const C_STATE = '/scan/state';
/** HOME and working directory, owned by the runner's uid. */
export const C_HOME = `${C_STATE}/home`;
/**
 * Codex's temporary directory in the Codex home upstream keeps under its state dir: a tmpfs, not
 * part of the state mount (runtime/docker.ts, mounts).
 */
export const CODEX_TMP_DIR = 'codex-home/tmp';
export const C_CODEX_TMP = `${C_STATE}/${CODEX_TMP_DIR}`;
/** The architecture review agent's directory: its home, index, reader and answer. */
export const C_REVIEW = '/scan/review';
/** The code graph's home inside its container. */
export const C_GRAPH_HOME = '/scan/graph';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'] as const;
export type Severity = (typeof SEVERITIES)[number];
