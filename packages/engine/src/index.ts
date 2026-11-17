/**
 * @averlon-ai/cynos-scan-engine: upstream @openai/codex-security, pinned and unmodified,
 * run through cynos with a knowledge base, on the native or the docker runtime.
 *
 * The scan is the same wherever it runs; only what surrounds it differs. The GitHub action
 * decides what to scan from the event and publishes the reports; the cynos CLI scans a
 * laptop's checkout and keeps the results in upstream's history; the benchmark CLI scans staged
 * repositories and keeps everything as evidence. All of them call scanCheckout, and this file is
 * the package's whole interface:
 *
 *   scan        scanCheckout and its config, hooks and result
 *   runtime     the runtime seam, upstream's install, the state dir, tracked processes
 *   host        checkHost and fixHost: doctor and the scan's preflight
 *   progress    the scan's progress events
 *   knowledge   the knowledge base's store and summary types, as run.json and result.json record them
 *   bench       benchMain, the benchmark CLI (build-image, scan, doctor)
 *   action      what the action's own steps share with the scan: the outcome and report rules,
 *               the stage's cleanup, report and log helpers
 */

// scan
export {
  containerNames,
  filesContaining,
  readScanInputs,
  redact,
  scanCheckout,
  type ScanConfig,
  type ScanIO,
  type ScannedRun,
  type ScanResult,
  type ScanSettings,
} from './pipeline';
export { type FalsePositive, type ScanInputs } from './scan-inputs';
export { BASE_URL, ENGINE_VERSION } from './constants';
export { checkKey, keyCheckFailure, type Fetch, type KeyCheck, type KeyRefusal } from './key-check';

// runtime
export {
  createRuntime,
  DockerRuntime,
  NativeRuntime,
  RUNTIMES,
  type PrepareOptions,
  type ReviewAgentPlan,
  type RuntimeCommand,
  type RuntimeName,
  type RuntimeOptions,
  type ScanPaths,
  type ScanRuntime,
} from './runtime';
export { killContainer, type HostPaths } from './runtime/docker';
export {
  nodeExecutable,
  resolveUpstream,
  upstreamCommand,
  UPSTREAM_PIN,
  verifyUpstream,
  type Upstream,
} from './upstream';
export { resolveStateDir, type ScanLayout } from './layout';
export {
  ProcessRegistry,
  spawnTracked,
  stopProcess,
  stopProcesses,
  STOP_GRACE_MS,
  type TrackedProcess,
  type TrackedSpawn,
} from './processes';

// host
export {
  checkHost,
  fixHost,
  FIXABLE_CHECKS,
  type HostCheck,
  type HostCheckGroup,
  type HostCheckOptions,
  type HostCheckStatus,
  type HostDeps,
} from './host-check';

// progress
export {
  phase,
  say,
  SCAN_PHASES,
  skipped,
  type ProgressIO,
  type ScanEvent,
  type ScanPhase,
  type ScanStep,
  type TokenUsage,
} from './progress';

// knowledge
export { LocalKnowledgeBaseStore, type KnowledgeBaseStore } from './knowledge-base/store';
export type { DiffKnowledgeBaseSummary, KnowledgeBaseSummary, ScanKind } from './knowledge-base';
export type { BriefSummary } from './knowledge-base/briefing';
export type { ReviewStats } from './knowledge-base/architecture';
export type { AgentStats } from './knowledge-base/architecture-agent';
export type { ReuseStats } from './knowledge-base/stored-review';
export {
  CODE_GRAPH_VERSION,
  defaultToolCache,
  ensureCodeGraphBinary,
} from './knowledge-base/code-graph-binary';

// bench
export { benchMain } from './bench/cli';

// action
export { DEFAULT_MODEL, REASONING_EFFORTS, SEVERITIES, type Severity } from './constants';
export { discardWorkspace } from './layout';
export { dockerEnvironment } from './runtime/docker';
export { arr, at, isRecord, obj, text, type JsonObject } from './json';
export { plain, safeLogLines } from './log-lines';
export { type ValidatedReports } from './reports';
export {
  decide,
  type Outcome,
  type PolicyStatus,
  type Report,
  type ReportStatus,
  type ScanStatus,
} from './results';
export { isFile, type ContainerRun, type ScannerRun, type Usage } from './scan-run';
