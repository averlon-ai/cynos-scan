# @averlon-ai/cynos-scan-engine

Upstream `@openai/codex-security`, pinned and unmodified, run through cynos with a knowledge base:
the scan of a checkout, on one of two runtimes:

- **native**: upstream exactly as upstream runs on a laptop, from `node_modules` on the host,
  under Codex's own OS sandbox (Seatbelt, Bubblewrap); no jail or narrowed read scope of ours;
- **docker**: the hardened scanner container (upstream's seccomp and AppArmor profiles,
  `--cap-drop ALL`, the checkout read-only, the key by name, no network for the preflight and
  the code graph).

Both are `ScanRuntime`s (`src/runtime/`), sibling implementations of the same methods.

The engine is shared by the cynos CLI (`packages/cli`), integrations using `scanCheckout`,
and benchmarks through `src/bench/cli.ts`. The CLI uses the native runtime by default;
integrations choose their runtime and how to publish results.

## Interface

`src/index.ts` is the package's whole interface.

| Export                                        | What it is                                                                                       |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `scanCheckout(config, io)`                    | One scan of `config.project` in `config.stage`: image, preflight, knowledge base, scan, reports  |
| `ScanConfig`, `ScanIO`, `ScanResult`          | What to scan, on which runtime, with which keys; the caller's hooks (log, progress, store, processes, stop); what came back (outcome, `scanId`, `scanDir`, upstream's `exitCode`) |
| `ScanRuntime`, `createRuntime`, `ScanPaths`   | The runtime seam: the paths the scanner sees and every command it runs                          |
| `checkHost`, `fixHost`, `HostCheck`           | Doctor and the scan's preflight: whether this machine can scan on a runtime, and the fix         |
| `resolveUpstream`, `upstreamCommand`, `UPSTREAM_PIN` | The pinned upstream and Codex in `node_modules`                                           |
| `resolveStateDir`                             | upstream's state dir, by upstream's rule                                                         |
| `spawnTracked`, `ProcessRegistry`, `stopProcesses` | The native runtime's process groups, and stopping them                                      |
| `ScanEvent`, `ScanPhase`                      | Progress events, carried by `ScanIO.progress`                                                    |
| `KnowledgeBaseStore`, `LocalKnowledgeBaseStore` | Carries the knowledge-base cache between scans                                                 |
| `benchMain(argv)`                             | The benchmark CLI: `build-image`, `scan`, `doctor`                                               |
| `KnowledgeBaseSummary`, `ReviewStats`, ...    | The knowledge base's numbers, as `run.json` and `result.json` record them                        |
| `decide`, `discardWorkspace`, `killContainer` | What the action's own steps share with the scan: the report rule, the stage's cleanup            |

`scanCheckout` runs, in order:

1. **stage**: the stage's directories, the model catalog, the runtime prepared (docker: the
   vendored profiles, sha256-checked, the image, built or pulled from `assets/image.json`,
   AppArmor; native: upstream's pins, the code-graph binary), the versions it runs;
2. **preflight**: `checkHost`, upstream's sandbox check, the scan cut off from the model (no
   network, or natively a dead endpoint), and the key check;
3. **knowledge**: a full scan's knowledge base (code graph, Jev labels, architecture review agent,
   packets, helper briefs, and hypotheses shared out between up to 3 hypothesis
   packets), or a diff's (the change, the call paths through it, the last full
   scan's threat model brought up to date, packets from upstream's own rules, helper briefs;
   `src/knowledge-base/diff.ts`). A diff with no full scan's threat model stored fails here, as a
   failed build does: the prompt plans the scan around the knowledge base. Every model call it makes goes
   through cynos with the scan's key: Jev's labels through cynos's Decisions API
   (`POST /v1/decisions`, OpenAI's Decisions shape), capped at $10 of Jev spend;
4. **brief**: the scan's documents from `assets/scan-prompt/`: our copies of upstream's workflow
   files at their plugin paths (a full scan's `references/core-scan.md`, the lead's whole audit,
   and the `security-scan` skill that sends the lead to it; a diff's `security-diff-scan` skill),
   and the helpers' instructions (`helper-<kind>.md`). Each is written for a scan with a knowledge
   base, with upstream's policy (severity, secrets, validation, the helpers' tasks) kept word for
   word. Sections more than one document holds are in `parts/`, and the `exec` scripts the lead
   runs in `scripts/*.js` (typechecked and tested). They are rendered at the runtime's paths
   (`{{PROJECT}}`, `{{KB_INDEX}}`, `{{HELPER_CONTEXT}}`, `{{KNOWLEDGE_BASE}}`, `{{SCAN_DIR}}`) into
   a copy of upstream's plugin given to upstream with `--plugin-path` (`src/scan-plugin.ts`). The
   caller's addendum is the scan prompt. Every helper prints its instructions, with the addendum's
   sections marked `<!-- helper-context -->`, as its first command;
5. **scan**: upstream's scan on the runtime, headless (`--headless --json`) or with upstream's
   own dashboard (`interactive`); upstream's outcome rules; `run.json`;
6. **report**: strict SARIF, and the key-leak check when the caller publishes.

Everything stays in the stage and the scan dir; the caller decides what to keep. The docker
runtime keeps upstream's state dir in the stage; the native runtime uses upstream's own (or the
caller's path), creating the scan dir where upstream would, so scans appear in upstream's history.

## Benchmark CLI

```sh
node dist/bench.js build-image
node dist/bench.js doctor [--runtime docker|native|all] [--json] [--fix [--allow-sudo]]
CYNOS_API_KEY=... \
  node dist/bench.js scan --project <staged checkout> --out <new dir> --name rv-<id> \
  [--runtime docker|native] \
  [--model ID] [--effort xhigh] [--base-url URL] [--judge on|off] [--routing on|off] \
  [--cache-dir DIR] [--timeout SECONDS] [--prompt-addendum FILE] [--host-path HERE=HOST]... \
  [--price IN,CACHED,OUT] [--apparmor]
```

- **The key** (cynos's, the only one) comes from the environment only, and is removed from it
  once read. Before `result.json` is written, every file under `--out` (Codex's state included)
  is searched for it and any value found is replaced with `***`; the files are listed in
  `keys_scrubbed`.
- **`--out`** must be new or empty, and nothing under it is deleted: the reports, `run.json`, the
  knowledge base and Codex's state for the scan and the architecture agent all stay as evidence.
- **`--host-path HERE=HOST`**: for a harness that runs in a container and reaches the host's
  Docker through its socket. The daemon resolves bind mounts on the host, so each mount source
  under `HERE` is given as the same path under `HOST`.
- **`--timeout`** stops the run and kills its containers; `result.json` then says `stopped`.
- **`--price`** (USD per 1M tokens: uncached input, cached input, output) prices the scan's and the
  review agent's tokens when the CLI has no estimate (it prices no cynos model id). Jev's labels
  are priced at cynos's catalog rate for Jev (`src/knowledge-base/jev.ts`).
- **`--prompt-addendum`**: benchmark-only rules appended to the scan prompt. Each benchmark keeps
  its own; the engine ships none.
- **Diff scans** are the action's alone: the CLI runs full scans.

`result.json`: `status` (`completed`, `failed`, `key-leak`, `stopped` or `error`),
`outcome`, `findings` (the validated `reports/findings.json`, or null), `state_dirs`, `run_json`,
`knowledge_base`, `usage`, `cost`, `seconds`, `versions`, `keys_scrubbed` and the settings.

## Files

| File                                                                   | What it is                                                                                 |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `src/pipeline.ts`                                                      | `scanCheckout` as named phases, the leak check, the run prompt                             |
| `src/runtime/`                                                         | `ScanRuntime`: `docker.ts` (every `docker run`) and `native.ts` (upstream on the host)     |
| `src/scan-command.ts`, `src/prompt-template.ts`                        | upstream's scan arguments and the prompt, at the runtime's paths                           |
| `src/scan-run.ts`, `src/sandbox.ts`                                    | The scan's run and the preflight                                                           |
| `src/upstream.ts`, `src/layout.ts`, `src/processes.ts`                 | The pinned upstream, the state dir and scan dir, tracked process groups                    |
| `src/host-check.ts`, `src/progress.ts`                                 | `checkHost`/`fixHost`; progress events                                                     |
| `src/key-check.ts`, `src/results.ts`, `src/reports.ts`, `src/sarif.ts` | The key check, upstream's outcome rules, report checks, strict SARIF export                |
| `src/knowledge-base/`                                                  | The knowledge base: `index.ts` (the steps, the prompt filters), the graph and its pinned binary, Jev, the review, the store |
| `src/hypotheses/`                                                      | Hypotheses: templates of Jev questions and code-graph queries, no imports from the rest of the engine |
| `src/bench/cli.ts`                                                     | The benchmark CLI                                                                          |
| `assets/`                                                              | Dockerfile, entrypoint, versions.sh, profiles, base instructions, scan prompt              |

Run the tests with `bun test packages/engine`. The end-to-end native mock scan is opt-in:
`CYNOS_SCAN_E2E=1 bun test packages/engine/src/__tests__/e2e-native.test.ts`, with a Node in
upstream's range (^22.13, 24 or 26) first on PATH; it works under the git-ignored
`packages/engine/.e2e/`.
