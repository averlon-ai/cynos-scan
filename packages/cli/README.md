# cynos

Find security issues in your code on your own machine. `cynos` runs upstream
[Codex Security](https://learn.chatgpt.com/docs/security/cli) (`@openai/codex-security`, pinned)
through cynos, with what Averlon adds on top: a knowledge base built before each scan (for a
diff, sized to the change, with the last full scan's threat model brought up to date), and an
optional hardened Docker runtime.

Each scan's results and log are in its run dir, on either runtime, and `cynos scans` reads them
there. upstream's own history (`codex-security scans`) has the native scans only: a docker scan's upstream
kept its history in the container.

## Install

`cynos` runs on macOS and Linux, with Node.js 22.13+ (22.x), 24.x or 26.x. On Windows, run it
inside WSL 2.

Install it from npm. No registry token or `~/.npmrc` entry is needed.

```bash
npm i -g @averlon-ai/cynos      # or: pnpm add -g / bun add -g
cynos --version
```

Or without installing: `npx @averlon-ai/cynos scan .`

## Quick start

```bash
cynos login                 # paste your cynos key (masked); the only key a scan needs
cynos doctor                # will my next scan work?
cynos scan .                # a full scan of this checkout
cynos scan . --since-last-scan
cynos scans list            # every scan on this machine, native and docker alike
```

In a terminal, `scan` shows a live view of its own phases (stage, preflight, knowledge, brief),
then hands the terminal to upstream's dashboard (`d` details, `a` all sources, `m` the main scan,
`1`–`9` a worker). CI, pipes, `--headless`, `--verbose` and `--format json` print plain lines on
stderr instead. Results always go to stdout, progress and diagnostics to stderr.

## Commands

Every command has `--help` with examples; `cynos help <topic>` explains the concepts (auth,
runtimes, diff-scans, knowledge-base, scan-inputs, exit-codes, env).

### Scan

| Command | What it does |
| --- | --- |
| `scan [PATH]` | Scan a checkout (default `.`). |

`scan` options:

| Option | Meaning |
| --- | --- |
| `--diff REV` | Only the changes from REV to HEAD. |
| `--since-last-scan` | Only the changes since this repository's last completed scan, if its revision is an ancestor of HEAD; otherwise a full scan, saying why. |
| `--path PATH` | Limit the scan to a file or directory (repeatable). |
| `--rubric FILE` | Grade severity with the rubric in FILE instead of upstream's default (upstream's `--rubric`; every helper prints it too). |
| `--false-positives FILE` | A JSON array of findings reviewers dismissed, each with a `reason`, the finding's `title` and `locations`, and optionally its `fingerprint`. The scan drops a finding only if its recorded reason still holds (`help scan-inputs`). |
| `--timeout DURATION` | Stop the whole run after DURATION and keep what it has: hours (`2`) or `90s` / `30m` / `2h`, up to 96h. A stopped run exits 2. A hard limit, except for preparing the runtime, which runs to completion first: the docker runtime's scanner image (its build or pull) and the native runtime's code-graph binary (its one-time download). Prepare it beforehand (`doctor --fix`), and on docker pass `--no-build-image`, to keep the whole run inside the limit. |
| `--scan-prompt-file FILE` | Append scan instructions from FILE to the scan prompt (upstream's flag name). |
| `--fail-on-severity LEVEL` | Exit 1 for findings at or above `critical`, `high`, `medium` or `low`. |
| `--dry-run` | Validate the configuration only. |
| `--runtime native\|docker` | Where upstream runs (default `native`, or `CYNOS_SCAN_RUNTIME`). |
| `--host-path HERE=HOST` | Docker runtime, with cynos in a container driving the host's Docker through its socket: the directory HERE is HOST on the Docker host (repeatable). The daemon resolves bind mounts there. |
| `--headless` | Plain progress lines instead of the live view and upstream's dashboard. |
| `--format pretty\|json\|jsonl` | `json`: one JSON object on stdout (`scanId`, `scanStatus`, `scanDir`, `exitCode`, `counts`, …, `knowledgeBase`: what the knowledge base built, a full scan's or a diff's, told apart by its `kind`, `diffThreatModel`: the threat model a diff started from (its `source`: `stored`, a full scan's, or `built`, one the diff built with none stored) and whether it was updated, `rubric` and `falsePositives`: the scan's inputs, and `stopped`: why a stop ended the run). `jsonl`: every progress event, then the result. |

Ctrl-C once stops the scan gracefully and keeps what it has; twice exits at once (130). Any stop
(Ctrl-C, SIGTERM or `--timeout`) also kills the run's scanner containers on the docker runtime.

### Review results

| Command | What it does |
| --- | --- |
| `scans list [--json]` | Every scan on this machine, newest first: its id, when it finished, runtime, kind, status, findings and repository. |
| `scans findings ID` | A scan's findings, most severe first. |
| `scans export ID [--format sarif\|json\|md] [--output FILE]` | A scan's SARIF (the default), `findings.json` or Markdown report, to stdout or FILE. |
| `scans logs [ID] [--follow]` | A scan's log (default: the newest run's, a running scan included). |

An `ID` is a scan id, a unique prefix of one, or the run name of a run that never got one. These
commands read each scan's run dir, which a native and a docker scan both have, so they work the
same on either runtime. upstream's own history (`codex-security scans`) has only native scans.

### Sign in

| Command | What it does |
| --- | --- |
| `login [--with-api-key]` | Save the cynos key, after a 16-token check against the endpoint. `--with-api-key` reads it from stdin. |
| `auth status [--json]` | Which key a scan uses and from where (env, keychain or file), a fingerprint, and the endpoint. |
| `logout` | Remove the saved key. |

Keys are kept in the macOS keychain, the Secret Service on Linux (`secret-tool`), or a 0600 file
in `~/.config/averlon/cynos/` when neither is available. A key never appears in a command
line or a log.

The cynos key is the only key: a full scan's knowledge base makes its model calls, Jev's labels
included, through cynos.

### Setup and support

| Command | What it does |
| --- | --- |
| `doctor [--runtime native\|docker\|all] [--fix] [--json] [--quick]` | Check this machine for a scan; `--fix` repairs what it can (asking before sudo). Exit 0 when nothing failed, else 2. |
| `update [--check]` | Install the latest version with the package manager that installed this one, then `doctor --quick`. |
| `info [--json]` | Versions, runtime, model, endpoint and paths. |
| `debug bundle [ID] [--output FILE] [--yes]` | A tarball to share for a scan, with every key scrubbed. |
| `gc [--dry-run] [--yes]` | Remove stale run dirs, old knowledge-base snapshots and exited scan containers. |
| `completion bash\|zsh\|fish` | Shell completion. |
| `help [TOPIC\|COMMAND]` | Help topics, or a command's help. |
| `--llms` | A JSON manifest of every command, for agents. |

Global options: `-q, --quiet`, `-v, --verbose`, `--no-color`, `-V, --version`.

## Environment variables

| Variable | Effect |
| --- | --- |
| `CYNOS_API_KEY` | The cynos key; takes precedence over the saved login. |
| `CYNOS_BASE_URL` | The cynos endpoint (default: `https://api.cynos.averlon.ai/v1`). |
| `CYNOS_SCAN_RUNTIME` | The default runtime: `native` or `docker`. |
| `CYNOS_LOG_LEVEL` | `debug` for diagnostics; passed to upstream as `CODEX_SECURITY_LOG_LEVEL`. |
| `CYNOS_CREDENTIAL_STORE` | `file` to keep saved keys in the 0600 file instead of the keychain. |
| `CYNOS_NO_UPDATE_NOTICE`, `NO_UPDATE_NOTIFIER` | Turn off the daily update notice. |
| `CI` | No prompts, no live view, no update notice. |
| `NO_COLOR` | No colour. |
| `CODEX_SECURITY_STATE_DIR`, `CODEX_HOME` | upstream's state dir: native scans' upstream history, and every scan's run dir under `averlon/`, which `cynos scans` reads. |

Keys from the environment are read once at startup and removed from it, so no child process
inherits them.

## Exit codes

upstream's, unchanged:

| Code | Meaning |
| --- | --- |
| 0 | Completed, or passes the severity policy. |
| 1 | Severity policy violation (`--fail-on-severity`). |
| 2 | Every failure: invalid input, login, host check, knowledge base, runtime error, target change, a scan upstream stopped short, required-output failure, a scan stopped by `--timeout`. |
| 130 / 143 | Interrupted (Ctrl-C) / terminated (SIGTERM). |

The cause is on stderr, and with `--format json` in `error.kind` (`usage`, `auth`, `budget`,
`model`, `network`, `gateway`, `host-check`, `knowledge-base`, `engine`, `upstream`, `interrupted`,
`timed-out`, `internal`). `auth` is a key cynos does not know; `budget` a key whose budget is spent;
`model` a model cynos cannot serve for the key; `network` cynos unreachable; `gateway` cynos failing.

## Where files go

| Path | What |
| --- | --- |
| `<state>/` | upstream's state dir: `$CODEX_SECURITY_STATE_DIR`, else `$CODEX_HOME/state/plugins/codex-security` (`~/.codex/…`). A native scan's upstream history and scan dir. |
| `<state>/averlon/scans/<run name>/` | A scan's run dir, on either runtime: its result (`cli-result.json`), the validated reports (`reports/`), the engine's `run.json`, the knowledge base, `cli.log`, `events.jsonl`, `timings.json`. A docker scan's upstream state dir is its `state/`. `<state>/averlon/scans/<scan id>` links to it. |
| `<state>/averlon/knowledge-base-cache/` | Knowledge-base snapshots between scans, one per scanned commit. |
| `~/.config/averlon/cynos/` | Without a keychain, the saved key in `credentials.json` (0600). |
| `~/.cache/averlon/cynos/` | The update check's cache. |

## Troubleshooting

1. `cynos doctor` (or `doctor --runtime all`) says what is missing and how to fix it;
   `doctor --fix` repairs what it can.
2. `cynos scans logs [ID]` shows the scan's log; `-v` (or `CYNOS_LOG_LEVEL=debug`) adds
   diagnostics to any command.
3. `cynos debug bundle [ID]` writes one tarball with the scan's run dir, versions and the doctor
   report. It lists every file and asks before writing; every known key is replaced with `***`,
   and it refuses to write if a key is still present. Session transcripts (which hold your source
   code), databases and credentials are always left out.

Common problems:

- **"No cynos key"**: run `cynos login`, or set `CYNOS_API_KEY`.
- **`update` cannot reach the registry**: check your network and npm's registry
  (`npm config get registry`). The npm package needs no registry token.
- **Node version errors**: install Node 24 (`nvm install 24`) and reinstall.

## License

Apache-2.0; see [LICENSE](LICENSE).
