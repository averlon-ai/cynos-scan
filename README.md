# Cynos

Cynos is a security scanner to evaluate code. It finds, validates and reports vulnerabilities in a
repository on your own machine, in CI, or in a container. It is built on OpenAI's
[Codex Security](https://github.com/openai/codex-security).

- **In a terminal:** [install the CLI and scan a repository](#quick-start).
- **In CI or a benchmark harness:** [use the GitHub Action, or run the CLI headless](#ci-and-automation).
- **Contributing:** [build and test from source](#development).

## Why Cynos

Cynos runs security scans on open-source models served through the Cynos gateway. This makes a
scan cheaper and faster than running it on a frontier model, with accuracy that matches the
frontier models. A scan builds a threat model of the repository, looks for candidate
vulnerabilities, validates them, and writes a report with source evidence for each finding.

## Key features

- **Full scans and diff scans.** Scan a whole checkout, selected paths, the changes since a
  revision (`--diff origin/main`), or the changes since the last completed scan
  (`--since-last-scan`).
- **Validated findings.** Each candidate finding is validated before it is reported, and findings
  come with source locations and evidence.
- **Your own severity policy.** Grade severity with your own rubric (`--rubric`), and pass in
  findings that reviewers already dismissed (`--false-positives`) so that the scan drops them
  while their reason still holds.
- **Two runtimes.** The native runtime runs on the host in a sandbox (Seatbelt on macOS,
  Bubblewrap on Linux). The docker runtime runs inside a hardened scanner container with a seccomp
  profile, all capabilities dropped, and a read-only checkout, plus an AppArmor profile on Linux
  hosts where Docker supports AppArmor and the profile is loaded. Docker Desktop runs without
  AppArmor.
- **Review, export and CI gating.** List every scan on the machine, native and docker alike, show a
  scan's findings, export them as SARIF, JSON or a Markdown report (`cynos scans`), and fail a
  build on findings at or above a severity (`--fail-on-severity high`).
- **Built-in diagnostics.** `cynos doctor` checks the machine and fixes what it can, and
  `cynos debug bundle` packages a scan for support with your Cynos key removed.

## Setup

### Requirements

- macOS or Linux. On Windows, run Cynos inside WSL 2.
- Node.js 22.13+ (within 22.x), 24.x or 26.x.
- Python 3.10+ (on Python 3.10, also install `tomli`) and git.
- Docker, only if you use the docker runtime.

### 1. Create a Cynos API key

1. Sign up or log in at [app.cynos.averlon.ai](https://app.cynos.averlon.ai/).
2. Open **API keys** and create a new key.
3. Copy the key. It starts with `sk-cy-`.

### 2. Install the CLI

The CLI is published on npm as [`@averlon-ai/cynos`](https://www.npmjs.com/package/@averlon-ai/cynos).
Installing it needs no npm token.

```bash
npm install --global @averlon-ai/cynos
cynos --version
```

To run it without installing, use `npx @averlon-ai/cynos` in place of `cynos`.

### 3. Sign in and check the machine

```bash
cynos login     # paste the key from step 1; the prompt is masked
cynos doctor    # checks Node, Python, git and the sandbox; --fix repairs what it can
```

`cynos login` checks the key against the Cynos endpoint before saving it in the macOS keychain, the
Secret Service on Linux, or a `0600` file under `~/.config/averlon/cynos/` when neither is
available.

## Inference

Cynos uses one API key for every model call a scan makes.

| Provider                | Endpoint                          | Key                               |
| ----------------------- | --------------------------------- | --------------------------------- |
| **Cynos** (recommended) | `https://api.cynos.averlon.ai/v1` | `cynos login`, or `CYNOS_API_KEY` |

To get a key, sign up at [app.cynos.averlon.ai](https://app.cynos.averlon.ai/) and create one under
**API keys**. `CYNOS_BASE_URL` points the CLI at a different Cynos endpoint, and
`cynos auth status` shows which key and endpoint a scan will use.

A scan that calls the model also reports its start and finish to Cynos with that key: its outcome,
each phase's status and duration, and on failure the error's kind and a redacted message. The
repository is sent only as a hash, and no code or findings are sent. See
[Scan telemetry](packages/cli/README.md#scan-telemetry) for exactly what is sent.

## Quick start

From the repository you want to scan:

```bash
cynos scan .
```

In a terminal, the scan first shows its preparation steps and then a live dashboard of the scan
itself. When it finishes, it prints the path of the
Markdown report and the commands to see its findings again:

```bash
cynos scans findings <scan id>
```

### Scan options

```bash
# Scan selected paths.
cynos scan . --path src --path services/api

# Scan the changes from a base revision to HEAD.
cynos scan . --diff origin/main

# Scan only what changed since the last completed scan.
cynos scan . --since-last-scan

# Run in the hardened scanner container.
cynos scan . --runtime docker

# Grade with your own rubric and skip known false positives.
cynos scan . --rubric rubric.md --false-positives dismissed.json
```

Run `cynos scan --help` for every option, and `cynos help <topic>` for the concepts behind them
(`auth`, `runtimes`, `diff-scans`, `scan-inputs`, `exit-codes`, `env`).

### Review and export results

```bash
cynos scans list                                         # every scan on this machine, native and docker
cynos scans findings <scan id>                           # a scan's findings, most severe first
cynos scans export <scan id> --output results.sarif      # its SARIF; --format json or md for the others
cynos scans logs <scan id>                               # its log
```

An id can be a unique prefix of one, such as the first eight characters.

## CI and automation

### GitHub Actions

On GitHub, use the [cynos-scan action](https://github.com/averlon-ai/actions/tree/main/cynos-scan)
from `averlon-ai/actions`. It runs full scans and diff scans, comments findings on pull requests,
writes SARIF for code scanning, and can file one GitHub issue for each finding. To add it to a
repository:

1. Copy
   [`examples/cynos-scan.yml`](https://github.com/averlon-ai/actions/blob/main/cynos-scan/examples/cynos-scan.yml)
   to `.github/workflows/cynos-scan.yml`. Keep its `run-name`: the action fails a run whose title
   does not match the scan it runs.
2. Replace `ACTION_REF` with the commit SHA of a
   [release tag](https://github.com/averlon-ai/actions/releases) of `averlon-ai/actions`. Only
   release tags carry the built action.
3. Create the `cynos-scan` environment, restrict it to the default branch, and give it the secret
   `CYNOS_API_KEY`.

To scan pull requests too, copy
[`examples/cynos-scan-pr.yml`](https://github.com/averlon-ai/actions/blob/main/cynos-scan/examples/cynos-scan-pr.yml)
and create its `cynos-scan-pr` environment with its own `CYNOS_API_KEY`. The
[action's README](https://github.com/averlon-ai/actions/tree/main/cynos-scan#readme) lists its
inputs and outputs, and the permissions each job needs.

### Other CI systems and harnesses

Set `CYNOS_API_KEY` in the scan's environment. When `CI` is set, Cynos does not prompt and prints
plain progress lines instead of the live view.

```bash
export CYNOS_API_KEY=...   # from your CI secret store
npx @averlon-ai/cynos scan . --headless --format json --fail-on-severity high
```

`--format json` prints one JSON object on stdout with the scan's ID, status and counts. Progress and diagnostics always go to stderr. The exit code is `0` when the
scan completes or passes the severity policy, `1` when `--fail-on-severity` is violated, `2` for
any failure, `130` when the scan is interrupted (SIGINT) and `143` when it is terminated (SIGTERM);
`cynos help exit-codes` lists the causes.

A harness that scans many repositories, such as a benchmark, can use `--scan-prompt-file` for
its own rules, `--timeout` as a hard limit per scan, and `--host-path` when Cynos runs in a
container that drives the host's Docker.

## Troubleshooting

1. Run `cynos doctor` (or `cynos doctor --runtime all`) to see what is missing, and
   `cynos doctor --fix` to repair what it can.
2. Run `cynos scans logs [ID]` for a scan's log, and add `-v` (or `CYNOS_LOG_LEVEL=debug`) to
   any command for diagnostics.
3. Run `cynos debug bundle [ID]` to package a scan for support. Your Cynos key (from the
   environment or the saved login) is replaced with `***`, and session transcripts (which hold
   your source code) are never included. The bundle is not checked for other secrets, so review
   it before you share it.

See [`packages/cli/README.md`](packages/cli/README.md) for the full command reference, environment
variables and file locations.

## Packages

| Package                                            | What it is                                                                                             |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| [`@averlon-ai/cynos`](packages/cli)                | The `cynos` command.                                                                                   |
| [`@averlon-ai/cynos-scan-engine`](packages/engine) | `scanCheckout(config, io)`, one scan of a checkout, used by the CLI, the GitHub action and benchmarks. |

## Development

To build and test Cynos from source, and for releases, CI workflows and repository settings, see
[CONTRIBUTING.md](CONTRIBUTING.md). Agent and code guidance is in [AGENTS.md](AGENTS.md).

## License

Apache-2.0; see [LICENSE](LICENSE).
