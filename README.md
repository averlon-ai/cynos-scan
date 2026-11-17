# cynos

Averlon's security scanner for a repository on your machine, in CI, or in a container. It runs
OpenAI's [`@openai/codex-security`](https://www.npmjs.com/package/@openai/codex-security) unchanged,
with three additions:

- cynos (`https://api.cynos.averlon.ai/v1`) is the model endpoint;
- a knowledge base the scan reads instead of searching: a code graph, labelled entry points and
  sinks, an architecture review, and one brief for each helper;
- diff scans get a knowledge base for the change: the call paths through every changed function,
  the last full scan's threat model brought up to date, and one brief for each helper.

Install the CLI from npm:

```sh
npm install --global @averlon-ai/cynos
cynos login
cynos doctor
cynos scan .
```

Node.js 22.13+, 24 or 26 is required. Installing the package needs no npm token.
See [`packages/cli/README.md`](packages/cli/README.md) for commands and troubleshooting.

## Packages

| Package                                                  | What it is                                                                                        |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| [`@averlon-ai/cynos`](packages/cli)           | The `cynos` command                                                                          |
| [`@averlon-ai/cynos-scan-engine`](packages/engine) | `scanCheckout(config, io)`: one scan of a checkout, for the CLI, the GitHub action and benchmarks |

The engine runs a scan on one of two **runtimes**:

- **native**: upstream as upstream runs it, on the host under Codex's own sandbox (Seatbelt on
  macOS, Bubblewrap on Linux). This is the CLI's default.
- **docker**: upstream inside our hardened scanner container (upstream's seccomp and AppArmor
  profiles, `--cap-drop ALL`, a read-only checkout, the key by name, no network for the preflight
  and the code graph). Use `--runtime docker` to select it.

A scan can be steered with `--rubric` (how it grades severity) and `--false-positives` (findings
reviewers already dismissed, with their reasons); see `cynos help scan-inputs`.

A harness that scans many repositories with `cynos`, such as a benchmark, has what it needs on
`scan`: `--scan-prompt-file` for its rules, `--no-judge` and `--no-routing` for cynos's switches,
`--timeout` for a hard limit per scan, and `--host-path` for the docker runtime when cynos runs
in a container that drives the host's Docker. See [`packages/cli/README.md`](packages/cli/README.md).

## Development

Use Bun 1.3 or later and Node.js 22.13+, 24 or 26.

```sh
bun install
bun run test
bun run typecheck
bun run lint && bun run format:check
bun run build
bash scripts/e2e.sh native     # upstream's synthetic scan of a fixture, no key needed
bash scripts/install-smoke.sh <packed cynos .tgz> native   # the same, as npm installs it
```

## Workflows

- **CI** runs tests on Linux and macOS, checks workflow security, builds both packages, and
  runs a native mock scan and dependency audit against the packed CLI. PR jobs have read-only
  permissions and no release credentials.
- **Stage npm release** runs manually from `main`. It repeats CI, then stages the tested tarballs
  through the protected `npm-publish` environment. A maintainer reviews and approves the staged
  packages with npm 2FA before they become available to users.
- **OpenSSF Scorecard** runs on pushes to `main` and weekly. It
  publishes results to [Scorecard](https://scorecard.dev/viewer/?uri=github.com/averlon-ai/cynos-scan)
  and uploads SARIF to GitHub code scanning. It uses the official action required by Scorecard's
  result-verification service, pinned to a commit. Its container runtime is managed by that action.
- **Dependabot** proposes weekly action-pin updates with a seven-day cooldown.

## Releases

The packages are `@averlon-ai/cynos` and `@averlon-ai/cynos-scan-engine` on npmjs.com.
Both package manifests must contain the same stable version. Merge the version changes and the
updated `bun.lock` through review, then dispatch `npm-publish.yml` from `main`.

The build jobs have no publishing authority. The release job has no checkout, dependency install,
shared cache, or lifecycle scripts: it downloads only the artifact from the same workflow run,
checks its hashes and package identities, and submits it with `npm stage publish`. No npm token
is stored in GitHub. The npm trust is restricted to this repository, this workflow, and the
`npm-publish` environment. Forks have a different repository identity; PRs do not trigger releases.

After GitHub environment approval, review both staged packages on npm, including their versions,
provenance and hashes, then approve with 2FA. If staging one package fails, inspect npm's staged
packages before retrying so the successful stage is not mistaken for a completed release.
Package approval is per package, so approve both versions. These releases build Docker images
locally when needed; they do not publish a scanner image to a registry.

## License

Apache-2.0; see [LICENSE](LICENSE).
