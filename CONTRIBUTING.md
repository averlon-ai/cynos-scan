# Contributing to Cynos

For using Cynos, see [README.md](README.md). Agent and code guidance is in [AGENTS.md](AGENTS.md).

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
  permissions and no release credentials. Installation checks also verify Windows guidance and
  run the packed CLI in Ubuntu on WSL 2.
- **Stage npm release** runs manually from `main`. It publishes the scanner image to
  `ghcr.io/averlon-ai/cynos-scan`, repeats CI with the packages pinning that image, then stages
  the tested tarballs through the protected `npm-publish` environment. A maintainer reviews and
  approves the staged packages with npm 2FA before they become available to users.
- **OpenSSF Scorecard** runs on pushes to `main` and weekly. It
  publishes results to [Scorecard](https://scorecard.dev/viewer/?uri=github.com/averlon-ai/cynos-scan)
  and uploads SARIF to GitHub code scanning. It uses the official action required by Scorecard's
  result-verification service, pinned to a commit. Its container runtime is managed by that action.
- **Dependabot** proposes weekly action-pin updates with a seven-day cooldown.

## Releases

The packages are `@averlon-ai/cynos` and `@averlon-ai/cynos-scan-engine` on npmjs.com.
Both package manifests must contain the same stable version. Merge the version changes and the
updated `bun.lock` through review, then dispatch `npm-publish.yml` from `main`.

The release first publishes the docker runtime's scanner image, and the packages pin it. It builds
`packages/engine/assets/Dockerfile` natively for amd64 and arm64 and scans every layer for
secrets before pushing anything. It then pushes both images, merges them into the index
`ghcr.io/averlon-ai/cynos-scan:v<version>` (refused when that tag exists), and checks that the
index can be pulled without credentials. CI writes that index's digest to the engine's `assets/image.json` before building,
then packs the engine and the CLI (with the same pin in `dist/assets/image.json`), so the installed CLI's docker runtime pulls exactly that image (a checkout,
with no `image.json`, builds it), and runs the packed CLI on both runtimes. The image is built
from this repository with its own token, so its labels, provenance and attestations name only this
repository.

The first release creates the `cynos-scan` package as private and fails the credential-free
check. A package admin sets the package's visibility to Public once in its settings, then re-runs
the failed jobs.

Apart from the image jobs, which can write only packages, the build jobs have no publishing
authority. The release job has no checkout, dependency install,
shared cache, or lifecycle scripts: it downloads only the artifact from the same workflow run,
checks its hashes, package identities and both image pins, and submits it with `npm stage publish`. No npm token
is stored in GitHub. The npm trust is restricted to this repository, this workflow, and the
`npm-publish` environment. Forks have a different repository identity; PRs do not trigger releases.

After GitHub environment approval, review both staged packages on npm, including their versions,
provenance and hashes, then approve with 2FA. If staging one package fails, inspect npm's staged
packages before retrying so the successful stage is not mistaken for a completed release.
Package approval is per package, so approve both versions.
