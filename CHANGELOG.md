# Changelog

## 0.3.2 - 2026-11-26

### Added

- A scan that calls the model reports its start and finish to Cynos, with the scan's own key, so a failed or slow scan is seen without you reporting it. It sends the outcome, duration, scan kind, runtime, CLI version, each phase's status and duration, and the number of files scanned; on failure, the failed phase and its error message with the key, the checkout's path and the home directory removed. The repository is sent only as a hash, and no code or findings are sent. A mock scan and `--dry-run` send nothing, and a report that can't be sent never fails the scan. See [Scan telemetry](packages/cli/README.md#scan-telemetry).

### Fixed

- A native scan in a terminal no longer ends by asking "Open findings for review?", which opened a patch review cynos does not offer. The dashboard no longer reads the keyboard during a scan.
- A scan no longer fails at the end with "The latest saved scan draft is incomplete" after resubmitting an already accepted draft. The scan's workflow now says that a later draft must be complete and must keep the findings already submitted.
- A scan no longer slows to a crawl on a repository with very long runs of one character: a remote URL with many slashes, a C file with a long run of spaces or name characters, or a long minified line. These were read with patterns that took quadratic time on such input.

## 0.3.1 - 2026-11-24

### Fixed

- Keep Codex's temporary sandbox launchers on a private tmpfs in Docker runs, preventing Docker Desktop on Mac from deleting active launchers and breaking subsequent shell commands.
- Point scan drafts and validation retries to the draft tool's schema, avoiding rejected threat-model scope fields.
- Require trace checks to account for every failed call, including yielded exec cells, and exclude duplicate run directories and the check's own sessions.

## 0.3.0 - 2026-11-19

### Changed

- **Breaking:** scan history commands read each scan's run directory for both native and Docker runs. Use `scans list`, `scans findings`, `scans export`, and `scans logs`; the previous `scans show` command is removed.
- **Breaking:** simplify the scan and garbage-collection interfaces. Model selection uses `CYNOS_SCAN_MODEL`; removed scan flags include `--model`, `--effort`, `--mode`, `--max-time`, `--no-knowledge-base`, `--load-apparmor`, `--no-judge`, and `--no-routing`. `gc --max-cache-size` is also removed (the cache limit is 2 GiB); see the CLI command reference for supported options.
- Debug bundles exclude session transcripts and read results from the scan's run directory.
- Rewrite the user guide and move public release documentation to `CONTRIBUTING.md`.

### Fixed

- Save helper results through a script and use slug identities for findings, avoiding invalid helper output and finding identifiers.
- Include the release's scanner image digest in both the engine and bundled CLI packages, and verify both pins before publishing.
- Stop releases on registry inspection errors; only an explicit missing manifest allows a new image version.
