# Changelog

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
