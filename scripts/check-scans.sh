#!/usr/bin/env bash
# Every command that reads a finished scan, checked against one scan: `scans list`, `scans
# findings`, `scans export` (each format, to a file and to stdout), `scans logs` and `debug bundle`.
# They read only the scan's run dir, which both runtimes leave the same, so one set of checks
# serves both. e2e.sh runs it after its mock scan, e2e-real.sh after its real one.
#
#   bash scripts/check-scans.sh WORK SCAN_ID native|docker mock|real
#
# WORK is the e2e's private directory (the output goes under WORK/scans); CODEX_SECURITY_STATE_DIR
# must be the state dir the scan ran with. It runs this checkout's build, or CYNOS_BIN. With
# CYNOS_API_KEY set, the debug bundle must not hold it.
set -euo pipefail

work="${1:?usage: check-scans.sh WORK SCAN_ID native|docker mock|real}"
scan_id="${2:?scan id}"
runtime="${3:?native|docker}"
kind="${4:?mock|real}"
root="$(cd "$(dirname "$0")/.." && pwd)"
if [ -n "${CYNOS_BIN:-}" ]; then cli=("$CYNOS_BIN"); else cli=(node "$root/packages/cli/dist/cynos.mjs"); fi
out="$work/scans"
mkdir -p "$out" && chmod 700 "$out"

# A command that must fail (exit 2, upstream's code for every failure), with its message.
fails() {
  local status=0
  "$@" > /dev/null 2> "$out/error.txt" || status=$?
  [ "$status" = 2 ] || {
    echo "expected exit 2 from: $*, got $status" >&2
    exit 1
  }
}

echo "== scans list"
"${cli[@]}" scans list --json > "$out/list.json"
"${cli[@]}" scans list > "$out/list.txt"
# The run dir it names is where the other commands read; its reports are what they must show.
run_dir="$(node - "$out/list.json" "$scan_id" "$runtime" "$kind" <<'JS'
const { readFileSync } = require('node:fs');
const [file, id, runtime, kind] = process.argv.slice(2);
const scan = JSON.parse(readFileSync(file, 'utf8')).scans.find(s => s.scanId === id);
if (!scan) throw new Error(`scans list --json has no scan ${id}`);
const expected = { scanStatus: 'completed', runtime, mock: kind === 'mock' };
for (const [field, value] of Object.entries(expected))
  if (scan[field] !== value) throw new Error(`scans list says ${field} ${scan[field]}, not ${value}`);
console.log(scan.runDir);
JS
)"
grep -q "^$scan_id .*$runtime" "$out/list.txt" || {
  echo "scans list has no row for $scan_id on $runtime:" >&2
  cat "$out/list.txt" >&2
  exit 1
}

echo "== scans findings"
"${cli[@]}" scans findings "$scan_id" > "$out/findings.txt"
# A unique prefix names the same scan.
"${cli[@]}" scans findings "${scan_id:0:8}" | cmp -s - "$out/findings.txt" || {
  echo "scans findings ${scan_id:0:8} differs from scans findings $scan_id" >&2
  exit 1
}
fails "${cli[@]}" scans findings no-such-scan
grep -q 'No scan no-such-scan' "$out/error.txt"

echo "== scans export"
"${cli[@]}" scans export "$scan_id" --output "$out/results.sarif"
"${cli[@]}" scans export "$scan_id" --format json --output "$out/findings.json"
"${cli[@]}" scans export "$scan_id" --format md --output "$out/report.md"
# To stdout, byte for byte the file.
"${cli[@]}" scans export "$scan_id" --format json | cmp -s - "$out/findings.json" || {
  echo "scans export --format json to stdout differs from --output" >&2
  exit 1
}
fails "${cli[@]}" scans export "$scan_id" --format csv
node - "$out" "$run_dir" <<'JS'
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const [out, runDir] = process.argv.slice(2);
const read = name => readFileSync(join(out, name), 'utf8');
// Each export is the run dir's validated report, unchanged.
for (const [exported, report] of [
  ['results.sarif', 'results.sarif'],
  ['findings.json', 'findings.json'],
  ['report.md', 'report.md'],
])
  if (read(exported) !== readFileSync(join(runDir, 'reports', report), 'utf8'))
    throw new Error(`${exported} is not the run dir's reports/${report}`);
const sarif = JSON.parse(read('results.sarif'));
if (sarif.version !== '2.1.0') throw new Error(`not SARIF 2.1.0: ${sarif.version}`);
if (!read('report.md').startsWith('# ')) throw new Error('report.md is not a Markdown report');
// `scans findings` prints one line per finding of findings.json.
const findings = JSON.parse(read('findings.json')).findings;
const lines = read('findings.txt').split('\n').filter(line => /^ {2}[A-Z]+ /.test(line));
if (!findings.length) throw new Error('the scan found nothing');
if (lines.length !== findings.length)
  throw new Error(`scans findings printed ${lines.length} findings, findings.json has ${findings.length}`);
console.log(`${findings.length} findings, exported as SARIF, JSON and Markdown`);
JS

echo "== scans logs"
"${cli[@]}" scans logs "$scan_id" > "$out/log.txt"
cmp -s "$out/log.txt" "$run_dir/cli.log" || {
  echo "scans logs $scan_id is not the run dir's cli.log" >&2
  exit 1
}

echo "== debug bundle"
"${cli[@]}" debug bundle "$scan_id" --yes --output "$out/bundle.tar.gz" 2> "$out/bundle.txt"
mkdir -p "$out/bundle" && tar -xzf "$out/bundle.tar.gz" -C "$out/bundle"
for file in run/cli-result.json run/run.json run/cli.log run/reports/findings.json versions.json doctor.json; do
  [ -f "$out/bundle/$file" ] || {
    echo "the debug bundle has no $file" >&2
    exit 1
  }
done
# Never a database, a credential or a session transcript.
if find "$out/bundle" \( -name '*.sqlite3*' -o -name 'auth.json' -o -name 'rollout-*.jsonl' -o -path '*/sessions/*' \) | grep -q .; then
  echo "the debug bundle holds a file it must leave out:" >&2
  find "$out/bundle" \( -name '*.sqlite3*' -o -name 'auth.json' -o -name 'rollout-*.jsonl' -o -path '*/sessions/*' \) >&2
  exit 1
fi
# Nor the key the scan ran with, checked without printing it or putting it in a process's argv:
# grep reads it from a file descriptor that printf, a shell builtin, writes.
if [ -n "${CYNOS_API_KEY:-}" ] && grep -rqF -f <(printf '%s\n' "$CYNOS_API_KEY") "$out/bundle"; then
  echo "the debug bundle holds the cynos key" >&2
  exit 1
fi
[ "$(stat -c %a "$out/bundle.tar.gz" 2> /dev/null || stat -f %Lp "$out/bundle.tar.gz")" = 600 ] || {
  echo "the debug bundle is not private (0600)" >&2
  exit 1
}

# The unpacked copy was only for these checks; the run dir it copies is the scan's, and a later
# reader of the work dir (check-scan-traces.mjs) must not take it for another run.
rm -rf "$out/bundle"

echo "scans commands ($runtime, $kind) passed"
