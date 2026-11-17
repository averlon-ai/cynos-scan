#!/usr/bin/env bash
# A real scan, end to end, for one runtime: the knowledge base and the scan with the cynos key, of
# DSVW (Damn Small Vulnerable Web), a deliberately vulnerable one-file Python web app from the
# RealVuln benchmark. It spends cynos money (cents to a few dollars a run); the release runs it
# with a key whose budget caps that.
#
#   CYNOS_API_KEY=… bash scripts/e2e-real.sh native|docker
#
# e2e.sh runs upstream's mock scan: no key, no model call, and so no knowledge base, no key check
# and no report of a scan the model ran. A change that breaks only those passes it, so this checks:
#
#   - the scan completes, with a knowledge base built;
#   - it finds DSVW's SQL injection in dsvw.py (CWE-89). DSVW has six, in plain string
#     concatenation, so a scan that misses all of them is broken, not unlucky.
#
# It runs this checkout's build, or CYNOS_BIN (an installed cynos). The key is read by cynos from
# CYNOS_API_KEY, never passed in argv; CYNOS_BASE_URL names another cynos gateway than the
# default. Work goes under one private directory outside /tmp, as in e2e.sh.
set -euo pipefail

runtime="${1:?usage: e2e-real.sh native|docker}"
root="$(cd "$(dirname "$0")/.." && pwd)"
if [ -n "${CYNOS_BIN:-}" ]; then cli=("$CYNOS_BIN"); else cli=(node "$root/packages/cli/dist/cynos.mjs"); fi
[ -n "${CYNOS_API_KEY:-}" ] || {
  echo "e2e-real.sh needs the cynos key in CYNOS_API_KEY" >&2
  exit 1
}
work="${RUNNER_TEMP:-$root/.e2e}/cynos-scan-e2e-real-$runtime-$$"
mkdir -p "$work" && chmod 700 "$work"
export CODEX_SECURITY_STATE_DIR="$work/state"

# DSVW at the commit RealVuln's ground truth was written against.
dsvw_url=https://github.com/stamparm/DSVW
dsvw_sha=7d40f4b7939c901610ed9b85724552d60e7d63fa
fixture="$work/dsvw"
git init -q "$fixture"
git -C "$fixture" fetch -q --depth 1 "$dsvw_url" "$dsvw_sha"
git -C "$fixture" checkout -q --detach FETCH_HEAD

if [ "$runtime" = docker ]; then
  echo "== doctor --fix (docker)"
  "${cli[@]}" doctor --runtime docker --fix --yes
fi

echo "== real scan of DSVW ($runtime)"
# Judge and routing off: every turn on the requested model, and the judge's cost saved.
"${cli[@]}" scan "$fixture" --runtime "$runtime" --headless --format json --no-judge --no-routing \
  --timeout 45m > "$work/scan.json" || true

node - "$work/scan.json" <<'JS'
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const result = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const fail = message => {
  console.error(`real scan: ${message}`);
  process.exit(1);
};
console.log(
  `scan ${result.scanId}: ${result.scanStatus}, cost ${JSON.stringify(result.cost)}, ${result.seconds}s`
);
if (result.scanStatus !== 'completed') fail(`not completed: ${result.reason ?? 'no reason given'}`);
if (!result.knowledgeBase) fail('no knowledge base was built');

// A finding of DSVW's SQL injection: CWE-89 with a location in dsvw.py.
const findings = JSON.parse(readFileSync(join(result.scanDir, 'findings.json'), 'utf8')).findings ?? [];
const paths = finding =>
  [...(finding.locations ?? []), ...(finding.codeEvidence ?? [])].map(place => place.path ?? '');
const sqlInjection = findings.find(
  finding =>
    (finding.taxonomy?.cwe ?? []).includes('CWE-89') &&
    paths(finding).some(path => path.endsWith('dsvw.py'))
);
console.log(`${findings.length} findings`);
for (const finding of findings)
  console.log(`  ${finding.severity?.level ?? '?'}: ${finding.title} [${(finding.taxonomy?.cwe ?? []).join(', ')}]`);
if (!sqlInjection) fail("no CWE-89 finding in dsvw.py: DSVW's SQL injection was missed");
JS

echo "e2e real ($runtime) passed; evidence in $work"
