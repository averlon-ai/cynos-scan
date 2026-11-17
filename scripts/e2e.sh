#!/usr/bin/env bash
# End to end on this machine, for one runtime: doctor, then upstream's synthetic scan of a fixture
# repository (no key, no model call), then the scan in its own upstream history and not in the
# repository's. The CLI runs a mock scan only when CYNOS_SCAN_MOCK=1 asks for it: it is not a
# scan option, because its findings are synthetic.
#
#   bash scripts/e2e.sh native|docker
#
# It runs this checkout's build (packages/cli/dist), or CYNOS_BIN when that is set: an
# installed cynos, as the install smoke test runs it.
#
# Everything goes under one private directory (under RUNNER_TEMP, else the checkout's git-ignored
# .e2e/), outside /tmp (macOS does not fully enforce Codex's write restrictions under /tmp), with
# its own upstream state dir, so a run never touches the developer's own scan history.
set -euo pipefail

runtime="${1:?usage: e2e.sh native|docker}"
root="$(cd "$(dirname "$0")/.." && pwd)"
if [ -n "${CYNOS_BIN:-}" ]; then cli=("$CYNOS_BIN"); else cli=(node "$root/packages/cli/dist/cynos.mjs"); fi
work="${RUNNER_TEMP:-$root/.e2e}/cynos-scan-e2e-$runtime-$$"
mkdir -p "$work" && chmod 700 "$work"
export CODEX_SECURITY_STATE_DIR="$work/state"

# A small repository with one obvious finding, committed so the scan has a revision.
fixture="$work/fixture"
mkdir -p "$fixture"
cat > "$fixture/app.py" <<'PY'
import sqlite3
def find_user(name):
    db = sqlite3.connect("app.db")
    return db.execute("SELECT * FROM users WHERE name = '%s'" % name).fetchall()
PY
git -C "$fixture" init -q
git -C "$fixture" -c user.name=e2e -c user.email=e2e@example.invalid add .
git -C "$fixture" -c user.name=e2e -c user.email=e2e@example.invalid commit -q -m fixture

# The docker runtime's image (built from the package's assets, or pulled at the digest a release
# stamped) and upstream's AppArmor profile are doctor's to set up, as a user would. doctor checks the
# checkout it runs in, so it runs in the fixture, as a user runs it in the repository they scan: run
# from this checkout, it would find the default work dir (.e2e) inside it and fail its state-dir
# check.
if [ "$runtime" = docker ]; then
  echo "== doctor --fix (docker)"
  (cd "$fixture" && "${cli[@]}" doctor --runtime docker --fix --yes)
fi

echo "== doctor ($runtime)"
(cd "$fixture" && "${cli[@]}" doctor --runtime "$runtime" --json) > "$work/doctor.json" || {
  cat "$work/doctor.json"
  exit 1
}

echo "== mock scan ($runtime)"
CYNOS_SCAN_MOCK=1 "${cli[@]}" scan "$fixture" --runtime "$runtime" --headless --format json > "$work/scan.json"
node -e '
  const result = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
  if (!result.scanId) throw new Error("the mock scan returned no scan id");
  console.log(`scan ${result.scanId}: ${result.scanStatus}`);
' "$work/scan.json"

if [ "$runtime" = native ]; then
  # A mock scan keeps its own history in its run dir, so its synthetic findings never reach the
  # repository's real one: it is listed there, and not in the state dir every other scan uses.
  scan_id="$(node -p 'require(process.argv[1]).scanId' "$work/scan.json")"
  mock_state="$(node -p 'require(process.argv[1]).runDir' "$work/scan.json")/mock-state"
  echo "== scans list (the mock scan's own history)"
  CODEX_SECURITY_STATE_DIR="$mock_state" "${cli[@]}" scans list "$fixture" --format json > "$work/scans.json"
  grep -q "$scan_id" "$work/scans.json"
  echo "== scans list (the repository's history: no mock scan)"
  if "${cli[@]}" scans list "$fixture" --format json 2> /dev/null | grep -q "$scan_id"; then
    echo "the mock scan $scan_id is in the repository's scan history" >&2
    exit 1
  fi
fi

echo "e2e ($runtime) passed; evidence in $work"
