#!/usr/bin/env bash
# Installs cynos as a user would and runs it: a packed tarball from this checkout, or a
# version published to the registry.
#
#   bash scripts/install-smoke.sh <cynos-X.Y.Z.tgz | X.Y.Z> [native] [docker]
#
# A checkout's tests run its sources, and e2e.sh its build; neither sees what npm installs: the
# package's files list, its bin, upstream resolved beside the bundle, the Node versions in
# engines. This installs into an empty global prefix, checks the version and the help, then runs
# the end to end scan on each runtime given with the installed bin.
set -euo pipefail

package="${1:?usage: install-smoke.sh <tarball | version> [native] [docker]}"
shift
root="$(cd "$(dirname "$0")/.." && pwd)"
work="${RUNNER_TEMP:-$root/.e2e}/cynos-install-$$"
mkdir -p "$work" && chmod 700 "$work"

# A tarball names itself; a version is the published package at that version.
if [ -f "$package" ]; then
  spec="$(cd "$(dirname "$package")" && pwd)/$(basename "$package")"
  version="$(tar -xOzf "$spec" package/package.json | node -p 'JSON.parse(require("fs").readFileSync(0)).version')"
else
  spec="@averlon-ai/cynos@$package"
  version="$(npm view "$spec" version)"
fi

echo "== install $spec"
npm install --global --prefix "$work/prefix" --no-fund "$spec"
bin="$work/prefix/bin/cynos"

echo "== --version and --help"
installed="$("$bin" --version)"
[ "$installed" = "$version" ] || {
  echo "cynos --version is '$installed', not $version" >&2
  exit 1
}
"$bin" --help > /dev/null

# The release stamps every package with the tag's version, so the bundled engine must report the
# CLI's: a version kept anywhere but package.json is not stamped (0.1.5 shipped engine 0.1.0).
echo "== info --json: the engine's version"
engine_version="$("$bin" info --json | node -p 'JSON.parse(require("fs").readFileSync(0)).engine.version')"
[ "$engine_version" = "$version" ] || {
  echo "cynos info reports engine $engine_version, not $version" >&2
  exit 1
}

for runtime in "$@"; do
  CYNOS_BIN="$bin" bash "$root/scripts/e2e.sh" "$runtime"
done

echo "install smoke ($version) passed"
