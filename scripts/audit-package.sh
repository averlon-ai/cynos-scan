#!/usr/bin/env bash
# Audits what `npm install @averlon-ai/cynos` installs: a packed tarball from this
# checkout, or a published version.
#
#   bash scripts/audit-package.sh <cynos-X.Y.Z.tgz | X.Y.Z>
#
# The CLI bundles our own code, so its installed tree is upstream's dependencies, which bun.lock
# does not cover: npm resolves them at install time. npm audits a project with a lockfile, so
# the package is installed into an empty one, then audited for known vulnerabilities (high and
# above) and for the registry's signatures on every package it installed.
set -euo pipefail

package="${1:?usage: audit-package.sh <tarball | version>}"
if [ -f "$package" ]; then
  spec="$(cd "$(dirname "$package")" && pwd)/$(basename "$package")"
else
  spec="@averlon-ai/cynos@$package"
fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"
npm init --yes > /dev/null
npm install --no-fund --no-audit "$spec" > /dev/null

echo "== npm audit (high and above)"
npm audit --omit=dev --audit-level=high
echo "== npm audit signatures"
npm audit signatures
