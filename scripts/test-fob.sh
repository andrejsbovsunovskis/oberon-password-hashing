#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
toolchain=${FREEOBERON_HOME:?set FREEOBERON_HOME to the FreeOberon checkout}
fob="$toolchain/fob"
test -x "$fob"
echo "FreeOberon builder: $fob"
if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$fob"; else sha256sum "$fob"; fi
# fob's command buffer limits source paths to 79 characters. Keep paths short
# independently of macOS's long default TMPDIR and the repository location.
build=$(mktemp -d /tmp/pwh-fob.XXXXXX)
trap 'rm -rf "$build"' EXIT HUP INT TERM
cp "$root"/src/*.Mod "$root"/platform/*.Mod "$root"/tests/*.Mod "$root"/examples/*.Mod "$build"/
cd "$build"
for module in TestDialect TestPasswordWord TestSha TestVectors TestPasswordHash TestSecurity TestSecureRandom TestProductionCost TestParser; do
  echo "fob: $module"
  "$fob" "$build/$module.Mod" -o "$build/$module"
  "$build/$module"
done
echo "All fob tests passed."
