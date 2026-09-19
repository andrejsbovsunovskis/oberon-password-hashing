#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
toolchain=${FREEOBERON_HOME:?set FREEOBERON_HOME to the FreeOberon checkout}
case "$(uname -s):$(uname -m)" in
  Darwin:arm64|Darwin:x86_64) target=macOS ;;
  Linux:x86_64) target=Linux_amd64 ;;
  Linux:aarch64) target=Linux_aarch64 ;;
  *) echo "unsupported host: $(uname -s) $(uname -m)" >&2; exit 2 ;;
esac
translator="$toolchain/Data/bin/OfrontPlus/Target/$target/ofront+"
runtime="$toolchain/Data/bin/OfrontPlus/Target/$target"

test -x "$translator"
build=$(mktemp -d "${TMPDIR:-/tmp}/oberon-password-hashing.XXXXXX")
trap 'rm -rf "$build"' EXIT HUP INT TERM
cp "$root"/src/*.Mod "$root"/platform/SecureRandom.Mod "$root"/tests/TestSha.Mod "$root"/tests/TestVectors.Mod "$root"/tests/TestPasswordHash.Mod "$build"/
cp "$runtime/Lib/Sym/Platform.sym" "$build"/

cd "$build"
"$translator" -sxtap88 PasswordStatus.Mod PasswordBytes.Mod PasswordWord.Mod Sha256.Mod HmacSha256.Mod Pbkdf2.Mod SecureRandom.Mod PasswordHash.Mod
"$translator" -m -sxtap88 TestSha.Mod
clang -O2 -I "$toolchain/Data/bin/OfrontPlus/Mod/Lib" -I "$runtime/Lib/Obj" \
  PasswordStatus.c PasswordBytes.c PasswordWord.c Sha256.c TestSha.c "$runtime/Lib/libOfront.a" -o test-sha
./test-sha
"$translator" -m -sxtap88 TestVectors.Mod
clang -O2 -I "$toolchain/Data/bin/OfrontPlus/Mod/Lib" -I "$runtime/Lib/Obj" \
  PasswordStatus.c PasswordBytes.c PasswordWord.c Sha256.c HmacSha256.c Pbkdf2.c TestVectors.c "$runtime/Lib/libOfront.a" -o test-vectors
./test-vectors
"$translator" -m -sxtap88 TestPasswordHash.Mod
clang -O2 -I "$toolchain/Data/bin/OfrontPlus/Mod/Lib" -I "$runtime/Lib/Obj" \
  PasswordStatus.c PasswordBytes.c PasswordWord.c Sha256.c HmacSha256.c Pbkdf2.c SecureRandom.c PasswordHash.c TestPasswordHash.c "$runtime/Lib/Obj/Platform.c" "$runtime/Lib/libOfront.a" -o test-password-hash
./test-password-hash
