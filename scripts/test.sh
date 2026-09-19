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
cflags=${CFLAGS:-}
release_flags="-O3 -flto $cflags"
wipe_flags="-O2 $cflags"

test -x "$translator"
echo "Ofront translator: $translator"
if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$translator"; else sha256sum "$translator"; fi
clang --version | sed -n '1p'
build=$(mktemp -d "${TMPDIR:-/tmp}/oberon-password-hashing.XXXXXX")
trap 'rm -rf "$build"' EXIT HUP INT TERM
cp "$root"/src/*.Mod "$root"/platform/SecureRandom.Mod "$root"/tests/TestSha.Mod "$root"/tests/TestPasswordWord.Mod "$root"/tests/TestVectors.Mod "$root"/tests/TestPasswordHash.Mod "$root"/tests/TestSecurity.Mod "$root"/tests/TestParser.Mod "$root"/tests/TestSecureRandom.Mod "$root"/examples/PasswordRecords.Mod "$root"/examples/BinaryDigest.Mod "$build"/
cp "$runtime/Lib/Sym/Platform.sym" "$build"/

cd "$build"
"$translator" -s88 PasswordStatus.Mod PasswordBytes.Mod PasswordWord.Mod Sha256.Mod HmacSha256.Mod Pbkdf2.Mod SecureRandom.Mod PasswordHash.Mod
"$translator" -s88 PasswordRecords.Mod
"$translator" -s88 BinaryDigest.Mod
clang $wipe_flags -I "$toolchain/Data/bin/OfrontPlus/Mod/Lib" -I "$runtime/Lib/Obj" -c PasswordBytes.c -o PasswordBytes.o
"$translator" -m -s88 TestPasswordWord.Mod
clang $release_flags -I "$toolchain/Data/bin/OfrontPlus/Mod/Lib" -I "$runtime/Lib/Obj" \
  PasswordStatus.c PasswordWord.c TestPasswordWord.c PasswordBytes.o "$runtime/Lib/libOfront.a" -o test-password-word
./test-password-word
"$translator" -m -s88 TestSha.Mod
clang $release_flags -I "$toolchain/Data/bin/OfrontPlus/Mod/Lib" -I "$runtime/Lib/Obj" \
  PasswordStatus.c PasswordWord.c Sha256.c TestSha.c PasswordBytes.o "$runtime/Lib/libOfront.a" -o test-sha
./test-sha
"$translator" -m -s88 TestVectors.Mod
clang $release_flags -I "$toolchain/Data/bin/OfrontPlus/Mod/Lib" -I "$runtime/Lib/Obj" \
  PasswordStatus.c PasswordWord.c Sha256.c HmacSha256.c Pbkdf2.c TestVectors.c PasswordBytes.o "$runtime/Lib/libOfront.a" -o test-vectors
./test-vectors
"$translator" -m -s88 TestPasswordHash.Mod
clang $release_flags -I "$toolchain/Data/bin/OfrontPlus/Mod/Lib" -I "$runtime/Lib/Obj" \
  PasswordStatus.c PasswordWord.c Sha256.c HmacSha256.c Pbkdf2.c SecureRandom.c PasswordHash.c TestPasswordHash.c "$runtime/Lib/Obj/Platform.c" PasswordBytes.o "$runtime/Lib/libOfront.a" -o test-password-hash
./test-password-hash
"$translator" -m -s88 TestSecurity.Mod
clang $release_flags -I "$toolchain/Data/bin/OfrontPlus/Mod/Lib" -I "$runtime/Lib/Obj" \
  PasswordStatus.c PasswordWord.c Sha256.c HmacSha256.c Pbkdf2.c SecureRandom.c PasswordHash.c TestSecurity.c "$runtime/Lib/Obj/Platform.c" PasswordBytes.o "$runtime/Lib/libOfront.a" -o test-security
./test-security
"$translator" -m -s88 TestSecureRandom.Mod
clang $release_flags -I "$toolchain/Data/bin/OfrontPlus/Mod/Lib" -I "$runtime/Lib/Obj" \
  PasswordStatus.c PasswordWord.c Sha256.c HmacSha256.c Pbkdf2.c SecureRandom.c TestSecureRandom.c "$runtime/Lib/Obj/Platform.c" PasswordBytes.o "$runtime/Lib/libOfront.a" -o test-secure-random
./test-secure-random
"$translator" -m -s88 TestParser.Mod
clang $release_flags -I "$toolchain/Data/bin/OfrontPlus/Mod/Lib" -I "$runtime/Lib/Obj" \
  PasswordStatus.c PasswordWord.c Sha256.c HmacSha256.c Pbkdf2.c SecureRandom.c PasswordHash.c TestParser.c "$runtime/Lib/Obj/Platform.c" PasswordBytes.o "$runtime/Lib/libOfront.a" -o test-parser
./test-parser
