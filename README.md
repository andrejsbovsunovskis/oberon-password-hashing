# Oberon Password Hashing

Password-storage library for FreeOberon. It implements SHA-256, HMAC-SHA-256, PBKDF2-HMAC-SHA-256, strict `oberon-pwh` records, and password rehash decisions.

The current supported build is macOS arm64 with the documented FreeOberon/Ofront+ toolchain. The code is self-reviewed and covered by reference vectors, parser mutation tests, and sanitizer runs. It is not FIPS-validated and does not implement Argon2id, pepper management, sessions, rate limiting, or TLS; those remain application responsibilities.

## Quick start

```sh
export FREEOBERON_HOME=/path/to/FreeOberon
./scripts/test.sh
```

The script builds in a temporary directory, so generated C and symbol files never enter the source tree. It supports macOS arm64/x86_64 and Linux x86_64/aarch64 when the matching FreeOberon target is installed.

`PasswordHash.DefaultPolicy` uses 600,000 PBKDF2 iterations. The canonical v1 representation requires `PasswordHash.EncodedCapacity` (143 bytes, including the terminating NUL), enough for the full signed-32-bit iteration range accepted by v1.

For an additional memory-safety run, use:

```sh
CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' ./scripts/test.sh
```

Documentation: [English contract](docs/requirements.md) · [Русский](docs/requirements.ru.md) · [build](docs/build.md) · [portability](docs/portability.md)
