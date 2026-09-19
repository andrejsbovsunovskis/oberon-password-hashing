# Oberon Password Hashing

Experimental password-storage library for FreeOberon. It implements SHA-256, HMAC-SHA-256, PBKDF2-HMAC-SHA-256, strict `oberon-pwh` records, and password rehash decisions.

This is not an audited cryptographic library. Do not describe it as production-ready until an independent cryptographic review is complete.

## Quick start

```sh
export FREEOBERON_HOME=/path/to/FreeOberon
./scripts/test.sh
```

The script builds in a temporary directory, so generated C and symbol files never enter the source tree. It supports macOS arm64/x86_64 and Linux x86_64/aarch64 when the matching FreeOberon target is installed.

`PasswordHash.DefaultPolicy` uses 600,000 PBKDF2 iterations. The canonical v1 representation requires `PasswordHash.EncodedCapacity` (143 bytes, including the terminating NUL), enough for the full signed-32-bit iteration range accepted by v1.

Documentation: [English contract](docs/requirements.md) · [Русский](docs/requirements.ru.md) · [build](docs/build.md) · [portability](docs/portability.md)
