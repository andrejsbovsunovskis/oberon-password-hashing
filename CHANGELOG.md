# Changelog

## Unreleased

- **Build compatibility:** sources, examples, and tests now compile with the stock FreeOberon `fob` flags (`-s -88 -7w`). Read-only array/record parameters use Oberon-07 syntax, early returns are replaced by guarded control flow, and the duplicate type section is merged.
- **ABI/arithmetic:** use explicit `SYSTEM.CHAR8` octets and `SYSTEM.INT64` intermediates; `-7w` makes `CHAR` 16-bit and `LONGINT` 32-bit. This preserves byte buffers and overflow-safe arithmetic without changing the record format.
- **Regression checks:** `scripts/test.sh` now pins the actual builder dialect, and `scripts/test-fob.sh` builds and runs all nine tests through the unmodified stock builder. `TestDialect` checks type sizes, all 256 octet values, arithmetic carry, input preservation, and both example imports.

- **Security:** cryptographic octets now use Ofront+'s 8-bit `SYSTEM.CHAR8` ABI end-to-end. This fixes incorrect `/dev/urandom` reads into 16-bit `CHAR` arrays and makes newly created records verifiable.
- **Security:** prepared HMAC/SHA contexts, PBKDF2 work buffers, derived keys, and password-record work buffers are cleared on success and error paths. Wipe routines are compiled separately without LTO so the release linker retains the calls.
- **Security:** `PasswordHash.Create` consumes the password before writing the output, preventing overlapping buffers from changing the password being hashed.
- **Correctness:** PBKDF2 now distinguishes invalid derived-key lengths from insufficient output buffers, and all verification errors leave both result flags false.
- **Performance:** SHA-256 words now use native 32-bit bit operations with overflow-safe 64-bit modular addition. Release tests use `-O3 -flto`; the default 600,000-iteration policy is covered by an end-to-end create/verify test.
- **Testing:** added SHA-256 padding-boundary fixtures, HMAC keys of 0/20/63/64/65 bytes, PBKDF2 fixtures at 1/2/4096/600000 iterations, multi-block and empty-input cases, API/error-path coverage, real RNG checks, 100,000 deterministic parser mutations, and ASan/UBSan support through `CFLAGS`.
- **Examples:** added safe verify-and-rehash handling and binary SHA-256 input.
- **Documentation:** aligned the implementation contract, supported-platform statement, arithmetic ADR, build flags, and sanitizer workflow with the tested macOS arm64 implementation.
- **Compatibility:** public APIs now accept `ARRAY OF SYSTEM.CHAR8`; callers using 16-bit `CHAR` must explicitly encode their password text as UTF-8 octets first.
- **Format/API:** `EncodedCapacity` is 143 bytes including NUL, accommodating every positive signed-32-bit iteration count accepted by v1. The encoded wire format itself is unchanged.

## 0.1.0 — 2026-09-19

- Initial experimental FreeOberon implementation of SHA-256, HMAC-SHA-256, PBKDF2, `oberon-pwh`, policy checks, and OS salt acquisition.
- Added clean-tree build/test script and standard-vector tests.
