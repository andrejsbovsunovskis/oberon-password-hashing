# Changelog

## Unreleased

- **Security:** cryptographic octets now use Ofront+'s 8-bit `SHORTCHAR` ABI end-to-end. This fixes incorrect `/dev/urandom` reads into 16-bit `CHAR` arrays and makes newly created records verifiable.
- **Security:** restore Ofront+ runtime checks in the test build; corrected HMAC/PBKDF2 fixtures and added RFC 4231, multi-block PBKDF2, parser-bound, and state-machine regression coverage.
- **Security:** clear prepared HMAC/SHA contexts on reuse and error paths.
- **Compatibility:** public APIs now accept `ARRAY OF SHORTCHAR`; callers using 16-bit `CHAR` must explicitly encode their password text as UTF-8 octets first.
- **Format/API:** `EncodedCapacity` is 143 bytes including NUL, accommodating every positive signed-32-bit iteration count accepted by v1. The encoded wire format itself is unchanged.

## 0.1.0 — 2026-09-19

- Initial experimental FreeOberon implementation of SHA-256, HMAC-SHA-256, PBKDF2, `oberon-pwh`, policy checks, and OS salt acquisition.
- Added clean-tree build/test script and standard-vector tests.

No cryptographic review has been completed.
