# Requirements for the Oberon Password Hashing Library

Requirements version: 1.0, 19 September 2026
Status: implementation contract. The code is reviewed in this repository through reference vectors, boundary tests, parser mutation tests, and sanitizer runs on supported targets.

## 1. Purpose and scope

The library is a reusable set of Oberon modules: `Sha256`, `HmacSha256`, `Pbkdf2`, and `PasswordHash`. It creates, verifies, and upgrades password representations independently of an application's data model, UI, or infrastructure.

**MUST** and **MUST NOT** are mandatory. **SHOULD** permits an exception only with written justification and documented consequences. Requirement IDs are used by tests and reviews.

### Oberon-only boundary

- The cryptographic core, KDF, encoding, and parser are implemented in Oberon. Production code MUST NOT call OpenSSL, libsodium, external programs, or network services to compute hashes.
- The standard runtime/compiler and isolated operating-system calls for random bytes are allowed. Generated C does not violate this boundary.
- Platform adapters SHOULD use existing Oberon foreign declarations. Custom C code is an explicit change to this boundary.
- Creating a hash without a supplied cryptographic random source MUST fail.

### Algorithm choice

**SCOPE-01.** v1 implements PBKDF2-HMAC-SHA-256. This is a pragmatic choice for an Oberon implementation with a tractable review surface; it does not mean PBKDF2 is preferable to Argon2id. OWASP prefers Argon2id for new systems. The preparation-time reference for PBKDF2-HMAC-SHA-256 is 600,000 iterations. A custom implementation is not FIPS-validated. See [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

**SCOPE-02.** v1 excludes Argon2, encryption, digital signatures, sessions, temporary-password generation, HTTP, SQL, database migrations, password-complexity policy, and pepper management. HMAC is a shared-secret MAC, not a digital signature.

## 2. Threat model and guarantees

**SEC-01.** Assume an attacker can obtain the database, submit arbitrary passwords and malformed hash strings, call verification repeatedly, and observe responses and processing time. Salt, algorithm, and iteration count are not secret.

**SEC-02.** The library MUST prevent silent truncation, out-of-bounds access, incomplete formats, uncontrolled work caused by input parameters, and authentication after an error. It raises the cost of offline guessing but cannot make a weak password unguessable or compensate for a compromised process or OS.

**SEC-03.** Rate limiting, TLS, user-enumeration protection, concurrent-KDF limits, secure sessions, and password reset are application responsibilities.

## 3. Architecture and portability

| ID | Area | Requirement |
|---|---|---|
| ARCH-01 | `Sha256` | One-shot and streaming hashing, with no randomness or higher-layer dependencies. |
| ARCH-02 | `HmacSha256` | HMAC over SHA-256 and prepared key state for repeated computations. |
| ARCH-03 | `Pbkdf2` | PBKDF2-HMAC-SHA-256 over bytes; the caller supplies parameters. |
| ARCH-04 | `PasswordHash` | Policy, format, salt, creation, verification, and rehash detection. |
| ARCH-05 | `SecureRandom` | Buffer-fill contract with an adapter for each supported system. |
| ARCH-06 | Internal utilities | 32-bit arithmetic, hex, comparison, and clearing as needed; do not automatically make them public APIs. |
| ARCH-07 | Dependencies | Acyclic imports; no application model, database, HTTP, session, logger, or hidden file/network actions in the core. |
| ARCH-08 | State | Independent contexts and immutable constants; no global mutable work buffer or global last-error state. |

**PORT-01.** The target dialect is FreeOberon translated by Ofront+ with the `-88` memory model. Builds MUST print the translator path and hash, C compiler version, target architecture, and effective C flags.

**PORT-02.** Verify the sizes and behavior of `SHORTCHAR`, integer types, `SET`, shifts, conversions, bounds checks, and byte order in executable tests and `docs/portability.md`. Never rely on signed `INTEGER` overflow.

**PORT-03.** The required release platform is macOS arm64. No “any Oberon” portability claim is made. A new platform becomes supported only after the complete test and sanitizer commands pass there.

**PORT-04.** SHA-256 words are exactly 32 bits. Addition modulo 2^32 and logical shifts MUST avoid undefined signed overflow in generated C and language-range violations. Byte order is explicit and CPU-independent.

## 4. Data, strings, and memory

**DATA-01.** Core APIs accept `ARRAY OF SHORTCHAR` byte arrays and explicit lengths. `SHORTCHAR` is required to keep octets 8-bit in the supported Ofront+ ABI. NUL bytes are ordinary data. Algorithmic modules MUST NOT use NUL-terminated string operations.

**DATA-02.** Lengths are measured in bytes. Every call checks `0 <= length <= LEN(buffer)`. Slices check `offset <= LEN(buffer)` and `length <= LEN(buffer) - offset` before calculating a potentially overflowing sum. Hex lengths, block counts, and output capacities are checked likewise.

**DATA-03.** Text applications pass UTF-8. The library does not change case, trim whitespace, normalize Unicode, or recode passwords. Different byte sequences are different passwords. Normalization must be an explicit, consistent application decision.

**DATA-04.** The high-level password limit is 1024 bytes inclusive. An empty password is cryptographically valid but applications MUST reject it at enrollment. Longer passwords are rejected before KDF and never truncated.

**DATA-05.** Output buffers belong to the caller and inputs are not modified before the operation has consumed them. Overlap is not a supported API contract. On error, the safely addressable output range is cleared.

**DATA-06.** Secret temporary buffers and key state are cleared on every exit path. The wiping module is linked without LTO so its clear calls remain observable in the generated binary. Do not promise removal of every stack, register, or runtime copy.

## 5. Cryptographic primitives

**SHA-01.** SHA-256 MUST conform to [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final), including empty and binary messages, streaming input, padding, and length accounting. Constants are checked with reference vectors.

**SHA-02.** The streaming state machine is `Init → Update* → Final → finished`. Repeated `Final`, `Update` after completion, and use before `Init` return `InvalidState`; `Init` permits reuse. An update error requires a new `Init`, and length overflow is detected before the counter wraps.

**HMAC-01.** HMAC-SHA-256 handles empty, short, exactly 64-byte, and long keys according to HMAC. The result is 32 bytes. Truncated MAC is not a public v1 operation. See [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231.html).

**HMAC-02.** PBKDF2 prepares the key once, including long-password hashing and ipad/opad state. Working states are independent; an iteration MUST NOT inherit a mutated previous-iteration context.

**KDF-01.** PBKDF2 uses HMAC-SHA-256, a four-byte big-endian block index, correct U chains, and XOR. It supports multiple blocks and a partial final block. Iterations are positive and zero-length derived keys are rejected. See [RFC 8018, §5.2](https://www.rfc-editor.org/rfc/rfc8018.html#section-5.2).

**KDF-02.** Low-level `Derive` permits one and two iterations for vectors and tests. `PasswordHash.Create` never inherits such unsafe settings. Low-level documentation states that parameter security is the caller's responsibility.

**KDF-03.** KDF memory does not grow with the iteration count. No per-iteration allocation or accumulation of all U values is allowed; current U and an XOR accumulator are sufficient.

## 6. Randomness

**RNG-01.** Every `Create`, including a rehash of the same password, generates a new 16-byte salt using the operating system's cryptographic source.

**RNG-02.** FreeOberon `Random`, time, PID, user ID, counters, unknown-origin GUIDs, hashes of these values, and fallbacks to them are forbidden. A random source MUST NOT report success with an all-zero buffer.

**RNG-03.** An adapter succeeds only after filling the entire range. Partial output, interruption, and OS failure follow the selected API contract with bounded retry. If bytes cannot be obtained, `Create` returns `RandomUnavailable`, clears output, and creates no record.

**RNG-04.** The OS API and its contract are recorded in an ADR and tested on each supported platform. The library does not implement or cache its own PRNG/DRBG sequence between processes.

**RNG-05.** A deterministic source is allowed only in test builds/test adapters and MUST be separated from production configuration.

## 7. Encoded format

**FMT-01.** The canonical format is UTF-8 ASCII text:

```text
oberon-pwh$1$pbkdf2-sha256$i=<decimal>$s=<lowercase-hex>$dk=<lowercase-hex>
```

The version, algorithm, iteration count, salt, and derived key are explicit. The serializer emits one exact form; the parser does not silently normalize alternate forms.

**FMT-02.** Salt is exactly 16 bytes and the derived key exactly 32 bytes in v1. Hex is lowercase ASCII, two characters per byte. Iterations are decimal ASCII with no sign, leading zero, whitespace, or alternate base. Output capacity includes the terminating NUL.

**FMT-03.** Parsing is bounded and rejects unknown versions/algorithms, missing or duplicate fields, malformed hex, overflow, trailing data, impossible lengths, and policy-disallowed values before KDF. Invalid input never falls back to another algorithm or default.

**FMT-04.** Serialization is deterministic. Accepted input followed by canonical serialization is stable; parser acceptance MUST NOT silently broaden over time.

## 8. Policy and public API

**POL-01.** Policy contains minimum, target, maximum, and hard-limit iterations plus explicit salt, derived-key, and password limits. Invariants are `0 < min <= target <= max <= hardLimit`; invalid policy is rejected before randomness or KDF.

**POL-02.** Verification rejects records above the hard limit and does not spend unbounded work. It accepts valid records at or below the configured maximum. A lower policy target never downgrades a more expensive stored hash.

**POL-03.** Rehash is recommended after successful verification when stored cost is below target. Migration mode may explicitly accept a bounded legacy format; legacy acceptance is never an implicit fallback.

The core API is equivalent to:

```text
PasswordHash.Create(password, passwordLen, policy, OUT encoded, OUT encodedLen) -> Status
PasswordHash.Verify(password, passwordLen, encoded, encodedLen, policy,
                    OUT matches, OUT needsRehash) -> Status
PasswordHash.NeedsRehash(encoded, encodedLen, policy, OUT needed) -> Status
Sha256.Hash(data, dataLen, OUT digest) -> Status
Sha256.Init/Update/Final(context, ...) -> Status
HmacSha256.Compute(key, keyLen, data, dataLen, OUT mac) -> Status
Pbkdf2.Derive(password, passwordLen, salt, saltLen,
              iterations, dkLen, OUT key) -> Status
```

**API-01.** All parameters document units, ownership, ranges, output capacity, aliasing, clearing, and valid call order. Examples compile in `scripts/test.sh`.

**API-02.** Stable status codes include `Ok`, `InvalidArgument`, `InvalidState`, `BufferTooSmall`, `PasswordTooLong`, `InvalidPolicy`, `InvalidFormat`, `UnsupportedVersion`, `UnsupportedAlgorithm`, `PolicyRejected`, `RandomUnavailable`, and `InternalError`. Any verification error returns failure with both output flags false; access is denied.

**API-03.** Higher cost within policy is accepted and never downgraded. The library recommends rehash after success but never writes to storage. `NeedsRehash` parses without running KDF and does not prove that a password is correct.

**API-04.** Statuses are returned to the caller. The library does not print, halt, assert on ordinary malformed external input, or log passwords, keys, or full hashes. Boolean wrappers are allowed only when every error means rejection.

## 9. Comparison and performance

**TIME-01.** Derived keys are compared across all 32 bytes without early exit or ordinary string comparison. The comparison loop must not branch or address memory based on secret-byte values.

**TIME-02.** Review generated C and machine code for comparison, clearing, and critical operations whenever the compiler, optimization flags, or target architecture changes. Timing measurements are evidence, not proof of constant-time behavior.

**PERF-01.** Derivation cost scales as `O(passwordLen + iterations × ceil(dkLen / 32))` for a fixed short salt. A long password is not rehashed on every HMAC iteration.

**PERF-02.** Benchmark release builds at the deployment iteration count and representative password lengths before integration. Do not lower the configured work factor merely to improve an unmeasured result.

**PERF-03.** Each integrating project defines and measures its verification latency and concurrency budget on its target hardware. Never silently lower the configured work factor to meet that budget.

**PERF-04.** Independent operations remain isolated when calls are interleaved. Claim thread safety only after validating the runtime and adapter; otherwise document application-level serialization.

## 10. Testing and quality gates

Tests use synthetic data, not production databases or real passwords. Independent reference implementations are allowed in test tools, never in the production library.

| Test ID | Required coverage |
|---|---|
| T-SHA | FIPS fixtures for empty input, `abc`, and a binary padding boundary; streaming chunks and invalid state transitions. |
| T-HMAC | SHA-256 fixtures for key lengths 0/20/63/64/65 and prepared-state use through PBKDF2. |
| T-KDF | Independent PBKDF2-HMAC-SHA-256 fixtures at c=1/2/4096/600000, multi-block output, empty input, and invalid output sizes. |
| T-ARITH | Carry, high-bit rotation, and logical shift boundaries. |
| T-API | Create/verify, wrong passwords, output clearing, aliasing, invalid SHA state, policy/rehash behavior, and buffer limits. |
| T-PARSER | Malformed record handling plus 100,000 deterministic one-byte record mutations through the public verifier. |
| T-RNG | Invalid lengths, zero-length success, and successful complete OS-buffer fills. |
| T-COST | One create and one verify using `DefaultPolicy`. |
| T-TIMING | Generated-code review for full-length comparison and wipe calls under the documented release flags. |
| T-FUZZ | At least 100,000 reproducible parser/API mutations within a bounded execution budget and without uncontrolled expensive KDF calls. |
| T-BUILD | Clean release and sanitizer builds of examples and tests on every supported platform. |

**TEST-01.** PBKDF2 fixtures use hex inputs and outputs generated with Python `hashlib.pbkdf2_hmac`; RFC 6070 is PBKDF2-HMAC-SHA-1 and is not a SHA-256 vector set.

**TEST-02.** Preserve standard fixtures and regressions for SHA/HMAC/PBKDF2, including low-iteration and deployment-cost cases. Check statuses and memory boundaries, not only happy-path outputs.

**TEST-03.** Run available sanitizers on generated C after changes to cryptography, parsing, buffer handling, compiler flags, or platform support. Do not treat coverage as a replacement for vectors and boundary tests.

**TEST-04.** Test the real RNG adapter's argument validation and successful full-buffer behavior on every supported operating system. The implementation must retain its bounded-read and no-fallback behavior.

## 11. Development and release

**DEV-01.** Ship the library as a standalone repository with `src/`, `platform/`, `tests/`, `examples/`, `docs/`, a license, changelog, build instructions, and a support matrix. Installation must not require application files.

**DEV-02.** Minimum examples cover creating a hash, handling every verification outcome, rehashing after successful verification, and hashing binary data. Error handling is required even in short examples; deterministic test RNG is never used in a production example.

**DEV-03.** Record major decisions as short ADRs covering arithmetic, platform/randomness, format/API, policy/limits, clearing, and concurrency. Comments explain invariants and standards. Do not modify algorithms “for extra strength” or add unverified micro-optimizations.

**DEV-04.** Run `scripts/test.sh` after every algorithm, format, API, and build change. Run it once more with sanitizer flags before adding a supported platform or changing cryptographic code. Optional analysis tools and fixture generators are not runtime dependencies.

**DEV-05.** Before use in a project, review the changed cryptographic implementation and parser against this contract, run the complete test suite and sanitizer command, and record the supported toolchain and target in the project documentation.

**DEV-06.** Version public API changes. A format change requires a new format version, while increasing `targetIterations` does not. Document legacy verification, support removal, migration, vulnerability reporting, and security-release procedures.

## 12. Implementation milestones and acceptance

1. **G0 — contract and platform:** dialect, types, API, arithmetic/RNG ADRs, OS matrix, and format are fixed; a minimal interface example compiles.
2. **G1 — SHA-256:** T-SHA and T-ARITH pass in debug/release; streaming state and length overflow are verified.
3. **G2 — HMAC and PBKDF2:** T-HMAC/T-KDF fixtures pass; long keys and multiple output blocks are covered.
4. **G3 — format, policy, and RNG:** negative, mutation, and supported-platform RNG tests pass; no unsafe fallback exists.
5. **G4 — PasswordHash:** end-to-end contracts, buffers, rehash, errors, deployment-cost test, and generated-code analysis are complete.
6. **G5 — library release:** a clean checkout builds with the documented toolchain, examples and limitations are published, and the complete test and sanitizer commands pass on every supported operating system.

**DONE-01.** Unsupported platforms, unexplained reference mismatches, crashes on external input, sanitizer findings, and failed parser mutations block G5.

## 13. Sources and design decisions

Checked 19 September 2026:

- [FIPS 180-4 — Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) — SHA-256 definition.
- [RFC 8018, §5.2](https://www.rfc-editor.org/rfc/rfc8018.html#section-5.2) — PBKDF2.
- [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231.html) — HMAC-SHA-256 test vectors.
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — password-hashing guidance and cost reference.

The `oberon-pwh` format, API statuses, 1024-byte password limit, iteration ceilings, supported-platform matrix, and test thresholds are project decisions in this specification. Reassess compatibility, load, and tests before changing them, and re-check current KDF-cost guidance before release.
