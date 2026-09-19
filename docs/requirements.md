# Requirements for the Oberon Password Hashing Library

Requirements version: 1.0, 19 September 2026
Status: development specification; the implementation and its security have not yet been reviewed.

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
| ARCH-05 | `SecureRandom` | Buffer-fill contract with separate adapters for supported systems. |
| ARCH-06 | Internal utilities | 32-bit arithmetic, hex, comparison, and clearing as needed; do not automatically make them public APIs. |
| ARCH-07 | Dependencies | Acyclic imports; no application model, database, HTTP, session, logger, or hidden file/network actions in the core. |
| ARCH-08 | State | Independent contexts and immutable constants; no global mutable work buffer or global last-error state. |

**PORT-01.** The first target dialect is FreeOberon with a fixed toolchain. Builds MUST record compiler-binary version and hash, translator version, C compiler, runtime, and flags.

**PORT-02.** Verify the sizes and behavior of `SHORTCHAR`, `CHAR`, integer types, `SET`, shifts, conversions, overflow, bounds checks, and byte order. Record results in `docs/portability.md` and executable checks. Never assume `INTEGER` is unsigned 32-bit.

**PORT-03.** Required release platforms are macOS arm64 and Linux x86_64. No “any Oberon” portability claim is made.

**PORT-04.** SHA-256 words are exactly 32 bits. Addition modulo 2^32 and logical shifts MUST avoid undefined signed overflow in generated C and language-range violations. Byte order is explicit and CPU-independent.

## 4. Data, strings, and memory

**DATA-01.** Core APIs accept `ARRAY OF SHORTCHAR` byte arrays and explicit lengths. `SHORTCHAR` is required to keep octets 8-bit in the supported Ofront+ ABI. NUL bytes are ordinary data. Algorithmic modules MUST NOT use NUL-terminated string operations.

**DATA-02.** Lengths are measured in bytes. Every call checks `0 <= length <= LEN(buffer)`. Slices check `offset <= LEN(buffer)` and `length <= LEN(buffer) - offset` before calculating a potentially overflowing sum. Hex lengths, block counts, and output capacities are checked likewise.

**DATA-03.** Text applications pass UTF-8. The library does not change case, trim whitespace, normalize Unicode, or recode passwords. Different byte sequences are different passwords. Normalization must be an explicit, consistent application decision.

**DATA-04.** The high-level password limit is 1024 bytes inclusive. An empty password is cryptographically valid but applications MUST reject it at enrollment. Longer passwords are rejected before KDF and never truncated.

**DATA-05.** Output buffers belong to the caller and inputs are not modified. Overlap is forbidden unless explicitly supported. On error, the declared output range is cleared for valid non-overlapping buffers; invalid lengths clear only the safely addressable part.

**DATA-06.** Secret temporary buffers and key state are cleared on every exit path. Verify that the optimizer has not removed clearing. Do not promise removal of every stack, register, or GC copy when the runtime cannot guarantee it.

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

**RNG-04.** The OS API and its contract are recorded in an ADR before adapter implementation and tested on macOS and Linux. The library does not implement or cache its own PRNG/DRBG sequence between processes.

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

**API-01.** All parameters document units, ownership, ranges, output capacity, aliasing, clearing, and valid call order. Examples compile in CI.

**API-02.** Stable status codes include `Ok`, `InvalidArgument`, `InvalidState`, `BufferTooSmall`, `PasswordTooLong`, `InvalidPolicy`, `InvalidFormat`, `UnsupportedVersion`, `UnsupportedAlgorithm`, `PolicyRejected`, `RandomUnavailable`, and `InternalError`. Any verification error returns failure with both output flags false; access is denied.

**API-03.** Higher cost within policy is accepted and never downgraded. The library recommends rehash after success but never writes to storage. `NeedsRehash` parses without running KDF and does not prove that a password is correct.

**API-04.** Statuses are returned to the caller. The library does not print, halt, assert on ordinary malformed external input, or log passwords, keys, or full hashes. Boolean wrappers are allowed only when every error means rejection.

## 9. Comparison and performance

**TIME-01.** Derived keys are compared across all 32 bytes without early exit or ordinary string comparison. The comparison loop must not branch or address memory based on secret-byte values.

**TIME-02.** Review generated C and machine code for comparison, clearing, and critical operations under release flags on both target architectures. Timing measurements are evidence, not proof of constant-time behavior.

**PERF-01.** Derivation cost scales as `O(passwordLen + iterations × ceil(dkLen / 32))` for a fixed short salt. A long password is not rehashed on every HMAC iteration.

**PERF-02.** Before integration, benchmark release builds at 600,000 iterations, the policy maximum, and password lengths 0/64/65/1024 bytes. Record CPU, OS, tools, parameters, sample count, p50/p95, and memory. Do not benchmark automatically on user data.

**PERF-03.** The initial deployment target is p95 verification time no greater than 500 ms on the target server without contention. This is a project goal, not an algorithm guarantee. Define and test budgets for planned concurrency and request limits; never silently lower the minimum.

**PERF-04.** Independent operations remain isolated when calls are interleaved. Claim thread safety only after validating the runtime and adapter; otherwise document application-level serialization.

## 10. Testing and quality gates

Tests use synthetic data, not production databases or real passwords. Independent reference implementations are allowed in test tools, never in the production library.

| Test ID | Required coverage |
|---|---|
| T-SHA | Standard vectors, empty input, `abc`, one million `a`, boundary message lengths, all byte values, and different chunkings. |
| T-HMAC | RFC 4231 SHA-256 vectors, key lengths 0/63/64/65, binary data, and prepared-state reuse. |
| T-KDF | Independent PBKDF2-HMAC-SHA-256 at c=1/2/4096/600000, boundary `dkLen`, empty/binary P/S, and invalid parameters. |
| T-ARITH | Carries, high bits, shifts 0/1/31, boundary words, and length-counter limits. |
| T-ROUNDTRIP | Create/verify, wrong password, fresh test salt, UTF-8, NUL, spaces, and password-boundary cases. |
| T-FORMAT | Malformed delimiters/fields, case/hex errors, extra data, signs, leading zeros, huge integers, unknown version/algorithm, and canonical round-trip. |
| T-LIMIT | Passwords 1023/1024/1025, output capacities 0/1/130…134, exact/insufficient buffers, invalid lengths, and guard bytes. |
| T-POLICY | All min/target/max/hard-limit boundaries, invalid policies, migration mode, and no downgrade. |
| T-FAIL | RNG failure/partial output, malformed input, invalid SHA state, post-error calls, clearing, and output initialization. |
| T-COST | Invalid format/limits rejected before KDF; invalid policy and small output rejected before RNG. |
| T-ISOLATION | Interleaved independent contexts and Create/Verify calls; declared concurrency behavior. |
| T-TIMING | First/middle/last-byte mismatches, machine-code review, and clearing under optimization. |
| T-FUZZ | At least 100,000 reproducible parser/API mutations within a bounded execution budget and without uncontrolled expensive KDF calls. |
| T-BUILD | Clean debug/release builds of examples and tests from a separate checkout on both target platforms. |

**TEST-01.** PBKDF2 fixtures record provenance, tool versions, and hex inputs. Use independent implementations such as Python `hashlib.pbkdf2_hmac` and Go `crypto/pbkdf2`; RFC 6070 is PBKDF2-HMAC-SHA-1 and is not a SHA-256 vector set.

**TEST-02.** Include at least 1,000 deterministic differential SHA/HMAC/PBKDF2 cases with small iteration counts, plus a bounded production-cost set. Preserve seeds and regressions. Check statuses and memory boundaries, not only happy-path outputs.

**TEST-03.** Debug and release outputs must match. Run available sanitizers on generated C, record runtime limitations, and do not treat coverage as a replacement for vectors, boundary tests, or review.

**TEST-04.** Test the real RNG adapter and its error handling on both operating systems by replacing the system layer. A small no-repeat smoke test is not evidence of a CSPRNG.

## 11. Development and release

**DEV-01.** Ship the library as a standalone repository with `src/`, `platform/`, `tests/`, `examples/`, `docs/`, a license, changelog, build instructions, and a support matrix. Installation must not require application files.

**DEV-02.** Minimum examples cover creating a hash, handling every verification outcome, rehashing after successful verification, and hashing binary data. Error handling is required even in short examples; deterministic test RNG is never used in a production example.

**DEV-03.** Record major decisions as short ADRs covering arithmetic, platform/randomness, format/API, policy/limits, clearing, and concurrency. Comments explain invariants and standards. Do not modify algorithms “for extra strength” or add unverified micro-optimizations.

**DEV-04.** CI runs for every algorithm, format, API, and build change. Releases are tied to source, tool versions, and test results. Optional analysis tools and fixture generators are not runtime dependencies.

**DEV-05.** Before production release, an appropriately qualified person independent of the author must review the cryptographic implementation and parser. Tests and AI review alone do not make a cryptographic library audited. Until then, releases are marked experimental.

**DEV-06.** Version public API changes. A format change requires a new format version, while increasing `targetIterations` does not. Document legacy verification, support removal, migration, vulnerability reporting, and security-release procedures.

## 12. Implementation milestones and acceptance

1. **G0 — contract and platform:** dialect, types, API, arithmetic/RNG ADRs, OS matrix, and format are fixed; a minimal interface example compiles.
2. **G1 — SHA-256:** T-SHA and T-ARITH pass in debug/release; streaming state and length overflow are verified.
3. **G2 — HMAC and PBKDF2:** T-HMAC/T-KDF and independent differential tests pass; long keys and multiple output blocks are covered.
4. **G3 — format, policy, and RNG:** negative, fault-injection, fuzz, and two-platform tests pass; no unsafe fallback exists.
5. **G4 — PasswordHash:** end-to-end contracts, buffers, rehash, errors, reproducible benchmarks, and generated-code analysis are complete.
6. **G5 — library release:** independent review is closed, clean-checkout builds are reproducible, examples and limitations are published, and all required tests pass on both operating systems.

**DONE-01.** Each requirement ID in a release has a link to code/documentation and a test or manual-review record. Unsupported platforms, unexplained reference mismatches, crashes on external input, and open material review findings block G5.

## 13. Sources and design decisions

Checked 19 September 2026:

- [FIPS 180-4 — Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) — SHA-256 definition.
- [RFC 8018, §5.2](https://www.rfc-editor.org/rfc/rfc8018.html#section-5.2) — PBKDF2.
- [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231.html) — HMAC-SHA-256 test vectors.
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — password-hashing guidance and cost reference.

The `oberon-pwh` format, API statuses, 1024-byte password limit, iteration ceilings, OS matrix, 500 ms budget, and quantitative test thresholds are project decisions in this specification. Reassess compatibility, load, and tests before changing them, and re-check current KDF-cost guidance before release.
