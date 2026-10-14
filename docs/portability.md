# Portability record

[Русская версия](portability.ru.md)

SHA-256 words are 32-bit `INTEGER` bit patterns. Addition converts operands to a bounded 64-bit `SYSTEM.INT64`, reduces modulo `2^32`, and converts back without signed `INTEGER` overflow. XOR, AND, NOT, rotations, shifts, input decoding, and digest encoding use Ofront+'s defined `SYSTEM` bit operations; byte order is explicit and CPU-independent. Cryptographic octets use FreeOberon's 8-bit `SYSTEM.CHAR8`, never its 16-bit `CHAR`.

The code relies on Ofront+ `-s -88 -7w` having a 32-bit two's-complement `INTEGER`, a 64-bit `SYSTEM.INT64`, an 8-bit `SYSTEM.CHAR8` with `ORD` and `SYSTEM.VAL` conversions in `0..255`, and `SET` operations over `INTEGER` bit patterns. `scripts/test.sh` keeps Ofront+'s bounds, type, assertion, and pointer checks enabled. The test suite verifies word carries, rotations, logical shifts, standard SHA vectors, HMAC/PBKDF2 fixtures, API boundaries, and 100,000 parser mutations.

`SecureRandom` uses the FreeOberon `Platform` file API to read `/dev/urandom` on macOS and Linux. It rejects incomplete reads, failures, and all-zero output; no pseudo-random fallback exists.

The stock `fob` selects Oberon-07 and wide characters (`-7w`): `CHAR` is 2 bytes and `LONGINT` is 4 bytes. Cryptographic buffers therefore use `SYSTEM.CHAR8`, and intermediate addition uses `SYSTEM.INT64` with `SYSTEM.LONG`/`SYSTEM.SHORT` conversions. `TestDialect` checks these sizes, all octet values `0..255`, addition carry, and preservation of the input array.

Array and record parameters without `VAR` are passed by read-only reference in this Ofront+ mode. They replace Component Pascal `IN` without copying secret inputs and still accept string literals. Functions use one terminal `RETURN`; procedures without a result use conditional execution instead of early `RETURN`.
