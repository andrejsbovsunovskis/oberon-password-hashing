# Portability record

SHA-256 words are not signed `INTEGER`. `PasswordWord.Word` is a `LONGINT` restricted to `0..2^32-1`; addition uses two 16-bit halves, so neither Oberon nor generated C relies on signed 32-bit overflow. Rotations, shifts, input decoding, and digest encoding are explicit and byte-order independent. Cryptographic octets use FreeOberon's 8-bit `SHORTCHAR`, never its 16-bit `CHAR`.

The code relies on Ofront+ `-88` having a 32-bit two's-complement `INTEGER`, a 64-bit `LONGINT`, an 8-bit `SHORTCHAR` accepted by `ORD`/`CHR` in `0..255`, and `SET` operations over `INTEGER` bit patterns. `scripts/test.sh` keeps Ofront+'s bounds, type, assertion, and pointer checks enabled. The test suite verifies word carries, rotations, logical shifts, standard SHA vectors, HMAC/PBKDF2 fixtures, API boundaries, and 100,000 parser mutations.

`SecureRandom` uses the FreeOberon `Platform` file API to read `/dev/urandom` on macOS and Linux. It rejects incomplete reads, failures, and all-zero output; no pseudo-random fallback exists.
