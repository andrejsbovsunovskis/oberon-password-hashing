# Build and test

The pinned source dialect is FreeOberon translated by Ofront+ with the `-88` memory model. The project uses no cryptographic C library: generated C is only the FreeOberon backend.

Install FreeOberon, point `FREEOBERON_HOME` to its checkout, then run `./scripts/test.sh`.

The script selects `macOS`, `Linux_amd64`, or `Linux_aarch64`, translates modules in dependency order, and links test executables against the target `libOfront.a`. It also links the target's `Platform.c`, the documented boundary used by `platform/SecureRandom.Mod` to read `/dev/urandom`.

The script prints the translator path and SHA-256 plus the C compiler version. Before a release, preserve this output with the FreeOberon revision, flags, host architecture, and results. macOS arm64 and Linux x86_64 remain the required release checks.
