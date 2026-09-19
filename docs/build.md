# Build and test

The pinned source dialect is FreeOberon translated by Ofront+ with the `-88` memory model. The project uses no cryptographic C library: generated C is only the FreeOberon backend.

Install FreeOberon, point `FREEOBERON_HOME` to its checkout, then run `./scripts/test.sh`.

The script selects `macOS`, `Linux_amd64`, or `Linux_aarch64`, translates modules in dependency order, and links test executables against the target `libOfront.a`. It also links the target's `Platform.c`, the documented boundary used by `platform/SecureRandom.Mod` to read `/dev/urandom`.

Normal test executables use `clang -O3 -flto`. `PasswordBytes.c`, which contains secret-buffer wiping routines, is compiled separately without LTO so those writes remain an external observable call. Extra C compiler flags are appended from `CFLAGS`; for example, run AddressSanitizer and UndefinedBehaviorSanitizer with:

```sh
CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' ./scripts/test.sh
```

The script prints the translator path and SHA-256 plus the C compiler version. Record this output together with the host architecture whenever changing the toolchain. macOS arm64 is the currently validated platform; add a platform to the support matrix only after this command and the sanitizer run pass there.
