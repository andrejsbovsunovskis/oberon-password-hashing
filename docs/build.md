# Build and test

[Русская версия](build.ru.md)

The pinned source dialect is FreeOberon/Oberon-07: Ofront+ runs with `-s -88 -7w`, matching the stock `fob`. The project uses no cryptographic C library: generated C is only the FreeOberon backend.

Install FreeOberon, point `FREEOBERON_HOME` to its checkout, then run `./scripts/test.sh`.

The script selects `macOS`, `Linux_amd64`, or `Linux_aarch64`, translates modules in dependency order, and links test executables against the target `libOfront.a`. It also links the target's `Platform.c`, the documented boundary used by `platform/SecureRandom.Mod` to read `/dev/urandom`.

Normal test executables use `clang -O3 -flto`. `PasswordBytes.c`, which contains secret-buffer wiping routines, is compiled separately without LTO so those writes remain an external observable call. Extra C compiler flags are appended from `CFLAGS`; for example, run AddressSanitizer and UndefinedBehaviorSanitizer with:

```sh
CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' ./scripts/test.sh
```

The script prints the translator path and SHA-256 plus the C compiler version. Record this output together with the host architecture whenever changing the toolchain. macOS arm64 is the currently validated platform; add a platform to the support matrix only after this command and the sanitizer run pass there.

To verify the complete stock builder pipeline, run:

```sh
./scripts/test-fob.sh
```

The script stages sources, examples, and tests in a temporary directory, then builds and runs all nine test programs using the actual `$FREEOBERON_HOME/fob`, including type-size checks and imports of both examples. It does not change FreeOberon flags or scripts. `fob` uses its own `_Build` directory inside the FreeOberon checkout and stock C compiler settings; optimized and sanitizer builds remain separate checks through `scripts/test.sh`. Do not run concurrent `fob` builds in the same checkout.

For your own program, place `src/*.Mod` and `platform/SecureRandom.Mod` beside the main module and invoke:

```sh
"$FREEOBERON_HOME/fob" /short/path/MyProgram.Mod -o /short/path/my-program
```

Declare byte arguments as `ARRAY OF SYSTEM.CHAR8` with an import of `SYSTEM`; explicitly encode 16-bit `CHAR` text into UTF-8 first. Source paths must be shorter than 80 characters because of the current `fob` command buffer. The test script uses a short directory under `/tmp`, independently of `TMPDIR`.
