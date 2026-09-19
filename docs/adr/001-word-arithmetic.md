# ADR 001: SHA-256 word representation

Use `INTEGER` as a 32-bit bit pattern for SHA words. Addition converts through bounded 64-bit `LONGINT` arithmetic before reducing modulo `2^32`; bitwise operations and rotations use Ofront+ `SYSTEM` operations. This keeps generated C free of signed-overflow arithmetic while allowing the compiler to emit native 32-bit instructions.
