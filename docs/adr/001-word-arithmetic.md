# ADR 001: SHA-256 word representation

Use a bounded `LONGINT` word operated on as two 16-bit halves. FreeOberon applications commonly use signed `INTEGER`; relying on its overflow would make generated C behaviour toolchain-dependent. The representation is simple to inspect but requires performance measurement before deployment.
