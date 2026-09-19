# Oberon Password Hashing

An independent FreeOberon library for storing and verifying passwords with PBKDF2-HMAC-SHA-256.

This project is currently at the requirements stage; no implementation has been released yet. The complete specification, including the API, storage format, randomness, portability, and testing requirements, is available in [docs/requirements.md](docs/requirements.md).

Planned repository layout:

```text
src/       cryptographic core and public API
platform/  operating-system adapters for cryptographic randomness
tests/     vectors, negative tests, and differential tests
examples/  compilable usage examples
docs/      requirements, ADRs, and portability documentation
```

Until an independent cryptographic review has been completed, this project must not be presented as production-ready.
