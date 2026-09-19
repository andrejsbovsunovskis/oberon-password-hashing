# Support and security

Supported release targets are macOS arm64 and Linux x86_64 with the documented FreeOberon/Ofront+ toolchain. Other targets may be useful during development but are not a compatibility promise.

This project is experimental and unaudited. Report a suspected vulnerability privately to the maintainers; do not include passwords, live password records, salts paired with user data, or production database extracts. A security fix must receive a new version, changelog entry, affected-format assessment, and a documented migration path.

The v1 reader accepts only `oberon-pwh$1$pbkdf2-sha256` records. It has no implicit legacy reader. Future format readers must be explicitly selected, bounded by policy, and removed only through a documented migration window.
