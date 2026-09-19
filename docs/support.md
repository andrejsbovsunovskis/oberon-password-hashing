# Support and security

The supported target is macOS arm64 with the documented FreeOberon/Ofront+ toolchain. Other targets may be useful during development but are not a compatibility promise until the full test and sanitizer commands have passed on them.

The project is self-reviewed. Report a suspected vulnerability privately to the maintainers; do not include passwords, live password records, salts paired with user data, or production database extracts. A security fix must assess affected records and document any required migration.

The v1 reader accepts only `oberon-pwh$1$pbkdf2-sha256` records. It has no implicit legacy reader. Future format readers must be explicitly selected, bounded by policy, and removed only through a documented migration window.
