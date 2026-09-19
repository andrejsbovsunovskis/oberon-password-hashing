# ADR 002: random salt source

Use `/dev/urandom` through FreeOberon's existing `Platform` adapter on macOS and Linux. The adapter requires a complete bounded read, closes the descriptor, rejects all-zero output, and has no fallback.
