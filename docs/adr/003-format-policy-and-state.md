# ADR 003: format, policy, clearing, and concurrency

The v1 serializer emits exactly one ASCII form and parser acceptance is intentionally narrower than convenience parsers: lowercase hex, fixed salt/key lengths, and canonical decimal iterations. Policy validation precedes randomness and KDF work; stored costs above limits are rejected and stored costs below target request a replacement only after successful verification.

Output buffers and local salt/key work buffers are cleared on error paths and after use where the Oberon runtime makes that practical. The library has no mutable global work buffer or global last-error state. Calls own their contexts and local buffers; nevertheless, thread-safety is not claimed until the selected FreeOberon runtime and random-device adapter are validated under the deployment's concurrency model.
