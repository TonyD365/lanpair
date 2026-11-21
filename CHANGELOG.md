# Changelog

## Unreleased

- Security: deeply nested JSON (about 100,000 levels) made `Opener.open` raise
  `RecursionError` instead of `EnvelopeError`, before any signature check, so anyone on
  the LAN could crash a receive loop that only catches `EnvelopeError`. It is now rejected
  as malformed, and envelopes over `Opener.max_size` (1 MiB by default) are refused before
  parsing. Found by the simulated-network test.
- `load_or_create_identity()` keeps the device's seed in the OS key store (macOS Keychain,
  Windows Credential Manager, Secret Service), with `load_identity`, `save_identity` and
  `delete_identity` in `lanpair.keystore`. Optional: `pip install "lanpair[keyring]"`.
- `lanpair.discovery`: `Announcer` tells the LAN where a device listens, and
  `browse()` / `find(device_id)` locate devices with mDNS / DNS-SD. Announcements are
  validated and treated as untrusted hints. Optional: `pip install "lanpair[discovery]"`.
- Property-based tests (Hypothesis) and coverage-guided fuzzing of `Opener.open` (Atheris,
  60 s on every CI run). CI installs from hash-pinned lock files (`requirements/`).

## 0.1.0 (2026-11-21)

First release: the cryptographic core. Discovery, pairing and the high-level `Host` /
`Device` API come in later releases.

- `Identity`: one 32-byte seed per device gives an Ed25519 signing key and an X25519
  encryption key. `PublicIdentity` is 64 bytes (`to_bytes` / `from_bytes`).
- `Sealer` / `Opener`: envelopes that are encrypted to the recipient (X25519,
  HKDF-SHA256, ChaCha20-Poly1305), signed by the sender, bound to the recipient, and
  rejected when stale (±30 s) or replayed.
- Replay protection survives restarts: time-based sender sequence numbers, and
  `JsonFileSeqStore` (or a start-up window with `MemorySeqStore`) on the receiver.
- Strict validation: malformed input of any kind raises `EnvelopeError`.
