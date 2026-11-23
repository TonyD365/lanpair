# Changelog

## 1.4.1 (2026-11-23)

- Fixed: a file or socket error while handling a UDP message, such as a locked state file
  on Windows, stopped the node from receiving until it was restarted. It now drops that
  message and keeps listening.
- New wordmark logo and icon.

## 1.4.0 (2026-11-23)

- Reliable delivery: `send(..., ack=True)` retries until the peer confirms, delivers once,
  and raises `DeliveryError` on timeout.
- `request()` / `reply()` for request and response, including recovery from a lost reply.
- `Host.broadcast()` sends to every paired device and reports the result per device.
- `AsyncHost` and `AsyncDevice` for asyncio.
- Optional pairing code check: `confirm=` on `Host.pairing_offer()` and `Device.pair()`.

## 1.3.0 (2026-11-21)

- **Forward secrecy** for `Host` / `Device`: messages are encrypted to short-lived session
  keys that exist only in memory, are replaced every 10 minutes and deleted after one more
  period, so a seed stolen later can't decrypt recorded messages. Peers exchange session
  keys inside signed, encrypted control messages; a message sealed to a key the receiver
  no longer has (after a restart) is resent to its new key. Works with peers on 1.2 and
  older, which keep using the long-term key.
- `Sealer.seal(..., box_key=...)`, `Opener.add_session_key()`, `Opener.remove_session_key()`
  and `Opener.open_detailed()` let the building blocks use session keys too.
- Releases carry the wheel and source archive with signed SLSA build provenance
  (`gh attestation verify ... -R TonyD365/lanpair`).
- Tested on Python 3.10 to 3.15, and the package now lists those versions.
- Homepage at https://tonyd365.github.io/lanpair/ (`site/`, deployed by GitHub Pages), and
  Documentation, Source, Issues and Changelog links on PyPI.

## 1.2.0 (2026-11-21)

- `Host` / `Device` send messages of any size up to 1 MiB: those too big for one UDP
  datagram (over about 6 KB) go over a short TCP connection to the peer's port (the same
  number as its UDP port), with the same checks. TCP connections are limited to 16 at a
  time and 5 seconds each, and oversized frames are refused before they are read.
  The TCP listener can be rebound right after a restart (`SO_REUSEADDR` on POSIX), so a
  node keeps its port even after it closed connections itself.
- README: a demo GIF, and host / device examples you can run as they are.
- `e2e/` also runs `Host` / `Device` across separate environments, with pairing and
  message attacks.

## 1.1.0 (2026-11-21)

- `Host` and `Device`: the high-level API. UDP transport, QR-code pairing, mDNS
  discovery, keys in the OS key store, and peers and replay counters on disk, so a
  device pairs once and keeps working across restarts and address changes.
  They listen on all interfaces (other devices must reach them); `bind=` limits that
  to one interface.
- `PairingOffer` / `lanpair.pairing`: one-time pairing offers (`lanpair://pair?...`) with
  the host's keys, address and a 128-bit secret; one device per offer, 5 minutes, 5 tries;
  the secret travels encrypted. `offer.print_qr()` with `pip install "lanpair[qr]"`.
- New extras: `qr`, and `all` for keyring, discovery and qr together.
- Nodes keep their port across restarts, and say hello to their peers when they start
  (after an mDNS lookup), so messages keep arriving when either side restarts or moves.

## 1.0.0 (2026-11-21)

The API documented in the README is now stable and follows semantic versioning.

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
- `e2e/`: an end-to-end test in a simulated LAN with an attacker node, run before releases.

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
