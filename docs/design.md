# lanpair design

## Goal

Two devices on the same LAN find each other, establish trust once with a human in the
loop, and then exchange messages that the receiver can prove came from the paired peer,
were meant for it, and are not replays.

## Threat model

- Attacker is on the same LAN: can read, inject, drop, delay and replay packets, and can
  advertise fake mDNS services.
- Attacker does **not** see the device screens during pairing.
- Out of scope (v1): a compromised host, physical access to stored keys.

## Layers

1. **Discovery (mDNS / zeroconf).** Only finds addresses. Never a source of trust.
2. **Identity.** Each device generates an Ed25519 key pair on first run. The private key
   goes to the OS key store (Keychain / Windows Credential Manager / Secret Service via
   `keyring`); it is never written to a plain file.
3. **Pairing (once).**
   - *QR code* (`pairing.py`): carries the host's full public identity, address and a
     128-bit one-time secret (`lanpair://pair?...`). Scanning it is the out-of-band trust
     step: the device learns the host's real keys. The device answers with its public
     identity in the clear and an envelope sealed to the host whose encrypted body holds
     the secret; the host checks the envelope's signature against that identity, then the
     secret in constant time. One device per offer; the offer expires (5 min) and locks
     after 5 wrong answers; replayed requests are refused. The host confirms with a sealed
     message, so the device knows the pairing took.
   - *6-digit code* (`codepair.py`, `cpace.py`): for devices that cannot scan. The code
     is far too short to send or check in the clear, so it only keys CPace
     (draft-irtf-cfrg-cpace-21, X25519 + SHA-512, initiator-responder mode, checked
     against the draft's test vectors). The device (initiator) sends a random 16-byte
     `sid`, its share and `ADa` = its public identity and name; the host answers with its
     share, `ADb` = its identity and name, and an HMAC tag under a key derived from ISK;
     the device answers with its own tag and an Ed25519 signature over the `sid` and the
     transcript hash, proving it holds its key. `CI` binds the app name. Both identities
     are in the transcript, so swapping either changes the key and the tags fail. Each run
     tests one guess; the host counts every new run as an attempt (a resent first message
     with the same `sid` is not), allows 5, for 5 minutes, and pairs one device per offer,
     shared with the QR code. Field arithmetic for Elligator 2 uses Python integers, which
     are not constant time; a local timing attacker on the host or device could learn about
     the code, a LAN attacker sees only network timing.
   - Both sides show a short fingerprint of the peer key for an optional visual check.
4. **Messaging.** Every message is a signed envelope (`envelope.py`): the signature
   covers version, sender id, recipient id, timestamp, sequence number and body.
   Receivers drop anything with an unknown sender, bad signature, wrong recipient,
   timestamp outside ±30 s, or non-increasing sequence number. Rejected messages never
   reach application code.
   - *Restarts.* Sender sequence numbers start at the current time in microseconds, so
     they keep increasing across restarts with nothing stored. The receiver keeps the last
     accepted number per peer in a `SeqStore`: `JsonFileSeqStore` survives restarts; with
     the default in-memory store the receiver refuses anything stamped earlier than
     30 s after it started, so messages recorded before a restart cannot be replayed.
5. **Confidentiality.** Each identity also has an X25519 key, derived from the same seed
   with HKDF. Every body is encrypted to the recipient's X25519 key with a fresh
   ephemeral key (HKDF-SHA256, ChaCha20-Poly1305); the header is the AEAD associated data
   and the signature covers the ciphertext. Envelope version 2.
6. **Forward secrecy (1.3).** Each `Host` / `Device` also holds short-lived X25519
   *session keys*, generated in memory and never stored. It tells every peer its current
   session public key inside sealed, signed control messages (`hello`, `paired`, `key`),
   and peers encrypt to that key instead of the long-term one (same envelope; the
   receiver tries its session keys, then its long-term key). A new session key starts
   every 10 minutes and the previous one is kept for one more period, then deleted:
   messages sealed to a deleted key can't be decrypted again, not even with the seed.
   A message that arrives sealed to a key the receiver no longer has (it restarted, or
   missed a `key` message) is signed but undecryptable; the receiver answers with its new
   key and the message's sequence number, and the sender seals that message again to the
   new key (senders keep their last 16 messages per peer for 60 s). Peers on 1.2 or older
   never announce a session key, so they keep getting the long-term key.

7. **Delivery (1.4).** `ack=True`, `request()` and `broadcast(ack=True)` give each
   message a random id inside the encrypted body. Each retry is sealed again with a new
   sequence number; the receiver remembers the last 256 ids per peer, delivers an id once,
   and resends a cached reply if the answer was lost.
8. **Pairing code (optional).** With `confirm=`, both sides derive a 6-digit code with
   HMAC-SHA256 over both public identities, keyed by the one-time secret. Pairing completes
   only if the callback returns True.

## Open questions

- Mobile clients: a small web page or app speaking the same protocol.
- External security review before 1.0.

## Status

| Piece | State |
|---|---|
| Identity + signed envelopes | done, tested |
| Replay protection across restarts | done, tested |
| Key storage via OS key store | done, tested (`lanpair[keyring]`) |
| mDNS discovery | done, tested (`lanpair[discovery]`) |
| QR pairing | done, tested |
| PAKE code pairing (CPace) | done, tested |
| Encrypted message bodies | done, tested |
| `Host` / `Device` high-level API (UDP, TCP for large messages) | done, tested |
