# Security

**Looking for security holes in lanpair is welcome.** It exists to keep forged and replayed
messages out of other people's projects, so a hole here matters. Reports are answered, fixed
and credited.

## Reporting a problem

**Please do not open a public issue for a security problem.** Report it privately instead:

- on GitHub, open the repository's **Security** tab and choose **Report a vulnerability**, or
- if that is not available, write to the maintainer through the contact on
  [TonyD365's GitHub profile](https://github.com/TonyD365).

Say what the problem is, how to reproduce it (a short script is ideal), and which version you
used. You will get an answer within a week. Please give a reasonable time to fix it before
telling anyone else.

## What happens after you report

1. You get an answer within a week, saying whether it is a vulnerability and how serious it is.
2. The fix is made in a private fork of the repository, where you are welcome to check it.
3. It is released on PyPI.
4. A security advisory is published here, with a CVE number when it is serious, and **you are
   credited in it** (unless you would rather not be).

Please keep it private until the advisory is out.

## What is in scope

The latest release on PyPI and the `main` branch. Fixes go into a new release; older
releases are not patched.

The threat model is in [docs/design.md](docs/design.md): an attacker on the same network who can
read, inject, replay and drop traffic and advertise fake devices, but cannot see the devices'
screens during pairing. Especially welcome:

- a way to get a message accepted that the paired peer did not send, or that was meant for
  another device, or that was already accepted once;
- a way to pair without seeing the QR code, the 6-digit code or the short code;
- key material showing up anywhere outside the OS key store.

## Verifying a release

Releases are built by GitHub Actions and uploaded to PyPI with trusted publishing (no
tokens). From 1.3, each GitHub release also carries the wheel and source archive with
signed build provenance (SLSA, via Sigstore). To check that a file was built from this
repository by its release workflow:

```bash
gh attestation verify lanpair-1.3.0-py3-none-any.whl -R TonyD365/lanpair
```

## Known limits

- **Forward secrecy has a window.** `Host` and `Device` (1.3+) encrypt to short-lived session
  keys that live only in memory and are replaced every 10 minutes (the previous one is kept
  for one more period). Someone who steals a device's seed later cannot decrypt recorded
  messages, except those of the last ~20 minutes if they take the running device itself.
  Control messages that carry session keys, and messages to peers on lanpair ≤ 1.2, use the
  long-term key. The low-level `Sealer` / `Opener` give forward secrecy only if you use
  session keys yourself (`Opener.add_session_key`, `Sealer.seal(..., box_key=...)`).
- **Metadata is visible**: message sizes and who talks to whom stay visible on the network.
- **Pairing offers can be locked by guessing**: anyone on the network can send five wrong
  answers and lock an open offer (they cannot pair or learn the secret). Make a new offer.
- **Addresses follow authenticated messages**: an attacker who can delay a device's packet
  and deliver a copy from another address first makes the host reply to that address. The
  replies stay unreadable and unusable there; the next real message moves the address back.
- **No external security review yet.**
