# End-to-end test: a simulated LAN with an attacker

Run before every release, against the package as users get it (from PyPI or a built wheel):

```bash
python e2e/run.py "lanpair[keyring,discovery]==1.0.0"
```

What it sets up:

- **Four devices**, each a separate virtual environment with its own `HOME` and its own key
  store (keyrings.alt file backend): `desk`, `room1`, `room2` and `attacker`.
- **A bridge** (`bridge.py`): a UDP hub that forwards every frame and mirrors it to the
  attacker, like an unswitched network segment.
- **Real mDNS** on this machine for discovery.

What it checks:

1. The desk finds both rooms by device id with mDNS, with the right address and name.
2. Three real messages reach room1 intact and in order; the attacker cannot read them.
3. room1 rejects a replay, a tampered ciphertext, a tampered sequence number, a message
   signed with the attacker's key, one claiming to be from the desk, and five kinds of
   garbage; room2 rejects a message redirected to it from room1.
4. Hostile input too big for one UDP packet (200,000 levels of nesting, 2 MiB) is rejected
   with `EnvelopeError`, not a crash.
5. After every device restarts: identities are the same (key store), all replays of
   messages recorded before the restart are rejected, and a new message gets through.
6. **Host / Device** (lanpair 1.1+), in the same venvs (`hl_node.py`): the device pairs from
   the link (standing in for the QR code); a small message (UDP) and a 300 KB one (TCP)
   go both ways; an attacker is refused with the already-used offer even knowing its
   secret, and with a second offer after five wrong guesses locked it; forged messages,
   a message claiming to be the device and bad TCP frames are dropped; after both
   restart, messages flow without pairing again.

Needs Python 3.10+, network access to PyPI, and multicast on the loopback interface (macOS
and most Linux desktops; not GitHub-hosted runners, so it is not part of CI). Output goes
to `e2e/work/`, which is ignored by git.
7. **6-digit code pairing** (lanpair 1.5+): an attacker's two wrong codes are rejected; the
   device then finds the host with mDNS and pairs with the right code; its first message
   arrives; the used code is refused afterwards, even when right; only the real device is
   paired.
