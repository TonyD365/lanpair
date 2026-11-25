"""Pairing with a 6-digit code, for devices that cannot scan a QR code.

A 6-digit code is far too short to carry a key or to be checked in the clear: an attacker
could try all million values offline. So the code only keys CPace (:mod:`lanpair.cpace`):

1. The device sends a random session id ``sid``, its CPace share ``Ya`` and its public
   identity and name (``ADa``).
2. The host answers with ``Yb``, its own identity and name (``ADb``) and a tag that proves
   it derived the same key. A wrong code gives a different key, so the tag fails.
3. The device answers with its own tag and an Ed25519 signature over the session, proving
   it holds the key it claimed.

Both public identities are inside the CPace transcript, so an attacker in the middle who
swaps a key changes the derived key and both tags fail. Each run lets an attacker test one
guess of the code; the host allows ``max_attempts`` runs per code (5 by default: a 1 in
200,000 chance), for 5 minutes, and one device.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from . import cpace
from .identity import Identity, PublicIdentity
from .pairing import DEFAULT_MAX_ATTEMPTS, DEFAULT_TTL, PairingError

_CI_LABEL = b"lanpair code pairing v1"
_SIG_LABEL = b"lanpair code pairing signature v1"
_PENDING_KEEP = 30.0  # seconds a started exchange may take to finish
_PENDING_MAX = 8


def new_code() -> str:
    """Six random digits."""
    return f"{secrets.randbelow(1_000_000):06d}"


def normalize(code: str) -> str:
    """``"123 456"`` or ``"123-456"`` to ``"123456"``; raises PairingError otherwise."""
    digits = "".join(c for c in code if c not in " -")
    if len(digits) != 6 or not digits.isascii() or not digits.isdigit():
        raise PairingError("a pairing code is 6 digits")
    return digits


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: object, size: int | None = None) -> bytes:
    if not isinstance(text, str) or len(text) > 200:
        raise PairingError("malformed pairing message")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, binascii.Error):
        raise PairingError("malformed pairing message") from None
    if size is not None and len(raw) != size:
        raise PairingError("malformed pairing message")
    return raw


def _load(raw: bytes, kind: str) -> dict[str, object]:
    if len(raw) > 2048:
        raise PairingError("malformed pairing message")
    try:
        msg = json.loads(raw)
    except (ValueError, RecursionError):
        raise PairingError("malformed pairing message") from None
    if not isinstance(msg, dict) or msg.get("t") != kind:
        raise PairingError("malformed pairing message")
    return msg


def _dump(msg: dict[str, object]) -> bytes:
    return json.dumps(msg, separators=(",", ":")).encode()


def _ad(identity: PublicIdentity, name: str) -> bytes:
    return cpace.lv_cat(identity.to_bytes(), name[:63].encode())


def _read_ad(ad: bytes) -> tuple[PublicIdentity, str]:
    try:
        parts: list[bytes] = []
        i = 0
        while i < len(ad):
            n = ad[i]
            if n >= 128:
                raise ValueError
            parts.append(ad[i + 1 : i + 1 + n])
            i += 1 + n
        if len(parts) != 2 or i != len(ad) or len(parts[0]) != 64:
            raise ValueError
        return PublicIdentity.from_bytes(parts[0]), parts[1].decode()
    except (ValueError, IndexError, UnicodeDecodeError):
        raise PairingError("malformed pairing message") from None


def _ci(app: str) -> bytes:
    return cpace.lv_cat(_CI_LABEL, app.encode())


def _mac_key(sid: bytes, isk: bytes) -> bytes:
    return hashlib.sha512(b"CPaceMac" + sid + isk).digest()


def _tag(mac_key: bytes, y: bytes, ad: bytes) -> bytes:
    return hmac.new(mac_key, cpace.lv_cat(y, ad), hashlib.sha512).digest()


def _signed(sid: bytes, transcript: bytes) -> bytes:
    return _SIG_LABEL + sid + hashlib.sha512(transcript).digest()


@dataclass
class _Started:
    created: float
    reply: bytes
    ya: bytes
    ada: bytes
    yb: bytes
    adb: bytes
    mac_key: bytes
    device: PublicIdentity
    name: str


@dataclass
class CodeSession:
    """The host's side of one 6-digit code: limited runs, one device."""

    me: Identity
    name: str
    code: str
    app: str = "lanpair"
    ttl: float = DEFAULT_TTL
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    clock: Callable[[], float] = time.time
    expires: float = 0.0
    _attempts: int = 0
    _paired: PublicIdentity | None = None
    _started: dict[bytes, _Started] = field(default_factory=dict, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        self.code = normalize(self.code)
        self.expires = self.clock() + self.ttl

    @property
    def open(self) -> bool:
        return (
            self._paired is None
            and self._attempts < self.max_attempts
            and self.clock() < self.expires
        )

    def close(self) -> None:
        """No more pairing with this code (the QR code was used instead)."""
        with self._lock:
            self._attempts = self.max_attempts

    def start(self, raw: bytes) -> bytes:
        """Step 1 from the device: returns the answer. Each new run counts as an attempt."""
        msg = _load(raw, "code1")
        sid = _unb64(msg.get("sid"), 16)
        ya = _unb64(msg.get("y"), 32)
        ada = _unb64(msg.get("ad"))
        device, device_name = _read_ad(ada)
        now = self.clock()
        with self._lock:
            for old in [s for s, st in self._started.items() if now - st.created > _PENDING_KEEP]:
                del self._started[old]
            again = self._started.get(sid)
            if again is not None and again.ya == ya and again.ada == ada:
                return again.reply  # the device resent step 1: same answer, no new attempt
            if not self.open or len(self._started) >= _PENDING_MAX:
                raise PairingError("pairing code expired, used or locked")
            self._attempts += 1
            g = cpace.calculate_generator(self.code.encode(), _ci(self.app), sid)
            yb_scalar = os.urandom(32)
            yb = cpace.scalar_mult(yb_scalar, g)
            adb = _ad(self.me.public, self.name)
            try:
                isk = cpace.isk(
                    sid, cpace.scalar_mult(yb_scalar, ya), cpace.transcript_ir(ya, ada, yb, adb)
                )
            except cpace.CPaceError:
                raise PairingError("invalid pairing share") from None
            mac_key = _mac_key(sid, isk)
            reply = _dump(
                {
                    "t": "code2",
                    "sid": _b64(sid),
                    "y": _b64(yb),
                    "ad": _b64(adb),
                    "tag": _b64(_tag(mac_key, yb, adb)),
                }
            )
            self._started[sid] = _Started(
                now, reply, ya, ada, yb, adb, mac_key, device, device_name
            )
            return reply

    def finish(self, raw: bytes) -> tuple[PublicIdentity, str]:
        """Step 3 from the device: returns the paired device, or raises PairingError."""
        msg = _load(raw, "code3")
        sid = _unb64(msg.get("sid"), 16)
        tag = _unb64(msg.get("tag"), 64)
        sig = _unb64(msg.get("sig"), 64)
        with self._lock:
            st = self._started.get(sid)
            if st is None:
                raise PairingError("unknown pairing run")
            if not hmac.compare_digest(tag, _tag(st.mac_key, st.ya, st.ada)):
                raise PairingError("wrong pairing code")
            transcript = cpace.transcript_ir(st.ya, st.ada, st.yb, st.adb)
            if not st.device.verify(_signed(sid, transcript), sig):
                raise PairingError("bad pairing signature")
            if self._paired is not None and self._paired != st.device:
                raise PairingError("pairing code already used")
            if self.clock() >= self.expires and self._paired is None:
                raise PairingError("pairing code expired")
            self._paired = st.device
            return st.device, st.name


@dataclass
class CodeAttempt:
    """The device's side of one run."""

    me: Identity
    name: str
    code: str
    app: str = "lanpair"
    sid: bytes = field(default_factory=lambda: os.urandom(16))
    _scalar: bytes = field(default_factory=lambda: os.urandom(32), repr=False)

    def __post_init__(self) -> None:
        self.code = normalize(self.code)
        g = cpace.calculate_generator(self.code.encode(), _ci(self.app), self.sid)
        self._ya = cpace.scalar_mult(self._scalar, g)
        self._ada = _ad(self.me.public, self.name)

    def request(self) -> bytes:
        """Step 1, to send to the host (resend it unchanged if no answer comes)."""
        return _dump(
            {"t": "code1", "sid": _b64(self.sid), "y": _b64(self._ya), "ad": _b64(self._ada)}
        )

    def answer(self, raw: bytes) -> tuple[PublicIdentity, str, bytes]:
        """Checks the host's step 2. Returns the host's identity, its name and step 3."""
        msg = _load(raw, "code2")
        if _unb64(msg.get("sid"), 16) != self.sid:
            raise PairingError("answer for another pairing run")
        yb = _unb64(msg.get("y"), 32)
        adb = _unb64(msg.get("ad"))
        tag = _unb64(msg.get("tag"), 64)
        host, host_name = _read_ad(adb)
        transcript = cpace.transcript_ir(self._ya, self._ada, yb, adb)
        try:
            isk = cpace.isk(self.sid, cpace.scalar_mult(self._scalar, yb), transcript)
        except cpace.CPaceError:
            raise PairingError("invalid pairing share") from None
        mac_key = _mac_key(self.sid, isk)
        if not hmac.compare_digest(tag, _tag(mac_key, yb, adb)):
            raise PairingError("wrong pairing code, or not the host showing it")
        finish = _dump(
            {
                "t": "code3",
                "sid": _b64(self.sid),
                "tag": _b64(_tag(mac_key, self._ya, self._ada)),
                "sig": _b64(self.me.sign(_signed(self.sid, transcript))),
            }
        )
        return host, host_name, finish
