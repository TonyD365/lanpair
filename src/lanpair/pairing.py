"""One-time pairing offers, shown as a QR code.

The host makes a :class:`PairingOffer` and shows it, usually as a QR code. It carries the
host's full public identity, its address and a 128-bit one-time secret. Scanning it is the
trust step: an attacker on the LAN cannot change what is on the host's screen, so the
device learns the host's real keys.

The device then sends its own public identity and the secret to the host, sealed to the
host's key, so nobody on the network can read the secret. The host accepts the device
only if the secret matches, the offer has not expired, has not been used, and fewer than
``max_attempts`` wrong answers came in. The host's reply, sealed to the device, confirms
the pairing.

:class:`lanpair.Host` and :class:`lanpair.Device` use this; the functions here are for
building your own transport.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, quote, urlencode, urlsplit

from .envelope import EnvelopeError, Opener, Sealer
from .identity import Identity, PublicIdentity

SCHEME = "lanpair"
DEFAULT_TTL = 300.0  # seconds an offer stays valid
DEFAULT_MAX_ATTEMPTS = 5
_ADDR = re.compile(r"^[0-9A-Za-z.\-]{1,253}:[0-9]{1,5}$")


class PairingError(Exception):
    """A pairing offer is invalid or expired, or a pairing attempt was refused."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass(frozen=True)
class PairingOffer:
    """What the host shows and the device scans. Contains a secret: show it, don't log it."""

    host: PublicIdentity
    name: str
    address: str  # "ip:port" where the host listens
    secret: bytes = field(repr=False)
    expires: float  # Unix time
    app: str = "lanpair"
    code: str = field(default="", repr=False, compare=False)
    """Six digits to type instead of scanning (host side only; not in the QR code)."""

    @classmethod
    def create(
        cls,
        host: PublicIdentity,
        name: str,
        address: str,
        *,
        ttl: float = DEFAULT_TTL,
        app: str = "lanpair",
        clock: Callable[[], float] = time.time,
    ) -> PairingOffer:
        return cls(
            host,
            name,
            address,
            os.urandom(16),
            clock() + ttl,
            app,
            f"{secrets.randbelow(10**6):06d}",
        )

    def to_uri(self) -> str:
        """``lanpair://pair?...``: put this in the QR code."""
        query = urlencode(
            {
                "v": "1",
                "app": self.app,
                "name": self.name,
                "addr": self.address,
                "id": _b64(self.host.to_bytes()),
                "s": _b64(self.secret),
                "exp": str(int(self.expires)),
            },
            quote_via=quote,
        )
        return f"{SCHEME}://pair?{query}"

    @classmethod
    def from_uri(cls, uri: str) -> PairingOffer:
        """Parse a scanned offer. Raises :class:`PairingError` if it is not a valid one."""
        try:
            parts = urlsplit(uri.strip())
            if parts.scheme != SCHEME or parts.netloc != "pair":
                raise ValueError("not a lanpair pairing link")
            q = {k: v[0] for k, v in parse_qs(parts.query, strict_parsing=True).items()}
            if q.get("v") != "1":
                raise ValueError("unsupported pairing link version")
            if not _ADDR.match(q["addr"]) or not 0 < int(q["addr"].rsplit(":", 1)[1]) < 65536:
                raise ValueError("bad address")
            secret = _unb64(q["s"])
            if len(secret) != 16:
                raise ValueError("bad secret")
            return cls(
                PublicIdentity.from_bytes(_unb64(q["id"])),
                q.get("name", "")[:63],
                q["addr"],
                secret,
                float(int(q["exp"])),
                q.get("app", "lanpair"),
            )
        except (KeyError, ValueError, binascii.Error) as e:
            raise PairingError(f"invalid pairing link: {e}") from e

    def expired(self, now: float | None = None) -> bool:
        return (time.time() if now is None else now) >= self.expires

    def qr(self) -> Any:
        """A ``segno`` QR code object (``.save("pair.png")``, ``.terminal()``, ...).

        Needs ``pip install "lanpair[qr]"``.
        """
        try:
            import segno
        except ImportError as e:  # pragma: no cover - depends on the install
            raise PairingError('QR codes need the segno package: pip install "lanpair[qr]"') from e
        return segno.make(self.to_uri(), error="m")

    def print_qr(self) -> None:
        """Print the QR code in the terminal, to scan from the screen."""
        self.qr().terminal(compact=True)


def pairing_code(offer: PairingOffer, device: PublicIdentity) -> str:
    """A short code both sides can show, to check by eye that they paired with each other."""
    data = b"lanpair pairing code v1" + offer.host.to_bytes() + device.to_bytes()
    digest = hmac.new(offer.secret, data, hashlib.sha256).digest()
    number = int.from_bytes(digest[:8], "big") % 1_000_000
    return f"{number // 1000:03d}-{number % 1000:03d}"


# --- wire format ------------------------------------------------------------------------
# A pairing request is {"id": <device public identity>, "env": <envelope>}: the identity
# travels in the clear (it is public) so the host can check the envelope's signature
# before decrypting anything; the secret is inside the encrypted body.

_REQUEST_TYPE = "lanpair/pair-request"


def make_request(device: Identity, offer: PairingOffer, name: str, sealer: Sealer) -> bytes:
    """The device's answer to *offer*, ready to send to ``offer.address``."""
    body = {"t": _REQUEST_TYPE, "secret": _b64(offer.secret), "name": name[:63]}
    env = sealer.seal(offer.host, body)
    wrapper = {"id": _b64(device.public.to_bytes()), "env": env.decode()}
    return json.dumps(wrapper, separators=(",", ":")).encode()


class _SessionStore:
    """Sequence numbers seen during one pairing session, so a replayed request fails.

    Marked persistent: the session is new, so there is nothing from before a restart to
    guard against, and no start-up window is needed.
    """

    persistent = True

    def __init__(self) -> None:
        self._seqs: dict[str, int] = {}

    def get(self, device_id: str) -> int:
        return self._seqs.get(device_id, 0)

    def set(self, device_id: str, seq: int) -> None:
        self._seqs[device_id] = seq

    def forget(self, device_id: str) -> None:
        self._seqs.pop(device_id, None)


@dataclass
class PairingSession:
    """The host's side of one offer: checks requests, at most one device, limited tries."""

    me: Identity
    offer: PairingOffer
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    clock: Callable[[], float] = time.time
    _attempts: int = 0
    _paired: PublicIdentity | None = None
    _store: _SessionStore = field(default_factory=_SessionStore, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def open(self) -> bool:
        """Still accepting requests."""
        return (
            self._paired is None
            and self._attempts < self.max_attempts
            and not self.offer.expired(self.clock())
        )

    def close(self) -> None:
        """No more pairing with this offer (the 6-digit code was used instead)."""
        with self._lock:
            self._attempts = self.max_attempts

    def accept(self, raw: bytes) -> tuple[PublicIdentity, str]:
        """Check a pairing request. Returns the device's identity and name.

        Raises :class:`PairingError` for anything that must not pair. A new request with the
        right secret from the device that already paired returns it again, so a device
        whose confirmation was lost can retry; a replayed request is refused.
        """
        try:
            wrapper = json.loads(raw)
            device = PublicIdentity.from_bytes(_unb64(wrapper["id"]))
            env = wrapper["env"].encode()
        except (ValueError, KeyError, TypeError, AttributeError, RecursionError, binascii.Error):
            raise PairingError("malformed pairing request") from None
        with self._lock:  # one request at a time: attempts and replays are counted exactly
            if self._paired is None and not self.open:
                raise PairingError("pairing offer expired, used or locked")
            opener = Opener(self.me, clock=self.clock, store=self._store)
            opener.add_peer(device)
            try:
                _, body = opener.open(env)
            except EnvelopeError as e:
                raise PairingError(f"pairing request rejected: {e}") from None
            if not isinstance(body, dict) or body.get("t") != _REQUEST_TYPE:
                raise PairingError("not a pairing request")
            try:
                given = _unb64(str(body.get("secret", "")))
            except (ValueError, binascii.Error):
                given = b""
            match = hmac.compare_digest(given, self.offer.secret)
            if self._paired is not None:
                if not (match and self._paired == device):
                    raise PairingError("pairing offer already used")
            elif not match:
                self._attempts += 1
                raise PairingError("wrong pairing secret")
            else:
                self._paired = device
        name = body.get("name")
        return device, (name if isinstance(name, str) else "")[:63]
