"""The high-level API: a :class:`Host` and the :class:`Device` objects paired with it.

Everything is included: UDP transport, pairing by QR code, discovery with mDNS, keys in
the OS key store, and replay protection that survives restarts::

    host = Host("Front desk")                 # device side:
    host.start()                              # dev = Device("Room 3")
    host.pairing_offer().print_qr()           # dev.start()
    for msg in host.messages():               # dev.pair(scanned_text)
        print(msg.sender.name, msg.body)      # dev.send({"type": "close"})

Small messages travel in one UDP datagram; larger ones (over about 6 KB, up to 1 MiB)
go over a short TCP connection to the same port, with the same checks.
"""

from __future__ import annotations

import base64
import json
import os
import queue
import re
import secrets
import socket
import struct
import tempfile
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple, TypeVar

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .codepair import CodeAttempt, CodeSession
from .envelope import DEFAULT_MAX_SIZE, EnvelopeError, JsonFileSeqStore, Opener, Sealer
from .identity import Identity, PublicIdentity
from .pairing import PairingError, PairingOffer, PairingSession, make_request, pairing_code

_MSG = b"M"  # an envelope
_PAIR = b"P"  # a pairing request
_CODE = b"C"  # a step of pairing with a 6-digit code
MAX_DATAGRAM = 9000  # bytes; macOS refuses larger UDP datagrams by default
MAX_MESSAGE = DEFAULT_MAX_SIZE  # bytes of envelope; what a receiver accepts by default
_POLL = 0.25  # seconds; how quickly the receive thread notices close()
_TCP_TIMEOUT = 5.0  # seconds a TCP connection may take to deliver its message
_TCP_MAX_CONNECTIONS = 16  # handled at once; more are closed right away
_LEN = struct.Struct(">I")  # TCP frame: 4-byte big-endian length, then the message
SESSION_ROTATE = 600.0  # seconds between new session keys (forward secrecy)
_SESSION_KEEP = 2  # session keys kept: the current one and the one before it
_REANNOUNCE = 10.0  # seconds between telling one peer our session key again
_OUTBOX_KEEP = 16  # recent messages kept per peer, to resend if it couldn't decrypt one
_OUTBOX_AGE = 60.0  # seconds they are kept
_SEEN_KEEP = 256  # acknowledged message ids remembered per peer, to drop retransmissions
_CONFIRM_WAIT = 120.0  # seconds a device waits while the host's user checks the code
Confirm = Callable[[str], bool]


@dataclass(frozen=True)
class PeerInfo:
    """A paired device (seen from the host) or the host (seen from a device)."""

    device_id: str
    name: str
    identity: PublicIdentity
    address: str | None  # last known "ip:port"


class Message(NamedTuple):
    """A message that passed every check: from a paired peer, intact, fresh, not a replay."""

    sender: PeerInfo
    body: Any


class Request(Message):
    """A message whose sender is waiting for an answer: pass it to ``reply()``."""

    request_id: str

    def __new__(cls, sender: PeerInfo, body: Any, request_id: str) -> Request:
        self = super().__new__(cls, sender, body)
        self.request_id = request_id
        return self


class DeliveryError(TimeoutError):
    """The peer did not acknowledge or answer in time."""


class _Pending:
    def __init__(self, device_id: str) -> None:
        self.device_id = device_id
        self.acked = threading.Event()
        self.replied = threading.Event()
        self.reply: Any = None


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "device"


def _lan_ip() -> str:
    """The address other devices on the LAN reach this one at (no packet is sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # TEST-NET-1: picks the outgoing interface only
        return str(s.getsockname()[0])
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _recv_exactly(conn: socket.socket, n: int) -> bytes:
    chunks, got = [], 0
    while got < n:
        chunk = conn.recv(min(n - got, 65536))
        if not chunk:
            raise ValueError("connection closed early")
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


def _split(address: str) -> tuple[str, int]:
    host, port = address.rsplit(":", 1)
    return host.strip("[]"), int(port)


class _PeerBook:
    """Paired peers in a JSON file: identity, name, last known address. Atomic writes."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._peers: dict[str, PeerInfo] = {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            data = {}
        if not isinstance(data, dict):
            raise ValueError(f"{path} is not a lanpair peer file")
        for entry in data.values():
            ident = PublicIdentity.from_bytes(base64.b64decode(entry["id"]))
            self._peers[ident.device_id] = PeerInfo(
                ident.device_id, str(entry.get("name", "")), ident, entry.get("addr")
            )

    def all(self) -> list[PeerInfo]:
        with self._lock:
            return list(self._peers.values())

    def get(self, device_id: str) -> PeerInfo | None:
        with self._lock:
            return self._peers.get(device_id)

    def put(self, peer: PeerInfo) -> None:
        with self._lock:
            if self._peers.get(peer.device_id) == peer:
                return
            self._peers[peer.device_id] = peer
            self._write()

    def remove(self, device_id: str) -> None:
        with self._lock:
            if self._peers.pop(device_id, None) is not None:
                self._write()

    def _write(self) -> None:
        data = {
            p.device_id: {
                "id": base64.b64encode(p.identity.to_bytes()).decode(),
                "name": p.name,
                "addr": p.address,
            }
            for p in self._peers.values()
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self._path.parent, prefix=".lanpair-peers-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=1)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self._path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise


_N = TypeVar("_N", bound="_Node")


class _Node:
    _role = "node"

    def __init__(
        self,
        name: str,
        *,
        app: str = "lanpair",
        port: int = 0,
        state_dir: str | os.PathLike[str] | None = None,
        identity: Identity | None = None,
        announce: bool = True,
        bind: str = "0.0.0.0",
    ) -> None:
        from .discovery import service_type

        service_type(app)  # validates the app name early
        self.name = name[:63]
        self.app = app
        slug = f"{self._role}-{_slug(name)}"
        if identity is None:
            from .keystore import load_or_create_identity

            identity = load_or_create_identity(f"{app}/{slug}")
        self.identity = identity
        self.state_dir = Path(state_dir) if state_dir else Path.home() / ".lanpair" / app / slug
        self._book = _PeerBook(self.state_dir / "peers.json")
        self._opener = Opener(identity, store=JsonFileSeqStore(self.state_dir / "seqs.json"))
        for peer in self._book.all():
            self._opener.add_peer(peer.identity)
        self._sealer = Sealer(identity)
        # All interfaces by default: other devices on the LAN must reach this one. Every
        # datagram is authenticated before use. Pass bind="192.168.1.10" to listen on one
        # interface only (e.g. not on a VPN or a public network).
        self._bind(bind, port)
        self._sock.settimeout(_POLL)
        self._tcp.settimeout(_POLL)
        self._tcp_slots = threading.BoundedSemaphore(_TCP_MAX_CONNECTIONS)
        self._announce = announce
        self._announcer: Any = None
        self._inbox: queue.Queue[Message] = queue.Queue()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.dropped = 0
        """Datagrams refused so far (forged, tampered, replayed, garbage, ...)."""
        # Forward secrecy: short-lived session keys, in memory only. Peers encrypt to our
        # current one; once a key is dropped, nothing sent to it can be decrypted again,
        # not even with this device's seed.
        self._session_rotate = SESSION_ROTATE
        self._sessions: list[tuple[float, bytes]] = []  # (created, public), oldest first
        self._peer_sessions: dict[str, bytes] = {}  # device id -> its current session key
        self._announced: dict[str, float] = {}  # device id -> when we last told it ours
        # Recent messages per peer by sequence number, so one it could not decrypt (sealed
        # to a session key it lost in a restart) can be sealed again to its new key.
        self._outbox: dict[str, dict[int, tuple[float, dict[str, Any]]]] = {}
        self._outbox_lock = threading.Lock()
        self._pending_sends: dict[str, _Pending] = {}
        self._seen: dict[str, OrderedDict[str, tuple[bool, Any]]] = {}
        self._delivery_lock = threading.Lock()
        self._session_lock = threading.Lock()
        self._rotate_session()

    def _bind(self, bind: str, port: int) -> None:
        """Bind UDP and TCP to one port, reusing the port from the last run if it is free,
        so peers' stored addresses stay right."""
        state = self.state_dir / "node.json"
        wanted = port
        if port == 0:
            try:
                saved = json.loads(state.read_text(encoding="utf-8")).get("port", 0)
                wanted = saved if isinstance(saved, int) and 0 < saved < 65536 else 0
            except (FileNotFoundError, ValueError, AttributeError):
                wanted = 0
        for attempt in range(20):
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if os.name != "nt":
                # Rebind right after a restart even while closed connections linger in
                # TIME_WAIT on this port. (POSIX: still only one listener per port. On
                # Windows this option would let others take the port, and isn't needed.)
                tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                udp.bind((bind, wanted))
                tcp.bind((bind, udp.getsockname()[1]))
                tcp.listen(_TCP_MAX_CONNECTIONS)
            except OSError:
                udp.close()
                tcp.close()
                if port != 0 and attempt == 0:
                    raise  # an explicitly requested port must be free
                wanted = 0  # taken by something else: any port free for both
                continue
            self._sock, self._tcp = udp, tcp
            break
        else:
            raise OSError("no port free for both UDP and TCP")
        port = wanted
        self._port = int(self._sock.getsockname()[1])
        if self._port != port:
            state.parent.mkdir(parents=True, exist_ok=True)
            state.write_text(json.dumps({"port": self.port}), encoding="utf-8")

    # --- session keys (forward secrecy) -------------------------------------------------

    def _rotate_session(self) -> bytes:
        """Start a new session key and drop the oldest; returns the new public key."""
        with self._session_lock:
            public = self._opener.add_session_key(X25519PrivateKey.generate())
            self._sessions.append((time.monotonic(), public))
            while len(self._sessions) > _SESSION_KEEP:
                _, old = self._sessions.pop(0)
                self._opener.remove_session_key(old)
            return public

    @property
    def _session_key(self) -> bytes:
        with self._session_lock:
            return self._sessions[-1][1]

    def _session_field(self) -> str:
        return base64.b64encode(self._session_key).decode()

    def _maybe_rotate(self) -> None:
        with self._session_lock:
            due = time.monotonic() - self._sessions[-1][0] >= self._session_rotate
        if due:
            self._rotate_session()
            threading.Thread(
                target=self._tell_all_sessions, name="lanpair-rekey", daemon=True
            ).start()

    def _tell_all_sessions(self) -> None:
        for peer in self._book.all():
            if self._stop.is_set():
                return
            self._tell_session(peer, force=True)

    def _tell_session(
        self, peer: PeerInfo, *, force: bool = False, retry: int | None = None
    ) -> None:
        """Tell *peer* our current session key (at most every few seconds unless forced, or
        asking it to resend message *retry*)."""
        now = time.monotonic()
        if retry is None and not force:
            if now - self._announced.get(peer.device_id, -1e9) < _REANNOUNCE:
                return
        self._announced[peer.device_id] = now
        body: dict[str, Any] = {"lanpair": "key", "session": self._session_field()}
        if retry is not None:
            body["retry"] = retry
        try:
            self._send(peer, body)
        except (OSError, LookupError, ValueError):
            pass  # unreachable now; it gets the key with our next hello or reply

    def _learn_session(self, peer: PeerInfo, body: dict[str, Any]) -> None:
        value = body.get("session")
        if not isinstance(value, str):
            return
        try:
            key = base64.b64decode(value, validate=True)
        except ValueError:
            return
        if len(key) != 32:
            return
        self._peer_sessions[peer.device_id] = key
        retry = body.get("retry")
        if type(retry) is int:
            with self._outbox_lock:
                kept = self._outbox.get(peer.device_id, {}).pop(retry, None)
            if kept is not None:
                try:
                    self._send(peer, kept[1])  # sealed again, to its new session key
                except (OSError, LookupError, ValueError):
                    pass

    def _remember(self, peer: PeerInfo, seq: int, body: dict[str, Any]) -> None:
        now = time.monotonic()
        with self._outbox_lock:
            box = self._outbox.setdefault(peer.device_id, {})
            box[seq] = (now, body)
            for old in [s for s, (t, _) in box.items() if now - t > _OUTBOX_AGE]:
                del box[old]
            while len(box) > _OUTBOX_KEEP:
                del box[min(box)]

    # --- lifecycle ---------------------------------------------------------------------

    @property
    def device_id(self) -> str:
        return self.identity.public.device_id

    @property
    def port(self) -> int:
        """The UDP port this node listens on (the same across restarts when possible)."""
        return self._port

    def start(self) -> None:
        """Start receiving, and announce this device on the network (unless announce=False)."""
        if self._thread is not None:
            return
        if self._announce:
            from .discovery import Announcer

            self._announcer = Announcer(self.identity.public, self.name, self.port, app=self.app)
        self._thread = threading.Thread(target=self._run, name=f"lanpair-{self.name}", daemon=True)
        self._thread.start()
        self._tcp_thread = threading.Thread(target=self._accept, name="lanpair-tcp", daemon=True)
        self._tcp_thread.start()
        if self._book.all():
            threading.Thread(target=self._greet, name="lanpair-greet", daemon=True).start()

    def _greet(self) -> None:
        """After a start: tell every peer where we are now, and find peers that moved.

        Each peer learns our current address from the signed hello. With mDNS on, peers are
        looked up first, in case they changed address while we were down.
        """
        for peer in self._book.all():
            if self._stop.is_set():
                return
            if self._announce:
                from .discovery import find

                found = find(peer.device_id, seconds=2.0, app=self.app)
                current = self._book.get(peer.device_id)
                if found is not None and current is not None:
                    peer = PeerInfo(
                        current.device_id, current.name, current.identity, found.address
                    )
                    self._book.put(peer)
            try:
                self._send(peer, {"lanpair": "hello", "session": self._session_field()})
            except (OSError, LookupError, ValueError):
                pass  # unreachable now; it will find us through its own hello or mDNS

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._tcp_thread.join(timeout=5)
        if self._announcer is not None:
            self._announcer.close()
            self._announcer = None
        self._sock.close()
        self._tcp.close()

    def __enter__(self: _N) -> _N:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- receiving ---------------------------------------------------------------------

    def receive(self, timeout: float | None = None) -> Message | None:
        """The next message, or None after *timeout* seconds."""
        try:
            return self._inbox.get(timeout=timeout)
        except queue.Empty:
            return None

    def messages(self) -> Iterator[Message]:
        """Every message, as it arrives, until :meth:`close`."""
        while not self._stop.is_set():
            msg = self.receive(timeout=_POLL)
            if msg is not None:
                yield msg

    def _run(self) -> None:
        while not self._stop.is_set():
            self._maybe_rotate()
            try:
                data, addr = self._sock.recvfrom(65535)
            except TimeoutError:
                continue
            except OSError:
                # Closed by close(), or (Windows) an ICMP "port unreachable" for an earlier
                # send surfacing here as ConnectionResetError: keep listening.
                if self._stop.is_set():
                    return
                continue
            try:
                self._handle(data, f"{addr[0]}:{addr[1]}")
            except (EnvelopeError, PairingError, ValueError, OSError):
                # OSError: a state file or reply failed. Lose this message, not the listener.
                self.dropped += 1

    def _accept(self) -> None:
        """TCP: one length-prefixed message per connection, for messages too big for UDP."""
        while not self._stop.is_set():
            try:
                conn, _ = self._tcp.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                continue
            if not self._tcp_slots.acquire(blocking=False):
                conn.close()  # too many at once: someone is holding connections open
                self.dropped += 1
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(_TCP_TIMEOUT)
            (length,) = _LEN.unpack(_recv_exactly(conn, _LEN.size))
            if not 0 < length <= self._opener.max_size + 1:
                raise ValueError("TCP message too large")
            data = _recv_exactly(conn, length)
            if data[:1] != _MSG:
                raise ValueError("only messages travel over TCP")
            # The sender's TCP port is temporary: don't move its address (learn=False).
            self._handle(data, None)
        except (EnvelopeError, PairingError, ValueError, OSError, struct.error):
            self.dropped += 1
        finally:
            conn.close()
            self._tcp_slots.release()

    def _handle(self, data: bytes, source: str | None) -> None:
        kind, payload = data[:1], data[1:]
        if kind == _PAIR:
            if source is None:
                raise ValueError("pairing requests travel over UDP")
            self._on_pair_request(payload, source)
            return
        if kind == _CODE:
            if source is None:
                raise ValueError("pairing requests travel over UDP")
            self._on_code(payload, source)
            return
        if kind != _MSG:
            raise ValueError("unknown datagram")
        try:
            ident, body, used = self._opener.open_detailed(payload)
        except EnvelopeError as e:
            if str(e) == "cannot decrypt":
                # Signed by a paired peer (that check comes first), but encrypted to a
                # session key we already dropped: it has missed our new one.
                self._reannounce_to_sender(payload)
            raise
        known = self._book.get(ident.device_id)
        if known is None:  # unpaired between the check and now
            raise ValueError("unknown peer")
        peer = PeerInfo(known.device_id, known.name, known.identity, source or known.address)
        self._book.put(peer)  # follow the peer to its current address
        if not isinstance(body, dict):
            raise ValueError("not a lanpair message")
        if "lanpair" in body:
            self._learn_session(peer, body)
        # A peer that uses session keys but encrypted this to an old one, or to our
        # long-term key, doesn't have our current session key: send it.
        if peer.device_id in self._peer_sessions and used != self._session_key:
            self._tell_session(peer)
        if "msg" in body:
            self._on_message(peer, body)
        elif body.get("lanpair") == "ack":
            self._on_ack(peer, body)
        elif body.get("lanpair") == "reply":
            self._on_reply(peer, body)
        elif "lanpair" in body:
            self._on_control(peer, body)

    def _on_message(self, peer: PeerInfo, body: dict[str, Any]) -> None:
        message_id = body.get("id")
        if not isinstance(message_id, str) or not 0 < len(message_id) <= 32:
            self._inbox.put(Message(peer, body["msg"]))
            return
        with self._delivery_lock:
            seen = self._seen.setdefault(peer.device_id, OrderedDict())
            previous = seen.get(message_id)
            if previous is None:
                seen[message_id] = (False, None)
                while len(seen) > _SEEN_KEEP:
                    seen.popitem(last=False)
        if previous is None:
            if body.get("req") is True:
                self._inbox.put(Request(peer, body["msg"], message_id))
            else:
                self._inbox.put(Message(peer, body["msg"]))
        self._send_quietly(peer, {"lanpair": "ack", "id": message_id})
        if previous is not None and previous[0]:  # the answer was lost: send it again
            answer = {"lanpair": "reply", "id": message_id, "body": previous[1]}
            threading.Thread(target=self._send_quietly, args=(peer, answer), daemon=True).start()

    def _on_ack(self, peer: PeerInfo, body: dict[str, Any]) -> None:
        pending = self._pending_for(peer, body)
        if pending is not None:
            pending.acked.set()

    def _on_reply(self, peer: PeerInfo, body: dict[str, Any]) -> None:
        pending = self._pending_for(peer, body)
        if pending is not None:
            pending.reply = body.get("body")
            pending.acked.set()
            pending.replied.set()

    def _pending_for(self, peer: PeerInfo, body: dict[str, Any]) -> _Pending | None:
        message_id = body.get("id")
        if not isinstance(message_id, str):
            return None
        with self._delivery_lock:
            pending = self._pending_sends.get(message_id)
        return pending if pending is not None and pending.device_id == peer.device_id else None

    def _send_quietly(self, peer: PeerInfo, body: dict[str, Any]) -> None:
        try:
            self._send(peer, body)
        except (OSError, LookupError, ValueError):
            pass  # the sender retransmits if this was lost

    def _deliver(
        self, device_id: str, value: Any, timeout: float, retries: int, *, request: bool = False
    ) -> Any:
        """Send until acknowledged (and answered, for a request), or raise DeliveryError."""
        if timeout <= 0 or retries < 0:
            raise ValueError("timeout must be positive and retries not negative")
        message_id = secrets.token_hex(8)
        body: dict[str, Any] = {"msg": value, "id": message_id, "ack": True}
        if request:
            body["req"] = True
        pending = _Pending(device_id)
        with self._delivery_lock:
            self._pending_sends[message_id] = pending
        deadline = time.monotonic() + timeout
        interval = timeout / (retries + 1)
        try:
            for _ in range(retries + 1):
                peer = self._book.get(device_id)
                if peer is None:
                    raise LookupError(f"no paired device {device_id}")
                try:
                    self._send(peer, body)
                except OSError:
                    pass  # counts as a failed try
                remaining = deadline - time.monotonic()
                done = pending.replied if request else pending.acked  # a reply can be lost too
                if remaining <= 0 or done.wait(min(interval, remaining)):
                    break
            if not pending.acked.is_set():
                raise DeliveryError(f"{device_id} did not acknowledge within {timeout} s")
            if not request:
                return None
            if not pending.replied.wait(max(0.0, deadline - time.monotonic())):
                raise DeliveryError(f"{device_id} did not answer within {timeout} s")
            return pending.reply
        finally:
            with self._delivery_lock:
                self._pending_sends.pop(message_id, None)

    def reply(self, request: Message, body: Any) -> None:
        """Answer a message that came from ``request()``."""
        if not isinstance(request, Request):
            raise ValueError("this message is not a request")
        peer = self._book.get(request.sender.device_id)
        if peer is None:
            raise LookupError(f"no paired device {request.sender.device_id}")
        with self._delivery_lock:
            seen = self._seen.setdefault(peer.device_id, OrderedDict())
            seen[request.request_id] = (True, body)
        self._send(peer, {"lanpair": "reply", "id": request.request_id, "body": body})

    def _reannounce_to_sender(self, payload: bytes) -> None:
        try:
            env = json.loads(payload)
            sender, seq = env["from"], env["seq"]
        except (ValueError, KeyError, TypeError, RecursionError):
            return
        peer = self._book.get(sender) if isinstance(sender, str) else None
        if peer is not None and type(seq) is int:
            self._tell_session(peer, retry=seq)

    def _on_pair_request(self, payload: bytes, source: str) -> None:
        raise PairingError("this device does not accept pairing requests")

    def _on_code(self, payload: bytes, source: str) -> None:
        raise PairingError("unexpected code pairing message")

    def _on_control(self, peer: PeerInfo, body: dict[str, Any]) -> None:
        pass

    # --- sending -----------------------------------------------------------------------

    def _add_peer(self, peer: PeerInfo) -> None:
        self._book.put(peer)
        self._opener.add_peer(peer.identity)

    def _resolve(self, peer: PeerInfo) -> str:
        if peer.address:
            return peer.address
        if self._announce:
            from .discovery import find

            found = find(peer.device_id, seconds=2.0, app=self.app)
            if found is not None:
                self._book.put(PeerInfo(peer.device_id, peer.name, peer.identity, found.address))
                return found.address
        raise LookupError(f"don't know where {peer.name or peer.device_id} is")

    def _send(self, peer: PeerInfo, body: dict[str, Any]) -> None:
        session = self._peer_sessions.get(peer.device_id)
        sealed = self._sealer.seal(peer.identity, body, box_key=session)
        if session is not None and "msg" in body:
            self._remember(peer, json.loads(sealed)["seq"], body)
        data = _MSG + sealed
        address = _split(self._resolve(peer))
        if len(data) <= MAX_DATAGRAM:
            self._sock.sendto(data, address)
            return
        if len(data) - 1 > MAX_MESSAGE:
            raise ValueError(f"message too large ({len(data)} bytes; the limit is 1 MiB)")
        # Too big for one datagram: one TCP connection to the peer's port. Raises OSError
        # (e.g. ConnectionRefusedError, TimeoutError) if the peer can't be reached.
        with socket.create_connection(address, timeout=_TCP_TIMEOUT) as conn:
            conn.sendall(_LEN.pack(len(data)) + data)


class Host(_Node):
    """The side that shows the QR code and that many devices pair with (a front desk, a hub).

    ``Host(name)`` keeps its keys in the OS key store (needs ``lanpair[keyring]``) and its
    paired devices and sequence numbers in ``~/.lanpair/<app>/host-<name>/``. Pass
    ``identity=`` and ``state_dir=`` to choose yourself. ``announce=False`` turns off mDNS
    (then devices must reach the address in the QR code). It listens on all interfaces;
    ``bind="<ip>"`` limits it to one, and ``port=`` fixes the port.
    """

    _role = "host"

    def __init__(self, name: str, **kwargs: Any) -> None:
        super().__init__(name, **kwargs)
        self._session: PairingSession | None = None
        self._code_session: CodeSession | None = None
        self._paired_events: queue.Queue[PeerInfo] = queue.Queue()
        self._confirm: Confirm | None = None
        self._confirming: dict[str, str] = {}  # device id -> waiting, accepted or refused

    @property
    def devices(self) -> list[PeerInfo]:
        """Every paired device."""
        return self._book.all()

    def pairing_offer(
        self,
        *,
        ttl: float = 300.0,
        max_attempts: int = 5,
        address: str | None = None,
        confirm: Confirm | None = None,
    ) -> PairingOffer:
        """A new one-time offer to show as a QR code (``offer.print_qr()``, ``offer.to_uri()``).

        Valid for *ttl* seconds and for one device; it is locked after *max_attempts* wrong
        answers. Making a new offer cancels the previous one. With *confirm*, the function
        gets a short code (``"123-456"``) to compare with the device's, and the device is
        paired only if it returns True.
        """
        offer = PairingOffer.create(
            self.identity.public,
            self.name,
            address or f"{_lan_ip()}:{self.port}",
            ttl=ttl,
            app=self.app,
        )
        self._session = PairingSession(self.identity, offer, max_attempts=max_attempts)
        self._code_session = CodeSession(
            self.identity, self.name, offer.code, app=self.app, ttl=ttl, max_attempts=max_attempts
        )
        self._confirm = confirm
        self._confirming = {}
        return offer

    def wait_for_pairing(self, timeout: float | None = None) -> PeerInfo | None:
        """The next device that pairs, or None after *timeout* seconds."""
        try:
            return self._paired_events.get(timeout=timeout)
        except queue.Empty:
            return None

    def send(
        self,
        device_id: str,
        body: Any,
        *,
        ack: bool = False,
        timeout: float = 5.0,
        retries: int = 3,
    ) -> None:
        """Send *body* (any JSON value) to a paired device.

        With ``ack=True``, retry until the device confirms it, delivered once, or raise
        :class:`DeliveryError` after *timeout* seconds.
        """
        peer = self._book.get(device_id)
        if peer is None:
            raise LookupError(f"no paired device {device_id}")
        if ack:
            self._deliver(device_id, body, timeout, retries)
        else:
            self._send(peer, {"msg": body})

    def request(self, device_id: str, body: Any, *, timeout: float = 5.0, retries: int = 3) -> Any:
        """Send *body* and return the device's ``reply()``, or raise DeliveryError."""
        return self._deliver(device_id, body, timeout, retries, request=True)

    def broadcast(
        self, body: Any, *, ack: bool = False, timeout: float = 5.0, retries: int = 3
    ) -> dict[str, bool]:
        """Send *body* to every paired device; returns ``{device_id: succeeded}``.

        Without *ack*, True means it was sent; with ``ack=True``, that the device confirmed it.
        """

        def one(peer: PeerInfo) -> bool:
            try:
                self.send(peer.device_id, body, ack=ack, timeout=timeout, retries=retries)
            except (OSError, LookupError):
                return False
            return True

        devices = self.devices
        if not devices:
            return {}
        with ThreadPoolExecutor(max_workers=min(16, len(devices))) as pool:
            results = pool.map(one, devices)
            return {d.device_id: ok for d, ok in zip(devices, results, strict=True)}

    def unpair(self, device_id: str) -> None:
        """Forget a device: nothing from it is accepted any more."""
        self._book.remove(device_id)
        self._opener.remove_peer(device_id)

    def _on_pair_request(self, payload: bytes, source: str) -> None:
        session = self._session
        if session is None:
            raise PairingError("no pairing offer is open")
        ident, name = session.accept(payload)
        peer = PeerInfo(ident.device_id, name, ident, source)
        confirm = self._confirm
        if confirm is None:
            self._finish_pairing(peer)
            return
        state = self._confirming.get(ident.device_id)
        if state == "accepted":
            self._finish_pairing(peer)
        elif state == "refused":
            self._send_quietly(peer, {"lanpair": "pair-refused"})
        else:
            self._send_quietly(peer, {"lanpair": "pair-wait"})
            if state is None:
                self._confirming[ident.device_id] = "waiting"
                code = pairing_code(session.offer, ident)
                threading.Thread(
                    target=self._ask_confirm, args=(peer, code, confirm), daemon=True
                ).start()

    def _on_code(self, payload: bytes, source: str) -> None:
        session = self._code_session
        if session is None:
            raise PairingError("no pairing code is open")
        if payload.startswith(b'{"t":"code1"'):
            self._sock.sendto(_CODE + session.start(payload), _split(source))
            return
        ident, name = session.finish(payload)
        self._finish_pairing(PeerInfo(ident.device_id, name, ident, source))

    def _ask_confirm(self, peer: PeerInfo, code: str, confirm: Confirm) -> None:
        try:
            accepted = confirm(code) is True
        except Exception:
            accepted = False
        self._confirming[peer.device_id] = "accepted" if accepted else "refused"
        if accepted:
            self._finish_pairing(peer)
        else:
            self._send_quietly(peer, {"lanpair": "pair-refused"})

    def _finish_pairing(self, peer: PeerInfo) -> None:
        # One device per offer, whichever way it paired (QR code or 6-digit code).
        if self._session is not None and self._session._paired is None:
            self._session.close()
        if self._code_session is not None and self._code_session._paired is None:
            self._code_session.close()
        known = self._book.get(peer.device_id)
        self._add_peer(peer)
        self._send(peer, {"lanpair": "paired", "name": self.name, "session": self._session_field()})
        if known is None:
            self._paired_events.put(peer)

    def _on_control(self, peer: PeerInfo, body: dict[str, Any]) -> None:
        if body.get("lanpair") == "unpair":  # the device's user rejected the pairing code
            self.unpair(peer.device_id)


class Device(_Node):
    """The side that scans the host's QR code (a room PC, a phone, a sensor).

    Same storage and options as :class:`Host`.
    """

    _role = "device"

    def __init__(self, name: str, **kwargs: Any) -> None:
        super().__init__(name, **kwargs)
        self._confirmed = threading.Event()
        self._pending: str | None = None  # the host being paired with right now
        self._host_waiting = threading.Event()
        self._host_refused = threading.Event()
        self._host_id: str | None = None
        self._code_replies: queue.Queue[tuple[bytes, str]] = queue.Queue(maxsize=16)
        peers = self._book.all()
        if peers:
            self._host_id = peers[0].device_id

    @property
    def host(self) -> PeerInfo | None:
        """The host this device is paired with, if any."""
        return self._book.get(self._host_id) if self._host_id else None

    def pair(
        self,
        offer: str | PairingOffer,
        *,
        timeout: float = 10.0,
        confirm: Confirm | None = None,
    ) -> PeerInfo:
        """Pair with the host whose QR code was scanned (the text, or a parsed offer).

        Returns the host. Raises :class:`PairingError` if the offer is invalid, expired or
        for another app, or if the host does not confirm within *timeout* seconds. With
        *confirm*, the function gets a short code (``"123-456"``) to compare with the host's;
        unless it returns True, the pairing is undone.
        """
        if self._thread is None:
            raise PairingError("call start() before pair()")
        if isinstance(offer, str):
            offer = PairingOffer.from_uri(offer)
        if offer.app != self.app:
            raise PairingError(f"this offer is for app {offer.app!r}, not {self.app!r}")
        if offer.expired():
            raise PairingError("this pairing offer has expired")
        previous = self.host
        host = PeerInfo(offer.host.device_id, offer.name, offer.host, offer.address)
        self._add_peer(host)
        self._pending = host.device_id
        self._confirmed.clear()
        self._host_waiting.clear()
        self._host_refused.clear()
        deadline = time.monotonic() + timeout
        extended = False
        step = timeout / max(1, int(timeout // 2))
        while time.monotonic() < deadline and not self._host_refused.is_set():
            if self._host_waiting.is_set() and not extended:
                extended = True  # the host's user is checking the code
                deadline = time.monotonic() + _CONFIRM_WAIT
            request = make_request(self.identity, offer, self.name, self._sealer)
            self._sock.sendto(_PAIR + request, _split(offer.address))
            if self._wait_for_host(min(step, max(0.0, deadline - time.monotonic()))):
                if confirm is not None:
                    try:
                        accepted = confirm(pairing_code(offer, self.identity.public)) is True
                    except Exception:
                        accepted = False
                    if not accepted:
                        confirmed = self._book.get(host.device_id)
                        if confirmed is not None:
                            self._send_quietly(confirmed, {"lanpair": "unpair"})
                        if previous is None or previous.device_id != host.device_id:
                            self._book.remove(host.device_id)
                            self._opener.remove_peer(host.device_id)
                        raise PairingError("the pairing code was not confirmed")
                if previous is not None and previous.device_id != host.device_id:
                    self._book.remove(previous.device_id)
                    self._opener.remove_peer(previous.device_id)
                self._host_id = host.device_id
                result = self._book.get(host.device_id)
                assert result is not None
                self._tell_session(result, force=True)  # our session key, for forward secrecy
                return result
        if previous is None or previous.device_id != host.device_id:
            self._book.remove(host.device_id)
            self._opener.remove_peer(host.device_id)
        if self._host_refused.is_set():
            raise PairingError("the host refused the pairing")
        raise PairingError("the host did not confirm the pairing")

    def pair_with_code(
        self, code: str, *, address: str | None = None, timeout: float = 10.0
    ) -> PeerInfo:
        """Pair with the host showing this 6-digit code (``host.pairing_offer().code``).

        The host is found with mDNS, or at *address* (``"ip:port"``). Returns the host.
        Raises :class:`PairingError` if the code is wrong, no host answers, or the host does
        not confirm within *timeout* seconds. Each try uses up one of the code's attempts.
        """
        if self._thread is None:
            raise PairingError("call start() before pair_with_code()")
        attempt = CodeAttempt(self.identity, self.name, code, app=self.app)
        targets = [address] if address else self._find_hosts()
        if not targets:
            raise PairingError("no host found on the network: pass address='ip:port'")
        while not self._code_replies.empty():
            self._code_replies.get_nowait()
        deadline = time.monotonic() + timeout
        found: tuple[PublicIdentity, str, bytes, str] | None = None
        while found is None and time.monotonic() < deadline:
            for target in targets:
                self._sock.sendto(_CODE + attempt.request(), _split(target))
            end = min(deadline, time.monotonic() + 1.0)
            while found is None and time.monotonic() < end:
                try:
                    raw, source = self._code_replies.get(timeout=max(0.0, end - time.monotonic()))
                except queue.Empty:
                    break
                try:
                    host_id, host_name, finish = attempt.answer(raw)
                except PairingError as e:
                    if "wrong pairing code" in str(e):
                        raise
                    continue
                found = (host_id, host_name, finish, source)
        if found is None:
            raise PairingError("no host answered: check the code and that it is still shown")
        host_id, host_name, finish, source = found
        previous = self.host
        host = PeerInfo(host_id.device_id, host_name, host_id, source)
        self._add_peer(host)
        self._pending = host.device_id
        self._confirmed.clear()
        while time.monotonic() < deadline:
            self._sock.sendto(_CODE + finish, _split(source))
            if self._wait_for_host(min(1.0, max(0.0, deadline - time.monotonic()))):
                if previous is not None and previous.device_id != host.device_id:
                    self._book.remove(previous.device_id)
                    self._opener.remove_peer(previous.device_id)
                self._host_id = host.device_id
                result = self._book.get(host.device_id)
                assert result is not None
                self._tell_session(result, force=True)
                return result
        if previous is None or previous.device_id != host.device_id:
            self._book.remove(host.device_id)
            self._opener.remove_peer(host.device_id)
        raise PairingError("the host did not confirm the pairing")

    def _find_hosts(self) -> list[str]:
        if not self._announce:
            return []
        from .discovery import browse

        return [d.address for d in browse(2.0, app=self.app) if d.device_id != self.device_id]

    def _on_code(self, payload: bytes, source: str) -> None:
        if self._code_replies.full():
            raise PairingError("too many pairing answers")
        self._code_replies.put((payload, source))

    def _wait_for_host(self, seconds: float) -> bool:
        end = time.monotonic() + seconds
        while time.monotonic() < end and not self._host_refused.is_set():
            if self._confirmed.wait(min(0.05, max(0.0, end - time.monotonic()))):
                return True
        return self._confirmed.is_set()

    def send(self, body: Any, *, ack: bool = False, timeout: float = 5.0, retries: int = 3) -> None:
        """Send *body* (any JSON value) to the host.

        With ``ack=True``, retry until the host confirms it, delivered once, or raise
        :class:`DeliveryError` after *timeout* seconds.
        """
        host = self.host
        if host is None:
            raise LookupError("not paired with a host yet: call pair() first")
        if ack:
            self._deliver(host.device_id, body, timeout, retries)
        else:
            self._send(host, {"msg": body})

    def request(self, body: Any, *, timeout: float = 5.0, retries: int = 3) -> Any:
        """Send *body* and return the host's ``reply()``, or raise DeliveryError."""
        host = self.host
        if host is None:
            raise LookupError("not paired with a host yet: call pair() first")
        return self._deliver(host.device_id, body, timeout, retries, request=True)

    def unpair(self) -> None:
        """Forget the host."""
        if self._host_id:
            self._book.remove(self._host_id)
            self._opener.remove_peer(self._host_id)
            self._host_id = None

    def _on_control(self, peer: PeerInfo, body: dict[str, Any]) -> None:
        if peer.device_id == self._pending and body.get("lanpair") == "pair-wait":
            self._host_waiting.set()
        elif peer.device_id == self._pending and body.get("lanpair") == "pair-refused":
            self._host_refused.set()
        elif body.get("lanpair") == "paired" and peer.device_id == self._pending:
            name = body.get("name")
            if isinstance(name, str) and name:
                self._book.put(PeerInfo(peer.device_id, name[:63], peer.identity, peer.address))
            self._confirmed.set()
