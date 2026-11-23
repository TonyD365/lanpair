"""Host and Device over real UDP sockets on 127.0.0.1 (mDNS off, so it runs anywhere)."""

import time

import pytest

from lanpair import Device, Host, Identity, PairingError, PairingOffer


def make(cls, name, tmp_path, identity=None):
    node = cls(
        name,
        identity=identity or Identity.generate(),
        state_dir=tmp_path / name,
        announce=False,
        app="lanpair-test",
        bind="127.0.0.1",  # tests never listen beyond this machine
    )
    node.start()
    return node


@pytest.fixture
def pair(tmp_path):
    host = make(Host, "desk", tmp_path)
    dev = make(Device, "room3", tmp_path)
    offer = host.pairing_offer(address=f"127.0.0.1:{host.port}")
    dev.pair(offer.to_uri(), timeout=4)
    yield host, dev
    host.close()
    dev.close()


def wait(cond, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


def test_pairing_both_sides_know_each_other(pair):
    host, dev = pair
    assert dev.host is not None and dev.host.device_id == host.device_id
    assert dev.host.name == "desk"
    joined = host.wait_for_pairing(timeout=2)
    assert joined is not None and joined.device_id == dev.device_id and joined.name == "room3"
    assert [d.device_id for d in host.devices] == [dev.device_id]


def test_messages_both_ways(pair):
    host, dev = pair
    dev.send({"type": "hello", "n": [1, 2]})
    msg = host.receive(timeout=2)
    assert msg is not None and msg.body == {"type": "hello", "n": [1, 2]}
    assert msg.sender.device_id == dev.device_id
    host.send(dev.device_id, {"type": "close"})
    msg = dev.receive(timeout=2)
    assert msg is not None and msg.body == {"type": "close"}


def test_survives_restart_without_pairing_again(pair, tmp_path):
    host, dev = pair
    ids = host.identity, dev.identity
    import socket

    # A real message from the device, sent and recorded the way an eavesdropper would.
    sniffed = b"M" + dev._sealer.seal(host.identity.public, {"msg": "before restart"})
    attacker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    attacker.sendto(sniffed, ("127.0.0.1", host.port))
    assert host.receive(timeout=2).body == "before restart"
    host.close()
    dev.close()

    host2 = make(Host, "desk", tmp_path, identity=ids[0])
    dev2 = make(Device, "room3", tmp_path, identity=ids[1])
    try:
        assert host2.port == host.port  # same port as before: stored addresses stay right
        dev2.send("after restart")
        assert host2.receive(timeout=2).body == "after restart"
        # A message recorded before the restart is refused.
        attacker.sendto(sniffed, ("127.0.0.1", host2.port))
        assert wait(lambda: host2.dropped >= 1)
        assert host2.receive(timeout=0.5) is None
    finally:
        host2.close()
        dev2.close()


def test_garbage_and_forgeries_are_dropped(pair):
    host, dev = pair
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for junk in [b"", b"M", b"Mnot json", b"P{}", b"X" + b"[" * 8000, b"M" + b"{" * 8000]:
        s.sendto(junk, ("127.0.0.1", host.port))
    assert wait(lambda: host.dropped >= 6)
    dev.send("still works")
    assert host.receive(timeout=2).body == "still works"


def test_unpaired_device_is_ignored(pair):
    host, dev = pair
    host.unpair(dev.device_id)
    dev.send("ignored")
    assert wait(lambda: host.dropped >= 1)
    assert host.receive(timeout=0.5) is None
    with pytest.raises(LookupError):
        host.send(dev.device_id, "x")


def test_offer_is_single_use(pair, tmp_path):
    host, _ = pair
    offer = host.pairing_offer(address=f"127.0.0.1:{host.port}")
    second = make(Device, "room4", tmp_path)
    third = make(Device, "room5", tmp_path)
    try:
        second.pair(offer, timeout=2)
        with pytest.raises(PairingError, match="did not confirm"):
            third.pair(offer, timeout=2)
        assert third.host is None
        assert {d.name for d in host.devices} == {"room3", "room4"}
    finally:
        second.close()
        third.close()


def test_expired_and_foreign_offers_refused(tmp_path):
    host = make(Host, "desk", tmp_path)
    dev = make(Device, "room3", tmp_path)
    try:
        expired = host.pairing_offer(ttl=-1, address=f"127.0.0.1:{host.port}")
        with pytest.raises(PairingError, match="expired"):
            dev.pair(expired)
        other_app = PairingOffer.create(host.identity.public, "x", "127.0.0.1:1", app="other")
        with pytest.raises(PairingError, match="for app"):
            dev.pair(other_app)
    finally:
        host.close()
        dev.close()


def test_large_messages_go_over_tcp_both_ways(pair):
    host, dev = pair
    big = {"blob": "x" * 200_000, "n": list(range(1000))}
    address_before = host.devices[0].address
    dev.send(big)
    msg = host.receive(timeout=3)
    assert msg is not None and msg.body == big
    assert host.devices[0].address == address_before  # a TCP source port is not an address
    host.send(dev.device_id, big)
    msg = dev.receive(timeout=3)
    assert msg is not None and msg.body == big


def test_too_large_message_refused(pair):
    _, dev = pair
    with pytest.raises(ValueError, match="too large"):
        dev.send("x" * 2_000_000)


def tcp_send(port, data):
    import socket

    with socket.create_connection(("127.0.0.1", port), timeout=2) as c:
        c.sendall(data)


def test_bad_tcp_frames_dropped(pair):
    import struct

    host, dev = pair
    before = host.dropped
    tcp_send(host.port, struct.pack(">I", 10) + b"Mshort")  # ends early
    tcp_send(host.port, struct.pack(">I", 50_000_000))  # claims 50 MB
    tcp_send(host.port, struct.pack(">I", 0))
    tcp_send(host.port, struct.pack(">I", 6) + b"P{...}")  # pairing only over UDP
    tcp_send(host.port, struct.pack(">I", 5) + b"Mjunk")
    assert wait(lambda: host.dropped >= before + 5)
    dev.send("x" * 20_000)
    assert host.receive(timeout=3).body == "x" * 20_000


def test_idle_tcp_connections_do_not_block_others(pair):
    import socket

    host, dev = pair
    idle = [socket.create_connection(("127.0.0.1", host.port)) for _ in range(4)]
    try:
        dev.send("y" * 20_000)
        assert host.receive(timeout=3).body == "y" * 20_000
    finally:
        for c in idle:
            c.close()


def test_large_send_to_a_peer_that_is_down_raises(pair):
    host, dev = pair
    host.close()
    with pytest.raises(OSError):
        dev.send("z" * 20_000)


def test_send_before_pairing(tmp_path):
    dev = make(Device, "room3", tmp_path)
    try:
        with pytest.raises(LookupError):
            dev.send("x")
    finally:
        dev.close()


def test_keeps_receiving_after_sending_to_a_closed_port(pair):
    host, dev = pair
    import socket

    closed = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    joined = host.devices[0]
    host._book.put(
        type(joined)(joined.device_id, joined.name, joined.identity, f"127.0.0.1:{port}")
    )
    host.send(dev.device_id, "lost")  # Windows reports the closed port on the next receive
    time.sleep(0.3)
    dev.send("still listening")
    msg = host.receive(timeout=2)
    assert msg is not None, f"listener alive: {host._thread.is_alive()}, dropped: {host.dropped}"
    assert msg.body == "still listening"


def test_keeps_receiving_after_a_file_error(pair, monkeypatch):
    host, dev = pair
    put = host._book.put
    calls = []

    def fail_once(peer):
        calls.append(peer)
        if len(calls) == 1:
            raise PermissionError("state file is locked")
        put(peer)

    monkeypatch.setattr(host._book, "put", fail_once)
    dev.send("maybe lost")  # the failure may hit this or a control message still in flight
    assert wait(lambda: host.dropped > 0)
    assert host._thread.is_alive()
    dev.send("still listening")
    msg = host.receive(timeout=2)
    if msg is not None and msg.body == "maybe lost":
        msg = host.receive(timeout=2)
    assert msg is not None and msg.body == "still listening"


def test_bind_limits_the_listening_interface(tmp_path):
    host = make(Host, "desk", tmp_path)
    try:
        assert host._sock.getsockname()[0] == "127.0.0.1"
    finally:
        host.close()


def test_device_on_a_new_port_tells_the_host(pair, tmp_path):
    host, dev = pair
    identity = dev.identity
    dev.close()
    (tmp_path / "room3" / "node.json").unlink()  # as if its old port were gone
    import socket

    blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    blocker.bind(("127.0.0.1", 0))  # likely a different port next time anyway
    dev2 = make(Device, "room3", tmp_path, identity=identity)
    try:
        # The device's signed hello moves the host to its new address.
        assert wait(lambda: host.devices[0].address == f"127.0.0.1:{dev2.port}")
        host.send(dev2.device_id, "found you")
        assert dev2.receive(timeout=2).body == "found you"
    finally:
        dev2.close()
        blocker.close()


def test_saved_port_taken_falls_back_to_a_free_one(tmp_path):
    import socket

    host = make(Host, "desk", tmp_path)
    port = host.port
    host.close()
    squatter = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    squatter.bind(("127.0.0.1", port))
    try:
        host2 = make(Host, "desk", tmp_path, identity=host.identity)
        assert host2.port != port
        host2.close()
        host3 = make(Host, "desk", tmp_path, identity=host.identity)  # remembers the new one
        assert host3.port == host2.port
        host3.close()
    finally:
        squatter.close()


def test_port_kept_after_tcp_traffic(pair, tmp_path):
    host, dev = pair
    dev.send("x" * 20_000)  # over TCP: the host closes the connection (TIME_WAIT on its port)
    assert host.receive(timeout=3) is not None
    port, identity = host.port, host.identity
    host.close()
    host2 = make(Host, "desk", tmp_path, identity=identity)
    try:
        assert host2.port == port
        dev.send("after restart")
        assert host2.receive(timeout=3).body == "after restart"
    finally:
        host2.close()


def test_port_kept_after_rejected_tcp_frames(pair, tmp_path):
    import socket
    import struct

    host, dev = pair
    # The host rejects these and closes first, leaving TIME_WAIT on its own port.
    for _ in range(3):
        c = socket.create_connection(("127.0.0.1", host.port))
        c.sendall(struct.pack(">I", 50_000_000))
        time.sleep(0.2)  # let the host close before we do
        c.close()
    port, identity = host.port, host.identity
    host.close()
    host2 = make(Host, "desk", tmp_path, identity=identity)
    try:
        assert host2.port == port
    finally:
        host2.close()


# --- forward secrecy --------------------------------------------------------------------


def test_peers_learn_each_others_session_keys(pair):
    host, dev = pair
    assert wait(lambda: dev._peer_sessions.get(host.device_id) == host._session_key)
    assert wait(lambda: host._peer_sessions.get(dev.device_id) == dev._session_key)


def test_messages_cannot_be_read_with_the_seed_alone(pair):
    from lanpair import EnvelopeError, Opener

    host, dev = pair
    assert wait(lambda: host.device_id in dev._peer_sessions)
    session = dev._peer_sessions[host.device_id]
    recorded = dev._sealer.seal(host.identity.public, {"msg": "secret"}, box_key=session)
    thief = Opener(type(host.identity).from_seed(host.identity.seed()))
    thief.add_peer(dev.identity.public)
    thief._started = 0  # skip the start-up window: only decryption matters here
    with pytest.raises(EnvelopeError, match="cannot decrypt"):
        thief.open(recorded)


def test_session_keys_rotate_and_old_ones_are_dropped(pair):
    host, dev = pair
    assert wait(lambda: host.device_id in dev._peer_sessions)
    first = host._session_key
    host._session_rotate = 0.3
    assert wait(lambda: first not in host._opener._session_keys, timeout=5)
    assert wait(lambda: dev._peer_sessions.get(host.device_id) == host._session_key)
    host._session_rotate = 600.0
    dev.send("after rotation")
    assert host.receive(timeout=3).body == "after rotation"


def test_message_to_a_restarted_peer_is_resent_to_its_new_key(pair, tmp_path):
    host, dev = pair
    assert wait(lambda: host.device_id in dev._peer_sessions)
    identity = host.identity
    host.close()
    host2 = make(Host, "desk", tmp_path, identity=identity)  # new session keys
    try:
        dev.send("right after the restart")  # still sealed to the old session key
        msg = host2.receive(timeout=5)
        assert msg is not None and msg.body == "right after the restart"
        assert host2.receive(timeout=1) is None  # delivered once
    finally:
        host2.close()


def test_works_with_a_peer_without_session_keys(pair):
    host, dev = pair
    # As a 1.2 device would: never announces or learns session keys.
    dev._tell_session = lambda *a, **k: None
    dev._learn_session = lambda *a, **k: None
    dev._peer_sessions.clear()
    host._peer_sessions.pop(dev.device_id, None)
    dev.send("old style")
    assert host.receive(timeout=3).body == "old style"
    host.send(dev.device_id, "reply")
    assert dev.receive(timeout=3).body == "reply"


# --- reliable delivery, requests, broadcast, pairing code, asyncio ---------------------


def test_ack_delivers_once_despite_lost_ack(pair):
    host, dev = pair
    real = dev._on_ack
    dropped = []

    def lose_first(peer, body):
        if not dropped:
            dropped.append(body)
            return
        real(peer, body)

    dev._on_ack = lose_first
    dev.send("close", ack=True, timeout=2, retries=3)
    assert host.receive(timeout=1).body == "close"
    assert host.receive(timeout=0.3) is None


def test_ack_times_out_when_peer_is_gone(pair):
    from lanpair import DeliveryError

    host, dev = pair
    host.close()
    with pytest.raises(DeliveryError):
        dev.send("close", ack=True, timeout=0.4, retries=1)


def test_request_reply_both_ways(pair):
    import threading

    host, dev = pair

    def answer(node):
        msg = node.receive(timeout=3)
        node.reply(msg, {"echo": msg.body})

    threading.Thread(target=answer, args=(host,), daemon=True).start()
    assert dev.request("ping", timeout=3) == {"echo": "ping"}
    threading.Thread(target=answer, args=(dev,), daemon=True).start()
    assert host.request(dev.device_id, "pong", timeout=3) == {"echo": "pong"}


def test_lost_reply_is_sent_again_without_redelivery(pair):
    import threading

    host, dev = pair
    real = dev._on_reply
    lost = []

    def lose_first(peer, body):
        if not lost:
            lost.append(body)
            return
        real(peer, body)

    dev._on_reply = lose_first

    def answer():
        msg = host.receive(timeout=3)
        host.reply(msg, "done")

    threading.Thread(target=answer, daemon=True).start()
    assert dev.request("work", timeout=3, retries=5) == "done"
    assert host.receive(timeout=0.3) is None


def test_reply_needs_a_request(pair):
    host, dev = pair
    dev.send("plain")
    msg = host.receive(timeout=2)
    assert tuple(msg) == (msg.sender, "plain")
    with pytest.raises(ValueError):
        host.reply(msg, "x")


def test_broadcast_reports_each_device(pair, tmp_path):
    host, dev = pair
    other = make(Device, "room4", tmp_path)
    other.pair(host.pairing_offer(address=f"127.0.0.1:{host.port}"), timeout=3)
    try:
        result = host.broadcast("closing", ack=True, timeout=2)
        assert result == {dev.device_id: True, other.device_id: True}
        assert dev.receive(timeout=1).body == "closing"
        assert other.receive(timeout=1).body == "closing"
        other_id = other.device_id
        other.close()
        assert host.broadcast("again", ack=True, timeout=0.4, retries=1)[other_id] is False
    finally:
        other.close()


def test_pairing_code_matches_on_both_sides(tmp_path):
    host = make(Host, "desk", tmp_path)
    dev = make(Device, "room3", tmp_path)
    codes = []
    try:
        offer = host.pairing_offer(
            address=f"127.0.0.1:{host.port}", confirm=lambda c: codes.append(c) or True
        )
        dev.pair(offer.to_uri(), timeout=4, confirm=lambda c: codes.append(c) or True)
        assert len(codes) == 2 and codes[0] == codes[1] and len(codes[0]) == 7
        assert host.wait_for_pairing(timeout=2) is not None
    finally:
        host.close()
        dev.close()


def test_host_can_reject_the_pairing_code(tmp_path):
    host = make(Host, "desk", tmp_path)
    dev = make(Device, "room3", tmp_path)
    try:
        offer = host.pairing_offer(address=f"127.0.0.1:{host.port}", confirm=lambda c: False)
        with pytest.raises(PairingError, match="refused"):
            dev.pair(offer.to_uri(), timeout=4)
        assert host.devices == [] and dev.host is None
    finally:
        host.close()
        dev.close()


def test_device_can_reject_the_pairing_code(tmp_path):
    host = make(Host, "desk", tmp_path)
    dev = make(Device, "room3", tmp_path)
    try:
        offer = host.pairing_offer(address=f"127.0.0.1:{host.port}")
        with pytest.raises(PairingError, match="not confirmed"):
            dev.pair(offer.to_uri(), timeout=4, confirm=lambda c: False)
        assert dev.host is None
        assert wait(lambda: host.devices == [])
    finally:
        host.close()
        dev.close()


def test_asyncio_api(tmp_path):
    import asyncio

    from lanpair import AsyncDevice, AsyncHost

    kw = {"announce": False, "bind": "127.0.0.1", "app": "lanpair-test"}

    async def main():
        host = AsyncHost("desk", identity=Identity.generate(), state_dir=tmp_path / "h", **kw)
        dev = AsyncDevice("room", identity=Identity.generate(), state_dir=tmp_path / "d", **kw)
        async with host, dev:
            offer = host.pairing_offer(address=f"127.0.0.1:{host.port}")
            await dev.pair(offer.to_uri(), timeout=4)

            async def serve():
                msg = await host.receive(timeout=3)
                await host.reply(msg, msg.body + 1)

            task = asyncio.create_task(serve())
            assert await dev.request(41, timeout=3) == 42
            await task
            await host.broadcast("hi", ack=True, timeout=2)
            assert (await dev.receive(timeout=2)).body == "hi"

    asyncio.run(main())
