"""6-digit code pairing: the protocol, without the network."""

import json

import pytest

from lanpair import Identity, PairingError
from lanpair.codepair import CodeAttempt, CodeSession, normalize


class Clock:
    t = 1000.0

    def __call__(self):
        return self.t


def run(session, attempt):
    reply = session.start(attempt.request())
    host, name, finish = attempt.answer(reply)
    return host, name, session.finish(finish)


def test_right_code_pairs_both_ways():
    host, dev = Identity.generate(), Identity.generate()
    s = CodeSession(host, "desk", "123456")
    got_host, name, (got_dev, dev_name) = run(s, CodeAttempt(dev, "room 3", "123 456"))
    assert got_host == host.public and name == "desk"
    assert got_dev == dev.public and dev_name == "room 3"
    assert not s.open


def test_wrong_code_fails_on_both_sides_and_counts():
    host, dev = Identity.generate(), Identity.generate()
    s = CodeSession(host, "desk", "123456", max_attempts=2)
    a = CodeAttempt(dev, "room", "654321")
    with pytest.raises(PairingError, match="wrong pairing code"):
        a.answer(s.start(a.request()))
    b = CodeAttempt(dev, "room", "000000")
    reply = s.start(b.request())
    assert not s.open  # two runs used up the attempts
    with pytest.raises(PairingError):
        s.start(CodeAttempt(dev, "room", "123456").request())
    with pytest.raises(PairingError):
        b.answer(reply)


def test_resent_first_message_is_not_a_new_attempt():
    s = CodeSession(Identity.generate(), "desk", "123456", max_attempts=1)
    a = CodeAttempt(Identity.generate(), "room", "123456")
    first = s.start(a.request())
    assert s.start(a.request()) == first
    s.finish(a.answer(first)[2])


def test_expired_code_is_refused():
    clock = Clock()
    s = CodeSession(Identity.generate(), "desk", "123456", ttl=300, clock=clock)
    clock.t += 301
    with pytest.raises(PairingError, match="expired"):
        s.start(CodeAttempt(Identity.generate(), "room", "123456").request())


def test_one_device_per_code():
    s = CodeSession(Identity.generate(), "desk", "123456")
    run(s, CodeAttempt(Identity.generate(), "a", "123456"))
    with pytest.raises(PairingError):
        s.start(CodeAttempt(Identity.generate(), "b", "123456").request())


def test_swapped_host_key_is_detected():
    """A man in the middle who replaces the host's identity breaks the tag."""
    host, dev, mallory = Identity.generate(), Identity.generate(), Identity.generate()
    s = CodeSession(host, "desk", "123456")
    a = CodeAttempt(dev, "room", "123456")
    reply = json.loads(s.start(a.request()))
    from lanpair.codepair import _ad, _b64

    reply["ad"] = _b64(_ad(mallory.public, "desk"))
    with pytest.raises(PairingError, match="wrong pairing code"):
        a.answer(json.dumps(reply).encode())


def test_swapped_device_key_is_detected():
    """Replacing the device's identity in step 1 makes the host's tag useless to it."""
    host, dev, mallory = Identity.generate(), Identity.generate(), Identity.generate()
    s = CodeSession(host, "desk", "123456")
    a = CodeAttempt(dev, "room", "123456")
    req = json.loads(a.request())
    from lanpair.codepair import _ad, _b64

    req["ad"] = _b64(_ad(mallory.public, "room"))
    with pytest.raises(PairingError, match="wrong pairing code"):
        a.answer(s.start(json.dumps(req).encode()))


def test_device_must_hold_its_key():
    host, dev, other = Identity.generate(), Identity.generate(), Identity.generate()
    s = CodeSession(host, "desk", "123456")
    a = CodeAttempt(dev, "room", "123456")
    finish = json.loads(a.answer(s.start(a.request()))[2])
    from lanpair.codepair import _b64

    finish["sig"] = _b64(other.sign(b"x"))
    with pytest.raises(PairingError, match="signature"):
        s.finish(json.dumps(finish).encode())


def test_low_order_share_is_refused():
    s = CodeSession(Identity.generate(), "desk", "123456")
    a = CodeAttempt(Identity.generate(), "room", "123456")
    req = json.loads(a.request())
    from lanpair.codepair import _b64

    req["y"] = _b64(bytes(32))
    with pytest.raises(PairingError, match="invalid"):
        s.start(json.dumps(req).encode())


def test_app_is_bound():
    s = CodeSession(Identity.generate(), "desk", "123456", app="a")
    a = CodeAttempt(Identity.generate(), "room", "123456", app="b")
    with pytest.raises(PairingError):
        a.answer(s.start(a.request()))


@pytest.mark.parametrize("bad", ["12345", "1234567", "12a456", "١٢٣٤٥٦", ""])
def test_code_format(bad):
    with pytest.raises(PairingError):
        normalize(bad)


@pytest.mark.parametrize(
    "raw",
    [b"", b"{", b"[]", b'{"t":"code1"}', b'{"t":"code1","sid":"x","y":"y","ad":"z"}', b"[" * 5000],
)
def test_garbage_is_a_pairing_error(raw):
    s = CodeSession(Identity.generate(), "desk", "123456")
    with pytest.raises(PairingError):
        s.start(raw)
    with pytest.raises(PairingError):
        s.finish(raw)
