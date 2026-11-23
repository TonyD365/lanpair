import os

import pytest

from lanpair import Identity
from lanpair.discovery import FoundDevice, _parse, service_type

ID = "0123456789abcdef"


def test_service_type():
    assert service_type() == "_lanpair._tcp.local."
    assert service_type("my-app") == "_my-app._tcp.local."
    for bad in ["", "UPPER", "-x", "x-", "a" * 16, "a.b", "a_b"]:
        with pytest.raises(ValueError):
            service_type(bad)


def test_parse_valid():
    d = _parse({b"v": b"1", b"id": ID.encode(), b"name": b"Room 3"}, ["10.0.0.5"], 8765)
    assert d == FoundDevice(ID, "Room 3", ("10.0.0.5",), 8765)
    assert d.address == "10.0.0.5:8765"


def test_parse_ipv6_address_and_default_name():
    d = _parse({b"v": b"1", b"id": ID.encode()}, ["fe80::1%en0"], 1)
    assert d is not None and d.name == ID and d.address == "[fe80::1%en0]:1"


@pytest.mark.parametrize(
    "props, addrs, port",
    [
        ({b"id": ID.encode()}, ["10.0.0.5"], 1),  # no version
        ({b"v": b"2", b"id": ID.encode()}, ["10.0.0.5"], 1),  # unknown version
        ({b"v": b"1", b"id": b"zz"}, ["10.0.0.5"], 1),  # bad id
        ({b"v": b"1", b"id": ID.encode()}, [], 1),  # no address
        ({b"v": b"1", b"id": ID.encode()}, ["10.0.0.5"], 0),  # bad port
        ({b"v": b"1", b"id": ID.encode(), b"name": b"\xff"}, ["10.0.0.5"], 1),  # not UTF-8
    ],
)
def test_parse_rejects(props, addrs, port):
    assert _parse(props, addrs, port) is None


def test_long_name_cut():
    d = _parse({b"v": b"1", b"id": ID.encode(), b"name": b"x" * 500}, ["10.0.0.5"], 1)
    assert d is not None and len(d.name) == 63


@pytest.mark.skipif(
    not os.environ.get("LANPAIR_NETWORK_TESTS"), reason="set LANPAIR_NETWORK_TESTS=1 (multicast)"
)
def test_announce_and_find_on_this_machine():
    from lanpair.discovery import Announcer, find

    me = Identity.generate()
    with Announcer(me.public, "Test device", 54321, app="lanpair-test"):
        found = find(me.public.device_id, seconds=3, app="lanpair-test")
    assert found is not None and found.port == 54321 and found.name == "Test device"
