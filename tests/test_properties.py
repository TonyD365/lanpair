"""Property-based tests (Hypothesis): the guarantees hold for any input, not just examples."""

import json

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from lanpair import EnvelopeError, Identity, Opener, Sealer


class Clock:
    def __init__(self) -> None:
        self.t = 1_000_000.0

    def __call__(self) -> float:
        return self.t


DESK, ROOM = Identity.generate(), Identity.generate()
json_values = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**53), max_value=2**53)
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(),
    lambda children: st.lists(children) | st.dictionaries(st.text(), children),
    max_leaves=30,
)


def pair() -> tuple[Clock, Sealer, Opener]:
    clock = Clock()
    opener = Opener(ROOM, clock=clock)
    opener.add_peer(DESK.public)
    clock.t += 31  # past the start-up window
    return clock, Sealer(DESK, clock=clock), opener


@given(json_values)
def test_any_json_body_round_trips(body):
    _, sealer, opener = pair()
    peer, got = opener.open(sealer.seal(ROOM.public, body))
    assert peer == DESK.public and got == body


@settings(suppress_health_check=[HealthCheck.too_slow])
@given(st.binary(max_size=4096))
def test_arbitrary_bytes_only_ever_raise_envelope_error(raw):
    _, _, opener = pair()
    try:
        opener.open(raw)
    except EnvelopeError:
        pass  # anything else (RecursionError, KeyError, ...) fails the test


@given(st.data())
def test_any_single_byte_change_is_rejected_or_harmless(data):
    _, sealer, opener = pair()
    body = {"cmd": "close", "room": 3}
    raw = bytearray(sealer.seal(ROOM.public, body))
    i = data.draw(st.integers(0, len(raw) - 1))
    new = data.draw(st.integers(0, 255).filter(lambda b: b != raw[i]))
    raw[i] = new
    try:
        peer, got = opener.open(bytes(raw))
    except EnvelopeError:
        return
    # Accepted only if it still means exactly the same signed message.
    assert peer == DESK.public and got == body
    assert json.loads(bytes(raw))["sig"]  # still a complete envelope
