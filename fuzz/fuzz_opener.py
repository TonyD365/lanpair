"""Coverage-guided fuzzing of Opener.open with Atheris.

Anything other than EnvelopeError (a crash, RecursionError, KeyError, ...) is a bug.
Starts from the valid and invalid envelopes in fuzz/corpus (made for the keys below) and
a JSON dictionary, so mutations get past the JSON parser into lanpair's own checks.
Run: python fuzz/fuzz_opener.py work-dir fuzz/corpus -dict=fuzz/json.dict -max_total_time=60
"""

import sys

import atheris

with atheris.instrument_imports():
    from lanpair import EnvelopeError, Identity, MemorySeqStore, Opener

DESK, ROOM = Identity.from_seed(bytes(32)), Identity.from_seed(bytes([1]) * 32)
OPENER = Opener(ROOM, max_skew=1e12, clock=lambda: 2e12)
OPENER._started = -1e12  # no start-up window: let fuzzed envelopes reach every check
OPENER.add_peer(DESK.public)


def test_one_input(data: bytes) -> None:
    OPENER.store = MemorySeqStore()  # every input is new, so valid ones reach decryption
    try:
        OPENER.open(data)
    except EnvelopeError:
        pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
