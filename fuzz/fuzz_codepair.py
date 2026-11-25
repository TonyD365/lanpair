"""Coverage-guided fuzzing of the 6-digit code pairing messages with Atheris.

Anything other than PairingError is a bug. Both the host's steps and the device's check of
the host's answer get the same input.
Run: python fuzz/fuzz_codepair.py work-dir -dict=fuzz/json.dict -max_total_time=60
"""

import sys

import atheris

with atheris.instrument_imports():
    from lanpair import Identity, PairingError
    from lanpair.codepair import CodeAttempt, CodeSession

HOST, DEVICE = Identity.from_seed(bytes(32)), Identity.from_seed(bytes([1]) * 32)
ATTEMPT = CodeAttempt(DEVICE, "room", "123456")


def test_one_input(data: bytes) -> None:
    session = CodeSession(HOST, "desk", "123456", max_attempts=10**9)
    for step in (session.start, session.finish, ATTEMPT.answer):
        try:
            step(data)
        except PairingError:
            pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
