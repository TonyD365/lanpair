"""CPace, a balanced PAKE, with X25519 and SHA-512 (draft-irtf-cfrg-cpace-21).

Two parties who share a short secret, such as a 6-digit code, get a strong shared key. An
attacker who joins the exchange can test one guess of the code per run, and one who only
watches learns nothing about it. :mod:`lanpair.codepair` builds pairing on top of this.

Field arithmetic uses Python integers, which are not constant time; the only secret it
touches is the code, through the generator. See docs/design.md.
"""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

DSI = b"CPace255"
IDENTITY = bytes(32)  # G.I: the neutral element
_P = 2**255 - 19
_A = 486662
_Z = 2  # the non-square used by Elligator 2 for Curve25519
_S_IN_BYTES = 128  # SHA-512 input block size


class CPaceError(Exception):
    """The other party's share is invalid (a low-order point)."""


def prepend_len(data: bytes) -> bytes:
    """``data`` with its length in LEB128 in front."""
    length = len(data)
    out = bytearray()
    while True:
        if length < 128:
            out.append(length)
        else:
            out.append((length & 0x7F) | 0x80)
        length >>= 7
        if length == 0:
            return bytes(out) + data


def lv_cat(*parts: bytes) -> bytes:
    return b"".join(prepend_len(p) for p in parts)


def generator_string(prs: bytes, ci: bytes, sid: bytes) -> bytes:
    zpad = max(0, _S_IN_BYTES - 1 - len(prepend_len(prs)) - len(prepend_len(DSI)))
    return lv_cat(DSI, prs, bytes(zpad), ci, sid)


def _elligator2(r: int) -> int:
    v = (-_A * pow(1 + _Z * r * r, _P - 2, _P)) % _P
    eps = pow((v * v * v + _A * v * v + v) % _P, (_P - 1) // 2, _P)
    half_a = _A * pow(2, _P - 2, _P) % _P
    return (eps * v - (1 - eps) * half_a) % _P


def calculate_generator(prs: bytes, ci: bytes, sid: bytes) -> bytes:
    digest = hashlib.sha512(generator_string(prs, ci, sid)).digest()[:32]
    u = int.from_bytes(digest, "little") & ((1 << 255) - 1)  # decodeUCoordinate
    return _elligator2(u % _P).to_bytes(32, "little")


def scalar_mult(scalar: bytes, point: bytes) -> bytes:
    """X25519(scalar, point), or :data:`IDENTITY` for a low-order point."""
    try:
        key = X25519PrivateKey.from_private_bytes(scalar)
        return key.exchange(X25519PublicKey.from_public_bytes(point))
    except ValueError:  # the result is all zeros
        return IDENTITY


def transcript_ir(ya: bytes, ada: bytes, yb: bytes, adb: bytes) -> bytes:
    return lv_cat(ya, ada) + lv_cat(yb, adb)


def isk(sid: bytes, k: bytes, transcript: bytes) -> bytes:
    """The intermediate session key. Raises :class:`CPaceError` if K is the neutral element."""
    if k == IDENTITY:
        raise CPaceError("invalid share")
    return hashlib.sha512(lv_cat(DSI + b"_ISK", sid, k) + transcript).digest()
