"""Secure pairing and signed messaging between devices on the same LAN."""

from .envelope import (
    EnvelopeError,
    JsonFileSeqStore,
    MemorySeqStore,
    Opener,
    Sealer,
    SeqStore,
)
from .identity import Identity, PublicIdentity
from .keystore import KeyStoreError, load_or_create_identity

__all__ = [
    "EnvelopeError",
    "Identity",
    "JsonFileSeqStore",
    "KeyStoreError",
    "MemorySeqStore",
    "Opener",
    "PublicIdentity",
    "Sealer",
    "SeqStore",
    "load_or_create_identity",
]
__version__ = "1.0.0rc1"
